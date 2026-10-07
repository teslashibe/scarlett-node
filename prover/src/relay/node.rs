//! Supplier side of a relay session: `scarlett-prover relay-x` and
//! `scarlett-prover relay-web`.
//!
//! The supplier opens the TCP connection to X, so X sees its address, and
//! carries the verifier's TLS session over it. It holds no session key. Its
//! only cryptographic act is to place its cookie and CSRF values into the one
//! request record the verifier sealed and finish that record's tag.
//!
//! A web hop is the same session to the address the node checked, with
//! nothing hidden: the supplier sends the canonical request for the hop,
//! still checks the opened record against it, and learns only the hop's
//! status and next URL, never the page. A `web-browser-v1` hop's request
//! also carries the node's User-Agent and clearance cookies, which the node
//! passes in `node_headers` and the verifier sees.

use std::{
    net::IpAddr,
    ops::Range,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};

use super::{
    MAX_REQUEST, VERSION,
    ot::NodeOt,
    record, tag,
    wire::{self, CHUNK},
};
use crate::{
    dial,
    diagnostics::{Outcome, Phase, Run, Snapshot, Trace},
    policy::find,
    webpolicy,
    xpolicy::{self, HOST},
    xprove::{MAX_RECV, Request},
};

/// Largest protected record the verifier may send before the request: its
/// TLS 1.3 Finished under SHA-256 is 53 bytes, far too small to matter if a
/// verifier put anything else there, and the server accepts nothing else first.
const MAX_FINISHED: usize = 64;

/// What the verifier may have the supplier write to X: its handshake and
/// nothing else. The verifier holds the session keys, so without this it
/// could send requests of its own from the supplier's address.
#[derive(Default)]
struct Handshake {
    buffer: Vec<u8>,
    hellos: usize,
    change_cipher_spec: bool,
    finished: bool,
    /// Keep the host out of errors, which the node may log.
    quiet: bool,
}

impl Handshake {
    /// Takes bytes from the verifier and returns the whole records among
    /// them that may go to the server. Anything outside a TLS 1.3 client
    /// handshake for `host` is refused.
    fn admit(&mut self, bytes: &[u8], host: &str) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some((kind, record)) = record::take(&mut self.buffer)? {
            match kind {
                // A ClientHello, or its repeat after a HelloRetryRequest.
                record::HANDSHAKE if self.hellos < 2 && !self.finished => {
                    if client_hello_name(&record[5..]) != Some(host.as_bytes()) {
                        if self.quiet {
                            bail!("verifier's handshake is not a ClientHello for this hop's host");
                        }
                        bail!("verifier's handshake is not a ClientHello for {host}");
                    }
                    self.hellos += 1;
                }
                record::CHANGE_CIPHER_SPEC if !self.change_cipher_spec && record[5..] == [1] => self.change_cipher_spec = true,
                record::APPLICATION_DATA if self.hellos > 0 && !self.finished && record.len() <= 5 + MAX_FINISHED => self.finished = true,
                _ => bail!("verifier tried to send more than its handshake"),
            }
            out.extend_from_slice(&record);
        }
        Ok(out)
    }
}

/// The single DNS name in a ClientHello's server_name extension, if `message`
/// is exactly one well-formed ClientHello that carries one.
fn client_hello_name(message: &[u8]) -> Option<&[u8]> {
    fn take<'a>(at: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        let (head, rest) = at.split_at_checked(n)?;
        *at = rest;
        Some(head)
    }
    fn vector<'a>(at: &mut &'a [u8], width: usize) -> Option<&'a [u8]> {
        let len = take(at, width)?.iter().fold(0usize, |n, &b| n << 8 | b as usize);
        take(at, len)
    }
    let mut at = message;
    if take(&mut at, 1)? != [1] {
        return None;
    }
    let mut body = vector(&mut at, 3)?;
    if !at.is_empty() {
        return None;
    }
    take(&mut body, 2 + 32)?; // legacy version and random
    vector(&mut body, 1)?; // session id
    vector(&mut body, 2)?; // cipher suites
    vector(&mut body, 1)?; // compression methods
    let mut extensions = vector(&mut body, 2)?;
    if !body.is_empty() {
        return None;
    }
    let mut name = None;
    while !extensions.is_empty() {
        let kind = take(&mut extensions, 2)?;
        let mut data = vector(&mut extensions, 2)?;
        if kind == [0, 0] {
            let mut list = vector(&mut data, 2)?;
            if name.is_some() || !data.is_empty() || take(&mut list, 1)? != [0] {
                return None;
            }
            name = Some(vector(&mut list, 2)?);
            if !list.is_empty() {
                return None;
            }
        }
    }
    name
}

#[derive(Serialize)]
pub struct Summary {
    /// Untrusted operational TCP payload counters, never billing or proof evidence.
    #[serde(flatten)]
    pub verifier_transport: crate::control::TrafficSnapshot,
    pub status: &'static str,
    /// Base64 of X's complete HTTP response as the verifier decrypted it.
    pub response: String,
    pub sent_bytes: usize,
    pub received_bytes: usize,
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Snapshot>,
}

pub async fn run(request: Request) -> Result<Summary> {
    let diagnostics = Run::new();
    let mut summary = run_observed(request, &diagnostics.trace()).await?;
    summary.diagnostics = Some(diagnostics.success());
    Ok(summary)
}

async fn run_observed(request: Request, trace: &Trace) -> Result<Summary> {
    let raw = STANDARD.decode(request.request.as_bytes()).context("request is not base64")?;
    if raw.len() > MAX_REQUEST || !raw.starts_with(b"GET /i/api/graphql/") {
        bail!("request must be an X GraphQL GET of at most {MAX_REQUEST} bytes");
    }
    if request.token.len() != 64 || !request.token.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("verifier token must be 64 hex characters");
    }
    let started = Instant::now();
    // Reach X first: presenting the token spends one of the job's attempts.
    let server = trace.measure(Phase::XTcpConnect, async { TcpStream::connect((HOST, 443)).await.context("x.com unreachable") }).await?;
    server.set_nodelay(true)?;
    let (mut socket, traffic) = crate::control::connect_observed(&request.verifier, request.verifier_ca_file.as_deref(), request.plaintext_fixture, Some(trace)).await?;
    socket.write_all(format!("{}\n", request.token).as_bytes()).await?;
    let response = trace.measure(Phase::RelaySession, async {
        tokio::time::timeout(std::time::Duration::from_secs(120), session_observed(socket, server, &raw, HOST, trace)).await.context("relay session timed out")?
    }).await?;
    Ok(Summary {
        verifier_transport: traffic.snapshot(),
        status: "proof_sent",
        received_bytes: response.len(),
        response: STANDARD.encode(&response),
        sent_bytes: raw.len(),
        duration_ms: started.elapsed().as_millis(),
        diagnostics: None,
    })
}

/// Input of `scarlett-prover relay-web`: one hop of a web job, to the
/// address the node resolved and checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebRequest {
    pub verifier: String,
    pub verifier_ca_file: Option<String>,
    #[serde(default)]
    pub plaintext_fixture: bool,
    pub token: String,
    pub hop: u32,
    pub url: String,
    pub ip: String,
    pub port: u16,
    pub proxy: Option<dial::Proxy>,
    pub payload: serde_json::Value,
    /// Required for a `web-browser-v1` job and refused otherwise; `null` is
    /// refused too. Its values are never printed.
    #[serde(default, deserialize_with = "webpolicy::present")]
    pub node_headers: Option<webpolicy::NodeHeaders>,
    pub timeout_ms: u64,
}

#[derive(Serialize)]
pub struct WebSummary {
    /// Untrusted operational TCP payload counters, never billing or proof evidence.
    #[serde(flatten)]
    pub verifier_transport: crate::control::TrafficSnapshot,
    pub status: &'static str,
    pub hop: u32,
    /// The hop URL the verifier reported, already checked against the input.
    pub url: String,
    pub status_code: u16,
    #[serde(rename = "final")]
    pub is_final: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_url: Option<String>,
    /// TCP payload bytes to and from the target (TLS records, or the tunnel).
    pub target_sent_bytes: u64,
    pub target_received_bytes: u64,
    pub duration_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<Snapshot>,
}

/// A failed hop: `class` is what the node maps to a failure code
/// (`connect_failed`, `proxy_failed` or `fetch_failed`).
pub struct WebError {
    pub class: &'static str,
    pub error: anyhow::Error,
}

impl WebError {
    fn fetch(error: anyhow::Error) -> Self {
        Self { class: "fetch_failed", error }
    }
}

pub async fn run_web(input: &[u8]) -> Result<WebSummary, WebError> {
    let diagnostics = Run::new();
    let mut summary = run_web_observed(input, &diagnostics.trace()).await?;
    summary.diagnostics = Some(diagnostics.success());
    Ok(summary)
}

/// Defense in depth only: the node's egress check is the authority on
/// which addresses a job may reach.
fn public_address(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_link_local() || v4.is_private() || v4.is_broadcast() || a == 0 || (a == 100 && b & 0xc0 == 64))
        }
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || v6.is_unicast_link_local() || v6.is_unique_local()),
    }
}

/// Checks a hop request before any connection and returns the hop's
/// request bytes, the target and the timeout. Errors name the rule,
/// never the URL, address or a node header value.
fn validate_hop(request: &WebRequest) -> Result<(Vec<u8>, IpAddr, Duration)> {
    if request.token.len() != 64 || !request.token.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("verifier token must be 64 hex characters");
    }
    let job = webpolicy::validate_job(&request.payload)?;
    if webpolicy::canonical_url(&request.url).ok().as_deref() != Some(request.url.as_str()) {
        bail!("hop URL must be a canonical public https URL");
    }
    if request.hop as usize > job.max_redirects || (request.hop == 0 && request.url != job.url) {
        bail!("hop does not belong to this job");
    }
    let raw = job.hop_request(&request.url, request.node_headers.as_ref())?;
    let ip: IpAddr = request.ip.parse().ok().context("target must be an IP address literal")?;
    if !public_address(ip) {
        bail!("target address is not public");
    }
    if request.port != 443 {
        bail!("target port must be 443");
    }
    if !(1000..=webpolicy::HOP_LIMIT.as_millis() as u64).contains(&request.timeout_ms) {
        bail!("timeout_ms must be 1000-30000");
    }
    Ok((raw, ip, Duration::from_millis(request.timeout_ms)))
}

async fn run_web_observed(input: &[u8], trace: &Trace) -> Result<WebSummary, WebError> {
    let request: WebRequest = serde_json::from_slice(input).context("invalid relay-web input").map_err(WebError::fetch)?;
    let (raw, ip, timeout) = validate_hop(&request).map_err(WebError::fetch)?;
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + timeout;
    let host = webpolicy::url_host(&request.url);
    // Reach the target first: presenting the token spends one of the job's sessions.
    let dial_class = if request.proxy.is_some() { "proxy_failed" } else { "connect_failed" };
    let server = match tokio::time::timeout_at(deadline, trace.measure(Phase::XTcpConnect, dial::target(ip, request.port, request.proxy.as_ref()))).await {
        Ok(Ok(server)) => server,
        Ok(Err(dial::Error::Connect(error))) => return Err(WebError { class: "connect_failed", error }),
        Ok(Err(dial::Error::Proxy(error))) => return Err(WebError { class: "proxy_failed", error }),
        Err(_) => return Err(WebError { class: dial_class, error: anyhow::anyhow!("target connection timed out") }),
    };
    let (server, target) = crate::control::metered(server);
    let session = async {
        let (mut socket, traffic) = crate::control::connect_observed(&request.verifier, request.verifier_ca_file.as_deref(), request.plaintext_fixture, Some(trace)).await?;
        socket.write_all(format!("{}\n", request.token).as_bytes()).await?;
        let outcome = trace.measure(Phase::RelaySession, web_session(socket, server, &raw, host, request.hop, &request.url, trace)).await?;
        anyhow::Ok((outcome, traffic))
    };
    let (outcome, traffic) = match tokio::time::timeout_at(deadline, session).await {
        Ok(result) => result.map_err(WebError::fetch)?,
        Err(_) => return Err(WebError::fetch(anyhow::anyhow!("relay session timed out"))),
    };
    let (target_sent_bytes, target_received_bytes) = target.bytes();
    Ok(WebSummary {
        verifier_transport: traffic.snapshot(),
        status: "proof_sent",
        hop: outcome.hop,
        url: outcome.url,
        status_code: outcome.status_code,
        is_final: outcome.is_final,
        next_url: outcome.next_url,
        target_sent_bytes,
        target_received_bytes,
        duration_ms: started.elapsed().as_millis(),
        diagnostics: None,
    })
}

/// The hidden ranges of a request and the bytes in them.
fn secrets(raw: &[u8]) -> Result<(Vec<Range<usize>>, Vec<u8>)> {
    let head_end = find(raw, b"\r\n\r\n").context("request has no header terminator")?;
    let hidden = xpolicy::secret_spans(raw, head_end)?.into_iter().filter(|range| !range.is_empty()).collect::<Vec<_>>();
    let secret = hidden.iter().flat_map(|range| raw[range.clone()].to_vec()).collect();
    Ok((hidden, secret))
}

enum Event {
    Frame(u8, Vec<u8>),
    Server(Vec<u8>),
    ServerEof,
    Failed(anyhow::Error),
}

/// Runs the session over an established verifier socket and a connection to
/// `host`, and returns the response the verifier decrypted.
#[cfg(test)]
pub async fn session<V, X>(verifier: V, server: X, raw: &[u8], host: &str) -> Result<Vec<u8>>
where
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    X: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    session_observed(verifier, server, raw, host, &Trace::new()).await
}

pub(crate) async fn session_observed<V, X>(verifier: V, server: X, raw: &[u8], host: &str, trace: &Trace) -> Result<Vec<u8>>
where
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    X: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    exchange(verifier, server, raw, host, Mode::X, trace).await.map(|(response, _)| response)
}

/// Runs one web hop over an established verifier socket and a connection to
/// the target, and returns what the verifier reported for it. `raw` is the
/// canonical request for `url`, hop number `hop`.
pub(crate) async fn web_session<V, X>(verifier: V, server: X, raw: &[u8], host: &str, hop: u32, url: &str, trace: &Trace) -> Result<HopOutcome>
where
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    X: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (_, outcome) = exchange(verifier, server, raw, host, Mode::Web { hop, url }, trace).await?;
    outcome.context("verifier finished without reporting the hop")
}

#[derive(Clone, Copy)]
enum Mode<'a> {
    X,
    Web { hop: u32, url: &'a str },
}

/// What the verifier reports about a web hop once the supplier has checked
/// the opened request record.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HopOutcome {
    pub hop: u32,
    pub url: String,
    pub status_code: u16,
    #[serde(rename = "final")]
    pub is_final: bool,
    pub next_url: Option<String>,
}

async fn exchange<V, X>(verifier: V, server: X, raw: &[u8], host: &str, mode: Mode<'_>, trace: &Trace) -> Result<(Vec<u8>, Option<HopOutcome>)>
where
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    X: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let web = matches!(mode, Mode::Web { .. });
    // These begin together. Authorization is the locally observed wait until
    // MATERIAL confirms readiness; it also includes any remaining TLS/OT work.
    let mut authorization = Some(trace.span(Phase::RelayAuthorization));
    let mut tls_ready = Some(trace.span(Phase::XTlsReady));
    let mut ot_ready = Some(trace.span(Phase::OtReady));
    // A web request is public: nothing in it is hidden from the verifier.
    let (hidden, secret) = if web { (Vec::new(), Vec::new()) } else { secrets(raw)? };
    let bits = tag::hidden_bits(raw.len(), &hidden)?;
    let mut public = raw.to_vec();
    hidden.iter().for_each(|range| public[range.clone()].fill(0));

    let (mut from_verifier, mut to_verifier) = tokio::io::split(verifier);
    let (mut from_server, mut to_server) = tokio::io::split(server);
    let (events, mut inbox) = mpsc::channel(16);
    let frames = events.clone();
    let frame_reader = tokio::spawn(async move {
        loop {
            let event = match wire::recv(&mut from_verifier).await {
                Ok((kind, payload)) => Event::Frame(kind, payload),
                Err(e) => Event::Failed(e.context("verifier connection ended")),
            };
            let stop = matches!(event, Event::Failed(_));
            if frames.send(event).await.is_err() || stop {
                break;
            }
        }
    });
    let server_reader = tokio::spawn(async move {
        let mut chunk = vec![0u8; CHUNK];
        loop {
            let event = match from_server.read(&mut chunk).await {
                Ok(0) | Err(_) => Event::ServerEof,
                Ok(n) => Event::Server(chunk[..n].to_vec()),
            };
            let stop = matches!(event, Event::ServerEof);
            if events.send(event).await.is_err() || stop {
                break;
            }
        }
    });
    let _readers = Abort(vec![frame_reader.abort_handle(), server_reader.abort_handle()]);

    wire::send(&mut to_verifier, wire::HELLO, format!("{{\"version\":{VERSION},\"transfers\":{bits}}}").as_bytes()).await?;
    let mut ot = None;
    let mut received = None;
    if bits > 0 {
        let (state, (kind, setup)) = NodeOt::start(bits)?;
        wire::send(&mut to_verifier, kind, &setup).await?;
        ot = Some(state);
    } else {
        send_request(&mut to_verifier, &public, &hidden, &[]).await?;
        ot_ready.take().expect("OT readiness is pending").finish(Outcome::Success);
        received = Some(Vec::new());
    }

    let mut handshake = Handshake { quiet: web, ..Handshake::default() };
    let mut record_sent = false;
    let mut sealed: Option<Vec<u8>> = None;
    let mut checked = false;
    let mut response = Vec::new();
    let mut response_last_byte = None;
    let mut outcome: Option<HopOutcome> = None;
    while let Some(event) = inbox.recv().await {
        match event {
            Event::Failed(e) => {
                if record_sent && !checked {
                    return Err(e.context(format!("{MISUSE}: the session ended before it opened the request record")));
                }
                return Err(e);
            }
            // Once the response is whole the verifier stops reading, so a late
            // write to it may fail while its result is still on the way here.
            Event::Server(bytes) => {
                // The supplier never sees a web page, only when its records start to arrive.
                if web && record_sent && !bytes.is_empty() && response_last_byte.is_none() {
                    trace.milestone(Phase::ResponseFirstByte);
                    response_last_byte = Some(Instant::now());
                }
                let sent = wire::send(&mut to_verifier, wire::FROM_SERVER, &bytes).await;
                if !record_sent {
                    sent?;
                }
            }
            Event::ServerEof => {
                let sent = wire::send(&mut to_verifier, wire::SERVER_EOF, &[]).await;
                if !record_sent {
                    sent?;
                }
            }
            Event::Frame(wire::CO_CHOOSE, payload) => {
                for (kind, frame) in ot.as_mut().context("unexpected base-OT choice")?.on_choose(&payload)? {
                    wire::send(&mut to_verifier, kind, &frame).await?;
                }
            }
            Event::Frame(wire::KOS_CHI, payload) => {
                let ot = ot.as_mut().context("unexpected OT challenge")?;
                let (kind, check) = ot.on_chi(&payload)?;
                wire::send(&mut to_verifier, kind, &check).await?;
                let (choices, blocks) = ot.take(bits)?;
                if let Some(span) = ot_ready.take() {
                    span.finish(Outcome::Success);
                }
                send_request(&mut to_verifier, &public, &hidden, &tag::corrections(&secret, &choices)?).await?;
                received = Some(blocks);
            }
            Event::Frame(wire::TO_SERVER, payload) => {
                // Only the verifier's handshake travels this way, and nothing
                // at all once the request record is out.
                if record_sent {
                    bail!("verifier tried to send more than its handshake");
                }
                to_server.write_all(&handshake.admit(&payload, host)?).await?;
                if handshake.finished && let Some(span) = tls_ready.take() {
                    span.finish(Outcome::Success);
                }
            }
            Event::Frame(wire::MATERIAL, payload) => {
                if !handshake.finished {
                    bail!("verifier sent request material before finishing its handshake");
                }
                let blocks = received.take().context("verifier sent request material twice or before the request")?;
                let material = parse_material(&payload, public.len(), bits)?;
                if let Some(span) = authorization.take() {
                    span.finish(Outcome::Success);
                }
                let record = tag::node_record(&material, &hidden, &secret, &blocks)?;
                to_server.write_all(&record).await?;
                to_server.flush().await?;
                record_sent = true;
                trace.milestone(Phase::RequestSent);
                sealed = Some(record);
            }
            Event::Frame(wire::PLAIN, payload) => {
                if web {
                    bail!("verifier sent page plaintext in a web session");
                }
                if !record_sent || response.len() + payload.len() > MAX_RECV {
                    bail!("verifier returned an unexpected or oversized response");
                }
                if response.is_empty() && !payload.is_empty() {
                    trace.milestone(Phase::ResponseFirstByte);
                }
                response.extend_from_slice(&payload);
                if !payload.is_empty() {
                    response_last_byte = Some(Instant::now());
                }
            }
            Event::Frame(wire::OPENING, payload) => {
                // Check framing once, after the verifier stopped returning data,
                // to avoid a new repeated full-body scan for small PLAIN frames.
                if !web && xpolicy::response_complete(&response) && let Some(at) = response_last_byte.take() {
                    trace.milestone_at(Phase::ResponseComplete, at);
                }
                let record = sealed.take().context("verifier opened a record that was not sent")?;
                trace.measure_sync(Phase::OpeningCheck, || opened_as(&payload, &record, raw))?;
                checked = true;
            }
            Event::Frame(wire::OUTCOME, payload) if web => {
                let Mode::Web { hop, url } = mode else { unreachable!("web mode") };
                if !checked || outcome.is_some() {
                    bail!("verifier reported a hop before opening its request record, or twice");
                }
                let reported: HopOutcome = serde_json::from_slice(&payload).context("invalid hop outcome")?;
                if reported.hop != hop || reported.url != url {
                    bail!("outcome mismatch");
                }
                let next_ok = reported.next_url.as_deref().is_none_or(|next| webpolicy::canonical_url(next).ok().as_deref() == Some(next));
                if !(100..=999).contains(&reported.status_code) || reported.is_final != reported.next_url.is_none() || !next_ok {
                    bail!("verifier reported an invalid hop outcome");
                }
                trace.milestone(Phase::ResponseComplete);
                outcome = Some(reported);
            }
            Event::Frame(wire::DONE, _) => {
                if !record_sent {
                    bail!("verifier finished before the request was sent");
                }
                // No result is reported for a record the supplier could not check.
                if !checked {
                    bail!("{MISUSE}: it did not open the request record");
                }
                if web && outcome.is_none() {
                    bail!("verifier finished without reporting the hop");
                }
                return Ok((response, outcome));
            }
            Event::Frame(kind, _) => bail!("unexpected relay frame {kind}"),
        }
    }
    // The verifier went away. If it had this node send a record and never
    // showed what was in it, that is the one thing the node must not accept
    // quietly: it cannot tell a dropped connection from a hidden request.
    if record_sent && !checked {
        bail!("{MISUSE}: the session ended before it opened the request record");
    }
    bail!("relay session ended without a result")
}

/// Start of the error a supplier reports when the verifier made it send
/// something other than its own request, or would not show that it had not.
/// Only the verifier holds the key, so it decides what is sealed; this check
/// comes after the fact and cannot undo the request, but it is certain.
pub const MISUSE: &str = "verifier misused this node's X session";

/// Checks, with the key the verifier revealed, that the record this supplier
/// sent to X was exactly `raw`. A key that authenticates the record cannot
/// make another plaintext come out of it.
fn opened_as(opening: &[u8], record: &[u8], raw: &[u8]) -> Result<()> {
    let (Some(key), Some(iv), Some(seq)) = (opening.get(..16), opening.get(16..28), opening.get(28..36)) else { bail!("{MISUSE}: malformed record opening") };
    if opening.len() != 36 {
        bail!("{MISUSE}: malformed record opening");
    }
    let key: [u8; 16] = key.try_into().expect("sixteen bytes");
    let mut keys = record::Keys::new(&key, iv.try_into().expect("twelve bytes"), u64::from_be_bytes(seq.try_into().expect("eight bytes")))?;
    match keys.open(record) {
        Ok((record::APPLICATION_DATA, sent)) if sent == raw => Ok(()),
        Ok(_) => bail!("{MISUSE}: the record it sealed was not this node's request"),
        Err(_) => bail!("{MISUSE}: its key does not open the request record"),
    }
}

struct Abort(Vec<tokio::task::AbortHandle>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.iter().for_each(tokio::task::AbortHandle::abort);
    }
}

async fn send_request<W: AsyncWrite + Unpin>(writer: &mut W, public: &[u8], hidden: &[Range<usize>], corrections: &[bool]) -> Result<()> {
    let mut payload = Vec::with_capacity(public.len() + 64 + corrections.len() / 8);
    payload.extend_from_slice(&(public.len() as u32).to_be_bytes());
    payload.extend_from_slice(public);
    payload.extend_from_slice(&(hidden.len() as u16).to_be_bytes());
    for range in hidden {
        payload.extend_from_slice(&(range.start as u32).to_be_bytes());
        payload.extend_from_slice(&(range.end as u32).to_be_bytes());
    }
    let mut packed = vec![0u8; corrections.len().div_ceil(8)];
    for (k, _) in corrections.iter().enumerate().filter(|(_, bit)| **bit) {
        packed[k / 8] |= 0x80 >> (k % 8);
    }
    payload.extend_from_slice(&packed);
    wire::send(writer, wire::REQUEST, &payload).await
}

fn parse_material(payload: &[u8], request_len: usize, bits: usize) -> Result<tag::Material> {
    let len = payload.get(..4).map(|b| u32::from_be_bytes(b.try_into().expect("four bytes")) as usize).context("truncated request material")?;
    // The sealed request is exactly our request plus its content-type byte.
    if len != request_len + 1 || payload.len() != 4 + len + 16 + 16 * bits {
        bail!("verifier material does not match the request");
    }
    let ciphertext = payload[4..4 + len].to_vec();
    let tag_share = payload[4 + len..4 + len + 16].try_into().expect("sixteen bytes");
    let masked = payload[4 + len + 16..].chunks_exact(16).map(|block| block.try_into().expect("sixteen bytes")).collect();
    Ok(tag::Material { ciphertext, masked, tag_share })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn hello(name: &str) -> Vec<u8> {
        let config = crate::relay::verifier::tls_config(rustls::RootCertStore::empty()).unwrap();
        let mut conn = rustls::ClientConnection::new(config, rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap()).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }
    const CCS: [u8; 6] = [20, 3, 3, 0, 1, 1];
    fn protected(len: usize) -> Vec<u8> {
        [&[23, 3, 3, (len >> 8) as u8, len as u8][..], &vec![7; len]].concat()
    }

    #[test]
    fn only_a_client_handshake_for_the_host_is_forwarded() {
        let hello = hello("x.com");
        assert_eq!(client_hello_name(&hello[5..]), Some(&b"x.com"[..]));
        // The whole handshake, in pieces that split a record.
        let mut ok = Handshake::default();
        let flight = [&hello[..], &CCS, &protected(53)].concat();
        let (a, b) = flight.split_at(hello.len() - 3);
        let mut forwarded = ok.admit(a, "x.com").unwrap();
        assert!(forwarded.is_empty());
        forwarded.extend(ok.admit(b, "x.com").unwrap());
        assert_eq!(forwarded, flight);
        assert!(ok.finished);

        let refuses = |records: &[&[u8]]| {
            let mut state = Handshake::default();
            records.iter().any(|record| state.admit(record, "x.com").is_err())
        };
        // Another server name, a truncated or padded hello, or no hello at all.
        assert!(refuses(&[&self::hello("other.example")]));
        let mut longer = hello.clone();
        longer.push(0);
        longer[4] += 1;
        assert!(refuses(&[&longer]));
        assert!(refuses(&[&protected(53)]));
        // More than the handshake: a second protected record, a large one, a third hello.
        assert!(refuses(&[&hello, &CCS, &protected(53), &protected(53)]));
        assert!(refuses(&[&hello, &protected(200)]));
        assert!(refuses(&[&hello, &hello, &hello]));
        assert!(refuses(&[&hello, &CCS, &CCS]));
        assert!(refuses(&[&hello, &protected(53), &hello]));
        // A retried hello before the Finished is the HelloRetryRequest path.
        assert!(!refuses(&[&hello, &CCS, &hello, &protected(53)]));
        // An alert or anything else unprotected is not part of a client handshake.
        assert!(refuses(&[&hello, &[21, 3, 3, 0, 2, 1, 0]]));
    }

    #[test]
    fn a_verifier_that_seals_another_request_is_caught_when_it_opens_the_record() {
        // The verifier holds the key, so it can seal any plaintext of the same
        // length around the hidden positions and the supplier will complete a
        // valid record for it, secrets included. The supplier cannot stop that,
        // but once the key is shown it sees exactly what was sent.
        let (key, iv, seq) = (*b"relay-test-key-2", *b"relay-iv-345", 1u64);
        let raw = b"GET /i/api/graphql/q/Viewer HTTP/1.1\r\nCookie: ct0=SECRETSECRETSECR\r\n\r\n".to_vec();
        let hidden = [50..66];
        let secret = raw[50..66].to_vec();
        let seal = |public: &[u8]| {
            let (mut node, mut verifier) = crate::relay::ot::pair(128);
            let (choices, received) = node.take(128).unwrap();
            let corrections = tag::corrections(&secret, &choices).unwrap();
            let material = tag::verifier_material(&key, &iv, seq, public, &hidden, &corrections, &verifier.take(128).unwrap()).unwrap();
            tag::node_record(&material, &hidden, &secret, &received).unwrap()
        };
        let opening = [&key[..], &iv[..], &seq.to_be_bytes()[..]].concat();
        let mut honest = raw.clone();
        honest[50..66].fill(0);
        assert!(opened_as(&opening, &seal(&honest), &raw).is_ok());

        // Same length, same hidden positions, another request line.
        let mut other = honest.clone();
        other[..35].copy_from_slice(b"GET /i/api/1.1/dm/inbox.json?a=bbbb");
        let record = seal(&other);
        // The record is valid and carries the supplier's secret: X would act on it.
        let mut reader = record::Keys::new(&key, iv, seq).unwrap();
        let (_, sent) = reader.open(&record).unwrap();
        assert!(sent.starts_with(b"GET /i/api/1.1/dm/inbox.json") && sent[50..66] == secret[..]);
        let error = opened_as(&opening, &record, &raw).unwrap_err();
        assert!(format!("{error:#}").starts_with(MISUSE));
        // A different key cannot make the honest plaintext come out of that record.
        let mut wrong = opening.clone();
        wrong[0] ^= 1;
        assert!(opened_as(&wrong, &record, &raw).is_err());
        assert!(opened_as(&opening[..35], &record, &raw).is_err());
    }

    fn web_input() -> serde_json::Value {
        let vectors: serde_json::Value = serde_json::from_str(include_str!("../../../api/web-vectors.json")).unwrap();
        serde_json::json!({
            "verifier": "127.0.0.1:1", "plaintext_fixture": true, "token": "ab".repeat(32), "hop": 0,
            "url": "https://example.com/", "ip": "93.184.215.14", "port": 443,
            "payload": {"type":"web.fetch","proof_mode":"relay","proof_policy":"web-relay-v1","url":"https://example.com/","max_redirects":5,"max_response_bytes":10485760,"headers":vectors["default_headers"]},
            "timeout_ms": 1000
        })
    }

    async fn web_class(input: &serde_json::Value) -> (&'static str, String) {
        match run_web(&serde_json::to_vec(input).unwrap()).await {
            Ok(_) => panic!("hop succeeded"),
            Err(failure) => (failure.class, format!("{:#}", failure.error)),
        }
    }

    #[tokio::test]
    async fn relay_web_input_is_checked_before_any_connection() {
        let cases: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
            ("hostname", Box::new(|v| v["ip"] = "example.com".into())),
            ("ip with port", Box::new(|v| v["ip"] = "93.184.215.14:443".into())),
            ("loopback", Box::new(|v| v["ip"] = "127.0.0.1".into())),
            ("private", Box::new(|v| v["ip"] = "192.168.1.10".into())),
            ("cgnat", Box::new(|v| v["ip"] = "100.64.0.1".into())),
            ("link-local", Box::new(|v| v["ip"] = "169.254.169.254".into())),
            ("unspecified", Box::new(|v| v["ip"] = "0.0.0.0".into())),
            ("mapped loopback", Box::new(|v| v["ip"] = "::ffff:127.0.0.1".into())),
            ("v6 loopback", Box::new(|v| v["ip"] = "::1".into())),
            ("ula", Box::new(|v| v["ip"] = "fd00::1".into())),
            ("v6 link-local", Box::new(|v| v["ip"] = "fe80::1".into())),
            ("multicast", Box::new(|v| v["ip"] = "ff02::1".into())),
            ("port", Box::new(|v| v["port"] = 8443.into())),
            ("non-canonical url", Box::new(|v| v["url"] = "https://Example.com/".into())),
            ("x url", Box::new(|v| v["url"] = "https://x.com/".into())),
            ("hop 0 elsewhere", Box::new(|v| v["url"] = "https://www.example.com/".into())),
            ("hop beyond redirects", Box::new(|v| v["hop"] = 6.into())),
            ("payload", Box::new(|v| v["payload"]["max_redirects"] = 9.into())),
            ("timeout", Box::new(|v| v["timeout_ms"] = 30001.into())),
            ("short timeout", Box::new(|v| v["timeout_ms"] = 999.into())),
            ("token", Box::new(|v| v["token"] = "short".into())),
            ("unknown field", Box::new(|v| v["extra"] = true.into())),
            ("proxy field", Box::new(|v| v["proxy"] = serde_json::json!({"host":"127.0.0.1","port":1,"url":"x"}))),
        ];
        for (name, mutate) in cases {
            let mut input = web_input();
            mutate(&mut input);
            let (class, error) = web_class(&input).await;
            assert_eq!(class, "fetch_failed", "{name}: {error}");
            for private in ["example.com", "93.184.215.14", "192.168", "127.0.0.1"] {
                assert!(!error.contains(private), "{name}: {error}");
            }
        }
        // A later hop may fetch any canonical URL the verifier authorized.
        let mut later = web_input();
        later["hop"] = 1.into();
        later["url"] = "https://www.example.com/".into();
        later["proxy"] = serde_json::json!({"host":"127.0.0.1","port":1});
        assert_eq!(web_class(&later).await.0, "proxy_failed");
    }

    #[tokio::test]
    async fn relay_web_node_headers_follow_the_job_policy_and_are_never_echoed() {
        use crate::webpolicy::fixtures::{CLEARANCE, DARWIN_UA, browser_payload};
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        let browser = || {
            let mut input = web_input();
            input["payload"] = browser_payload("https://example.com/");
            input["node_headers"] = serde_json::json!({"user_agent": DARWIN_UA, "cookie": CLEARANCE});
            // A valid hop goes on to dial, which fails on a closed proxy.
            input["proxy"] = serde_json::json!({"host":"127.0.0.1","port":closed});
            input
        };
        assert_eq!(web_class(&browser()).await.0, "proxy_failed");
        let mut no_cookie = browser();
        no_cookie["node_headers"].as_object_mut().unwrap().remove("cookie");
        assert_eq!(web_class(&no_cookie).await.0, "proxy_failed");
        let cases: Vec<(&str, Box<dyn Fn(&mut serde_json::Value)>)> = vec![
            ("missing", Box::new(|v| drop(v.as_object_mut().unwrap().remove("node_headers")))),
            ("null", Box::new(|v| v["node_headers"] = serde_json::Value::Null)),
            ("null cookie", Box::new(|v| v["node_headers"]["cookie"] = serde_json::Value::Null)),
            ("empty cookie", Box::new(|v| v["node_headers"]["cookie"] = "".into())),
            ("unknown field", Box::new(|v| v["node_headers"]["accept"] = "*/*".into())),
            ("no user agent", Box::new(|v| drop(v["node_headers"].as_object_mut().unwrap().remove("user_agent")))),
            ("unpinned user agent", Box::new(|v| v["node_headers"]["user_agent"] = DARWIN_UA.replace("Chrome/155", "Chrome/154").into())),
            ("injected user agent", Box::new(|v| v["node_headers"]["user_agent"] = format!("{DARWIN_UA}\r\nX-Injected: 1").into())),
            ("session cookie", Box::new(|v| v["node_headers"]["cookie"] = "cf_clearance=abc.DEF-123_456; session=s3cr3t".into())),
            ("cookie grammar", Box::new(|v| v["node_headers"]["cookie"] = "cf_clearance=abc.DEF-123_456;__cf_bm=x1y2".into())),
            ("cookie line break", Box::new(|v| v["node_headers"]["cookie"] = "cf_clearance=abc.DEF-123_456\r\nX: y".into())),
            ("relay job", Box::new(|v| v["payload"] = web_input()["payload"].clone())),
        ];
        for (name, mutate) in cases {
            let mut input = browser();
            mutate(&mut input);
            let (class, error) = web_class(&input).await;
            assert_eq!(class, "fetch_failed", "{name}: {error}");
            for private in ["abc.DEF", "x1y2", "s3cr3t", "example.com"] {
                assert!(!error.contains(private), "{name}: {error}");
            }
        }
        // A relay job takes no node headers.
        let mut relay = web_input();
        relay["node_headers"] = serde_json::json!({"user_agent": DARWIN_UA});
        assert_eq!(web_class(&relay).await.0, "fetch_failed");
    }

    #[tokio::test]
    async fn an_unreachable_proxy_or_target_is_not_a_verifier_session() {
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        let mut input = web_input();
        input["proxy"] = serde_json::json!({"host":"127.0.0.1","port":closed,"authorization":"Basic c2VjcmV0"});
        let (class, error) = web_class(&input).await;
        assert_eq!(class, "proxy_failed");
        assert!(!error.contains("c2VjcmV0") && !error.contains("127.0.0.1"), "{error}");
        // A documentation address goes nowhere: the dial fails or times out.
        let mut input = web_input();
        input["ip"] = "192.0.2.1".into();
        assert_eq!(web_class(&input).await.0, "connect_failed");
    }

    #[test]
    fn malformed_hellos_have_no_name() {
        let hello = hello("x.com");
        let message = &hello[5..];
        for cut in [0, 1, 4, 40, message.len() - 1] {
            assert_eq!(client_hello_name(&message[..cut]), None);
        }
        let mut server_hello = message.to_vec();
        server_hello[0] = 2;
        assert_eq!(client_hello_name(&server_hello), None);
    }
}
