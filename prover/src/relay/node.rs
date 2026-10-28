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
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::mpsc,
};

use super::{
    MAX_REQUEST, TRANSPORT, VERSION,
    ot::NodeOt,
    record, tag,
    wire::{self, CHUNK, FrameReader},
};
use crate::{
    dial,
    diagnostics::{Outcome, Phase, Run, Snapshot, Trace},
    policy::find,
    serve::{Step, Steps},
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
    let (socket, traffic) = crate::control::connect_observed(&request.verifier, request.verifier_ca_file.as_deref(), request.plaintext_fixture, Some(trace)).await?;
    // One X session per connection: it closes when this returns.
    let mut conn = RelayConn::new(socket);
    conn.present(&request.token).await?;
    let response = trace.measure(Phase::RelaySession, async {
        tokio::time::timeout(std::time::Duration::from_secs(120), exchange(&mut conn, server, &raw, HOST, Mode::X, trace)).await.context("relay session timed out")?.map(|(response, ..)| response)
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

/// Input of `scarlett-prover relay-web` and of a `serve` hop: one hop of a
/// web job, to the address the node resolved and checked. The token may come
/// later, once the node's accept returned it: `relay-web` with `predial`
/// reads it from its next stdin line, `serve` from a token request. Until
/// then nothing is sent on the verifier connection and nothing reaches the
/// target.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebRequest {
    pub verifier: String,
    pub verifier_ca_file: Option<String>,
    #[serde(default)]
    pub plaintext_fixture: bool,
    #[serde(default)]
    pub token: Option<String>,
    /// `relay-web` only: dial the verifier now and wait for the token line.
    #[serde(default)]
    pub predial: bool,
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
/// (`connect_failed`, `proxy_failed`, `fetch_failed`, `page_too_large`, or
/// `verifier_busy`, which the node repeats within its hop budget).
pub struct WebError {
    pub class: &'static str,
    pub error: anyhow::Error,
}

/// A failure's cause on one bounded line, as the node logs it. It keeps the
/// relay misuse text the node looks for, and never a URL or address
/// (errors never carry them).
pub fn loggable_cause(error: &anyhow::Error) -> String {
    format!("{error:#}").chars().map(|c| if c.is_control() { ' ' } else { c }).take(2048).collect()
}

impl WebError {
    pub fn fetch(error: anyhow::Error) -> Self {
        Self { class: "fetch_failed", error }
    }

    /// A failed session: what the verifier said, if it said anything.
    fn session(error: anyhow::Error) -> Self {
        let class = match error.downcast_ref::<Refused>() {
            Some(Refused("verifier_busy")) => "verifier_busy",
            Some(Refused("page_too_large")) => "page_too_large",
            _ => "fetch_failed",
        };
        Self { class, error }
    }
}

/// The reasons a verifier may give in a FAILED frame (api/verifier-v1.md 8.3).
const REFUSALS: [&str; 9] = ["verifier_busy", "tls_failed", "request_rejected", "page_too_large", "response_invalid", "server_closed", "session_timeout", "execution_uncertain", "proof_rejected"];

/// The verifier ended a web hop without a result and said why: one of
/// `REFUSALS`, or `other` for anything else it sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refused(pub &'static str);

impl Refused {
    fn parse(payload: &[u8]) -> Self {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Frame {
            reason: String,
        }
        let reason = serde_json::from_slice::<Frame>(payload).ok().map(|f| f.reason);
        Self(REFUSALS.into_iter().find(|r| reason.as_deref() == Some(*r)).unwrap_or("other"))
    }
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verifier ended the hop: {}", self.0)
    }
}

impl std::error::Error for Refused {}

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
    if request.token.as_deref().is_some_and(|token| !valid_token(token)) {
        bail!("verifier token must be 64 lowercase hex characters");
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
        bail!("timeout_ms must be 1000-{}", webpolicy::HOP_LIMIT.as_millis());
    }
    Ok((raw, ip, Duration::from_millis(request.timeout_ms)))
}

/// Whether `token` is a session token as the verifier issues them.
pub fn valid_token(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A web hop checked before any connection: its request bytes, its target,
/// and the deadline its whole run, a pre-dial wait included, keeps to.
pub struct Hop {
    request: WebRequest,
    raw: Vec<u8>,
    ip: IpAddr,
    started: Instant,
    deadline: tokio::time::Instant,
    /// The daemon's id for the hop and where it notes the hop's steps; none
    /// in `relay-web`.
    log: Option<(String, Arc<Steps>)>,
}

impl Hop {
    pub fn prepare(request: WebRequest) -> Result<Self, WebError> {
        let (raw, ip, timeout) = validate_hop(&request).map_err(WebError::fetch)?;
        Ok(Self { request, raw, ip, started: Instant::now(), deadline: tokio::time::Instant::now() + timeout, log: None })
    }

    /// Names the hop in the daemon's log and notes its steps in `steps`.
    pub fn logged(mut self, id: &str, steps: Arc<Steps>) -> Self {
        self.log = Some((id.to_owned(), steps));
        self
    }

    /// One verbose daemon log line about this hop.
    fn detail(&self, line: std::fmt::Arguments) {
        if let Some((id, _)) = &self.log {
            crate::serve::detail(format_args!("hop {id}: {line}"));
        }
    }

    /// Notes the step the hop is in now, for the daemon's stuck-hop watch.
    fn step(&self, step: Step) {
        if let Some((id, steps)) = &self.log {
            steps.set(id, step);
        }
    }

    /// Milliseconds since the hop was prepared.
    fn ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    /// When the whole hop, any wait for its token included, must be over.
    pub fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    pub fn token(&self) -> Option<&str> {
        self.request.token.as_deref()
    }

    /// The verifier this hop's job uses.
    pub fn verifier(&self) -> VerifierAddress {
        VerifierAddress { address: self.request.verifier.clone(), ca_file: self.request.verifier_ca_file.clone(), plaintext_fixture: self.request.plaintext_fixture }
    }
}

/// Where and how to reach the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierAddress {
    pub address: String,
    pub ca_file: Option<String>,
    pub plaintext_fixture: bool,
}

/// How long a connection may still wait before the verifier ends its wait
/// (api/verifier-v1.md 12.3), with room for the token to get there.
const SHORT_WAIT: Duration = Duration::from_secs(8);
const LONG_WAIT: Duration = Duration::from_secs(55);
/// How long a supplier waits for a PONG.
pub const PONG_WAIT: Duration = Duration::from_secs(5);

/// A verifier connection that has not presented a token yet, with what a
/// hop has used of it.
pub struct Link {
    conn: RelayConn<crate::control::Socket>,
    traffic: crate::control::Traffic,
    /// The payload counters when the current hop took it.
    taken_at: (u64, u64),
    /// When it began waiting for a token, and whether the verifier gives it the long wait.
    waiting_since: Instant,
    long_wait: bool,
}

impl Link {
    /// A new connection: TCP and TLS to the verifier, nothing else.
    pub async fn dial(verifier: &VerifierAddress, trace: Option<&Trace>) -> Result<Self> {
        let (socket, traffic) = crate::control::connect_observed(&verifier.address, verifier.ca_file.as_deref(), verifier.plaintext_fixture, trace).await?;
        Ok(Self { conn: RelayConn::new(socket), traffic, taken_at: (0, 0), waiting_since: Instant::now(), long_wait: false })
    }

    /// Asks for the long wait, and checks the connection is alive.
    pub async fn ping(&mut self) -> Result<()> {
        self.conn.ping(PONG_WAIT).await?;
        self.long_wait = true;
        Ok(())
    }

    /// Whether a token sent now would still find the verifier waiting: the
    /// connection is open, has received nothing, and its wait is not nearly
    /// over. A connection that fails this is dropped; nothing was sent on it.
    pub fn usable(&mut self) -> bool {
        Instant::now() < self.usable_until() && self.conn.check_idle().is_ok()
    }

    /// When the verifier's wait for this connection's token is nearly over:
    /// from then on a token is no longer sent on it.
    pub fn usable_until(&self) -> Instant {
        self.waiting_since + if self.long_wait { LONG_WAIT } else { SHORT_WAIT }
    }

    /// How long it has waited for a token.
    pub fn idle(&self) -> Duration {
        self.waiting_since.elapsed()
    }

    pub fn long_wait(&self) -> bool {
        self.long_wait
    }

    /// The current hop takes it: its traffic counts from here.
    pub fn take(&mut self) {
        self.taken_at = self.traffic.bytes();
    }

    fn used(&self) -> crate::control::TrafficSnapshot {
        let mut snapshot = self.traffic.snapshot();
        snapshot.verifier_sent_bytes -= self.taken_at.0.min(snapshot.verifier_sent_bytes);
        snapshot.verifier_received_bytes -= self.taken_at.1.min(snapshot.verifier_received_bytes);
        snapshot
    }
}

/// The verifier connection a hop starts with: none yet, one in hand, or a
/// dial still on its way.
pub enum Source {
    None,
    Ready(Link),
    Dialing(tokio::task::JoinHandle<Result<Link>>),
}

impl Source {
    async fn resolve(self) -> Option<Link> {
        match self {
            Source::None => None,
            Source::Ready(link) => Some(link),
            Source::Dialing(dial) => dial.await.ok().and_then(Result::ok),
        }
    }
}

/// A hop that ended without a summary: why, whether its token went out
/// (after which nothing about it may be repeated), and the verifier
/// connection when nothing was sent on it.
pub struct Failed {
    pub error: WebError,
    pub presented: bool,
    pub link: Option<Link>,
}

impl From<WebError> for Failed {
    fn from(error: WebError) -> Self {
        Self { error, presented: false, link: None }
    }
}

/// Runs a hop whose token is now known. The target connection comes
/// first, as it always has (presenting the token spends one of the job's
/// sessions), while a dial in `source` finishes. Then a verifier
/// connection that is still usable, else a fresh one; `presenting` is
/// awaited right before the token goes out, and an error from it ends the
/// hop unsent; then the session. Returns the summary and the connection
/// when the verifier keeps it.
pub async fn finish(hop: &Hop, token: &str, source: Source, trace: &Trace, presenting: impl Future<Output = Result<()>>) -> Result<(WebSummary, Option<Link>), Failed> {
    if !valid_token(token) {
        return Err(WebError::fetch(anyhow::anyhow!("verifier token must be 64 lowercase hex characters")).into());
    }
    let request = &hop.request;
    hop.step(Step::Connecting);
    let (server, link) = tokio::join!(connect_target(hop, trace), source.resolve());
    hop.detail(format_args!("target {} at {} ms, verifier connection {}", if server.is_ok() { "connected" } else { "failed" }, hop.ms(), if link.is_some() { "in hand" } else { "to dial" }));
    let server = match server {
        Ok(server) => server,
        // Nothing went out on the verifier connection: it can serve another hop.
        Err(error) => return Err(Failed { error, presented: false, link }),
    };
    let (server, target) = crate::control::metered(server);
    let host = webpolicy::url_host(&request.url);
    let session = async {
        // A connection the verifier may already have given up on is replaced: that costs a dial, never a token.
        let mut link = match link.and_then(|mut link| link.usable().then_some(link)) {
            Some(link) => link,
            None => {
                hop.step(Step::Dialing);
                let mut link = dial_for_token(hop, trace).await.map_err(|e| (e, false))?;
                link.take();
                link
            }
        };
        // The node learns that the token is about to go out before it does.
        hop.step(Step::Presenting);
        presenting.await.map_err(|e| (e, false))?;
        link.conn.present(token).await.map_err(|e| (e, true))?;
        hop.step(Step::InSession);
        hop.detail(format_args!("token presented at {} ms", hop.ms()));
        let (outcome, keep) = trace.measure(Phase::RelaySession, web_session_on(&mut link.conn, server, &hop.raw, host, request.hop, &request.url, trace)).await.map_err(|e| (e, true))?;
        Ok::<_, (anyhow::Error, bool)>((outcome, keep, link))
    };
    let (outcome, keep, mut link) = match tokio::time::timeout_at(hop.deadline, session).await {
        Ok(Ok(done)) => done,
        Ok(Err((error, presented))) => {
            hop.detail(format_args!("session failed at {} ms (presented {presented}): {}", hop.ms(), loggable_cause(&error)));
            return Err(Failed { error: WebError::session(error), presented, link: None });
        }
        Err(_) => {
            hop.detail(format_args!("session timed out at {} ms", hop.ms()));
            return Err(Failed { error: WebError::fetch(anyhow::anyhow!("relay session timed out")), presented: true, link: None });
        }
    };
    hop.detail(format_args!("session done at {} ms (keep {keep})", hop.ms()));
    let (target_sent_bytes, target_received_bytes) = target.bytes();
    let summary = WebSummary {
        verifier_transport: link.used(),
        status: "proof_sent",
        hop: outcome.hop,
        url: outcome.url,
        status_code: outcome.status_code,
        is_final: outcome.is_final,
        next_url: outcome.next_url,
        target_sent_bytes,
        target_received_bytes,
        duration_ms: hop.started.elapsed().as_millis(),
        diagnostics: None,
    };
    // A kept connection waits for the next token from now, with the long wait.
    let kept = keep.then(|| {
        link.waiting_since = Instant::now();
        link.long_wait = true;
        link
    });
    Ok((summary, kept))
}

/// How long one attempt at the target's TCP connection (or at the proxy's
/// tunnel to it) may take: a connection that gets no answer is tried again
/// on a fresh socket, and so a new source port, while the hop has time. One
/// the target or the proxy turns away is not. Nothing has gone to the
/// verifier yet, so a retry costs time only (shorter in tests).
const CONNECT_ATTEMPTS: [Duration; 3] = if cfg!(test) {
    [Duration::from_secs(1), Duration::from_secs(1), Duration::from_secs(1)]
} else {
    [Duration::from_secs(5), Duration::from_secs(10), Duration::from_secs(10)]
};

/// The hop's TCP connection to its target, which comes before its token.
async fn connect_target(hop: &Hop, trace: &Trace) -> Result<TcpStream, WebError> {
    let request = &hop.request;
    let class = if request.proxy.is_some() { "proxy_failed" } else { "connect_failed" };
    trace
        .measure(Phase::XTcpConnect, async {
            for (attempt, limit) in CONNECT_ATTEMPTS.into_iter().enumerate() {
                let until = (tokio::time::Instant::now() + limit).min(hop.deadline);
                match tokio::time::timeout_at(until, dial::target(hop.ip, request.port, request.proxy.as_ref())).await {
                    Ok(Ok(server)) => return Ok(server),
                    Ok(Err(dial::Error::Connect(error))) => return Err(WebError { class: "connect_failed", error }),
                    Ok(Err(dial::Error::Proxy(error))) => return Err(WebError { class: "proxy_failed", error }),
                    Err(_) if tokio::time::Instant::now() >= hop.deadline => break,
                    Err(_) => hop.detail(format_args!("target connection attempt {} had no answer in {} ms", attempt + 1, limit.as_millis())),
                }
            }
            Err(WebError { class, error: anyhow::anyhow!("target connection timed out") })
        })
        .await
}

/// Dials the verifier for a hop that has its token. A dial that failed fast
/// sent nothing, and is most likely a verifier at its cap of connections
/// waiting for a token, which frees places as tokens arrive: it is tried
/// twice more, shortly, within the hop's time. A slow failure is final.
async fn dial_for_token(hop: &Hop, trace: &Trace) -> Result<Link> {
    let mut pause = Duration::from_millis(50);
    let mut tries = 1;
    loop {
        let started = Instant::now();
        match Link::dial(&hop.verifier(), Some(trace)).await {
            Ok(link) => {
                hop.detail(format_args!("dialed for the token (try {tries}) at {} ms", hop.ms()));
                return Ok(link);
            }
            Err(e) if tries >= DIAL_TRIES || started.elapsed() > FAST_FAILURE || tokio::time::Instant::now() + pause >= hop.deadline => {
                hop.detail(format_args!("dial for the token failed (try {tries}) at {} ms: {}", hop.ms(), loggable_cause(&e)));
                return Err(e);
            }
            Err(e) => {
                hop.detail(format_args!("dial for the token failed fast (try {tries}): {}", loggable_cause(&e)));
                tokio::time::sleep(pause).await;
                pause *= 3;
                tries += 1;
            }
        }
    }
}

const DIAL_TRIES: u32 = 3;
const FAST_FAILURE: Duration = Duration::from_secs(1);

/// What `relay-web` printed: a hop's summary, or the end of a pre-dial
/// whose accept failed, which sent no token and reached no target.
pub enum RelayWeb {
    Hop(WebSummary),
    Aborted(Aborted),
}

#[derive(Serialize)]
pub struct Aborted {
    #[serde(flatten)]
    pub verifier_transport: crate::control::TrafficSnapshot,
    /// `predial_aborted`: never `proof_sent`.
    pub status: &'static str,
    pub duration_ms: u128,
    pub diagnostics: Option<Snapshot>,
}

/// Reads one line of at most `max` bytes, without its newline; `None` at
/// end of input before any byte.
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(input: &mut R, max: usize) -> Result<Option<Vec<u8>>> {
    use tokio::io::AsyncBufReadExt;
    let mut line = Vec::new();
    let read = (&mut *input).take(max as u64 + 1).read_until(b'\n', &mut line).await?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.len() > max {
        bail!("input line is too long");
    }
    Ok(Some(line))
}

/// The pre-dial token line: `{"token":"<64 lowercase hex>"}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenLine {
    token: String,
}

/// `scarlett-prover relay-web`: one hop from the first line of `input`. With
/// `"predial": true` and no token it dials the verifier (TCP and TLS only)
/// at once and waits, at most the hop's own time, for the token on the next
/// line; end of input instead aborts with nothing sent and no target
/// reached. The node starts it so before its accept and writes the token
/// once the accept returns it (design E1).
pub async fn relay_web<R: tokio::io::AsyncBufRead + Unpin>(input: &mut R) -> Result<RelayWeb, WebError> {
    let diagnostics = Run::new();
    let trace = diagnostics.trace();
    let line = read_line(input, 1 << 20).await.context("reading relay-web input").map_err(WebError::fetch)?.unwrap_or_default();
    let request: WebRequest = serde_json::from_slice(&line).context("invalid relay-web input").map_err(WebError::fetch)?;
    if request.predial == request.token.is_some() {
        return Err(WebError::fetch(anyhow::anyhow!("relay-web takes a token, or pre-dials without one")));
    }
    let hop = Hop::prepare(request)?;
    let (token, source) = match hop.token() {
        Some(token) => (token.to_owned(), Source::None),
        None => {
            let verifier = hop.verifier();
            let dial_trace = trace.clone();
            let dial = tokio::spawn(async move { Link::dial(&verifier, Some(&dial_trace)).await });
            // The token line: `{"token":"<64 lowercase hex>"}`; end of input aborts.
            let next = async {
                read_line(input, 1 << 10).await.ok().flatten().map(|line| serde_json::from_slice::<TokenLine>(&line).map(|line| line.token).unwrap_or_default())
            };
            match wait_for_token(&hop, Source::Dialing(dial), next, &trace).await {
                Waited::Token(token, source) => (token, source),
                Waited::Ended(link) => {
                    let verifier_transport = link.map(|link| link.used()).unwrap_or_else(|| crate::control::Traffic::default().snapshot());
                    return Ok(RelayWeb::Aborted(Aborted { verifier_transport, status: "predial_aborted", duration_ms: hop.started.elapsed().as_millis(), diagnostics: Some(diagnostics.success()) }));
                }
                Waited::TimedOut(_) => return Err(WebError::fetch(anyhow::anyhow!("no token before the hop deadline"))),
                Waited::Invalid(_) => return Err(WebError::fetch(anyhow::anyhow!("invalid pre-dial token line"))),
            }
        }
    };
    let (mut summary, _) = finish(&hop, &token, source, &trace, async { Ok(()) }).await.map_err(|failed| failed.error)?;
    summary.diagnostics = Some(diagnostics.success());
    Ok(RelayWeb::Hop(summary))
}

/// One whole `relay-web` run on `input` that must end in a hop, for tests.
#[cfg(test)]
pub async fn run_web(input: &[u8]) -> Result<WebSummary, WebError> {
    match relay_web(&mut &input[..]).await? {
        RelayWeb::Hop(summary) => Ok(summary),
        RelayWeb::Aborted(_) => Err(WebError::fetch(anyhow::anyhow!("pre-dial aborted"))),
    }
}

/// How a hop's wait for its token ended. Every outcome but a token hands
/// back the verifier connection, on which nothing was sent.
pub enum Waited {
    Token(String, Source),
    /// The node said no (its accept failed): end of input, or a cancel.
    Ended(Option<Link>),
    TimedOut(Option<Link>),
    Invalid(Option<Link>),
}

/// Waits for a hop's token from `next` (`None`: the node ended the hop),
/// while its verifier connection in `source` is dialed. A new connection
/// whose wait grows long asks for the verifier's long wait with a PING; one
/// the verifier closed meanwhile is dropped, and the hop dials again once it
/// has its token. Bounded by the hop's deadline. Nothing is sent but PINGs.
pub async fn wait_for_token(hop: &Hop, source: Source, next: impl Future<Output = Option<String>>, trace: &Trace) -> Waited {
    let (mut link, mut dialing) = match source {
        Source::None => (None, None),
        Source::Ready(link) => (Some(link), None),
        Source::Dialing(dial) => (None, Some(dial)),
    };
    let waiting = trace.span(Phase::PredialWait);
    tokio::pin!(next);
    let ended = loop {
        let ping_at = link.as_ref().filter(|link| !link.long_wait()).map(|link| tokio::time::Instant::now() + KEEPALIVE_AFTER.saturating_sub(link.idle()));
        // A connection whose wait the verifier is about to end is closed:
        // holding it would keep a place among the verifier's waiting
        // connections for nothing. The hop dials again once it has its token.
        let expires_at = link.as_ref().map(|link| tokio::time::Instant::from_std(link.usable_until()));
        tokio::select! {
            token = &mut next => {
                let Some(token) = token else { break Outcome::Cancelled };
                if !valid_token(&token) {
                    break Outcome::Error;
                }
                waiting.finish(Outcome::Success);
                let source = match (link, dialing) {
                    (Some(link), _) => Source::Ready(link),
                    // The dial goes on while the target is reached.
                    (None, Some(dial)) => Source::Dialing(dial),
                    (None, None) => Source::None,
                };
                return Waited::Token(token, source);
            }
            dialed = async { dialing.as_mut().expect("guarded").await }, if dialing.is_some() => {
                dialing = None;
                // A failed dial costs nothing yet: the hop dials again once it has its token.
                link = dialed.ok().and_then(Result::ok);
                hop.detail(format_args!("dial while waiting {} at {} ms", if link.is_some() { "done" } else { "failed" }, hop.ms()));
            }
            _ = tokio::time::sleep_until(ping_at.unwrap_or(hop.deadline)), if ping_at.is_some() => {
                if let Some(mut pinged) = link.take() && pinged.ping().await.is_ok() {
                    link = Some(pinged);
                }
                hop.detail(format_args!("ping while waiting {} at {} ms", if link.is_some() { "answered" } else { "failed" }, hop.ms()));
            }
            _ = tokio::time::sleep_until(expires_at.unwrap_or(hop.deadline)), if expires_at.is_some() => {
                link = None;
                hop.detail(format_args!("closed its connection, whose wait was nearly over, at {} ms", hop.ms()));
            }
            _ = tokio::time::sleep_until(hop.deadline) => break Outcome::Error,
        }
    };
    if let Some(dial) = dialing {
        dial.abort();
    }
    let timed_out = tokio::time::Instant::now() >= hop.deadline;
    waiting.finish(ended);
    match ended {
        Outcome::Cancelled => Waited::Ended(link),
        _ if timed_out => Waited::TimedOut(link),
        _ => Waited::Invalid(link),
    }
}

/// How long a new connection waits for its token before it asks for the
/// verifier's long wait (shorter in tests).
pub const KEEPALIVE_AFTER: Duration = if cfg!(test) { Duration::from_millis(300) } else { Duration::from_secs(5) };

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

/// The supplier's end of a verifier connection. Each session on it presents
/// its own token; with transport 2 the verifier may keep a web session's
/// connection for the next one (`"keep":true` in DONE). The connection is
/// never reused after a failure.
pub struct RelayConn<V> {
    reader: FrameReader<ReadHalf<V>>,
    writer: WriteHalf<V>,
}

impl<V: AsyncRead + AsyncWrite + Unpin> RelayConn<V> {
    pub fn new(verifier: V) -> Self {
        let (reader, writer) = tokio::io::split(verifier);
        Self { reader: FrameReader::new(reader), writer }
    }

    /// Presents a session's token. Spends one of the job's sessions once the
    /// verifier admits it.
    pub async fn present(&mut self, token: &str) -> Result<()> {
        self.writer.write_all(format!("{token}\n").as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Sends PING and waits for PONG, while the connection waits for a
    /// token. The verifier's first PING on a new connection gives it the
    /// long pre-token wait.
    pub async fn ping(&mut self, within: Duration) -> Result<()> {
        wire::send(&mut self.writer, wire::PING, &[]).await?;
        match tokio::time::timeout(within, self.reader.recv()).await {
            Ok(Ok((wire::PONG, _))) => Ok(()),
            Ok(Ok((kind, _))) => bail!("verifier sent frame {kind} to a connection without a session"),
            Ok(Err(e)) => Err(e.context("verifier connection ended")),
            Err(_) => bail!("verifier did not answer a ping"),
        }
    }

    /// Fails if, while the connection waited, the verifier closed it or
    /// sent anything at all: nothing may arrive outside a session but a
    /// PONG that was asked for. Never waits.
    pub fn check_idle(&mut self) -> Result<()> {
        use futures::FutureExt;
        match self.reader.recv().now_or_never() {
            None => Ok(()),
            Some(Ok((kind, _))) => bail!("verifier sent frame {kind} to a connection without a session"),
            Some(Err(e)) => Err(e.context("verifier connection ended")),
        }
    }
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

#[cfg(test)]
pub(crate) async fn session_observed<V, X>(verifier: V, server: X, raw: &[u8], host: &str, trace: &Trace) -> Result<Vec<u8>>
where
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    X: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    exchange(&mut RelayConn::new(verifier), server, raw, host, Mode::X, trace).await.map(|(response, ..)| response)
}

/// Runs one web hop over an established verifier socket and a connection to
/// the target, and returns what the verifier reported for it. `raw` is the
/// canonical request for `url`, hop number `hop`.
#[cfg(test)]
pub(crate) async fn web_session<V, X>(verifier: V, server: X, raw: &[u8], host: &str, hop: u32, url: &str, trace: &Trace) -> Result<HopOutcome>
where
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    X: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    web_session_on(&mut RelayConn::new(verifier), server, raw, host, hop, url, trace).await.map(|(outcome, _)| outcome)
}

/// One web hop on `conn`, whose token was just presented: what the
/// verifier reported, and whether it keeps the connection for another
/// session.
pub(crate) async fn web_session_on<V, X>(conn: &mut RelayConn<V>, server: X, raw: &[u8], host: &str, hop: u32, url: &str, trace: &Trace) -> Result<(HopOutcome, bool)>
where
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    X: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (_, outcome, keep) = exchange(conn, server, raw, host, Mode::Web { hop, url }, trace).await?;
    Ok((outcome.context("verifier finished without reporting the hop")?, keep))
}

#[derive(Clone, Copy)]
enum Mode<'a> {
    X,
    Web { hop: u32, url: &'a str },
}

/// What the verifier reports about a web hop once the supplier has checked
/// the opened request record.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HopOutcome {
    pub hop: u32,
    pub url: String,
    pub status_code: u16,
    #[serde(rename = "final")]
    pub is_final: bool,
    pub next_url: Option<String>,
}

/// The HELLO that starts every session: the relay version, the hidden bits
/// to transfer, and transport 2.
pub(crate) fn hello(bits: usize) -> Vec<u8> {
    format!("{{\"version\":{VERSION},\"transfers\":{bits},\"transport\":{TRANSPORT}}}").into_bytes()
}

/// DONE's payload. `keep` says the verifier waits on this connection for
/// the supplier's next token (transport 2); anything else closes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Done {
    status: String,
    #[serde(default)]
    keep: bool,
}

/// One session on `conn`, whose token was just presented: the X response
/// (empty for a web hop), the web hop's outcome, and whether the verifier
/// keeps the connection for another session.
async fn exchange<V, X>(conn: &mut RelayConn<V>, server: X, raw: &[u8], host: &str, mode: Mode<'_>, trace: &Trace) -> Result<(Vec<u8>, Option<HopOutcome>, bool)>
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

    let RelayConn { reader: from_verifier, writer: to_verifier } = conn;
    let (mut from_server, mut to_server) = tokio::io::split(server);
    let (events, mut inbox) = mpsc::channel(16);
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
    let _readers = Abort(vec![server_reader.abort_handle()]);

    wire::send(to_verifier, wire::HELLO, &hello(bits)).await?;
    let mut ot = None;
    let mut received = None;
    if bits > 0 {
        let (state, (kind, setup)) = NodeOt::start(bits)?;
        wire::send(to_verifier, kind, &setup).await?;
        ot = Some(state);
    } else {
        send_request(to_verifier, &public, &hidden, &[]).await?;
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
    let mut server_open = true;
    loop {
        // FrameReader::recv is cancel-safe, so the two sources can race.
        let event = tokio::select! {
            frame = from_verifier.recv() => match frame {
                Ok((kind, payload)) => Event::Frame(kind, payload),
                Err(e) => Event::Failed(e.context("verifier connection ended")),
            },
            server = inbox.recv(), if server_open => match server {
                Some(event) => event,
                None => {
                    server_open = false;
                    continue;
                }
            },
        };
        match event {
            Event::Failed(e) => {
                if record_sent && !checked {
                    return Err(e.context(format!("{UNOPENED}: the verifier connection ended first")));
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
                let sent = wire::send(to_verifier, wire::FROM_SERVER, &bytes).await;
                if !record_sent {
                    sent?;
                }
            }
            Event::ServerEof => {
                let sent = wire::send(to_verifier, wire::SERVER_EOF, &[]).await;
                if !record_sent {
                    sent?;
                }
            }
            Event::Frame(wire::CO_CHOOSE, payload) => {
                for (kind, frame) in ot.as_mut().context("unexpected base-OT choice")?.on_choose(&payload)? {
                    wire::send(to_verifier, kind, &frame).await?;
                }
            }
            Event::Frame(wire::KOS_CHI, payload) => {
                let ot = ot.as_mut().context("unexpected OT challenge")?;
                let (kind, check) = ot.on_chi(&payload)?;
                wire::send(to_verifier, kind, &check).await?;
                let (choices, blocks) = ot.take(bits)?;
                if let Some(span) = ot_ready.take() {
                    span.finish(Outcome::Success);
                }
                send_request(to_verifier, &public, &hidden, &tag::corrections(&secret, &choices)?).await?;
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
            Event::Frame(wire::OPENING, mut payload) => {
                // Check framing once, after the verifier stopped returning data,
                // to avoid a new repeated full-body scan for small PLAIN frames.
                if !web && xpolicy::response_complete(&response) && let Some(at) = response_last_byte.take() {
                    trace.milestone_at(Phase::ResponseComplete, at);
                }
                let record = sealed.take().context("verifier opened a record that was not sent")?;
                let opened = trace.measure_sync(Phase::OpeningCheck, || opened_as(&payload, &record, raw));
                // The revealed key has done its one job.
                record::wipe(&mut payload);
                opened?;
                checked = true;
            }
            Event::Frame(wire::FAILED, payload) if web => {
                // A verifier opens a sealed record before it says why the hop failed.
                if record_sent && !checked {
                    bail!("{UNOPENED}: it ended the hop first ({})", Refused::parse(&payload).0);
                }
                return Err(Refused::parse(&payload).into());
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
            Event::Frame(wire::DONE, payload) => {
                if !record_sent {
                    bail!("verifier finished before the request was sent");
                }
                // No result is reported for a record the supplier could not check.
                if !checked {
                    bail!("{UNOPENED}: it finished the session without opening it");
                }
                if web && outcome.is_none() {
                    bail!("verifier finished without reporting the hop");
                }
                // The hop stands whatever DONE says; only an explicit keep reuses the connection.
                let keep = web && serde_json::from_slice::<Done>(&payload).is_ok_and(|done| done.status == "complete" && done.keep);
                return Ok((response, outcome, keep));
            }
            Event::Frame(kind, _) => bail!("unexpected relay frame {kind}"),
        }
    }
}

/// Start of the error a supplier reports when the verifier opened the record
/// and showed that it made the supplier send something other than its own
/// request. Only the verifier holds the key, so it decides what is sealed;
/// this check comes after the fact and cannot undo the request, but it is
/// certain. Through release 0.1.19 this text was "verifier misused this
/// node's X session" and also covered `UNOPENED`.
pub const MISUSE: &str = "verifier sealed a request this node did not authorize";

/// Start of the error a supplier reports when a session ends after its
/// request record went out but before the verifier opened it. The supplier
/// cannot tell what was sealed, but this proves nothing: a verifier that timed
/// the session out, a dropped connection or a machine that slept ends a
/// session the same way. The node rests relay after several of these and
/// resumes on its own; only `MISUSE` halts it.
pub const UNOPENED: &str = "verifier did not open this node's request record";

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
            "payload": {"type":"web.fetch","proof_mode":"relay","proof_policy":"web-relay-v1","url":"https://example.com/","max_redirects":5,"max_response_bytes":67108864,"headers":vectors["default_headers"]},
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
            ("timeout", Box::new(|v| v["timeout_ms"] = 280_001.into())),
            ("ten MiB pages", Box::new(|v| v["payload"]["max_response_bytes"] = 10_485_760.into())),
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
        // The longest hop budget is accepted and goes on to dial.
        let mut longest = web_input();
        longest["timeout_ms"] = 280_000.into();
        longest["proxy"] = serde_json::json!({"host":"127.0.0.1","port":1});
        assert_eq!(web_class(&longest).await.0, "proxy_failed");
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
