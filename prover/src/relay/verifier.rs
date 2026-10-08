//! Verifier side of a relay session.
//!
//! The verifier runs the TLS 1.3 handshake itself through the supplier's
//! tunnel, validates X's certificate, and keeps both traffic keys. It then
//! authorizes exactly one request record: the supplier's public request
//! bytes, checked against the X policy, with the supplier's hidden values
//! joined in through the split tag. It opens X's records itself, so the
//! response it returns is what X sent on this connection.
//!
//! A web hop (`web_session`) is the same session for any public https host
//! with nothing hidden: the verifier seals exactly the canonical request for
//! the hop URL, frames the response itself and streams its entity to a body
//! file (`WebReader`), and sends the supplier no plaintext. Once the caller
//! has recorded the hop it sends only the hop's status and the next URL it
//! authorizes (OUTCOME), or, when the hop failed, the reason (FAILED). A web
//! hop is held to its timing rules (`HopClock`) inside the session, so a
//! sealed request is always opened for the supplier however the hop ends.

use std::{
    collections::VecDeque,
    fmt, io,
    ops::Range,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use rustls::{ClientConfig, ClientConnection, ConnectionTrafficSecrets, RootCertStore, pki_types::ServerName};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

use super::{
    MAX_HIDDEN_BITS, MAX_REQUEST, VERSION,
    ot::VerifierOt,
    record::{self, Keys},
    tag,
    wire::{self, CHUNK, FrameReader},
};
use crate::{
    body::{Sink, Stored},
    webpolicy::{Counts, FrameError, Framer, Response},
    xpolicy,
    xprove::MAX_RECV,
};

/// Handshake bytes the verifier will accept from, or send to, the server.
const MAX_HANDSHAKE: usize = 64 << 10;

/// What the session established, in the shape the X policy checks.
pub struct Outcome {
    /// The request as the verifier saw it: hidden bytes are zero.
    pub sent: Vec<u8>,
    pub hidden: Vec<Range<usize>>,
    /// X's response, decrypted by the verifier.
    pub received: Vec<u8>,
}

/// The server's certificate chain and protocol, as one web hop saw them.
#[derive(Clone)]
pub struct TlsInfo {
    pub alpn: Option<String>,
    /// SHA-256 over each certificate as a big-endian u32 length and its DER.
    pub cert_chain_sha256: [u8; 32],
    pub leaf_cert_sha256: [u8; 32],
}

/// One verified web hop, for tests: the request the verifier sealed, the
/// response it framed and the entity it stored.
#[cfg(test)]
pub struct WebOutcome {
    pub sent: Vec<u8>,
    pub response: Response,
    pub tls: TlsInfo,
    pub body: Vec<u8>,
}

/// Why a web hop ended without a verified response. Every error from
/// `web_session` carries one; anything unclassified is `ProofRejected`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    TlsFailed,
    RequestRejected,
    PageTooLarge,
    ResponseInvalid,
    ServerClosed,
    SessionTimeout,
    ProofRejected,
}

impl Failure {
    pub fn reason(self) -> &'static str {
        match self {
            Self::TlsFailed => "tls_failed",
            Self::RequestRejected => "request_rejected",
            Self::PageTooLarge => "page_too_large",
            Self::ResponseInvalid => "response_invalid",
            Self::ServerClosed => "server_closed",
            Self::SessionTimeout => "session_timeout",
            Self::ProofRejected => "proof_rejected",
        }
    }

    pub fn of(error: &anyhow::Error) -> Self {
        error.downcast_ref::<Self>().copied().unwrap_or(Self::ProofRejected)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for Failure {}

/// Which timing rule ended a web hop (`session_timeout` in the receipt):
/// `hop_limit`, `ttfb_timeout`, `idle_timeout` or `throughput_floor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimedOut(pub &'static str);

impl fmt::Display for TimedOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for TimedOut {}

/// The timing rules of one web hop (api/verifier-v1.md section 8.2).
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// From the sealed request's release to the first decrypted response byte.
    pub ttfb: Duration,
    /// After the first response byte, the longest gap with no target bytes.
    pub idle: Duration,
    /// The throughput floor applies from this long after the first byte,
    pub floor_after: Duration,
    /// over the trailing window of this length,
    pub floor_window: Duration,
    /// at this many bytes per second.
    pub floor_rate: u64,
}

impl Timing {
    pub const WEB: Self = Self { ttfb: Duration::from_secs(60), idle: Duration::from_secs(20), floor_after: Duration::from_secs(30), floor_window: Duration::from_secs(30), floor_rate: 64 << 10 };

    /// The bytes the floor requires over its window.
    pub fn floor_bytes(&self) -> u64 {
        (u128::from(self.floor_rate) * self.floor_window.as_millis() / 1000) as u64
    }
}

/// The clock of one web hop: its deadline and timing rules, fed with the
/// session's events and asked when it must be checked next.
pub struct HopClock {
    timing: Timing,
    deadline: Instant,
    sent: Option<Instant>,
    first: Option<Instant>,
    last: Option<Instant>,
    /// Target bytes so far, and (time, total) after each arrival, pruned to
    /// one entry at or before the floor window.
    total: u64,
    samples: VecDeque<(Instant, u64)>,
    next_floor: Option<Instant>,
}

impl HopClock {
    pub fn new(timing: Timing, deadline: Instant) -> Self {
        Self { timing, deadline, sent: None, first: None, last: None, total: 0, samples: VecDeque::new(), next_floor: None }
    }

    /// The sealed request went to the supplier.
    pub fn request_sent(&mut self, now: Instant) {
        self.sent.get_or_insert(now);
    }

    /// `bytes` arrived from the target.
    pub fn target(&mut self, now: Instant, bytes: usize) {
        self.total += bytes as u64;
        self.samples.push_back((now, self.total));
        if self.first.is_some() {
            self.last = Some(now);
        }
    }

    /// The first decrypted response byte.
    pub fn first_byte(&mut self, now: Instant) {
        if self.first.is_none() {
            self.first = Some(now);
            self.last = Some(now);
            self.next_floor = Some(now + self.timing.floor_after);
        }
    }

    /// When `check` must run next.
    pub fn wake(&self) -> Instant {
        let mut wake = self.deadline;
        if let (Some(sent), None) = (self.sent, self.first) {
            wake = wake.min(sent + self.timing.ttfb);
        }
        if let Some(last) = self.last {
            wake = wake.min(last + self.timing.idle);
        }
        if let Some(floor) = self.next_floor {
            wake = wake.min(floor);
        }
        wake
    }

    /// Ends the hop when a rule is broken at `now`, naming the rule.
    pub fn check(&mut self, now: Instant) -> Result<(), TimedOut> {
        if now >= self.deadline {
            return Err(TimedOut("hop_limit"));
        }
        if let (Some(sent), None) = (self.sent, self.first)
            && now >= sent + self.timing.ttfb
        {
            return Err(TimedOut("ttfb_timeout"));
        }
        if let Some(last) = self.last
            && now >= last + self.timing.idle
        {
            return Err(TimedOut("idle_timeout"));
        }
        if let Some(floor) = self.next_floor
            && now >= floor
        {
            let start = now.checked_sub(self.timing.floor_window).unwrap_or(now);
            while self.samples.len() > 1 && self.samples[1].0 <= start {
                self.samples.pop_front();
            }
            let before = self.samples.front().filter(|(at, _)| *at <= start).map_or(0, |(_, total)| *total);
            if self.total - before < self.timing.floor_bytes() {
                return Err(TimedOut("throughput_floor"));
            }
            self.next_floor = Some(now + Duration::from_secs(1));
        }
        Ok(())
    }
}

/// How a session takes the server's response.
trait Reader {
    /// Whether the supplier receives the plaintext as it arrives.
    const PLAIN: bool;
    /// Whether the request may hide bytes from the verifier.
    const HIDDEN: bool;
    /// Takes decrypted application data; returns whether the response is complete.
    fn push(&mut self, data: &[u8]) -> Result<bool>;
    /// Passes on what `push` framed, before the next record is read.
    fn flush(&mut self) -> impl Future<Output = Result<()>> + Send;
    /// The server's close_notify.
    fn close_notify(&mut self) -> Result<()>;
    fn complete(&self) -> bool;
    /// Records why the session failed, where the caller wants to know.
    fn tag(error: anyhow::Error, failure: Failure) -> anyhow::Error;
}

/// An X read: the whole response, relayed to the supplier as it arrives.
struct XReader(Vec<u8>);

impl Reader for XReader {
    const PLAIN: bool = true;
    const HIDDEN: bool = true;
    fn push(&mut self, data: &[u8]) -> Result<bool> {
        if self.0.len() + data.len() > MAX_RECV {
            bail!("response exceeds {MAX_RECV} bytes");
        }
        self.0.extend_from_slice(data);
        Ok(xpolicy::response_complete(&self.0))
    }
    async fn flush(&mut self) -> Result<()> {
        Ok(())
    }
    fn close_notify(&mut self) -> Result<()> {
        bail!("server closed before the response was complete")
    }
    fn complete(&self) -> bool {
        xpolicy::response_complete(&self.0)
    }
    fn tag(error: anyhow::Error, _: Failure) -> anyhow::Error {
        error
    }
}

/// A web hop's response: framed as it arrives and kept by the verifier. Its
/// entity streams to the body file `path` unless the response is a
/// followable redirect.
pub struct WebReader {
    framer: Framer,
    path: PathBuf,
    sink: Option<Sink>,
}

impl WebReader {
    pub fn new(framer: Framer, path: PathBuf) -> Self {
        Self { framer, path, sink: None }
    }

    /// What the hop took, also when it failed.
    pub fn counts(&self) -> Counts {
        self.framer.counts()
    }

    /// After a complete session: the response, and its body file closed
    /// (flushed, fsynced, renamed, directory fsynced) unless it was a
    /// followable redirect.
    pub async fn finish(&mut self) -> Result<(Response, Option<Stored>)> {
        let response = self.framer.finish();
        if response.followable {
            return Ok((response, None));
        }
        let sink = self.sink.take().unwrap_or_else(|| Sink::open(self.path.clone()));
        let stored = sink.finish(response.body_bytes as u64).await?;
        Ok((response, Some(stored)))
    }
}

impl Reader for WebReader {
    const PLAIN: bool = false;
    const HIDDEN: bool = false;
    fn push(&mut self, data: &[u8]) -> Result<bool> {
        self.framer.push(data).map_err(frame_failure)
    }
    async fn flush(&mut self) -> Result<()> {
        if !self.framer.stores_body() {
            return Ok(());
        }
        let entity = self.framer.take_entity();
        if entity.is_empty() {
            return Ok(());
        }
        let path = &self.path;
        self.sink.get_or_insert_with(|| Sink::open(path.clone())).write(&entity).await.map_err(|e| e.context(Failure::ProofRejected))
    }
    fn close_notify(&mut self) -> Result<()> {
        self.framer.close_notify().map_err(frame_failure)
    }
    fn complete(&self) -> bool {
        self.framer.complete()
    }
    fn tag(error: anyhow::Error, failure: Failure) -> anyhow::Error {
        if error.downcast_ref::<Failure>().is_some() { error } else { error.context(failure) }
    }
}

fn frame_failure(error: FrameError) -> anyhow::Error {
    let failure = match error {
        FrameError::TooLarge => Failure::PageTooLarge,
        FrameError::Invalid => Failure::ResponseInvalid,
        FrameError::Closed => Failure::ServerClosed,
    };
    anyhow::Error::new(error).context(failure)
}

/// What a session sealed, and the server it reached.
pub struct Sealed {
    /// The request as the verifier saw it: hidden bytes are zero.
    pub sent: Vec<u8>,
    pub hidden: Vec<Range<usize>>,
    pub tls: TlsInfo,
}

/// The verifier's end of one supplier connection.
pub struct Conn<S> {
    reader: FrameReader<ReadHalf<S>>,
    writer: WriteHalf<S>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub fn new(socket: S) -> Self {
        let (reader, writer) = tokio::io::split(socket);
        Self { reader: FrameReader::new(reader), writer }
    }

    /// Ends a session with its result: a web hop's OUTCOME, then DONE.
    pub async fn done(&mut self, outcome: Option<&[u8]>) -> Result<()> {
        if let Some(frame) = outcome {
            wire::send(&mut self.writer, wire::OUTCOME, frame).await?;
        }
        wire::send(&mut self.writer, wire::DONE, b"{\"status\":\"complete\"}").await?;
        self.close().await;
        Ok(())
    }

    /// Ends a web session without a hop: one FAILED frame naming `reason`.
    pub async fn refuse(&mut self, reason: &str) -> Result<()> {
        wire::send(&mut self.writer, wire::FAILED, &serde_json::to_vec(&serde_json::json!({ "reason": reason }))?).await?;
        self.close().await;
        Ok(())
    }

    /// The supplier may still be forwarding the server's close. Dropping the
    /// socket with those frames unread can reset it and lose the last frame
    /// on its way out, so close our half and let the supplier finish, briefly.
    async fn close(&mut self) {
        let _ = self.writer.shutdown().await;
        let reader = self.reader.get_mut();
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            let mut sink = [0u8; 4096];
            while matches!(reader.read(&mut sink).await, Ok(n) if n > 0) {}
        })
        .await;
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    version: u8,
    transfers: usize,
}

struct Request {
    public: Vec<u8>,
    hidden: Vec<Range<usize>>,
    corrections: Vec<bool>,
}

/// TLS 1.3 with AES-128-GCM only: the one suite the split tag covers.
pub fn tls_config(roots: RootCertStore) -> Result<Arc<ClientConfig>> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites.retain(|suite| suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider)).with_protocol_versions(&[&rustls::version::TLS13])?.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_secret_extraction = true;
    Ok(Arc::new(config))
}

/// The pinned Mozilla roots TLSNotary proofs already trust.
pub fn mozilla_roots() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for root in tlsn::webpki::RootCertStore::mozilla().roots {
        roots.add(rustls::pki_types::CertificateDer::from(root.0))?;
    }
    Ok(roots)
}

fn parse_request(payload: &[u8], transfers: usize) -> Result<Request> {
    let take = |at: &mut usize, n: usize| -> Result<&[u8]> {
        let slice = payload.get(*at..*at + n).context("truncated relay request")?;
        *at += n;
        Ok(slice)
    };
    let mut at = 0;
    let len = u32::from_be_bytes(take(&mut at, 4)?.try_into()?) as usize;
    if len == 0 || len > MAX_REQUEST {
        bail!("request must be 1-{MAX_REQUEST} bytes");
    }
    let public = take(&mut at, len)?.to_vec();
    let ranges = u16::from_be_bytes(take(&mut at, 2)?.try_into()?) as usize;
    let mut hidden = Vec::with_capacity(ranges.min(8));
    for _ in 0..ranges {
        let start = u32::from_be_bytes(take(&mut at, 4)?.try_into()?) as usize;
        let end = u32::from_be_bytes(take(&mut at, 4)?.try_into()?) as usize;
        hidden.push(start..end);
    }
    let bits = tag::hidden_bits(public.len(), &hidden)?;
    if bits != transfers {
        bail!("request hides {bits} bits but the session prepared {transfers} transfers");
    }
    let packed = take(&mut at, bits.div_ceil(8))?;
    if at != payload.len() {
        bail!("trailing bytes after relay request");
    }
    // A hidden position that still carried a byte would be sealed as public.
    if hidden.iter().flat_map(|range| &public[range.clone()]).any(|&byte| byte != 0) {
        bail!("hidden request bytes must be zero in the public view");
    }
    let corrections = (0..bits).map(|k| packed[k / 8] & (0x80 >> (k % 8)) != 0).collect();
    Ok(Request { public, hidden, corrections })
}

/// Runs one relay session with a supplier and returns what X answered.
///
/// `authorize` sees the public request and its hidden ranges before any key
/// material is used for it, and must reject anything the job does not allow.
pub async fn run<S>(socket: S, config: Arc<ClientConfig>, server_name: &str, authorize: impl Fn(&[u8], &[Range<usize>]) -> Result<()>) -> Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = Conn::new(socket);
    let mut received = XReader(Vec::new());
    let sealed = session(&mut conn, config, server_name, authorize, &mut received, None).await?;
    conn.done(None).await?;
    Ok(Outcome { sent: sealed.sent, hidden: sealed.hidden, received: received.0 })
}

/// Runs one web hop for `server_name` on `conn`, up to the complete
/// response. The verifier authorizes only a request with nothing hidden that
/// `authorize` accepts (see `webpolicy::authorize`), frames the response with
/// `reader` (whose framer holds the hop's limits) and holds the hop to
/// `clock`. Whatever the outcome, a sealed request is opened for the
/// supplier before this returns. The caller then records the hop and ends
/// the session with `Conn::done` (OUTCOME) or `Conn::refuse` (FAILED), so the
/// supplier cannot start the next hop before this one is recorded. Errors
/// carry a `Failure`; a timing failure also carries its `TimedOut`.
pub async fn web_session<S>(conn: &mut Conn<S>, config: Arc<ClientConfig>, server_name: &str, authorize: impl Fn(&[u8]) -> Result<()>, reader: &mut WebReader, clock: &mut HopClock) -> Result<Sealed>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let authorize = |public: &[u8], hidden: &[Range<usize>]| {
        if !hidden.is_empty() {
            return Err(anyhow::Error::new(Failure::RequestRejected).context("a web request hides nothing"));
        }
        authorize(public).map_err(|e| e.context(Failure::RequestRejected))
    };
    session(conn, config, server_name, authorize, reader, Some(clock)).await
}

/// One whole web hop for tests: `web_session` with the default timing and
/// the body file `body` (read back into the outcome), then `conclude` for
/// the OUTCOME frame, and DONE.
#[cfg(test)]
pub async fn run_web<S>(
    socket: S,
    config: Arc<ClientConfig>,
    server_name: &str,
    authorize: impl Fn(&[u8]) -> Result<()>,
    framer: Framer,
    body: PathBuf,
    conclude: impl FnOnce(&WebOutcome) -> Result<Vec<u8>>,
) -> Result<WebOutcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = Conn::new(socket);
    let mut reader = WebReader::new(framer, body.clone());
    let mut clock = HopClock::new(Timing::WEB, Instant::now() + crate::webpolicy::HOP_LIMIT);
    let sealed = web_session(&mut conn, config, server_name, authorize, &mut reader, &mut clock).await?;
    let (response, stored) = reader.finish().await?;
    let body = match stored {
        Some(stored) => {
            stored.commit();
            std::fs::read(&body)?
        }
        None => Vec::new(),
    };
    let outcome = WebOutcome { sent: sealed.sent, response, tls: sealed.tls, body };
    let frame = conclude(&outcome)?;
    conn.done(Some(&frame)).await?;
    Ok(outcome)
}

/// The next frame, or the hop's first broken timing rule.
async fn next_frame<T: AsyncRead + Unpin>(reader: &mut FrameReader<T>, clock: &mut Option<&mut HopClock>) -> Result<(u8, Vec<u8>)> {
    let Some(clock) = clock.as_deref_mut() else {
        return reader.recv().await;
    };
    loop {
        tokio::select! {
            frame = reader.recv() => return frame,
            _ = tokio::time::sleep_until(clock.wake().into()) => clock.check(Instant::now())?,
        }
    }
}

/// Tags a timing failure as `session_timeout`.
fn timed<R: Reader>(error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<TimedOut>().is_some() { R::tag(error, Failure::SessionTimeout) } else { error }
}

async fn session<S, R: Reader>(
    conn: &mut Conn<S>,
    config: Arc<ClientConfig>,
    server_name: &str,
    authorize: impl Fn(&[u8], &[Range<usize>]) -> Result<()>,
    response: &mut R,
    mut clock: Option<&mut HopClock>,
) -> Result<Sealed>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Conn { reader, writer } = conn;
    let (kind, payload) = next_frame(reader, &mut clock).await.map_err(timed::<R>)?;
    if kind != wire::HELLO {
        bail!("relay session must start with a hello");
    }
    let hello: Hello = serde_json::from_slice(&payload).context("invalid relay hello")?;
    if hello.version != VERSION || hello.transfers > MAX_HIDDEN_BITS {
        bail!("unsupported relay hello");
    }
    if !R::HIDDEN && hello.transfers > 0 {
        return Err(R::tag(anyhow::anyhow!("this session hides nothing from the verifier"), Failure::RequestRejected));
    }
    let mut ot = (hello.transfers > 0).then(|| VerifierOt::new(hello.transfers));

    let mut tls = Some(ClientConnection::new(config, ServerName::try_from(server_name.to_owned())?).map_err(|e| R::tag(e.into(), Failure::TlsFailed))?);
    let mut to_server = 0usize;
    let mut from_server = 0usize;
    let mut keys: Option<(([u8; 16], [u8; 12], u64), Keys)> = None;
    let mut server_tls: Option<TlsInfo> = None;
    let mut inbound = Vec::new();
    let mut request: Option<Request> = None;
    let mut sent: Option<(Vec<u8>, Vec<Range<usize>>)> = None;

    // The ClientHello does not depend on the server, so it goes out first.
    flush_handshake(tls.as_mut().expect("handshake is in progress"), writer, &mut to_server).await.map_err(|e| R::tag(e, Failure::TlsFailed))?;

    // Whatever ends the session after a record was sealed, success or any
    // failure, the supplier gets the client key and so can always check what
    // it was made to send. A verifier that sealed and then went quiet would
    // otherwise be indistinguishable from one hiding a request of its own.
    let outcome: Result<()> = async {
    loop {
        let (kind, payload) = next_frame(reader, &mut clock).await.map_err(timed::<R>)?;
        match kind {
            wire::CO_SETUP => {
                let (kind, reply) = ot.as_mut().context("session prepared no transfers")?.on_setup(&payload)?;
                wire::send(writer, kind, &reply).await?;
            }
            wire::CO_PAYLOAD => ot.as_mut().context("session prepared no transfers")?.on_payload(&payload)?,
            wire::KOS_EXTEND => {
                if let Some((kind, chi)) = ot.as_mut().context("session prepared no transfers")?.on_extend(&payload)? {
                    wire::send(writer, kind, &chi).await?;
                }
            }
            wire::KOS_CHECK => ot.as_mut().context("session prepared no transfers")?.on_check(&payload)?,
            wire::REQUEST => {
                if request.is_some() || sent.is_some() {
                    bail!("a relay session authorizes one request");
                }
                let parsed = parse_request(&payload, hello.transfers).map_err(|e| R::tag(e, Failure::RequestRejected))?;
                authorize(&parsed.public, &parsed.hidden).map_err(|e| R::tag(e, Failure::RequestRejected))?;
                request = Some(parsed);
            }
            wire::FROM_SERVER => {
                if let Some(clock) = clock.as_deref_mut() {
                    clock.target(Instant::now(), payload.len());
                }
                inbound.extend_from_slice(&payload);
                while let Some((outer, record)) = record::take(&mut inbound)? {
                    if let Some(conn) = tls.as_mut() {
                        let failed = |e: anyhow::Error| R::tag(e, Failure::TlsFailed);
                        from_server += record.len();
                        if from_server > MAX_HANDSHAKE {
                            return Err(failed(anyhow::anyhow!("server handshake is too large")));
                        }
                        // One record at a time, so nothing past the handshake is ever inside the TLS library.
                        // The library takes a bounded amount per call, so a large
                        // record needs several.
                        let mut cursor = io::Cursor::new(&record);
                        while (cursor.position() as usize) < record.len() {
                            if conn.read_tls(&mut cursor).map_err(|e| failed(e.into()))? == 0 {
                                return Err(failed(anyhow::anyhow!("TLS library refused handshake bytes")));
                            }
                            conn.process_new_packets().context("TLS handshake with the server failed").map_err(failed)?;
                        }
                        flush_handshake(conn, writer, &mut to_server).await.map_err(failed)?;
                        if !conn.is_handshaking() {
                            let conn = tls.take().expect("handshake just completed");
                            server_tls = Some(tls_info(&conn));
                            keys = Some(traffic_keys(conn).map_err(failed)?);
                        }
                        continue;
                    }
                    let (_, server) = keys.as_mut().expect("keys exist once the handshake is done");
                    if outer != record::APPLICATION_DATA {
                        bail!("server sent an unprotected record after the handshake");
                    }
                    match server.open(&record)? {
                        (record::APPLICATION_DATA, data) => {
                            if sent.is_none() {
                                bail!("server sent application data before the request");
                            }
                            if !data.is_empty()
                                && let Some(clock) = clock.as_deref_mut()
                            {
                                clock.first_byte(Instant::now());
                            }
                            let complete = response.push(&data)?;
                            response.flush().await?;
                            if R::PLAIN {
                                for chunk in data.chunks(CHUNK) {
                                    wire::send(writer, wire::PLAIN, chunk).await?;
                                }
                            }
                            // X closes right behind a `Connection: close` response, and
                            // that alert can share a frame with the last data record.
                            // Stop at the response's own end rather than reading on.
                            if complete {
                                break;
                            }
                        }
                        // Session tickets are the only post-handshake message a plain read expects.
                        (record::HANDSHAKE, message) if message.first() == Some(&4) => {}
                        (record::HANDSHAKE, _) => bail!("unsupported post-handshake message"),
                        // An authenticated close ends a response whose length is the connection's.
                        (record::ALERT, alert) if alert == [1, 0] => {
                            if sent.is_none() {
                                return Err(R::tag(anyhow::anyhow!("server closed before the response was complete"), Failure::ServerClosed));
                            }
                            response.close_notify()?;
                            break;
                        }
                        (record::ALERT, _) => return Err(R::tag(anyhow::anyhow!("server sent a TLS alert"), Failure::ServerClosed)),
                        _ => bail!("unexpected TLS content type"),
                    }
                }
            }
            wire::SERVER_EOF => {
                let failure = if tls.is_some() { Failure::TlsFailed } else { Failure::ServerClosed };
                return Err(R::tag(anyhow::anyhow!("server connection ended before the response was complete"), failure));
            }
            _ => bail!("unexpected relay frame {kind}"),
        }

        if sent.is_none()
            && let (Some(parsed), Some(((key, iv, seq), _))) = (request.as_ref(), keys.as_ref())
            && ot.as_ref().is_none_or(VerifierOt::ready)
        {
            let transfers = match ot.as_mut() {
                Some(ot) => ot.take(hello.transfers)?,
                None => Vec::new(),
            };
            let material = tag::verifier_material(key, iv, *seq, &parsed.public, &parsed.hidden, &parsed.corrections, &transfers)?;
            // From here this key and sequence number are spent: there is no
            // second material for this record, whatever happens next.
            let parsed = request.take().expect("request was just read");
            sent = Some((parsed.public, parsed.hidden));
            let mut payload = Vec::with_capacity(4 + material.ciphertext.len() + 16 + 16 * material.masked.len());
            payload.extend_from_slice(&(material.ciphertext.len() as u32).to_be_bytes());
            payload.extend_from_slice(&material.ciphertext);
            payload.extend_from_slice(&material.tag_share);
            material.masked.iter().for_each(|block| payload.extend_from_slice(block));
            wire::send(writer, wire::MATERIAL, &payload).await?;
            if let Some(clock) = clock.as_deref_mut() {
                clock.request_sent(Instant::now());
            }
        }
        if sent.is_some() && response.complete() {
            break;
        }
        // A busy session may never let the timer win the race for the
        // next frame, so the rules are checked here too.
        if let Some(clock) = clock.as_deref_mut() {
            let now = Instant::now();
            if now >= clock.wake() {
                clock.check(now).map_err(|e| timed::<R>(e.into()))?;
            }
        }
    }
    Ok(())
    }
    .await;
    // The client key has no further use to us once a record is sealed:
    // there is no second material for it. Hand it over, on success or
    // failure, so the supplier can check that the record it completed was
    // its own request and nothing else. Best effort on failure: the supplier
    // treats a sealed record that is never opened as misuse.
    if sent.is_some()
        && let Some(((key, iv, seq), _)) = keys.as_ref()
    {
        let opening = wire::send(writer, wire::OPENING, &[&key[..], &iv[..], &seq.to_be_bytes()[..]].concat()).await;
        if outcome.is_ok() {
            opening?;
        }
    }
    outcome?;
    let (sent, hidden) = sent.expect("loop ends only after a request was sent");
    Ok(Sealed { sent, hidden, tls: server_tls.expect("a request is sent only after the handshake") })
}

fn tls_info(conn: &ClientConnection) -> TlsInfo {
    let chain = conn.peer_certificates().unwrap_or_default();
    let mut digest = Sha256::new();
    for der in chain {
        digest.update((der.len() as u32).to_be_bytes());
        digest.update(der.as_ref());
    }
    TlsInfo {
        alpn: conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
        cert_chain_sha256: digest.finalize().into(),
        leaf_cert_sha256: chain.first().map(|leaf| Sha256::digest(leaf.as_ref()).into()).unwrap_or_default(),
    }
}

/// Forwards whatever the handshake wants to write. Nothing is written
/// through the TLS library after the handshake.
async fn flush_handshake<W: AsyncWrite + Unpin>(conn: &mut ClientConnection, writer: &mut W, total: &mut usize) -> Result<()> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out)?;
    }
    *total += out.len();
    if *total > MAX_HANDSHAKE {
        bail!("client handshake is too large");
    }
    for chunk in out.chunks(CHUNK) {
        wire::send(writer, wire::TO_SERVER, chunk).await?;
    }
    Ok(())
}

type ClientKey = ([u8; 16], [u8; 12], u64);

/// Takes both application traffic keys out of the finished handshake.
fn traffic_keys(conn: ClientConnection) -> Result<(ClientKey, Keys)> {
    if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        bail!("server did not negotiate TLS 1.3");
    }
    let secrets = conn.dangerous_extract_secrets().context("extracting TLS traffic keys")?;
    let part = |(seq, secrets): (u64, ConnectionTrafficSecrets)| -> Result<ClientKey> {
        let ConnectionTrafficSecrets::Aes128Gcm { key, iv } = secrets else { bail!("server did not negotiate AES-128-GCM") };
        Ok((key.as_ref().try_into().context("unexpected traffic key length")?, iv.as_ref().try_into().context("unexpected traffic IV length")?, seq))
    };
    let client = part(secrets.tx)?;
    let (key, iv, seq) = part(secrets.rx)?;
    Ok((client, Keys::new(&key, iv, seq)?))
}

/// The X policy's request check alone, for tests that have no job.
#[cfg(test)]
pub fn authorize_x(public: &[u8], hidden: &[Range<usize>]) -> Result<()> {
    xpolicy::check_request(public, hidden).map(|_| ())
}
