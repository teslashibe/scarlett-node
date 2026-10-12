//! `scarlett-prover serve`: one long-lived helper per node process that runs
//! the node's web hops over warm verifier connections (design C1). It keeps
//! a small pool of connections that have done nothing but TCP, TLS and
//! PING, so a hop skips the verifier's TCP and TLS round trips, and it reuses
//! the connection a verifier keeps after a session (transport 2) for the
//! job's next redirect hop.
//!
//! Messages both ways are length-delimited JSON: a big-endian u32 length,
//! then that many bytes, at most 1 MiB. Requests, on stdin:
//!
//! - `{"type":"pool","size":2,"verifier":"host:port","verifier_ca_file":null,"plaintext_fixture":false}`
//!   sets the verifier and how many warm connections to keep (0 to 4).
//! - `{"type":"hop","id":"<id>","job":"<key>","input":{…}}` starts a hop:
//!   `input` is `relay-web`'s input without `predial`, its `token`
//!   optional. Without one the hop takes a connection and waits for
//!   `token`. A redirect hop gets the connection its previous hop left: the
//!   daemon groups a job's hops by their token (they share it), or by `job`
//!   when given.
//! - `{"type":"token","id":"<id>","token":"<64 lowercase hex>"}`: the
//!   accept returned the token; the hop runs.
//! - `{"type":"cancel","id":"<id>"}`: the accept failed. The hop ends; it
//!   sent nothing and reached no target. Ignored once a token was given.
//!
//! Replies, on stdout: `{"type":"ready","version":1}` once at start; per
//! hop `{"type":"presenting","id"}` right before its token goes out (it is
//! written and flushed first, so a node that never saw it knows the token
//! was not sent), then one of `{"type":"summary","id","summary":{…}}`
//! (`relay-web`'s summary), `{"type":"error","id","class","error",
//! "presented","diagnostics"}` or `{"type":"cancelled","id","diagnostics"}`.
//! It exits when stdin ends. Nothing else is ever written to stdout.
//!
//! Pool policy: warm connections are pinged once dialed (which gives them
//! the verifier's long wait) and every 15 s, and retired after 45 s idle.
//! One taken is replaced in the background at once. A connection that turns
//! out dead before its token was sent is dropped and the hop dials fresh.

use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{Notify, mpsc, oneshot},
};

use crate::{
    diagnostics::{Outcome, Phase, Snapshot, Trace},
    relay::node::{self, Hop, Link, Source, VerifierAddress, WebRequest, WebSummary, Waited},
};

pub const VERSION: u32 = 1;
/// The largest message either way.
const MAX_MESSAGE: usize = 1 << 20;
/// The most warm connections a node may ask for, and hops at once.
const MAX_POOL: usize = 4;
const MAX_HOPS: usize = 64;
/// Pool upkeep: how often, when to ping an idle connection, when to retire it.
const TICK: Duration = Duration::from_millis(500);
const PING_EVERY: Duration = Duration::from_secs(15);
const RETIRE_AFTER: Duration = Duration::from_secs(45);
/// How long a connection a redirect hop left waits for the job's next hop.
const RESERVE_FOR: Duration = Duration::from_secs(10);

/// The daemon's stderr goes to the node's log, line by line: a few lines
/// always (the pool losing or finding the verifier), and every hop's steps
/// as well with `SCARLETT_SERVE_LOG=1`, which the node sets for
/// `SCARLETT_WEB_DAEMON_LOG=1`. A line carries hop ids, steps, classes and
/// times: never a token, a job, or a target's URL or address.
static VERBOSE: AtomicBool = AtomicBool::new(false);
static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Writes one log line.
pub fn note(line: std::fmt::Arguments) {
    let ms = EPOCH.get_or_init(Instant::now).elapsed().as_millis();
    eprintln!("+{ms}ms {line}");
}

/// Writes one log line in verbose mode only.
pub fn detail(line: std::fmt::Arguments) {
    if VERBOSE.load(Ordering::Relaxed) {
        note(line);
    }
}

/// What a hop is doing now, for the stuck-hop watch and the verbose log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    WaitingForToken,
    Connecting,
    Dialing,
    Presenting,
    InSession,
}

impl Step {
    fn name(self) -> &'static str {
        match self {
            Step::WaitingForToken => "waiting for its token",
            Step::Connecting => "connecting to its target",
            Step::Dialing => "dialing the verifier",
            Step::Presenting => "presenting its token",
            Step::InSession => "in its session",
        }
    }

    /// How long a hop may stay in this step before the log says so: a
    /// session may stream a large page for minutes; the rest takes seconds.
    fn noteworthy_after(self) -> Duration {
        match self {
            Step::InSession => Duration::from_secs(120),
            _ => Duration::from_secs(15),
        }
    }
}

/// Each running hop's step and since when. The upkeep notes, once per step,
/// a hop that stays in one for long: a hop that hangs shows where.
#[derive(Default)]
pub struct Steps(Mutex<HashMap<String, (Step, Instant, bool)>>);

impl Steps {
    pub fn set(&self, id: &str, step: Step) {
        detail(format_args!("hop {id}: {}", step.name()));
        self.0.lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_owned(), (step, Instant::now(), false));
    }

    fn end(&self, id: &str) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
    }

    fn watch(&self) {
        for (id, (step, since, noted)) in self.0.lock().unwrap_or_else(|e| e.into_inner()).iter_mut() {
            if !*noted && since.elapsed() >= step.noteworthy_after() {
                *noted = true;
                note(format_args!("hop {id} has been {} for {} s", step.name(), since.elapsed().as_secs()));
            }
        }
    }
}

/// How long past its deadline a hop may take to reply. Every step keeps to
/// the deadline on its own; this bounds whatever does not.
const REPLY_GRACE: Duration = Duration::from_secs(1);

/// Reads one message; `None` at end of input between messages.
pub async fn read_message<R: AsyncRead + Unpin>(input: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MESSAGE {
        bail!("message of {len} bytes is too large");
    }
    let mut message = vec![0u8; len];
    input.read_exact(&mut message).await?;
    Ok(Some(message))
}

pub async fn write_message<W: AsyncWrite + Unpin>(output: &mut W, message: &[u8]) -> Result<()> {
    if message.len() > MAX_MESSAGE {
        bail!("message of {} bytes is too large", message.len());
    }
    output.write_all(&(message.len() as u32).to_be_bytes()).await?;
    output.write_all(message).await?;
    output.flush().await?;
    Ok(())
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Reply {
    Ready { version: u32 },
    Presenting { id: String },
    Summary { id: String, summary: WebSummary },
    Error { id: String, class: &'static str, error: String, presented: bool, diagnostics: Snapshot },
    Cancelled { id: String, diagnostics: Snapshot },
}

impl Reply {
    fn kind(&self) -> &'static str {
        match self {
            Reply::Ready { .. } => "ready",
            Reply::Presenting { .. } => "presenting",
            Reply::Summary { .. } => "summary",
            Reply::Error { .. } => "error",
            Reply::Cancelled { .. } => "cancelled",
        }
    }

    fn id(&self) -> &str {
        match self {
            Reply::Ready { .. } => "-",
            Reply::Presenting { id } | Reply::Summary { id, .. } | Reply::Error { id, .. } | Reply::Cancelled { id, .. } => id,
        }
    }
}

/// A reply on its way to stdout, and who wants to know it was written.
struct Out {
    reply: Reply,
    written: Option<oneshot::Sender<()>>,
}

#[derive(Clone)]
struct Replies(mpsc::UnboundedSender<Out>);

impl Replies {
    fn send(&self, reply: Reply) {
        let _ = self.0.send(Out { reply, written: None });
    }

    /// Sends `reply` and waits until it is written and flushed.
    async fn written(&self, reply: Reply) -> Result<()> {
        let (written, done) = oneshot::channel();
        self.0.send(Out { reply, written: Some(written) }).ok().context("stdout is gone")?;
        done.await.ok().context("stdout is gone")
    }
}

/// Warm connections, and the ones a job's redirect hop left for its next.
#[derive(Default)]
struct Pool {
    verifier: Option<VerifierAddress>,
    size: usize,
    idle: Vec<Idle>,
    reserved: HashMap<String, (Idle, Instant)>,
    dialing: usize,
    /// Dial failures in a row, and when the next refill may dial.
    failures: u32,
    retry_at: Option<Instant>,
}

struct Idle {
    link: Link,
    pinged: Instant,
}

impl Idle {
    /// A connection the verifier gives only the short wait (a pre-dial
    /// that was cancelled before its PING) is pinged at the next upkeep,
    /// which gives it the long one.
    fn new(link: Link) -> Self {
        let pinged = if link.long_wait() { Instant::now() } else { Instant::now().checked_sub(PING_EVERY).unwrap_or_else(Instant::now) };
        Self { link, pinged }
    }
}

struct Shared {
    pool: Mutex<Pool>,
    upkeep: Notify,
    hops: Mutex<HashMap<String, oneshot::Sender<Start>>>,
    steps: Arc<Steps>,
    replies: Replies,
}

enum Start {
    Token(String),
    Cancel,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PoolRequest {
    size: usize,
    verifier: String,
    verifier_ca_file: Option<String>,
    #[serde(default)]
    plaintext_fixture: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HopRequest {
    id: String,
    job: Option<String>,
    input: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    id: String,
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelRequest {
    id: String,
}

/// The key a job's hops share, from their token: never the token itself.
fn token_key(token: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(token.as_bytes()).iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Runs the daemon on these streams until `input` ends.
pub async fn run<R, W>(mut input: R, output: W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if std::env::var("SCARLETT_SERVE_LOG").as_deref() == Ok("1") {
        VERBOSE.store(true, Ordering::Relaxed);
    }
    EPOCH.get_or_init(Instant::now);
    let (sender, mut outbox) = mpsc::unbounded_channel::<Out>();
    let writer = tokio::spawn(async move {
        let mut output = output;
        while let Some(Out { reply, written }) = outbox.recv().await {
            let Ok(message) = serde_json::to_vec(&reply) else { continue };
            if write_message(&mut output, &message).await.is_err() {
                // The node is gone; nothing more can be told.
                return;
            }
            detail(format_args!("{} {} written", reply.kind(), reply.id()));
            if let Some(written) = written {
                let _ = written.send(());
            }
        }
    });
    let shared = Arc::new(Shared { pool: Mutex::new(Pool::default()), upkeep: Notify::new(), hops: Mutex::new(HashMap::new()), steps: Arc::default(), replies: Replies(sender) });
    shared.replies.send(Reply::Ready { version: VERSION });
    let upkeep = tokio::spawn(upkeep(shared.clone()));
    let result = async {
        while let Some(message) = read_message(&mut input).await? {
            let value: Value = serde_json::from_slice(&message).context("invalid request")?;
            let kind = value.get("type").and_then(Value::as_str).unwrap_or_default().to_owned();
            let mut body = value;
            if let Some(fields) = body.as_object_mut() {
                fields.remove("type");
            }
            match kind.as_str() {
                "pool" => set_pool(&shared, serde_json::from_value(body).context("invalid pool request")?),
                "hop" => start_hop(&shared, serde_json::from_value(body).context("invalid hop request")?),
                "token" => {
                    let TokenRequest { id, token } = serde_json::from_value(body).context("invalid token request")?;
                    let start = shared.hops.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                    let taken = start.map(|start| start.send(Start::Token(token)).is_ok());
                    detail(format_args!("hop {id}: token request ({})", match taken { Some(true) => "taken", Some(false) => "hop gone", None => "no such hop" }));
                }
                "cancel" => {
                    let CancelRequest { id } = serde_json::from_value(body).context("invalid cancel request")?;
                    let start = shared.hops.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                    let taken = start.map(|start| start.send(Start::Cancel).is_ok());
                    detail(format_args!("hop {id}: cancel request ({})", match taken { Some(true) => "taken", Some(false) => "hop gone", None => "no such hop" }));
                }
                _ => bail!("unknown request"),
            }
        }
        Ok(())
    }
    .await;
    upkeep.abort();
    drop(shared);
    // Replies already queued still go out.
    let _ = tokio::time::timeout(Duration::from_secs(1), writer).await;
    result
}

fn set_pool(shared: &Shared, request: PoolRequest) {
    let verifier = VerifierAddress { address: request.verifier, ca_file: request.verifier_ca_file, plaintext_fixture: request.plaintext_fixture };
    let mut pool = shared.pool.lock().unwrap_or_else(|e| e.into_inner());
    if pool.verifier.as_ref() != Some(&verifier) {
        // Another verifier: nothing from the old one is kept.
        pool.idle.clear();
        pool.reserved.clear();
        pool.failures = 0;
        pool.retry_at = None;
        pool.verifier = Some(verifier);
    }
    pool.size = request.size.min(MAX_POOL);
    detail(format_args!("pool: size {}, {} idle, {} reserved, {} dialing", pool.size, pool.idle.len(), pool.reserved.len(), pool.dialing));
    drop(pool);
    shared.upkeep.notify_one();
}

fn start_hop(shared: &Arc<Shared>, request: HopRequest) {
    let HopRequest { id, job, input } = request;
    let (start, started) = oneshot::channel();
    let refused = {
        let mut hops = shared.hops.lock().unwrap_or_else(|e| e.into_inner());
        if !valid_id(&id) || hops.contains_key(&id) {
            Some("invalid or duplicate hop id")
        } else if hops.len() >= MAX_HOPS {
            Some("too many hops at once")
        } else {
            hops.insert(id.clone(), start);
            None
        }
    };
    if let Some(reason) = refused {
        note(format_args!("a hop was refused: {reason}"));
        shared.replies.send(Reply::Error { id, class: "fetch_failed", error: reason.into(), presented: false, diagnostics: Trace::new().snapshot().ended(Outcome::Error) });
        return;
    }
    detail(format_args!("hop {id}: request"));
    let shared = shared.clone();
    tokio::spawn(async move {
        let trace = Trace::new();
        let begun = Instant::now();
        let presented = AtomicBool::new(false);
        // Whatever happens inside, the hop ends in a reply: a panic is
        // answered as a failure, never with silence.
        let reply = match AssertUnwindSafe(hop(&shared, &id, job, input, started, &trace, &presented)).catch_unwind().await {
            Ok(reply) => reply,
            Err(_) => {
                note(format_args!("hop {id} failed unexpectedly"));
                Reply::Error { id: id.clone(), class: "fetch_failed", error: "the hop failed unexpectedly".into(), presented: presented.load(Ordering::SeqCst), diagnostics: trace.snapshot().ended(Outcome::Error) }
            }
        };
        shared.hops.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        shared.steps.end(&id);
        match &reply {
            Reply::Error { class, presented, .. } => detail(format_args!("hop {id}: ends {class} (presented {presented}) after {} ms", begun.elapsed().as_millis())),
            reply => detail(format_args!("hop {id}: ends {} after {} ms", reply.kind(), begun.elapsed().as_millis())),
        }
        shared.replies.send(reply);
    });
}

/// The reply for a hop that failed with `error`.
fn failure(id: &str, error: node::WebError, presented: bool, trace: &Trace) -> Reply {
    Reply::Error { id: id.to_owned(), class: error.class, error: node::loggable_cause(&error.error), presented, diagnostics: trace.snapshot().ended(Outcome::Error) }
}

/// One hop, start to reply, by its deadline. `presented` is set once the
/// hop announces its token: from then on its session may have been spent.
async fn hop(shared: &Arc<Shared>, id: &str, job: Option<String>, input: Value, started: oneshot::Receiver<Start>, trace: &Trace, presented: &AtomicBool) -> Reply {
    let request: WebRequest = match serde_json::from_value(input) {
        Ok(request) => request,
        Err(e) => return failure(id, node::WebError::fetch(anyhow::Error::new(e).context("invalid hop input")), false, trace),
    };
    if request.predial {
        return failure(id, node::WebError::fetch(anyhow::anyhow!("a hop waits for its token without predial")), false, trace);
    }
    let hop = match Hop::prepare(request) {
        Ok(hop) => hop.logged(id, shared.steps.clone()),
        Err(error) => return failure(id, error, false, trace),
    };
    match tokio::time::timeout_at(hop.deadline() + REPLY_GRACE, run_hop(shared, id, job, &hop, started, trace, presented)).await {
        Ok(reply) => reply,
        Err(_) => {
            note(format_args!("hop {id} overran its deadline"));
            failure(id, node::WebError::fetch(anyhow::anyhow!("the hop overran its deadline")), presented.load(Ordering::SeqCst), trace)
        }
    }
}

/// A prepared hop: its connection, its token, its session.
async fn run_hop(shared: &Arc<Shared>, id: &str, job: Option<String>, hop: &Hop, started: oneshot::Receiver<Start>, trace: &Trace, presented: &AtomicBool) -> Reply {
    // Tests reach the guards above with hops that fail in ways no input can cause.
    #[cfg(test)]
    {
        if id.starts_with("panics") {
            panic!("a test hop panics");
        }
        if id.starts_with("stalls") {
            std::future::pending::<()>().await;
        }
    }
    let failed = |error: node::WebError, presented: bool| failure(id, error, presented, trace);
    let verifier = hop.verifier();
    // The job's hops share their token; a hop that has it can take the
    // connection the job's last hop left.
    let affinity = job.clone().or_else(|| hop.token().map(token_key));
    let source = match checkout(shared, affinity.as_deref(), &verifier) {
        Some(mut link) => {
            detail(format_args!("hop {id}: warm connection (token {})", if hop.token().is_some() { "given" } else { "to come" }));
            trace.span(Phase::PoolCheckoutWarm).finish(Outcome::Success);
            link.take();
            Source::Ready(link)
        }
        None => {
            detail(format_args!("hop {id}: dialing (token {})", if hop.token().is_some() { "given" } else { "to come" }));
            let (verifier, trace, id) = (verifier.clone(), trace.clone(), id.to_owned());
            Source::Dialing(tokio::spawn(async move {
                let span = trace.span(Phase::PoolCheckoutCold);
                let started = Instant::now();
                let dialed = Link::dial(&verifier, Some(&trace)).await;
                detail(format_args!("hop {id}: dial {} after {} ms", if dialed.is_ok() { "done" } else { "failed" }, started.elapsed().as_millis()));
                span.finish(if dialed.is_ok() { Outcome::Success } else { Outcome::Error });
                dialed.map(|mut link| {
                    link.take();
                    link
                })
            }))
        }
    };
    // Whatever was taken is replaced in the background.
    shared.upkeep.notify_one();
    let (token, source) = match hop.token() {
        Some(token) => (token.to_owned(), source),
        None => {
            let next = async {
                match started.await {
                    Ok(Start::Token(token)) => Some(token),
                    _ => None,
                }
            };
            shared.steps.set(id, Step::WaitingForToken);
            let waited = node::wait_for_token(hop, source, next, trace).await;
            detail(format_args!(
                "hop {id}: wait for the token ended: {}",
                match &waited {
                    Waited::Token(..) => "token",
                    Waited::Ended(_) => "cancelled",
                    Waited::TimedOut(_) => "deadline",
                    Waited::Invalid(_) => "invalid token",
                }
            ));
            match waited {
                Waited::Token(token, source) => (token, source),
                Waited::Ended(link) => {
                    give_back(shared, None, link, false);
                    return Reply::Cancelled { id: id.to_owned(), diagnostics: trace.snapshot().ended(Outcome::Cancelled) };
                }
                Waited::TimedOut(link) => {
                    give_back(shared, None, link, false);
                    return failed(node::WebError::fetch(anyhow::anyhow!("no token before the hop deadline")), false);
                }
                Waited::Invalid(link) => {
                    give_back(shared, None, link, false);
                    return failed(node::WebError::fetch(anyhow::anyhow!("verifier token must be 64 lowercase hex characters")), false);
                }
            }
        }
    };
    let affinity = job.or_else(|| Some(token_key(&token)));
    let presenting = async {
        presented.store(true, Ordering::SeqCst);
        shared.replies.written(Reply::Presenting { id: id.to_owned() }).await
    };
    match node::finish(hop, &token, source, trace, presenting).await {
        Ok((mut summary, kept)) => {
            // The job's next hop takes the connection its redirect left.
            give_back(shared, affinity.as_deref(), kept, !summary.is_final);
            summary.diagnostics = Some(trace.snapshot());
            Reply::Summary { id: id.to_owned(), summary }
        }
        Err(node::Failed { error, presented, link }) => {
            give_back(shared, None, link, false);
            failed(error, presented)
        }
    }
}

/// A connection for a hop: the one this job's last hop left, else the
/// most recently used warm one that is still usable. Dead ones are dropped.
fn checkout(shared: &Shared, job: Option<&str>, verifier: &VerifierAddress) -> Option<Link> {
    let mut pool = shared.pool.lock().unwrap_or_else(|e| e.into_inner());
    if pool.verifier.as_ref() != Some(verifier) {
        return None;
    }
    if let Some((mut idle, _)) = job.and_then(|job| pool.reserved.remove(job))
        && idle.link.usable()
    {
        return Some(idle.link);
    }
    while let Some(mut idle) = pool.idle.pop() {
        if idle.link.usable() {
            return Some(idle.link);
        }
    }
    None
}

/// Takes back a connection on which nothing is pending: for `job`'s next
/// hop when `reserve`, else into the pool while it wants one.
fn give_back(shared: &Shared, job: Option<&str>, link: Option<Link>, reserve: bool) {
    let Some(mut link) = link else { return };
    if !link.usable() {
        return;
    }
    let mut pool = shared.pool.lock().unwrap_or_else(|e| e.into_inner());
    match job {
        Some(job) if reserve => {
            pool.reserved.insert(job.to_owned(), (Idle::new(link), Instant::now()));
        }
        _ if pool.idle.len() < pool.size => pool.idle.push(Idle::new(link)),
        _ => {}
    }
}

/// Keeps the pool: pings, retires, expires reservations, refills.
async fn upkeep(shared: Arc<Shared>) {
    loop {
        tokio::select! {
            _ = shared.upkeep.notified() => {}
            _ = tokio::time::sleep(TICK) => {}
        }
        shared.steps.watch();
        let (to_ping, dials, verifier) = {
            let mut pool = shared.pool.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            // A redirect's connection the job did not come back for joins the pool.
            let expired: Vec<String> = pool.reserved.iter().filter(|(_, (_, at))| now.duration_since(*at) >= RESERVE_FOR).map(|(job, _)| job.clone()).collect();
            for job in expired {
                if let Some((idle, _)) = pool.reserved.remove(&job) {
                    pool.idle.push(idle);
                }
            }
            let before = pool.idle.len();
            pool.idle.retain(|idle| idle.link.idle() < RETIRE_AFTER);
            // Oldest first out when there are more than wanted.
            let excess = pool.idle.len().saturating_sub(pool.size);
            pool.idle.drain(..excess);
            if pool.idle.len() < before {
                detail(format_args!("pool: retired {} ({} idle)", before - pool.idle.len(), pool.idle.len()));
            }
            let mut to_ping = Vec::new();
            let mut kept = Vec::new();
            for idle in pool.idle.drain(..) {
                if idle.pinged.elapsed() >= PING_EVERY { to_ping.push(idle) } else { kept.push(idle) }
            }
            pool.idle = kept;
            let backing_off = pool.retry_at.is_some_and(|at| now < at);
            let dials = if pool.verifier.is_some() && !backing_off { pool.size.saturating_sub(pool.idle.len() + to_ping.len() + pool.dialing) } else { 0 };
            pool.dialing += dials;
            (to_ping, dials, pool.verifier.clone())
        };
        for mut idle in to_ping {
            let shared = shared.clone();
            tokio::spawn(async move {
                if idle.link.ping().await.is_ok() {
                    idle.pinged = Instant::now();
                    let mut pool = shared.pool.lock().unwrap_or_else(|e| e.into_inner());
                    if pool.idle.len() < pool.size {
                        pool.idle.push(idle);
                    }
                } else {
                    detail(format_args!("pool: a warm connection did not answer its ping"));
                }
            });
        }
        let Some(verifier) = verifier else { continue };
        if dials > 0 {
            detail(format_args!("pool: dialing {dials}"));
        }
        for _ in 0..dials {
            let (shared, verifier) = (shared.clone(), verifier.clone());
            tokio::spawn(async move {
                // A warm connection pings at once, which gives it the verifier's long wait.
                let started = Instant::now();
                let dialed = async {
                    let mut link = Link::dial(&verifier, None).await?;
                    link.ping().await?;
                    anyhow::Ok(link)
                }
                .await;
                let mut pool = shared.pool.lock().unwrap_or_else(|e| e.into_inner());
                pool.dialing -= 1;
                match dialed {
                    Ok(link) => {
                        if pool.failures > 0 {
                            note(format_args!("pool: the verifier answers again after {} failed dials", pool.failures));
                        }
                        detail(format_args!("pool: dialed in {} ms", started.elapsed().as_millis()));
                        pool.failures = 0;
                        pool.retry_at = None;
                        if pool.verifier.as_ref() == Some(&verifier) && pool.idle.len() < pool.size {
                            pool.idle.push(Idle::new(link));
                        }
                    }
                    Err(e) => {
                        // 1, 2, 4 … 30 s between tries while the verifier cannot be reached.
                        pool.failures += 1;
                        let backoff = Duration::from_secs(1u64 << pool.failures.min(5)).min(Duration::from_secs(30));
                        pool.retry_at = Some(Instant::now() + backoff);
                        if pool.failures == 1 {
                            note(format_args!("pool: a warm dial failed after {} ms: {}", started.elapsed().as_millis(), node::loggable_cause(&e)));
                        } else {
                            detail(format_args!("pool: dial failure {} after {} ms: {}", pool.failures, started.elapsed().as_millis(), node::loggable_cause(&e)));
                        }
                    }
                }
            });
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A daemon on in-memory pipes: its request writer and reply reader.
    pub(crate) struct Daemon {
        requests: tokio::io::DuplexStream,
        replies: tokio::io::DuplexStream,
        pub(crate) task: tokio::task::JoinHandle<Result<()>>,
    }

    impl Daemon {
        pub(crate) async fn start() -> Self {
            let (requests, input) = tokio::io::duplex(1 << 20);
            let (output, replies) = tokio::io::duplex(1 << 20);
            let task = tokio::spawn(run(input, output));
            let mut daemon = Self { requests, replies, task };
            assert_eq!(daemon.next().await, serde_json::json!({"type": "ready", "version": 1}));
            daemon
        }

        pub(crate) async fn send(&mut self, request: Value) {
            write_message(&mut self.requests, &serde_json::to_vec(&request).unwrap()).await.unwrap();
        }

        pub(crate) async fn next(&mut self) -> Value {
            let message = tokio::time::timeout(Duration::from_secs(30), read_message(&mut self.replies)).await.expect("no reply").unwrap().expect("daemon ended");
            serde_json::from_slice(&message).unwrap()
        }

        /// The next reply for hop `id` that is not `presenting`, and whether
        /// `presenting` came before it.
        pub(crate) async fn result(&mut self, id: &str) -> (Value, bool) {
            let mut presenting = false;
            loop {
                let reply = self.next().await;
                assert_eq!(reply["id"], id, "{reply}");
                if reply["type"] == "presenting" {
                    assert!(!presenting);
                    presenting = true;
                    continue;
                }
                return (reply, presenting);
            }
        }

        pub(crate) fn close(self) -> tokio::task::JoinHandle<Result<()>> {
            drop(self.requests);
            self.task
        }
    }

    #[tokio::test]
    async fn messages_are_length_delimited_and_bounded() {
        let (mut a, mut b) = tokio::io::duplex(1 << 21);
        write_message(&mut a, b"{}").await.unwrap();
        assert_eq!(read_message(&mut b).await.unwrap().unwrap(), b"{}");
        assert!(write_message(&mut a, &vec![b' '; MAX_MESSAGE + 1]).await.is_err());
        a.write_all(&((MAX_MESSAGE as u32 + 1).to_be_bytes())).await.unwrap();
        assert!(read_message(&mut b).await.is_err());
        drop(a);
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(read_message(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn requests_are_checked_and_ends_of_input_stop_the_daemon() {
        let mut daemon = Daemon::start().await;
        // A pool request with a field it does not know ends the daemon (below);
        // a hop with a bad id, a hop that cannot run, an unknown token: told, ignored.
        daemon.send(serde_json::json!({"type": "hop", "id": "bad id", "input": {}})).await;
        let reply = daemon.next().await;
        assert_eq!((reply["type"].as_str(), reply["class"].as_str(), reply["presented"].as_bool()), (Some("error"), Some("fetch_failed"), Some(false)));
        daemon.send(serde_json::json!({"type": "hop", "id": "h1", "input": {"verifier": "127.0.0.1:1"}})).await;
        let (reply, presenting) = daemon.result("h1").await;
        assert_eq!((reply["type"].as_str(), presenting), (Some("error"), false));
        daemon.send(serde_json::json!({"type": "token", "id": "nobody", "token": "a".repeat(64)})).await;
        daemon.send(serde_json::json!({"type": "cancel", "id": "nobody"})).await;
        assert!(daemon.close().await.unwrap().is_ok());
        // An unknown request, or an unknown field, ends it with an error.
        for request in [serde_json::json!({"type": "shell"}), serde_json::json!({"type": "pool", "size": 2, "verifier": "127.0.0.1:1", "verifier_ca_file": null, "extra": 1})] {
            let mut daemon = Daemon::start().await;
            daemon.send(request).await;
            assert!(daemon.task.await.unwrap().is_err());
        }
    }
}
