//! Validator side. The coordinator registers the exact job payload over a
//! bearer-protected HTTP API and receives a token for the supplier.
//! Suppliers connect to the session port, send `<token>\n`, then run TLSNotary.
//! Codex jobs use proxy mode: the verifier opens the connection to OpenAI
//! itself and the token is single use. X reads (`x.read`) use MPC-TLS so the
//! supplier's own connection reaches X; the job pins every read it pays for,
//! and the token allows `max_attempts` proofs until every pinned read is
//! fulfilled. The verifier records only what it verified; the coordinator
//! reads that result, never the supplier's copy.
//!
//! Environment: SCARLETT_VERIFIER_KEY (required, 32+ chars),
//! SCARLETT_VERIFIER_LISTEN (default 0.0.0.0:7047), SCARLETT_VERIFIER_API
//! (default 127.0.0.1:7070), UPSTREAM (default chatgpt.com:443),
//! SESSION_TIMEOUT_SECS (default 300).

use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tlsn::{
    Session,
    config::verifier::VerifierConfig,
    connection::ServerName,
    transcript::PartialTranscript,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{
    policy::{self, Verified},
    xpolicy::{self, Exchange, Spec},
    xprove::{MAX_RECV, MAX_SENT},
};

const MAX_TTL: Duration = Duration::from_secs(600);

struct Config {
    key: String,
    upstream: String,
    session_limit: Duration,
}

#[derive(Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Status {
    Pending,
    Running,
    Accepted {
        #[serde(flatten)]
        verified: Verified,
        duration_ms: u64,
    },
    Rejected {
        reason: String,
    },
    Expired,
    XRead {
        remaining_attempts: usize,
        /// Every pinned exchange is fulfilled.
        complete: bool,
        /// Indexes of pinned exchanges not yet fulfilled.
        pending: Vec<usize>,
        exchanges: Vec<XRecord>,
        rejections: Vec<String>,
    },
}

#[derive(Clone, Serialize)]
struct XRecord {
    /// The pinned exchange this proof matched.
    index: usize,
    /// Whether this proof fulfilled it, which takes HTTP 200 with data.
    fulfilled: bool,
    #[serde(flatten)]
    exchange: Exchange,
    /// Next-page cursors in a fulfilling response, for exchanges that page on from it.
    #[serde(skip)]
    cursors: Vec<String>,
    sent_bytes: usize,
    received_bytes: usize,
    duration_ms: u64,
}

enum Kind {
    Codex,
    X(Arc<Vec<Spec>>),
}

struct Entry {
    payload: Value,
    kind: Kind,
    expires: Instant,
    status: Status,
}

#[derive(Default)]
struct Sessions {
    by_job: HashMap<String, Entry>,
    by_token: HashMap<String, String>,
}

type Shared = Arc<(Config, Mutex<Sessions>)>;

pub async fn run() -> Result<()> {
    let key = env::var("SCARLETT_VERIFIER_KEY").unwrap_or_default();
    if key.len() < 32 {
        bail!("SCARLETT_VERIFIER_KEY must be at least 32 characters");
    }
    let listen = env::var("SCARLETT_VERIFIER_LISTEN").unwrap_or_else(|_| "0.0.0.0:7047".into());
    let api = env::var("SCARLETT_VERIFIER_API").unwrap_or_else(|_| "127.0.0.1:7070".into());
    let upstream = env::var("UPSTREAM").unwrap_or_else(|_| format!("{}:443", policy::HOST));
    let limit = env::var("SESSION_TIMEOUT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
    let shared: Shared =
        Arc::new((Config { key, upstream, session_limit: Duration::from_secs(limit) }, Mutex::new(Sessions::default())));

    let router = Router::new()
        .route("/v1/sessions", post(create))
        .route("/v1/sessions/{job_id}/{attempt}", get(status))
        .with_state(shared.clone());
    let api_listener = TcpListener::bind(&api).await.with_context(|| format!("binding {api}"))?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(api_listener, router).await {
            eprintln!("verifier API stopped: {e}");
        }
    });

    let listener = TcpListener::bind(&listen).await.with_context(|| format!("binding {listen}"))?;
    println!("verifier: sessions on {listen}, API on {api}, upstream {}", shared.0.upstream);
    loop {
        let (socket, peer) = listener.accept().await?;
        let _ = socket.set_nodelay(true);
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(shared, socket).await {
                println!("verifier: session from {peer} ended without a result: {e:#}");
            }
        });
    }
}

fn authorized(config: &Config, headers: &HeaderMap) -> bool {
    let given = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    given.len() == config.key.len() && given.bytes().zip(config.key.bytes()).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
}

fn job_key(job_id: &str, attempt: &str) -> String {
    format!("{job_id}\n{attempt}")
}

#[derive(Deserialize)]
struct CreateRequest {
    job_id: String,
    attempt: String,
    payload: Value,
    ttl_seconds: Option<u64>,
}

async fn create(State(shared): State<Shared>, headers: HeaderMap, Json(request): Json<CreateRequest>) -> (StatusCode, Json<Value>) {
    let (config, sessions) = &*shared;
    if !authorized(config, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "verifier key required"})));
    }
    if request.job_id.is_empty() || request.job_id.len() > 128 || request.attempt.is_empty() || request.attempt.len() > 128 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid job or attempt"})));
    }
    let validated = if request.payload["type"] == "x.read" {
        xpolicy::validate_job(&request.payload).map(|(specs, max)| {
            let pending = (0..specs.len()).collect();
            let initial = Status::XRead { remaining_attempts: max, complete: false, pending, exchanges: Vec::new(), rejections: Vec::new() };
            (Kind::X(Arc::new(specs)), initial)
        })
    } else {
        policy::validate_job(&request.payload).map(|_| (Kind::Codex, Status::Pending))
    };
    let (kind, initial) = match validated {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))),
    };
    let ttl = Duration::from_secs(request.ttl_seconds.unwrap_or(300)).min(MAX_TTL);
    let token: String = rand::random::<[u8; 32]>().iter().map(|b| format!("{b:02x}")).collect();
    let key = job_key(&request.job_id, &request.attempt);
    let mut sessions = sessions.lock().unwrap();
    let now = Instant::now();
    sessions.by_job.retain(|_, e| e.expires + MAX_TTL > now);
    let live: std::collections::HashSet<&String> = sessions.by_job.keys().collect();
    let stale: Vec<String> = sessions.by_token.iter().filter(|(_, k)| !live.contains(k)).map(|(t, _)| t.clone()).collect();
    for token in stale {
        sessions.by_token.remove(&token);
    }
    if sessions.by_job.contains_key(&key) {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "session already exists for this attempt"})));
    }
    sessions.by_job.insert(key.clone(), Entry { payload: request.payload, kind, expires: now + ttl, status: initial });
    sessions.by_token.insert(token.clone(), key);
    (StatusCode::CREATED, Json(serde_json::json!({"token": token})))
}

async fn status(
    State(shared): State<Shared>,
    headers: HeaderMap,
    Path((job_id, attempt)): Path<(String, String)>,
) -> (StatusCode, Json<Value>) {
    let (config, sessions) = &*shared;
    if !authorized(config, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "verifier key required"})));
    }
    let sessions = sessions.lock().unwrap();
    let Some(entry) = sessions.by_job.get(&job_key(&job_id, &attempt)) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "unknown session"})));
    };
    let status = match entry.status {
        Status::Pending if Instant::now() >= entry.expires => Status::Expired,
        ref other => other.clone(),
    };
    (StatusCode::OK, Json(serde_json::to_value(status).unwrap_or_default()))
}

enum Job {
    Codex(Value),
    X(Arc<Vec<Spec>>),
}

async fn handle(shared: Shared, mut socket: TcpStream) -> Result<()> {
    let (config, sessions) = &*shared;
    let mut line = [0u8; 65];
    tokio::time::timeout(Duration::from_secs(10), socket.read_exact(&mut line)).await.context("no session token")??;
    if line[64] != b'\n' {
        bail!("malformed session token");
    }
    let token = std::str::from_utf8(&line[..64])?;
    let (key, job) = {
        let mut guard = sessions.lock().unwrap();
        let s = &mut *guard;
        let key = s.by_token.get(token).cloned().context("unknown or used session token")?;
        let entry = s.by_job.get_mut(&key).context("session expired")?;
        if Instant::now() >= entry.expires {
            s.by_token.remove(token);
            if let Kind::Codex = entry.kind {
                entry.status = Status::Expired;
            }
            bail!("session expired");
        }
        let job = match &entry.kind {
            Kind::Codex => {
                // Codex tokens are single use: removing it here blocks replays and parallel attempts.
                s.by_token.remove(token);
                entry.status = Status::Running;
                Job::Codex(entry.payload.clone())
            }
            Kind::X(specs) => {
                let Status::XRead { remaining_attempts, complete, .. } = &mut entry.status else {
                    bail!("session is in an unexpected state")
                };
                if *remaining_attempts == 0 || *complete {
                    s.by_token.remove(token);
                    bail!("x.read session has no attempts left");
                }
                // Each connection spends one attempt; the token dies with the last one.
                *remaining_attempts -= 1;
                if *remaining_attempts == 0 {
                    s.by_token.remove(token);
                }
                Job::X(specs.clone())
            }
        };
        (key, job)
    };

    let started = Instant::now();
    let job_id = key.split('\n').next().unwrap_or_default().to_owned();
    let timed_out = || format!("session exceeded {}s", config.session_limit.as_secs());
    match job {
        Job::Codex(payload) => {
            let status = match tokio::time::timeout(config.session_limit, verify(socket, &payload, &config.upstream)).await {
                Ok(Ok(verified)) => Status::Accepted { verified, duration_ms: started.elapsed().as_millis() as u64 },
                Ok(Err(e)) => Status::Rejected { reason: format!("{e:#}") },
                Err(_) => Status::Rejected { reason: timed_out() },
            };
            match &status {
                Status::Accepted { verified, .. } => println!("verifier: job {job_id} accepted, model {}", verified.model),
                Status::Rejected { reason } => println!("verifier: job {job_id} rejected: {reason}"),
                _ => {}
            }
            if let Some(entry) = sessions.lock().unwrap().by_job.get_mut(&key) {
                entry.status = status;
            }
        }
        Job::X(specs) => {
            let outcome = match tokio::time::timeout(config.session_limit, verify_x(socket)).await {
                // Parse the response before taking the lock that every session shares.
                Ok(Ok((exchange, sent_bytes, received_bytes))) => Ok((xpolicy::outcome(&exchange), exchange, sent_bytes, received_bytes)),
                Ok(Err(e)) => Err(format!("{e:#}")),
                Err(_) => Err(timed_out()),
            };
            let mut guard = sessions.lock().unwrap();
            let s = &mut *guard;
            let Some(Entry { status: Status::XRead { complete, pending, exchanges, rejections, .. }, .. }) = s.by_job.get_mut(&key) else {
                return Ok(());
            };
            // Match under the lock, so concurrent proofs of one exchange cannot both fulfil it.
            let matched = outcome.and_then(|((fulfilled, cursors), exchange, sent_bytes, received_bytes)| {
                let done: Vec<(usize, &[String])> = exchanges.iter().filter(|r| r.fulfilled).map(|r| (r.index, r.cursors.as_slice())).collect();
                match xpolicy::assign(&specs, &done, &exchange) {
                    Ok(index) => Ok(XRecord {
                        index,
                        fulfilled,
                        exchange,
                        cursors,
                        sent_bytes,
                        received_bytes,
                        duration_ms: started.elapsed().as_millis() as u64,
                    }),
                    Err(e) => Err(format!("{e:#}")),
                }
            });
            match matched {
                Ok(record) => {
                    println!(
                        "verifier: job {job_id} proved X {} for exchange {} (HTTP {})",
                        record.exchange.operation, record.index, record.exchange.http_status
                    );
                    if record.fulfilled {
                        pending.retain(|&i| i != record.index);
                    }
                    exchanges.push(record);
                    if pending.is_empty() {
                        *complete = true;
                        s.by_token.retain(|_, k| *k != key);
                    }
                }
                Err(reason) => {
                    println!("verifier: job {job_id} rejected an X exchange: {reason}");
                    rejections.push(reason);
                }
            }
        }
    }
    Ok(())
}

async fn verify(socket: TcpStream, job: &Value, upstream: &str) -> Result<Verified> {
    let (server_name, transcript) = prove_session(socket, Some(upstream)).await?;
    let sent_hidden: Vec<_> = transcript.sent_unauthed().iter().collect();
    let received_hidden: Vec<_> = transcript.received_unauthed().iter().collect();
    policy::check(&server_name, transcript.sent_unsafe(), &sent_hidden, transcript.received_unsafe(), &received_hidden, job)
}

/// Returns the verified exchange and the transcript's sent and received sizes.
async fn verify_x(socket: TcpStream) -> Result<(Exchange, usize, usize)> {
    let (server_name, transcript) = prove_session(socket, None).await?;
    let sent_hidden: Vec<_> = transcript.sent_unauthed().iter().collect();
    let received_hidden: Vec<_> = transcript.received_unauthed().iter().collect();
    let (sent, received) = (transcript.sent_unsafe(), transcript.received_unsafe());
    let exchange = xpolicy::check(&server_name, sent, &sent_hidden, received, &received_hidden)?;
    Ok((exchange, sent.len(), received.len()))
}

/// Runs one TLSNotary session: proxy mode through `upstream` when given, else
/// MPC-TLS within the X size limits. Returns the proven server name and transcript.
async fn prove_session(socket: TcpStream, upstream: Option<&str>) -> Result<(String, PartialTranscript)> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier = handle.new_verifier(VerifierConfig::builder().root_store(RootCertStore::mozilla()).build()?)?;
    let verifier = match (verifier.commit().await?, upstream) {
        (VerifierCommitStart::Proxy(verifier), Some(upstream)) => {
            // The verifier, not the supplier, opens the connection to OpenAI.
            let server = TcpStream::connect(upstream).await?;
            server.set_nodelay(true)?;
            verifier.accept().await?.run(server.compat()).await?
        }
        (VerifierCommitStart::Mpc(verifier), None) => {
            let cfg = verifier.config();
            if cfg.max_sent_data() > MAX_SENT || cfg.max_recv_data() > MAX_RECV {
                verifier.reject(Some("MPC-TLS limits are too large")).await?;
                bail!("supplier asked for MPC-TLS limits above {MAX_SENT} sent / {MAX_RECV} received bytes");
            }
            verifier.accept().await?.run().await?
        }
        (VerifierCommitStart::Proxy(verifier), None) => {
            verifier.reject(Some("X reads must use MPC-TLS")).await?;
            bail!("X reads must use MPC-TLS");
        }
        (VerifierCommitStart::Mpc(verifier), Some(_)) => {
            verifier.reject(Some("only proxy mode is accepted")).await?;
            bail!("only proxy mode is accepted");
        }
    };
    let verifier = verifier.verify().await?;
    if !verifier.request().server_identity() {
        let verifier = verifier.reject(Some("server name must be revealed")).await?;
        verifier.close().await?;
        bail!("supplier did not reveal the server name");
    }
    let (VerifierOutput { server_name, transcript, .. }, verifier) = verifier.accept().await?;
    verifier.close().await?;
    handle.close();
    driver_task.await??;

    let ServerName::Dns(server_name) = server_name.context("server name missing")?;
    Ok((server_name.as_str().to_owned(), transcript.context("transcript missing")?))
}
