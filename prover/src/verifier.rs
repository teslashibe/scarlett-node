//! Validator side. The coordinator registers the exact job payload over a
//! bearer-protected HTTP API and receives a single-use token for the supplier.
//! Suppliers connect to the session port, send `<token>\n`, then run TLSNotary.
//! The verifier opens the connection to OpenAI itself and records only what it
//! verified; the coordinator reads that result, never the supplier's copy.
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
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::policy::{self, Verified};

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
}

struct Entry {
    payload: Value,
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
    if let Err(e) = policy::validate_job(&request.payload) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()})));
    }
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
    sessions.by_job.insert(key.clone(), Entry { payload: request.payload, expires: now + ttl, status: Status::Pending });
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

async fn handle(shared: Shared, mut socket: TcpStream) -> Result<()> {
    let (config, sessions) = &*shared;
    let mut line = [0u8; 65];
    tokio::time::timeout(Duration::from_secs(10), socket.read_exact(&mut line)).await.context("no session token")??;
    if line[64] != b'\n' {
        bail!("malformed session token");
    }
    let token = std::str::from_utf8(&line[..64])?;
    let (key, payload) = {
        let mut sessions = sessions.lock().unwrap();
        // Tokens are single use: removing it here blocks replays and parallel attempts.
        let key = sessions.by_token.remove(token).context("unknown or used session token")?;
        let entry = sessions.by_job.get_mut(&key).context("session expired")?;
        if Instant::now() >= entry.expires {
            entry.status = Status::Expired;
            bail!("session expired");
        }
        entry.status = Status::Running;
        (key, entry.payload.clone())
    };

    let started = Instant::now();
    let result = tokio::time::timeout(config.session_limit, verify(socket, &payload, &config.upstream)).await;
    let status = match result {
        Ok(Ok(verified)) => Status::Accepted { verified, duration_ms: started.elapsed().as_millis() as u64 },
        Ok(Err(e)) => Status::Rejected { reason: format!("{e:#}") },
        Err(_) => Status::Rejected { reason: format!("session exceeded {}s", config.session_limit.as_secs()) },
    };
    let job_id = key.split('\n').next().unwrap_or_default();
    match &status {
        Status::Accepted { verified, .. } => println!("verifier: job {job_id} accepted, model {}", verified.model),
        Status::Rejected { reason } => println!("verifier: job {job_id} rejected: {reason}"),
        _ => {}
    }
    if let Some(entry) = sessions.lock().unwrap().by_job.get_mut(&key) {
        entry.status = status;
    }
    Ok(())
}

async fn verify(socket: TcpStream, job: &Value, upstream: &str) -> Result<Verified> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier = handle.new_verifier(VerifierConfig::builder().root_store(RootCertStore::mozilla()).build()?)?;
    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Proxy(verifier) => {
            // The verifier, not the supplier, opens the connection to OpenAI.
            let server = TcpStream::connect(upstream).await?;
            verifier.accept().await?.run(server.compat()).await?
        }
        VerifierCommitStart::Mpc(_) => bail!("only proxy mode is accepted"),
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
    let transcript = transcript.context("transcript missing")?;
    let sent_hidden: Vec<_> = transcript.sent_unauthed().iter().collect();
    let received_hidden: Vec<_> = transcript.received_unauthed().iter().collect();
    policy::check(
        server_name.as_str(),
        transcript.sent_unsafe(),
        &sent_hidden,
        transcript.received_unsafe(),
        &received_hidden,
        job,
    )
}
