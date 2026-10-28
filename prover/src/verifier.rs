//! Validator side. The coordinator registers the exact job payload over a
//! bearer-protected HTTP API and receives a token for the supplier.
//! Suppliers connect to the session port, send `<token>\n`, then run TLSNotary.
//! Codex jobs use proxy mode: the verifier opens the connection to OpenAI
//! itself and the token is single use. X reads (`x.read`) use MPC-TLS so the
//! supplier's own connection reaches X; the job pins every read it pays for,
//! and the token allows `max_attempts` proofs until every pinned read is
//! fulfilled. The verifier records only what it verified; the coordinator
//! reads that result, never the supplier's copy.
//! Web fetches (`web.fetch`) are relay sessions to any public https host: one
//! session per redirect hop under one token, run one at a time. Hop 0 fetches
//! the job URL and each later hop only the canonical `Location` of the hop
//! before it. Every verified hop is committed before the supplier learns it,
//! and one failed session ends the job (see webpolicy.rs). A `web-browser-v1`
//! hop also records the node's User-Agent, its cookie names and a hash of
//! its Cookie value, never the value.
//!
//!
//! A web job's final page is never in its receipt: the verifier streams the
//! entity to a private body file beside it (see body.rs), which the
//! coordinator reads with `GET /v1/sessions/{job}/{attempt}/body` and
//! releases with `DELETE` once it has the result. Web sessions take one of
//! `SCARLETT_VERIFIER_WEB_CONCURRENCY` slots (else `verifier_busy`), and web
//! receipts and bodies live in a pool (`SCARLETT_VERIFIER_MAX_WEB_BYTES`)
//! that always leaves X and Codex a full receipt. The contract is
//! api/verifier-v1.md.
//!
//! Environment: SCARLETT_VERIFIER_KEY (required, 32+ chars),
//! SCARLETT_VERIFIER_LISTEN (default 0.0.0.0:7047), SCARLETT_VERIFIER_API
//! (default 127.0.0.1:7070), UPSTREAM (default chatgpt.com:443),
//! SESSION_TIMEOUT_SECS (default 300). Optional SCARLETT_VERIFIER_STATE_DIR
//! enables private durable receipts and requires absolute expiry/fence bindings.

use std::{
    collections::HashMap,
    env,
    net::IpAddr,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
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
    io::{AsyncReadExt, AsyncSeekExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::{compat::TokioAsyncReadCompatExt, io::ReaderStream};

use crate::{
    policy::{self, Verified},
    relay::verifier::{Conn, Failure, HopClock, TimedOut, Timing, TokenWait, WebReader, web_session},
    verifier_store::{self, Record, Store},
    webpolicy::{self, Framer},
    xpolicy::{self, Exchange, ProofMode, Spec},
    xprove::{MAX_RECV, MAX_SENT},
};

const MAX_TTL: Duration = Duration::from_secs(600);

/// A durable X job pins one to ten exchanges (a search of up to ten pages),
/// with one attempt each.
const MAX_DURABLE_X_EXCHANGES: usize = 10;

/// X and Codex always keep this many of the verifier's session slots.
const X_CODEX_SLOTS: usize = 16;

/// Connections that may wait for a token at once, all told and from one
/// source address (SCARLETT_VERIFIER_PRE_TOKEN_LIMIT and _PER_ADDRESS). One
/// node holds at most one per web slot (32 at most) for its hops and pre-
/// dials, plus its warm pool (2, and 2 replacing them): one node at full
/// concurrency never meets the per-address cap.
const PRE_TOKEN_LIMIT: usize = 2048;
const PRE_TOKEN_PER_ADDRESS: usize = 64;

struct Config {
    key: String,
    upstream: String,
    session_limit: Duration,
    limits: verifier_store::Limits,
    concurrency: usize,
    slots: Arc<tokio::sync::Semaphore>,
    /// TLS client settings for relay sessions, where the verifier is X's TLS peer.
    relay_tls: Arc<rustls::ClientConfig>,
    /// Web sessions admitted at once; beyond them a web session is turned
    /// away as `verifier_busy` without spending anything.
    web_concurrency: usize,
    web_slots: Arc<tokio::sync::Semaphore>,
    web_timing: Timing,
    busy_refusals: AtomicU64,
    /// Web sessions' terminal commits, for `GET /v1/events`.
    events: crate::verifier_events::Feed,
    /// Connections waiting for a token, and how long they may wait: a new
    /// connection `token_wait`, one that sent PING or finished a web session
    /// `idle_wait`.
    pre_token: Arc<PreToken>,
    token_wait: Duration,
    idle_wait: Duration,
}

impl Config {
    fn new(key: String, upstream: String, session_limit: Duration, limits: verifier_store::Limits, concurrency: usize, web_concurrency: usize, relay_tls: Arc<rustls::ClientConfig>) -> Self {
        Self {
            key,
            upstream,
            session_limit,
            limits,
            concurrency,
            slots: Arc::new(tokio::sync::Semaphore::new(concurrency)),
            relay_tls,
            web_concurrency,
            web_slots: Arc::new(tokio::sync::Semaphore::new(web_concurrency)),
            web_timing: Timing::WEB,
            busy_refusals: AtomicU64::new(0),
            events: crate::verifier_events::Feed::new(),
            pre_token: Arc::new(PreToken::new(PRE_TOKEN_LIMIT, PRE_TOKEN_PER_ADDRESS)),
            token_wait: Duration::from_secs(10),
            idle_wait: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
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
    WebRead {
        remaining_sessions: usize,
        /// The last hop was final: the job's response is recorded.
        complete: bool,
        /// The URL the next hop must fetch, while the chain may go on.
        next_url: Option<String>,
        hops: Vec<WebHop>,
        rejections: Vec<String>,
        /// The failed hop's byte counts, exactly when `rejections` is not empty.
        rejection: Option<Rejection>,
        /// When the coordinator released the page body file.
        body_released_at_ms: Option<u64>,
    },
}

/// Why a web hop failed, with what it had taken: lower bounds of the page's
/// size when the reason is `page_too_large`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rejection {
    reason: String,
    received_bytes: u64,
    entity_bytes: u64,
    /// The final head's Content-Length, if it had one.
    declared_bytes: Option<u64>,
}

impl Rejection {
    fn new(reason: &str, counts: webpolicy::Counts) -> Self {
        Self { reason: reason.into(), received_bytes: counts.received as u64, entity_bytes: counts.entity as u64, declared_bytes: counts.declared }
    }
}

/// One verified web hop.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WebHop {
    index: usize,
    /// Canonical; hop 0 is the job URL and each later hop the location before it.
    url: String,
    status_code: u16,
    /// The canonical next URL of a followable redirect, set even on the last allowed hop.
    location: Option<String>,
    /// Why a redirect's `Location` was not followable.
    location_refused: Option<String>,
    /// The final (non-1xx) status line and headers, through the blank line.
    head_base64: String,
    /// Whether the entity (dechunked, still content-encoded) is kept in the
    /// receipt's body file: exactly on the final hop of a complete chain.
    body_stored: bool,
    /// Entity bytes and their hash, on every hop: a followable redirect's
    /// body is counted and hashed but not kept.
    body_bytes: usize,
    body_sha256: String,
    /// Every decrypted response byte up to completion, interim heads included.
    response_sha256: String,
    framing: String,
    sent_bytes: usize,
    received_bytes: usize,
    server_name: String,
    tls_version: String,
    cipher_suite: String,
    alpn: Option<String>,
    cert_chain_sha256: String,
    leaf_cert_sha256: String,
    started_at_ms: u64,
    duration_ms: u64,
    /// `web-browser-v1` jobs only, and then always: the User-Agent the node sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    node_user_agent: Option<String>,
    /// `web-browser-v1` jobs only, and then always: the names of the
    /// clearance cookies the node sent, in header order, empty without a Cookie line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    node_cookie_names: Option<Vec<String>>,
    /// SHA-256 of the Cookie value the node sent, when it sent one. The
    /// value itself is never kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    node_cookie_sha256: Option<String>,
}

/// The reasons a web hop can be rejected for.
const WEB_REJECTIONS: [&str; 8] = ["tls_failed", "request_rejected", "page_too_large", "response_invalid", "server_closed", "session_timeout", "execution_uncertain", "proof_rejected"];
const WEB_TLS_VERSION: &str = "TLSv1_3";
/// The only suite a relay session negotiates (`relay::verifier::tls_config`).
const WEB_CIPHER_SUITE: &str = "TLS13_AES_128_GCM_SHA256";

#[derive(Clone, Serialize, Deserialize)]
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
    X(Arc<Vec<Spec>>, ProofMode),
    Web(Arc<webpolicy::Job>),
}

struct Entry {
    payload: Value,
    kind: Kind,
    expires: Instant,
    status: Status,
    expires_ms: u64,
    fence: String,
    in_flight: usize,
}

struct Sessions {
    by_job: HashMap<String, Entry>,
    by_token: HashMap<String, String>,
    store: Option<Store>,
    failed: bool,
    /// Without a store: a private temporary directory for page bodies.
    temp_bodies: Option<TempBodies>,
    /// Web receipts purged while this process ran, so their bodies read as
    /// released (410) rather than unknown.
    purged: HashMap<String, u64>,
}

impl Default for Sessions {
    fn default() -> Self {
        Self { by_job: HashMap::new(), by_token: HashMap::new(), store: None, failed: false, temp_bodies: Some(TempBodies::new()), purged: HashMap::new() }
    }
}

/// The page body directory of a verifier without durable state, removed
/// with it.
struct TempBodies(PathBuf);

impl TempBodies {
    fn new() -> Self {
        let dir = env::temp_dir().join(format!("scarlett-verifier-bodies-{:032x}", rand::random::<u128>()));
        let _ = std::fs::DirBuilder::new().mode(0o700).create(&dir);
        Self(dir)
    }
}

impl Drop for TempBodies {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Why a body cannot be read.
#[derive(Debug, PartialEq, Eq)]
enum NoBody {
    /// No such receipt.
    Unknown,
    /// The receipt never stored a body.
    None,
    /// Released, or purged while this process ran.
    Released,
}

/// Unlinks page body files on the blocking pool, after the receipts that
/// held them are gone.
fn unlink_later(paths: Vec<PathBuf>) {
    if paths.is_empty() {
        return;
    }
    tokio::task::spawn_blocking(move || {
        for path in paths {
            if let Err(e) = std::fs::remove_file(&path)
                && e.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!("verifier: could not remove a page body file: {}", e.kind());
            }
        }
    });
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}
fn kind(payload: &Value, durable: bool) -> Result<(Kind, Status)> {
    if payload["type"] == "x.read" {
        let (specs, max) = xpolicy::validate_job(payload)?;
        let mode = xpolicy::proof_mode(payload)?;
        if durable && (specs.len() > MAX_DURABLE_X_EXCHANGES || max != specs.len()) {
            bail!("durable X jobs require 1-{MAX_DURABLE_X_EXCHANGES} exchanges with one attempt each");
        }
        let pending = (0..specs.len()).collect();
        Ok((
            Kind::X(Arc::new(specs), mode),
            Status::XRead { remaining_attempts: max, complete: false, pending, exchanges: Vec::new(), rejections: Vec::new() },
        ))
    } else if payload["type"] == webpolicy::PAYLOAD_TYPE {
        let job = webpolicy::validate_job(payload)?;
        let sessions = job.max_redirects + 1;
        Ok((
            Kind::Web(Arc::new(job)),
            Status::WebRead { remaining_sessions: sessions, complete: false, next_url: None, hops: Vec::new(), rejections: Vec::new(), rejection: None, body_released_at_ms: None },
        ))
    } else {
        policy::validate_job(payload)?;
        Ok((Kind::Codex, Status::Pending))
    }
}
// Persisted status must describe the same job and spent attempts. A malformed
// local receipt must stop startup, never become an authoritative success.
fn validate_receipt(kind: &Kind, status: &Status, in_flight: usize) -> Result<()> {
    match (kind, status) {
        (Kind::Codex, Status::Pending) if in_flight == 0 => Ok(()),
        (Kind::Codex, Status::Accepted { verified, .. }) if in_flight == 0 && verified.cached_input_tokens.is_none_or(|cached| cached <= verified.input_tokens) => Ok(()),
        (Kind::Codex, Status::Running) if in_flight == 1 => Ok(()),
        (_, Status::Rejected { .. } | Status::Expired) if in_flight == 0 => Ok(()),
        (Kind::X(specs, _), Status::XRead { remaining_attempts, complete, pending, exchanges, rejections }) => {
            if remaining_attempts
                .checked_add(exchanges.len())
                .and_then(|n| n.checked_add(rejections.len()))
                .and_then(|n| n.checked_add(in_flight))
                != Some(specs.len())
            {
                bail!("invalid X receipt attempt count");
            }
            let mut done: Vec<(usize, &Exchange, &[String])> = Vec::new();
            let cursors: Vec<Vec<String>> = exchanges.iter().map(|r| xpolicy::outcome(&r.exchange).1).collect();
            for (record, cursors) in exchanges.iter().zip(&cursors) {
                if record.index != xpolicy::assign(specs, &done, &record.exchange)?
                    || record.fulfilled != xpolicy::outcome(&record.exchange).0
                    || record.sent_bytes > MAX_SENT
                    || record.received_bytes > MAX_RECV
                {
                    bail!("invalid X receipt exchange");
                }
                if record.fulfilled {
                    done.push((record.index, &record.exchange, cursors));
                }
            }
            let expected: Vec<_> = (0..specs.len()).filter(|i| !done.iter().any(|(k, _, _)| k == i)).collect();
            if pending != &expected || *complete != expected.is_empty() {
                bail!("invalid X receipt completion");
            }
            Ok(())
        }
        (Kind::Web(job), Status::WebRead { remaining_sessions, complete, next_url, hops, rejections, rejection, body_released_at_ms }) => {
            if in_flight > 1
                || remaining_sessions.checked_add(hops.len()).and_then(|n| n.checked_add(rejections.len())).and_then(|n| n.checked_add(in_flight)) != Some(job.max_redirects + 1)
                || rejections.len() > 1
                || rejections.iter().any(|r| !WEB_REJECTIONS.contains(&r.as_str()))
                || ((in_flight > 0 || *complete) && !rejections.is_empty())
                || (in_flight > 0 && *complete)
            {
                bail!("invalid web receipt session count");
            }
            if rejection.as_ref().map(|r| r.reason.as_str()) != rejections.first().map(String::as_str) || rejection.as_ref().is_some_and(|r| r.entity_bytes > r.received_bytes) {
                bail!("invalid web receipt rejection");
            }
            let is_final = |hop: &WebHop| hop.location.is_none() || hop.index == job.max_redirects;
            for (i, hop) in hops.iter().enumerate() {
                let url = if i == 0 { Some(&job.url) } else { hops[i - 1].location.as_ref() };
                let last = i + 1 == hops.len();
                if hop.index != i || Some(&hop.url) != url || (!last && is_final(hop)) || hop.body_stored != (last && *complete) {
                    bail!("invalid web receipt chain");
                }
                valid_web_hop(job, hop)?;
            }
            let followable = hops.last().and_then(|hop| hop.location.as_ref()).filter(|_| !*complete && rejections.is_empty());
            if *complete != hops.last().is_some_and(is_final) || next_url.as_ref() != followable || (body_released_at_ms.is_some() && !*complete) {
                bail!("invalid web receipt completion");
            }
            Ok(())
        }
        _ => bail!("receipt status does not match the job"),
    }
}

/// The most a web receipt's JSON can hold (verifier_store::web_json_bound).
fn web_json_bound(job: &webpolicy::Job) -> u64 {
    verifier_store::web_json_bound(job.max_redirects)
}

fn valid_web_hop(job: &webpolicy::Job, hop: &WebHop) -> Result<()> {
    let hex = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let canonical = |url: &str| webpolicy::canonical_url(url).ok().as_deref() == Some(url);
    let redirect = webpolicy::REDIRECTS.contains(&hop.status_code);
    let head = STANDARD.decode(&hop.head_base64).ok().filter(|head| head.len() <= webpolicy::MAX_HEAD);
    // A browser job's hops say what the node sent, and only those; never a cookie value.
    let node_ok = match job.policy {
        webpolicy::Policy::Relay => hop.node_user_agent.is_none() && hop.node_cookie_names.is_none() && hop.node_cookie_sha256.is_none(),
        webpolicy::Policy::Browser => {
            hop.node_user_agent.as_deref().is_some_and(webpolicy::browser_user_agent)
                && hop.node_cookie_names.as_deref().is_some_and(|names| webpolicy::allowed_cookie_names(names) && names.is_empty() == hop.node_cookie_sha256.is_none())
                && hop.node_cookie_sha256.as_deref().is_none_or(hex)
        }
    };
    if !node_ok {
        bail!("invalid web receipt node headers");
    }
    if !canonical(&hop.url)
        || hop.server_name != webpolicy::url_host(&hop.url)
        || !(200..=999).contains(&hop.status_code)
        || hop.location.as_deref().is_some_and(|next| !redirect || !canonical(next) || hop.location_refused.is_some())
        || hop.location_refused.as_deref().is_some_and(|reason| !redirect || !webpolicy::UrlError::ALL.iter().any(|e| e.code() == reason))
        || head.is_none()
        || hop.body_bytes > hop.received_bytes
        || hop.body_bytes > job.max_response_bytes
        || hop.received_bytes > webpolicy::max_wire(job.max_response_bytes)
        || !(1..=crate::relay::MAX_REQUEST).contains(&hop.sent_bytes)
        || ![&hop.body_sha256, &hop.response_sha256, &hop.cert_chain_sha256, &hop.leaf_cert_sha256].into_iter().all(|h| hex(h))
        || !["none", "content_length", "chunked", "close"].contains(&hop.framing.as_str())
        || hop.tls_version != WEB_TLS_VERSION
        || hop.cipher_suite != WEB_CIPHER_SUITE
    {
        bail!("invalid web receipt hop");
    }
    Ok(())
}
impl Sessions {
    fn restore(store: Store, records: Vec<Record>) -> Result<Self> {
        let mut s = Self { by_job: HashMap::new(), by_token: HashMap::new(), store: Some(store), failed: false, temp_bodies: None, purged: HashMap::new() };
        let now = now_ms();
        for r in records {
            if r.expires_ms > now.saturating_add(MAX_TTL.as_millis() as u64) {
                bail!("verifier receipt expiry exceeds the session bound");
            }
            if r.in_flight == 0 && r.status["reason"] != "execution_uncertain" && now > r.expires_ms.saturating_add(verifier_store::retention_ms(&r.payload)) {
                if let Some(body) = s.store.as_mut().unwrap().remove(&r.job_id, &r.attempt)?
                    && let Err(e) = std::fs::remove_file(body)
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    return Err(e.into());
                }
                continue;
            }
            let (kind, _) = kind(&r.payload, true)?;
            let mut status: Status = serde_json::from_value(r.status)?;
            validate_receipt(&kind, &status, r.in_flight)?;
            let mut token = r.token;
            if r.in_flight > 0 || matches!(status, Status::Running) {
                if let Status::WebRead { rejections, rejection, next_url, .. } = &mut status {
                    // A web receipt keeps the hops it verified; the interrupted one ends the job.
                    rejections.push("execution_uncertain".into());
                    *rejection = Some(Rejection::new("execution_uncertain", webpolicy::Counts::default()));
                    *next_url = None;
                } else {
                    status = Status::Rejected { reason: "execution_uncertain".into() };
                }
                token = None;
            }
            if let Status::XRead { exchanges, .. } = &mut status {
                for record in exchanges.iter_mut().filter(|r| r.fulfilled) {
                    record.cursors = xpolicy::outcome(&record.exchange).1;
                }
            }
            let reusable = match &status {
                Status::Pending | Status::XRead { remaining_attempts: 1.., complete: false, .. } => true,
                Status::WebRead { remaining_sessions, complete, rejections, .. } => *remaining_sessions > 0 && !complete && rejections.is_empty(),
                _ => false,
            };
            if r.expires_ms <= now || !reusable {
                token = None;
            }
            let key = job_key(&r.job_id, &r.attempt);
            if let Some(token) = token
                && s.by_token.insert(token, key.clone()).is_some()
            {
                bail!("duplicate persisted verifier token");
            }
            s.by_job.insert(
                key.clone(),
                Entry {
                    payload: r.payload,
                    kind,
                    status,
                    expires: Instant::now() + Duration::from_millis(r.expires_ms.saturating_sub(now)),
                    expires_ms: r.expires_ms,
                    fence: r.fence,
                    in_flight: 0,
                },
            );
            s.commit(&key)?;
        }
        Ok(s)
    }
    fn commit(&mut self, key: &str) -> Result<()> {
        let Some(store) = self.store.as_mut() else {
            return Ok(());
        };
        let entry = self.by_job.get(key).context("unknown receipt")?;
        let (job_id, attempt) = key.split_once('\n').context("invalid receipt key")?;
        let record = Record {
            schema: 1,
            job_id: job_id.into(),
            attempt: attempt.into(),
            fence: entry.fence.clone(),
            payload: entry.payload.clone(),
            status: serde_json::to_value(&entry.status)?,
            expires_ms: entry.expires_ms,
            in_flight: entry.in_flight,
            token: self.by_token.iter().find(|(_, k)| k.as_str() == key).map(|(t, _)| t.clone()),
        };
        let result = store.save(&record);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    /// Where a receipt's page body lives.
    fn body_path(&self, key: &str) -> PathBuf {
        let (job, attempt) = key.split_once('\n').unwrap_or((key, ""));
        match (&self.store, &self.temp_bodies) {
            (Some(store), _) => store.body_path(job, attempt),
            (None, Some(temp)) => temp.0.join(format!("{}{}", verifier_store::hash(key.as_bytes()), crate::body::SUFFIX)),
            (None, None) => PathBuf::from("/nonexistent"),
        }
    }

    /// The stored, unreleased page body of a receipt: its path, size and SHA-256.
    fn body(&self, key: &str) -> Result<(PathBuf, u64, String), NoBody> {
        let Some(entry) = self.by_job.get(key) else {
            return Err(if self.purged.contains_key(key) { NoBody::Released } else { NoBody::Unknown });
        };
        match &entry.status {
            Status::WebRead { complete: true, hops, body_released_at_ms, .. } if hops.last().is_some_and(|hop| hop.body_stored) => {
                if body_released_at_ms.is_some() {
                    return Err(NoBody::Released);
                }
                let hop = hops.last().expect("a stored body has a hop");
                Ok((self.body_path(key), hop.body_bytes as u64, hop.body_sha256.clone()))
            }
            _ => Err(NoBody::None),
        }
    }

    /// Removes receipts past retention and returns the page body files they
    /// may leave, for the caller to unlink outside the lock.
    fn purge(&mut self) -> Result<Vec<PathBuf>> {
        let now = now_ms();
        self.purged.retain(|_, at| now.saturating_sub(*at) < verifier_store::RETENTION_MS);
        // Expiry revokes unspent tokens and releases reserved result space.
        // In-flight proofs keep their reservation until their outcome commits.
        let expired: Vec<_> = self.by_token.values().filter(|key| self.by_job.get(*key).is_some_and(|e| e.in_flight == 0 && e.expires_ms <= now)).cloned().collect();
        for key in expired {
            self.by_token.retain(|_, value| value != &key);
            self.commit(&key)?;
        }
        let durable = self.store.is_some();
        let retention = |e: &Entry| if durable { verifier_store::retention_ms(&e.payload) } else { MAX_TTL.as_millis() as u64 };
        let stale: Vec<_> = self
            .by_job
            .iter()
            .filter(|(_, e)| e.in_flight == 0 && !matches!(&e.status, Status::Rejected { reason } if reason == "execution_uncertain") && now > e.expires_ms.saturating_add(retention(e)))
            .map(|(k, _)| k.clone())
            .collect();
        let mut bodies = Vec::new();
        for key in stale {
            if let Some(store) = self.store.as_mut() {
                let (job, attempt) = key.split_once('\n').context("invalid receipt key")?;
                match store.remove(job, attempt) {
                    Ok(body) => bodies.extend(body),
                    Err(e) => {
                        self.failed = true;
                        return Err(e);
                    }
                }
            } else if self.by_job.get(&key).is_some_and(|e| matches!(e.kind, Kind::Web(_))) {
                bodies.push(self.body_path(&key));
            }
            if self.by_job.get(&key).is_some_and(|e| matches!(&e.status, Status::WebRead { hops, .. } if hops.last().is_some_and(|h| h.body_stored))) {
                self.purged.insert(key.clone(), now);
            }
            self.by_job.remove(&key);
            self.by_token.retain(|_, k| k != &key);
        }
        Ok(bodies)
    }
}

/// Where test connections come from, and their place among the waiting.
#[cfg(test)]
const LOCAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
#[cfg(test)]
fn waiting(shared: &Shared) -> Waiting {
    shared.0.pre_token.take(LOCAL).expect("a place to wait for a token")
}

#[cfg(test)]
mod durable_tests {
    use super::*;
    use serde_json::json;
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = env::temp_dir().join(format!("scarlett-verifier-api-{}", rand::random::<u128>()));
            fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn shared(dir: &std::path::Path) -> Shared {
        let (store, records) = Store::open(dir).unwrap();
        Arc::new((
            Config::new("synthetic-fixture-key-never-used-remotely".into(), "127.0.0.1:1".into(), Duration::from_secs(30), verifier_store::Limits::default(), 64, 48, crate::relay::verifier::tls_config(rustls::RootCertStore::empty()).unwrap()),
            Mutex::new(Sessions::restore(store, records).unwrap()),
        ))
    }
    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer synthetic-fixture-key-never-used-remotely".parse().unwrap());
        h
    }
    fn request(expires: u64) -> CreateRequest {
        CreateRequest {
            job_id: "synthetic".into(),
            attempt: "1".into(),
            fence: Some("f1".into()),
            expires_at_ms: Some(expires),
            ttl_seconds: None,
            payload: json!({"type":"response.create","model":"synthetic-model"}),
        }
    }
    #[tokio::test]
    async fn registration_acknowledgement_is_idempotent_and_binds_fence_payload_expiry() {
        let dir = Temp::new();
        let expires = now_ms() + 30_000;
        let s = shared(&dir.0);
        let (code, Json(first)) = create(State(s.clone()), headers(), Json(request(expires))).await;
        assert_eq!(code, StatusCode::CREATED);
        assert_eq!(first["durable"], true);
        drop(s);
        let s = shared(&dir.0);
        let (code, Json(retry)) = create(State(s.clone()), headers(), Json(request(expires))).await;
        assert_eq!(code, StatusCode::CREATED);
        assert_eq!(first["token"], retry["token"]);
        for change in ["fence", "payload", "expiry"] {
            let mut r = request(expires);
            match change {
                "fence" => r.fence = Some("wrong".into()),
                "payload" => r.payload["model"] = "changed".into(),
                _ => r.expires_at_ms = Some(expires + 1),
            }
            assert_eq!(create(State(s.clone()), headers(), Json(r)).await.0, StatusCode::CONFLICT);
        }
        let (code, Json(view)) = status(State(s), headers(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(view["fence"], "f1");
        assert_eq!(view["expires_at_ms"], expires);
        assert_eq!(view["request_sha256"], verifier_store::hash(&serde_json::to_vec(&request(expires).payload).unwrap()));
        assert!(view.get("token").is_none());
    }
    #[tokio::test]
    async fn accepted_receipt_survives_restart_but_interrupted_proof_is_uncertain() {
        for (complete, cached) in [(true, None), (true, Some(0)), (true, Some(3)), (false, None)] {
            let dir = Temp::new();
            let s = shared(&dir.0);
            let expires = now_ms() + 30_000;
            assert_eq!(create(State(s.clone()), headers(), Json(request(expires))).await.0, StatusCode::CREATED);
            {
                let mut sessions = s.1.lock().unwrap();
                let key = job_key("synthetic", "1");
                sessions.by_token.clear();
                let e = sessions.by_job.get_mut(&key).unwrap();
                e.status = if complete {
                    Status::Accepted {
                        verified: Verified {
                            model: "synthetic-model".into(),
                            output: "synthetic accepted result".into(),
                            input_tokens: 8,
                            cached_input_tokens: cached,
                            output_tokens: 4,
                        },
                        duration_ms: 1,
                    }
                } else {
                    Status::Running
                };
                e.in_flight = usize::from(!complete);
                sessions.commit(&key).unwrap();
            }
            drop(s);
            let s = shared(&dir.0);
            let (_, Json(view)) = status(State(s.clone()), headers(), Path(("synthetic".into(), "1".into()))).await;
            if complete {
                assert_eq!(view["status"], "accepted");
                assert_eq!(view["output"], "synthetic accepted result");
                assert_eq!(view.get("cached_input_tokens"), cached.map(|n| json!(n)).as_ref());
            } else {
                assert_eq!(view["status"], "rejected");
                assert_eq!(view["reason"], "execution_uncertain");
            }
            assert!(s.1.lock().unwrap().by_token.is_empty());
            assert_eq!(create(State(s), headers(), Json(request(expires))).await.0, StatusCode::CONFLICT);
        }
    }
    #[tokio::test]
    async fn invalid_cached_usage_stops_durable_restore() {
        let dir = Temp::new();
        let s = shared(&dir.0);
        let expires = now_ms() + 30_000;
        assert_eq!(create(State(s.clone()), headers(), Json(request(expires))).await.0, StatusCode::CREATED);
        {
            let mut sessions = s.1.lock().unwrap();
            let key = job_key("synthetic", "1");
            let e = sessions.by_job.get_mut(&key).unwrap();
            e.status = Status::Accepted {
                verified: Verified {
                    model: "synthetic-model".into(), output: "synthetic result".into(),
                    input_tokens: 8, cached_input_tokens: Some(9), output_tokens: 4,
                },
                duration_ms: 1,
            };
            sessions.commit(&key).unwrap();
        }
        drop(s);
        let (store, records) = Store::open(&dir.0).unwrap();
        assert!(Sessions::restore(store, records).is_err());
    }
    #[tokio::test]
    async fn incomplete_x_exchange_crash_revokes_token_and_storage_failure_hides_success() {
        let dir = Temp::new();
        let s = shared(&dir.0);
        let expires = now_ms() + 30_000;
        let lease: Value = serde_json::from_str(include_str!("../../api/fixtures/lease-x.json")).unwrap();
        let mut r = request(expires);
        r.payload = lease["x_payload"].clone();
        assert_eq!(create(State(s.clone()), headers(), Json(r)).await.0, StatusCode::CREATED);
        {
            let mut sessions = s.1.lock().unwrap();
            let key = job_key("synthetic", "1");
            let e = sessions.by_job.get_mut(&key).unwrap();
            e.in_flight = 1;
            if let Status::XRead { remaining_attempts, .. } = &mut e.status {
                *remaining_attempts -= 1;
            }
            sessions.commit(&key).unwrap();
        }
        drop(s);
        let s = shared(&dir.0);
        let (_, Json(view)) = status(State(s.clone()), headers(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(view["reason"], "execution_uncertain");
        assert!(s.1.lock().unwrap().by_token.is_empty());
        // Losing the destination directory simulates a failed durable commit.
        fs::rename(&dir.0, dir.0.with_extension("moved")).unwrap();
        let mut r = request(expires);
        r.attempt = "2".into();
        assert_eq!(create(State(s.clone()), headers(), Json(r)).await.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status(State(s), headers(), Path(("synthetic".into(), "1".into()))).await.0, StatusCode::SERVICE_UNAVAILABLE);
        fs::rename(dir.0.with_extension("moved"), &dir.0).unwrap();
    }
    /// A search of up to ten pages registers durably, as
    /// api/fixtures/lease-x-pages10.json pins it: ten exchanges chained by
    /// cursor, one attempt each. An eleventh exchange or a retry is refused.
    #[tokio::test]
    async fn durable_x_jobs_take_one_to_ten_exchanges_with_one_attempt_each() {
        let lease: Value = serde_json::from_str(include_str!("../../api/fixtures/lease-x-pages10.json")).unwrap();
        let ten = lease["x_payload"].clone();
        assert_eq!(ten["exchanges"].as_array().unwrap().len(), MAX_DURABLE_X_EXCHANGES);
        let (k, st) = kind(&ten, true).unwrap();
        assert!(validate_receipt(&k, &st, 0).is_ok());
        assert!(matches!(&st, Status::XRead { remaining_attempts: 10, pending, .. } if pending.len() == 10));
        let mut eleven = ten.clone();
        let mut extra = eleven["exchanges"][9].clone();
        extra["cursor_from"] = 9.into();
        eleven["exchanges"].as_array_mut().unwrap().push(extra);
        eleven["max_attempts"] = 11.into();
        assert!(kind(&eleven, true).is_err());
        // Legacy ephemeral sessions keep the wider read policy.
        assert!(kind(&eleven, false).is_ok());
        let mut retry = ten.clone();
        retry["max_attempts"] = 11.into();
        assert!(kind(&retry, true).is_err());

        let dir = Temp::new();
        let s = shared(&dir.0);
        // A ten-page job's deadline is its creation second plus 298 s.
        let expires = now_ms() + 298_000;
        let mut r = request(expires);
        r.payload = ten;
        assert_eq!(create(State(s.clone()), headers(), Json(r)).await.0, StatusCode::CREATED);
        let mut r = request(expires);
        r.attempt = "2".into();
        r.payload = eleven;
        assert_eq!(create(State(s.clone()), headers(), Json(r)).await.0, StatusCode::BAD_REQUEST);
        let (code, Json(view)) = status(State(s), headers(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!((view["status"].as_str(), view["remaining_attempts"].as_u64(), view["complete"].as_bool()), (Some("x_read"), Some(10), Some(false)));
        assert_eq!(view["pending"].as_array().map(Vec::len), Some(10));
    }
    #[tokio::test]
    async fn durable_session_requires_fence_absolute_expiry_and_authorization() {
        let dir = Temp::new();
        let s = shared(&dir.0);
        let expires = now_ms() + 30_000;
        assert_eq!(create(State(s.clone()), HeaderMap::new(), Json(request(expires))).await.0, StatusCode::UNAUTHORIZED);
        let mut missing = request(expires);
        missing.fence = None;
        assert_eq!(create(State(s.clone()), headers(), Json(missing)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(create(State(s.clone()), headers(), Json(request(now_ms() + 601_000))).await.0, StatusCode::BAD_REQUEST);
        let mut invalid = request(expires);
        invalid.job_id = "job\nother-attempt".into();
        assert_eq!(create(State(s), headers(), Json(invalid)).await.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn malformed_receipt_cannot_turn_partial_x_work_into_success() {
        let lease: Value = serde_json::from_str(include_str!("../../api/fixtures/lease-x.json")).unwrap();
        let (kind, mut status) = kind(&lease["x_payload"], true).unwrap();
        assert!(validate_receipt(&kind, &status, 0).is_ok());
        if let Status::XRead { complete, .. } = &mut status {
            *complete = true;
        }
        assert!(validate_receipt(&kind, &status, 0).is_err());
        assert!(validate_receipt(&kind, &Status::Pending, 0).is_err());
        assert!(validate_receipt(&Kind::Codex, &status, 0).is_err());
    }

    #[tokio::test]
    async fn expired_incomplete_work_is_not_success_and_retention_removes_private_payloads() {
        let dir = Temp::new();
        let s = shared(&dir.0);
        let expiry = now_ms() + 30_000;
        assert_eq!(create(State(s.clone()), headers(), Json(request(expiry))).await.0, StatusCode::CREATED);
        {
            let mut sessions = s.1.lock().unwrap();
            let key = job_key("synthetic", "1");
            let e = sessions.by_job.get_mut(&key).unwrap();
            e.expires = Instant::now();
            e.expires_ms = now_ms().saturating_sub(1);
            sessions.commit(&key).unwrap();
        }
        let (_, Json(view)) = status(State(s.clone()), headers(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(view["status"], "expired");
        {
            let mut sessions = s.1.lock().unwrap();
            let key = job_key("synthetic", "1");
            sessions.by_job.get_mut(&key).unwrap().expires_ms = now_ms() - verifier_store::RETENTION_MS - 1;
            sessions.commit(&key).unwrap();
            sessions.purge().unwrap();
            assert!(sessions.by_job.is_empty());
            assert!(sessions.by_token.is_empty());
        }
        drop(s);
        let s = shared(&dir.0);
        assert!(s.1.lock().unwrap().by_job.is_empty());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1); // Only the process lock remains.
    }

    #[tokio::test]
    async fn duplicate_x_page_cannot_restore_as_completed_work() {
        let dir = Temp::new();
        let s = shared(&dir.0);
        let lease: Value = serde_json::from_str(include_str!("../../api/fixtures/lease-x.json")).unwrap();
        let mut payload = lease["x_payload"].clone();
        let first = payload["exchanges"][0].clone();
        let mut second = first.clone();
        second["cursor_from"] = 0.into();
        let mut third = first.clone();
        third["cursor_from"] = 1.into();
        payload["exchanges"] = json!([first, second, third]);
        payload["max_attempts"] = 3.into();
        let mut r = request(now_ms() + 30_000);
        r.payload = payload.clone();
        assert_eq!(create(State(s.clone()), headers(), Json(r)).await.0, StatusCode::CREATED);
        let spec = &payload["exchanges"][0];
        let first = Exchange {
            operation: spec["operation"].as_str().unwrap().into(), query_id: spec["query_id"].as_str().unwrap().into(),
            variables: spec["variables"].clone(), features: Some(spec["features"].clone()), field_toggles: None,
            http_status: 200,
            body: json!({"data":{"timeline":{"instructions":[{"entries":[{"content":{
                "entryType":"TimelineTimelineCursor","cursorType":"Bottom","value":"synthetic-loop"
            }}]}]}}}).to_string(),
        };
        let mut second = first.clone();
        second.variables["cursor"] = json!("synthetic-loop");
        {
            let mut sessions = s.1.lock().unwrap();
            let key = job_key("synthetic", "1");
            sessions.by_job.get_mut(&key).unwrap().status = Status::XRead {
                complete: true, remaining_attempts: 0, pending: vec![], rejections: vec![],
                exchanges: [first, second.clone(), second].into_iter().enumerate().map(|(index, exchange)| XRecord {
                    index, fulfilled: true, cursors: vec!["synthetic-loop".into()], exchange,
                    sent_bytes: 100, received_bytes: 100, duration_ms: 1,
                }).collect(),
            };
            sessions.commit(&key).unwrap();
        }
        drop(s);
        let (store, records) = Store::open(&dir.0).unwrap();
        assert!(Sessions::restore(store, records).is_err());
    }

    #[tokio::test]
    async fn persisted_x_response_restores_cursor_binding_without_counting_partial_work_complete() {
        let dir = Temp::new();
        let s = shared(&dir.0);
        let expiry = now_ms() + 30_000;
        let lease: Value = serde_json::from_str(include_str!("../../api/fixtures/lease-x.json")).unwrap();
        let mut payload = lease["x_payload"].clone();
        let first = payload["exchanges"][0].clone();
        let mut second = first.clone();
        second["cursor_from"] = 0.into();
        let mut third = first.clone();
        third["cursor_from"] = 1.into();
        payload["exchanges"] = json!([first, second, third]);
        payload["max_attempts"] = 3.into();
        let mut r = request(expiry);
        r.payload = payload.clone();
        assert_eq!(create(State(s.clone()), headers(), Json(r)).await.0, StatusCode::CREATED);
        let spec = &payload["exchanges"][0];
        let exchange = Exchange { operation: spec["operation"].as_str().unwrap().into(), query_id: spec["query_id"].as_str().unwrap().into(), variables: spec["variables"].clone(), features: Some(spec["features"].clone()), field_toggles: None, http_status: 200, body: json!({"data":{"timeline":{"instructions":[{"type":"TimelineAddEntries","entries":[{"entryId":"cursor-bottom-0","content":{"entryType":"TimelineTimelineCursor","cursorType":"Bottom","value":"synthetic-next"}}]}]}}}).to_string() };
        let (fulfilled, cursors) = xpolicy::outcome(&exchange);
        assert!(fulfilled);
        assert_eq!(cursors, vec!["synthetic-next"]);
        {
            let mut sessions = s.1.lock().unwrap();
            let key = job_key("synthetic", "1");
            let e = sessions.by_job.get_mut(&key).unwrap();
            if let Status::XRead { remaining_attempts, pending, exchanges, .. } = &mut e.status {
                *remaining_attempts -= 1;
                pending.retain(|&i| i != 0);
                exchanges.push(XRecord { index: 0, fulfilled, exchange, cursors, sent_bytes: 100, received_bytes: 100, duration_ms: 1 });
            }
            sessions.commit(&key).unwrap();
        }
        drop(s);
        let s = shared(&dir.0);
        let sessions = s.1.lock().unwrap();
        if let Status::XRead { complete, remaining_attempts, exchanges, .. } = &sessions.by_job[&job_key("synthetic", "1")].status {
            assert!(!complete);
            assert_eq!(*remaining_attempts, 2);
            assert_eq!(exchanges[0].cursors, vec!["synthetic-next"]);
        } else {
            panic!("lost partial X receipt");
        }
    }
    #[tokio::test]
    async fn a_relay_job_keeps_its_proof_mode_across_restart_and_cannot_change_it() {
        let dir = Temp::new();
        let s = shared(&dir.0);
        let lease: Value = serde_json::from_str(include_str!("../../api/fixtures/lease-x.json")).unwrap();
        let mut r = request(now_ms() + 30_000);
        r.payload = lease["x_payload"].clone();
        r.payload["proof_mode"] = "relay".into();
        r.payload["proof_policy"] = crate::relay::POLICY.into();
        let relay = r.payload.clone();
        let (code, Json(first)) = create(State(s.clone()), headers(), Json(r)).await;
        assert_eq!(code, StatusCode::CREATED);
        drop(s);
        let s = shared(&dir.0);
        assert!(matches!(s.1.lock().unwrap().by_job[&job_key("synthetic", "1")].kind, Kind::X(_, ProofMode::Relay)));
        // The same attempt cannot be re-registered as MPC-TLS; the identical job gets its token back.
        let mut mpc = request(now_ms() + 30_000);
        mpc.payload = lease["x_payload"].clone();
        assert_eq!(create(State(s.clone()), headers(), Json(mpc)).await.0, StatusCode::CONFLICT);
        let mut again = request(first["token"].as_str().map(|_| now_ms() + 30_000).unwrap());
        again.payload = relay;
        assert_ne!(create(State(s), headers(), Json(again)).await.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn capacity_requires_authority_and_reports_storage_health() {
        let dir = Temp::new(); let s = shared(&dir.0);
        assert_eq!(capacity(State(s.clone()), HeaderMap::new()).await.0, StatusCode::UNAUTHORIZED);
        let (code, Json(body)) = capacity(State(s.clone()), headers()).await;
        assert_eq!(code, StatusCode::OK); assert_eq!(body["healthy"], true); assert_eq!(body["durable"], true);
        s.1.lock().unwrap().failed = true;
        assert_eq!(capacity(State(s), headers()).await.0, StatusCode::SERVICE_UNAVAILABLE);
    }
    #[tokio::test]
    async fn expiry_releases_reservation_without_losing_receipt() {
        let dir = Temp::new(); let s = shared(&dir.0);
        assert_eq!(create(State(s.clone()), headers(), Json(request(now_ms() + 10_000))).await.0, StatusCode::CREATED);
        let key = job_key("synthetic", "1");
        let mut sessions = s.1.lock().unwrap();
        assert_eq!(sessions.store.as_ref().unwrap().capacity().reserved_bytes, verifier_store::MAX_RECORD_BYTES);
        sessions.by_job.get_mut(&key).unwrap().expires_ms = now_ms() - 1;
        sessions.purge().unwrap();
        assert!(sessions.by_token.is_empty());
        assert!(sessions.by_job.contains_key(&key));
        let capacity = sessions.store.as_ref().unwrap().capacity();
        assert_eq!(capacity.reserved_bytes, capacity.bytes);
    }
    #[tokio::test]
    async fn old_interrupted_receipt_is_retained_as_uncertain() {
        let dir = Temp::new(); let s = shared(&dir.0);
        assert_eq!(create(State(s.clone()), headers(), Json(request(now_ms() + 1000))).await.0, StatusCode::CREATED);
        let key = job_key("synthetic", "1");
        {
            let mut sessions = s.1.lock().unwrap();
            sessions.by_token.clear();
            let e = sessions.by_job.get_mut(&key).unwrap();
            e.status = Status::Running; e.in_flight = 1;
            e.expires_ms = now_ms() - verifier_store::RETENTION_MS - 1000;
            sessions.commit(&key).unwrap();
        }
        drop(s);
        let s = shared(&dir.0);
        let mut sessions = s.1.lock().unwrap(); sessions.purge().unwrap();
        assert!(matches!(&sessions.by_job[&key].status, Status::Rejected { reason } if reason == "execution_uncertain"));
        assert!(sessions.by_token.is_empty());
    }

}

#[cfg(test)]
mod relay_tests {
    use super::*;
    use crate::relay::tests::{RESPONSE_BODY, request, response, server};
    use serde_json::json;
    use tokio::io::AsyncWriteExt;

    const KEY: &str = "synthetic-fixture-key-never-used-remotely";

    fn shared(roots: rustls::RootCertStore) -> Shared {
        Arc::new((
            Config::new(KEY.into(), "127.0.0.1:1".into(), Duration::from_secs(20), verifier_store::Limits::default(), 64, 48, crate::relay::verifier::tls_config(roots).unwrap()),
            Mutex::new(Sessions::default()),
        ))
    }
    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {KEY}").parse().unwrap());
        h
    }
    fn job(screen_name: &str, mode: Option<(&str, Option<&str>)>) -> CreateRequest {
        let mut payload = json!({"type":"x.read","max_attempts":1,"exchanges":[{"operation":"UserByScreenName","query_id":"qid_1","variables":{"screen_name":screen_name},"features":{}}]});
        if let Some((mode, policy)) = mode {
            payload["proof_mode"] = mode.into();
            if let Some(policy) = policy {
                payload["proof_policy"] = policy.into();
            }
        }
        CreateRequest { job_id: "synthetic".into(), attempt: "1".into(), fence: None, expires_at_ms: None, ttl_seconds: Some(60), payload }
    }
    /// Registers `job`, runs a supplier relay session for the fixture request
    /// against it and returns the supplier's result and the job's status.
    async fn prove(job: CreateRequest) -> (Result<Vec<u8>>, Value, Option<Vec<u8>>) {
        let x = server(response(), |_| {}).await;
        let s = shared(x.roots.clone());
        let (code, Json(created)) = create(State(s.clone()), headers(), Json(job)).await;
        assert_eq!(code, StatusCode::CREATED);
        let (mut node_end, verifier_end) = tokio::io::duplex(1 << 20);
        let session = tokio::spawn(handle(s.clone(), Box::new(verifier_end), waiting(&s), LOCAL));
        node_end.write_all(format!("{}\n", created["token"].as_str().unwrap()).as_bytes()).await.unwrap();
        let tcp = tokio::net::TcpStream::connect(x.addr).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(30), crate::relay::node::session(node_end, tcp, &request(), xpolicy::HOST)).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(30), session).await.unwrap();
        let (_, Json(view)) = status(State(s), headers(), Path(("synthetic".into(), "1".into()))).await;
        (result, view, x.seen.lock().unwrap().clone())
    }

    #[tokio::test]
    async fn relay_job_records_the_read_exactly_as_an_mpc_proof_would() {
        let (result, view, seen) = prove(job("jack", Some(("relay", Some(crate::relay::POLICY))))).await;
        assert_eq!(result.unwrap(), response());
        assert_eq!(seen.as_deref(), Some(&request()[..]));
        assert_eq!(view["status"], "x_read");
        assert_eq!(view["complete"], true);
        assert_eq!(view["remaining_attempts"], 0);
        let exchange = &view["exchanges"][0];
        assert_eq!((exchange["index"].as_u64(), exchange["fulfilled"].as_bool(), exchange["http_status"].as_u64()), (Some(0), Some(true), Some(200)));
        assert_eq!(exchange["body"], RESPONSE_BODY);
        assert_eq!(exchange["operation"], "UserByScreenName");
        assert_eq!(exchange["variables"], json!({"screen_name":"jack"}));
        // The recorded request size is the request's, with nothing about the secrets.
        assert_eq!(exchange["sent_bytes"].as_u64(), Some(request().len() as u64));
        assert!(!view.to_string().contains(crate::relay::tests::AUTH));
    }

    #[tokio::test]
    async fn relay_job_authorizes_only_a_read_it_pinned() {
        // The job pins a different profile than the supplier asks for.
        let (result, view, seen) = prove(job("someone_else", Some(("relay", Some(crate::relay::POLICY))))).await;
        assert!(result.is_err());
        assert!(seen.is_none(), "an unpinned request reached X under the verifier's keys");
        assert_eq!(view["complete"], false);
        assert_eq!(view["rejections"], json!(["proof_rejected"]));
        assert_eq!(view["remaining_attempts"], 0);
    }

    #[tokio::test]
    async fn an_mpc_job_does_not_accept_a_relay_session() {
        for mode in [None, Some(("mpc", None))] {
            let (result, view, seen) = prove(job("jack", mode)).await;
            assert!(result.is_err());
            assert!(seen.is_none());
            assert_eq!(view["complete"], false);
            assert_eq!(view["rejections"], json!(["proof_rejected"]));
        }
    }

    #[tokio::test]
    async fn a_relay_job_refuses_a_session_that_is_not_a_relay_session() {
        // What an MPC-TLS supplier would send first is not a relay hello.
        let x = server(response(), |_| {}).await;
        let s = shared(x.roots.clone());
        let (_, Json(created)) = create(State(s.clone()), headers(), Json(job("jack", Some(("relay", Some(crate::relay::POLICY)))))).await;
        let (mut node_end, verifier_end) = tokio::io::duplex(1 << 16);
        let session = tokio::spawn(handle(s.clone(), Box::new(verifier_end), waiting(&s), LOCAL));
        node_end.write_all(format!("{}\n", created["token"].as_str().unwrap()).as_bytes()).await.unwrap();
        node_end.write_all(&[0, 0, 0, 0, 0, 0, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8]).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(30), session).await.unwrap();
        let (_, Json(view)) = status(State(s), headers(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(view["rejections"], json!(["proof_rejected"]));
        assert_eq!((view["complete"].as_bool(), view["remaining_attempts"].as_u64()), (Some(false), Some(0)));
        assert!(x.seen.lock().unwrap().is_none());
    }

    #[test]
    fn a_failed_session_logs_one_bounded_line_whatever_the_supplier_sent() {
        let hostile = anyhow::anyhow!("Viewer\nverifier: job other accepted, model forged \u{202e}{}", "x".repeat(1000));
        let line = loggable(&hostile);
        assert!(line.len() <= 240 && line.is_ascii() && !line.contains('\n') && !line.contains('\r'));
        assert!(line.starts_with("Viewer\\nverifier"));
    }

    #[tokio::test]
    async fn a_relay_job_pins_only_the_reads_the_public_catalog_sells() {
        // The node's catalog is the list; the verifier's must equal it.
        let catalog: Value = serde_json::from_str(include_str!("../../api/x-request-catalog.json")).unwrap();
        let mut sold: Vec<&str> = catalog["operations"].as_object().unwrap().values().map(|o| o["operation"].as_str().unwrap()).collect();
        let mut allowed = xpolicy::RELAY_OPERATIONS.to_vec();
        sold.sort();
        allowed.sort();
        assert_eq!(sold, allowed);

        let x = server(response(), |_| {}).await;
        for operation in xpolicy::READ_OPERATIONS {
            let s = shared(x.roots.clone());
            let payload = |mode: bool| {
                let mut p = json!({"type":"x.read","max_attempts":1,"exchanges":[{"operation":operation,"query_id":"qid_1","variables":{},"features":{}}]});
                if mode {
                    p["proof_mode"] = "relay".into();
                    p["proof_policy"] = crate::relay::POLICY.into();
                }
                CreateRequest { job_id: "synthetic".into(), attempt: "1".into(), fence: None, expires_at_ms: None, ttl_seconds: Some(60), payload: p }
            };
            let expected = if xpolicy::RELAY_OPERATIONS.contains(operation) { StatusCode::CREATED } else { StatusCode::BAD_REQUEST };
            assert_eq!(create(State(s.clone()), headers(), Json(payload(true))).await.0, expected, "relay {operation}");
            // The same read under MPC-TLS is unaffected, where the supplier alone decides what it sends.
            let s = shared(x.roots.clone());
            assert_eq!(create(State(s), headers(), Json(payload(false))).await.0, StatusCode::CREATED, "mpc {operation}");
        }
    }

    #[tokio::test]
    async fn a_job_must_name_the_relay_policy_exactly() {
        let x = server(response(), |_| {}).await;
        for mode in [("relay", None), ("relay", Some("x-relay-v2")), ("mpc", Some(crate::relay::POLICY)), ("proxy", None)] {
            let s = shared(x.roots.clone());
            assert_eq!(create(State(s), headers(), Json(job("jack", Some(mode)))).await.0, StatusCode::BAD_REQUEST, "{mode:?}");
        }
    }
}

#[cfg(test)]
mod web_tests {
    use super::*;
    use crate::{
        diagnostics::Trace,
        relay::{
            node,
            tests::{End, Respond, Server, web_headers, web_origin},
        },
        webpolicy::fixtures::{CLEARANCE, CLEARANCE_SHA256, DARWIN_UA, browser_payload},
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const KEY: &str = "synthetic-fixture-key-never-used-remotely";

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = env::temp_dir().join(format!("scarlett-verifier-web-{}", rand::random::<u128>()));
            fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn shared(roots: rustls::RootCertStore, dir: Option<&std::path::Path>) -> Shared {
        let sessions = match dir {
            Some(dir) => {
                let (store, records) = Store::open(dir).unwrap();
                Sessions::restore(store, records).unwrap()
            }
            None => Sessions::default(),
        };
        Arc::new((
            Config::new(KEY.into(), "127.0.0.1:1".into(), Duration::from_secs(20), verifier_store::Limits::default(), 64, 48, crate::relay::verifier::tls_config(roots).unwrap()),
            Mutex::new(sessions),
        ))
    }
    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {KEY}").parse().unwrap());
        h
    }
    fn payload(url: &str, max_redirects: u64) -> Value {
        json!({"type":"web.fetch","proof_mode":"relay","proof_policy":"web-relay-v1","url":url,"max_redirects":max_redirects,"max_response_bytes":webpolicy::PAGE_MAX,"headers":web_headers()})
    }
    fn job(payload: Value, expires: u64) -> CreateRequest {
        CreateRequest { job_id: "synthetic".into(), attempt: "1".into(), fence: Some("f1".into()), expires_at_ms: Some(expires), ttl_seconds: None, payload }
    }
    async fn register(s: &Shared, payload: Value) -> String {
        let (code, Json(created)) = create(State(s.clone()), headers(), Json(job(payload, now_ms() + 60_000))).await;
        assert_eq!(code, StatusCode::CREATED, "{created}");
        created["token"].as_str().unwrap().to_owned()
    }
    /// Runs one supplier hop against the verifier: the canonical request for
    /// `url` unless `raw` says otherwise.
    async fn hop(s: &Shared, origin: &Server, token: &str, index: u32, url: &str, raw: Option<Vec<u8>>) -> (Result<node::HopOutcome>, Result<()>) {
        let (mut node_end, verifier_end) = tokio::io::duplex(1 << 20);
        let session = tokio::spawn(handle(s.clone(), Box::new(verifier_end), waiting(s), LOCAL));
        node_end.write_all(format!("{token}\n").as_bytes()).await.unwrap();
        let tcp = TcpStream::connect(origin.addr).await.unwrap();
        let raw = raw.unwrap_or_else(|| webpolicy::request(url, &web_headers()));
        let host = webpolicy::url_host(url).to_owned();
        let result = tokio::time::timeout(Duration::from_secs(30), node::web_session(node_end, tcp, &raw, &host, index, url, &Trace::new())).await.unwrap();
        let verifier = tokio::time::timeout(Duration::from_secs(30), session).await.unwrap().unwrap();
        (result, verifier)
    }
    async fn view(s: &Shared) -> Value {
        let (code, Json(view)) = status(State(s.clone()), headers(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(code, StatusCode::OK);
        view
    }
    fn tokens(s: &Shared) -> usize {
        s.1.lock().unwrap().by_token.len()
    }
    fn routes(table: &'static [(&'static str, &'static [u8], End)]) -> Respond {
        Arc::new(move |request: &[u8]| {
            let text = String::from_utf8_lossy(request);
            let target = text.split(' ').nth(1).unwrap_or_default().to_owned();
            let host = text.lines().find_map(|l| l.strip_prefix("Host: ")).unwrap_or_default().to_owned();
            let key = format!("{host}{target}");
            table.iter().find(|(k, _, _)| *k == key).map(|(_, r, e)| (r.to_vec(), *e)).unwrap_or((b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(), End::Wait))
        })
    }
    fn decode(value: &Value) -> Vec<u8> {
        STANDARD.decode(value.as_str().unwrap()).unwrap()
    }
    /// `GET …/body` for job `synthetic` attempt `attempt`, with an optional Range.
    async fn read_body(s: &Shared, attempt: &str, range: Option<&str>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut h = headers();
        if let Some(range) = range {
            h.insert(header::RANGE, range.parse().unwrap());
        }
        let response = get_body(State(s.clone()), h, Path(("synthetic".into(), attempt.into()))).await;
        let (parts, body) = response.into_parts();
        (parts.status, parts.headers, axum::body::to_bytes(body, usize::MAX).await.unwrap().to_vec())
    }
    /// The stored body of attempt 1, which must be whole.
    async fn stored(s: &Shared) -> Vec<u8> {
        let (code, headers, body) = read_body(s, "1", None).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(headers["x-body-sha256"].to_str().unwrap(), verifier_store::hash(&body));
        assert_eq!(headers["x-body-bytes"].to_str().unwrap(), body.len().to_string());
        body
    }

    const PAGE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 20\r\n\r\n<title>hello</title>";

    #[tokio::test]
    async fn a_single_hop_records_the_page_and_ends_the_job() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5)).await;
        let (reported, verifier) = hop(&s, &origin, &token, 0, "https://example.com/", None).await;
        verifier.unwrap();
        let reported = reported.unwrap();
        assert_eq!((reported.hop, reported.status_code, reported.is_final, reported.next_url), (0, 200, true, None));
        let request = webpolicy::request("https://example.com/", &web_headers());
        assert_eq!(origin.seen.lock().unwrap().as_deref(), Some(&request[..]));
        let view = view(&s).await;
        assert_eq!((view["status"].as_str(), view["complete"].as_bool(), view["remaining_sessions"].as_u64()), (Some("web_read"), Some(true), Some(5)));
        assert_eq!((view["next_url"].clone(), view["rejections"].clone()), (Value::Null, json!([])));
        assert_eq!(view["request_sha256"], verifier_store::hash(&serde_json::to_vec(&payload("https://example.com/", 5)).unwrap()));
        assert_eq!(view["request_sha256"], "d4362de8c9e08295b9a777f758e8f9833a4257b30b689c391d609c0e4a7c610c");
        let h = &view["hops"][0];
        let head_end = PAGE.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!((h["index"].as_u64(), h["url"].as_str(), h["status_code"].as_u64()), (Some(0), Some("https://example.com/"), Some(200)));
        assert_eq!((h["location"].clone(), h["location_refused"].clone()), (Value::Null, Value::Null));
        assert_eq!(decode(&h["head_base64"]), &PAGE[..head_end]);
        assert_eq!((h["body_stored"].as_bool(), view["body_released_at_ms"].clone(), view["rejection"].clone()), (Some(true), Value::Null, Value::Null));
        assert_eq!(stored(&s).await, &PAGE[head_end..]);
        assert_eq!(h["body_bytes"].as_u64(), Some(20));
        assert_eq!(h["body_sha256"], verifier_store::hash(&PAGE[head_end..]));
        assert_eq!(h["response_sha256"], verifier_store::hash(PAGE));
        assert_eq!((h["framing"].as_str(), h["sent_bytes"].as_u64(), h["received_bytes"].as_u64()), (Some("content_length"), Some(request.len() as u64), Some(PAGE.len() as u64)));
        assert_eq!((h["server_name"].as_str(), h["tls_version"].as_str(), h["cipher_suite"].as_str(), h["alpn"].as_str()), (Some("example.com"), Some("TLSv1_3"), Some("TLS13_AES_128_GCM_SHA256"), Some("http/1.1")));
        for field in ["cert_chain_sha256", "leaf_cert_sha256"] {
            assert_eq!(h[field].as_str().unwrap().len(), 64);
        }
        assert_ne!(h["cert_chain_sha256"], h["leaf_cert_sha256"]);
        assert!(h["started_at_ms"].as_u64().unwrap() > 0);
        assert_eq!(h.as_object().unwrap().len(), 21);
        // The job is over: its token is gone and nothing more can run.
        assert_eq!(tokens(&s), 0);
        let (again, _) = hop(&s, &origin, &token, 0, "https://example.com/", None).await;
        assert!(again.is_err());
    }

    #[tokio::test]
    async fn a_redirect_chain_runs_one_session_per_hop_under_one_token() {
        const GZIP_CHUNKED: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n\x1f\x8b\x08\x00\r\n2;x=1\r\nzz\r\n0\r\nTrailer: 1\r\n\r\n";
        let origin = web_origin(
            routes(&[
                ("example.com/a/b?x=1", b"HTTP/1.1 301 Moved Permanently\r\nLocation: //www.example.com/next?q=%7e#frag\r\nContent-Length: 5\r\n\r\nmoved", End::Wait),
                ("www.example.com/next?q=%7e", GZIP_CHUNKED, End::Close),
            ]),
            false,
        )
        .await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/a/b?x=1", 5)).await;
        let (first, verifier) = hop(&s, &origin, &token, 0, "https://example.com/a/b?x=1", None).await;
        verifier.unwrap();
        let first = first.unwrap();
        let next = "https://www.example.com/next?q=%7e";
        assert_eq!((first.status_code, first.is_final, first.next_url.as_deref()), (301, false, Some(next)));
        let view = view(&s).await;
        assert_eq!((view["complete"].as_bool(), view["next_url"].as_str(), view["remaining_sessions"].as_u64()), (Some(false), Some(next), Some(5)));
        assert_eq!((view["hops"][0]["body_stored"].as_bool(), view["hops"][0]["body_bytes"].as_u64()), (Some(false), Some(5)));
        assert_eq!(view["hops"][0]["body_sha256"], verifier_store::hash(b"moved"));
        // A followable redirect keeps no body.
        assert_eq!(read_body(&s, "1", None).await.0, StatusCode::NOT_FOUND);
        assert_eq!(tokens(&s), 1);

        let (second, verifier) = hop(&s, &origin, &token, 1, next, None).await;
        verifier.unwrap();
        let second = second.unwrap();
        assert_eq!((second.hop, second.status_code, second.is_final), (1, 200, true));
        let view = super::web_tests::view(&s).await;
        assert_eq!((view["complete"].as_bool(), view["remaining_sessions"].as_u64(), view["next_url"].clone()), (Some(true), Some(4), Value::Null));
        let hops = view["hops"].as_array().unwrap();
        assert_eq!((hops.len(), hops[0]["location"].as_str(), hops[1]["url"].as_str()), (2, Some(next), Some(next)));
        assert_eq!((hops[1]["server_name"].as_str(), hops[1]["framing"].as_str()), (Some("www.example.com"), Some("chunked")));
        // The entity body is dechunked and still gzip-encoded.
        assert_eq!(stored(&s).await, b"\x1f\x8b\x08\x00zz");
        assert_eq!((hops[1]["body_stored"].as_bool(), hops[1]["body_sha256"].as_str()), (Some(true), Some(verifier_store::hash(b"\x1f\x8b\x08\x00zz").as_str())));
        assert_eq!(hops[1]["response_sha256"], verifier_store::hash(GZIP_CHUNKED));
        assert_eq!(tokens(&s), 0);
    }

    #[tokio::test]
    async fn a_redirect_that_cannot_be_followed_is_final_and_says_why() {
        for (location, reason) in [("http://example.com/", "insecure"), ("https://x.com/home", "x_host"), ("https://10.0.0.1/", "ip_literal"), ("", "empty")] {
            let response: &'static [u8] = Box::leak(format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 4\r\n\r\nbody").into_bytes().into_boxed_slice());
            let table: &'static [(&str, &[u8], End)] = Box::leak(vec![("example.com/", response, End::Wait)].into_boxed_slice());
            let origin = web_origin(routes(table), false).await;
            let s = shared(origin.roots.clone(), None);
            let token = register(&s, payload("https://example.com/", 5)).await;
            let (reported, _) = hop(&s, &origin, &token, 0, "https://example.com/", None).await;
            assert!(reported.unwrap().is_final);
            let view = view(&s).await;
            let h = &view["hops"][0];
            assert_eq!((view["complete"].as_bool(), h["location"].clone(), h["location_refused"].as_str()), (Some(true), Value::Null, Some(reason)), "{location}");
            assert_eq!(stored(&s).await, b"body");
        }
    }

    #[tokio::test]
    async fn the_last_allowed_hop_is_final_even_when_it_redirects() {
        let origin = web_origin(
            routes(&[
                ("example.com/a", b"HTTP/1.1 308 Permanent Redirect\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n", End::Wait),
                ("example.com/b", b"HTTP/1.1 307 Temporary Redirect\r\nLocation: c\r\nContent-Length: 0\r\n\r\n", End::Wait),
            ]),
            false,
        )
        .await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/a", 1)).await;
        assert_eq!(hop(&s, &origin, &token, 0, "https://example.com/a", None).await.0.unwrap().next_url.as_deref(), Some("https://example.com/b"));
        let last = hop(&s, &origin, &token, 1, "https://example.com/b", None).await.0.unwrap();
        assert!(last.is_final && last.next_url.is_none());
        let view = view(&s).await;
        assert_eq!((view["complete"].as_bool(), view["remaining_sessions"].as_u64()), (Some(true), Some(0)));
        // The followable location is still recorded, so the buyer sees where it pointed.
        assert_eq!(view["hops"][1]["location"], "https://example.com/c");
        assert_eq!(view["hops"][1]["body_stored"], true);
        assert_eq!(stored(&s).await, b"");
        assert_eq!(tokens(&s), 0);
        assert!(hop(&s, &origin, &token, 2, "https://example.com/c", None).await.0.is_err());
    }

    #[tokio::test]
    async fn a_failed_hop_ends_the_job_revokes_the_token_and_names_the_reason() {
        let url = "https://example.com/";
        let mut tampered = webpolicy::request(url, &web_headers());
        tampered[5] = b'x';
        const TOO_LARGE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 67108865\r\n\r\n";
        let cases: Vec<(&str, &'static [(&str, &[u8], End)], bool, Option<Vec<u8>>, &str)> = vec![
            ("tampered", &[("example.com/", PAGE, End::Wait)], false, Some(tampered), "request_rejected"),
            ("tls 1.2", &[("example.com/", PAGE, End::Wait)], true, None, "tls_failed"),
            ("too large", &[("example.com/", TOO_LARGE, End::Wait)], false, None, "page_too_large"),
            ("bad framing", &[("example.com/", b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", End::Wait)], false, None, "response_invalid"),
            ("cut short", &[("example.com/", b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", End::Close)], false, None, "server_closed"),
        ];
        for (case, table, tls12, raw, reason) in cases {
            let origin = web_origin(routes(table), tls12).await;
            let s = shared(origin.roots.clone(), None);
            let token = register(&s, payload(url, 5)).await;
            let (reported, _) = hop(&s, &origin, &token, 0, url, raw).await;
            let error = reported.err().unwrap_or_else(|| panic!("{case}: reported"));
            // The node learns the reason, after its record was opened.
            assert_eq!(error.downcast_ref::<node::Refused>(), Some(&node::Refused(reason)), "{case}: {error:#}");
            assert!(!format!("{error:#}").contains(node::MISUSE), "{case}");
            let view = view(&s).await;
            assert_eq!(view["rejections"], json!([reason]), "{case}");
            assert_eq!(view["rejection"]["reason"], reason, "{case}");
            if case == "too large" {
                assert_eq!(view["rejection"], json!({"reason":"page_too_large","received_bytes":TOO_LARGE.len(),"entity_bytes":0,"declared_bytes":67108865}));
            }
            if case == "cut short" {
                assert_eq!(view["rejection"], json!({"reason":"server_closed","received_bytes":44,"entity_bytes":5,"declared_bytes":10}));
            }
            assert_eq!(read_body(&s, "1", None).await.0, StatusCode::NOT_FOUND, "{case}");
            assert_eq!((view["complete"].as_bool(), view["remaining_sessions"].as_u64(), view["hops"].as_array().unwrap().len()), (Some(false), Some(5), 0), "{case}");
            assert_eq!(tokens(&s), 0, "{case}");
        }
    }

    #[tokio::test]
    async fn a_later_hop_must_fetch_the_authorized_location() {
        let origin = web_origin(
            routes(&[("example.com/", b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n", End::Wait), ("example.com/other", PAGE, End::Wait)]),
            false,
        )
        .await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5)).await;
        hop(&s, &origin, &token, 0, "https://example.com/", None).await.0.unwrap();
        let (reported, _) = hop(&s, &origin, &token, 1, "https://example.com/other", None).await;
        assert!(reported.is_err());
        assert_ne!(origin.seen.lock().unwrap().as_deref().map(|r| r.starts_with(b"GET /other")), Some(true));
        let view = view(&s).await;
        assert_eq!((view["rejections"].clone(), view["next_url"].clone(), view["hops"].as_array().unwrap().len()), (json!(["request_rejected"]), Value::Null, 1));
        assert_eq!(view["rejection"], json!({"reason":"request_rejected","received_bytes":0,"entity_bytes":0,"declared_bytes":null}));
        assert_eq!(tokens(&s), 0);
    }

    #[tokio::test]
    async fn a_second_concurrent_session_is_refused_without_spending_one() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5)).await;
        let key = job_key("synthetic", "1");
        s.1.lock().unwrap().by_job.get_mut(&key).unwrap().in_flight = 1;
        let (reported, verifier) = hop(&s, &origin, &token, 0, "https://example.com/", None).await;
        assert!(reported.is_err() && verifier.is_err());
        assert!(origin.seen.lock().unwrap().is_none());
        assert_eq!((view(&s).await["remaining_sessions"].as_u64(), tokens(&s)), (Some(6), 1));
        s.1.lock().unwrap().by_job.get_mut(&key).unwrap().in_flight = 0;
        hop(&s, &origin, &token, 0, "https://example.com/", None).await.0.unwrap();
        assert_eq!(view(&s).await["complete"], true);
    }

    #[tokio::test]
    async fn verified_hops_survive_restart_and_an_interrupted_hop_is_uncertain() {
        let origin = web_origin(routes(&[("example.com/", b"HTTP/1.1 301 Moved\r\nLocation: https://www.example.com/\r\nContent-Length: 0\r\n\r\n", End::Wait)]), false).await;
        let dir = Temp::new();
        let s = shared(origin.roots.clone(), Some(&dir.0));
        let expires = now_ms() + 60_000;
        let (code, Json(created)) = create(State(s.clone()), headers(), Json(job(payload("https://example.com/", 5), expires))).await;
        assert_eq!(code, StatusCode::CREATED);
        // Registration is idempotent for the same binding.
        let (_, Json(again)) = create(State(s.clone()), headers(), Json(job(payload("https://example.com/", 5), expires))).await;
        assert_eq!(created["token"], again["token"]);
        let token = created["token"].as_str().unwrap().to_owned();
        hop(&s, &origin, &token, 0, "https://example.com/", None).await.0.unwrap();
        // A hop that is still pending survives a restart with its token.
        drop(s);
        let s = shared(origin.roots.clone(), Some(&dir.0));
        assert_eq!((view(&s).await["next_url"].as_str(), tokens(&s)), (Some("https://www.example.com/"), 1));
        // Now the verifier dies in the middle of hop 1.
        {
            let mut sessions = s.1.lock().unwrap();
            let key = job_key("synthetic", "1");
            let e = sessions.by_job.get_mut(&key).unwrap();
            e.in_flight = 1;
            if let Status::WebRead { remaining_sessions, .. } = &mut e.status {
                *remaining_sessions -= 1;
            }
            sessions.commit(&key).unwrap();
        }
        drop(s);
        let s = shared(origin.roots.clone(), Some(&dir.0));
        let view = view(&s).await;
        assert_eq!((view["status"].as_str(), view["rejections"].clone(), view["next_url"].clone()), (Some("web_read"), json!(["execution_uncertain"]), Value::Null));
        assert_eq!(view["rejection"], json!({"reason":"execution_uncertain","received_bytes":0,"entity_bytes":0,"declared_bytes":null}));
        assert_eq!((view["hops"].as_array().unwrap().len(), view["remaining_sessions"].as_u64()), (1, Some(4)));
        assert_eq!(tokens(&s), 0);
        assert_eq!(create(State(s.clone()), headers(), Json(job(payload("https://example.com/", 5), expires))).await.0, StatusCode::CONFLICT);
        // The finished receipt no longer reserves a full record.
        let capacity = s.1.lock().unwrap().store.as_ref().unwrap().capacity();
        assert_eq!(capacity.reserved_bytes, capacity.bytes);
    }

    #[tokio::test]
    async fn expiry_keeps_verified_hops_readable() {
        let origin = web_origin(routes(&[("example.com/", b"HTTP/1.1 301 Moved\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n", End::Wait)]), false).await;
        for verified in [false, true] {
            let s = shared(origin.roots.clone(), None);
            let token = register(&s, payload("https://example.com/", 5)).await;
            if verified {
                hop(&s, &origin, &token, 0, "https://example.com/", None).await.0.unwrap();
            }
            s.1.lock().unwrap().by_job.get_mut(&job_key("synthetic", "1")).unwrap().expires = Instant::now();
            let view = view(&s).await;
            assert_eq!(view["status"], if verified { "web_read" } else { "expired" });
            // A session after expiry spends nothing and leaves the receipt as it was.
            let next = if verified { "https://example.com/x" } else { "https://example.com/" };
            assert!(hop(&s, &origin, &token, u32::from(verified), next, None).await.0.is_err());
            assert_eq!(super::web_tests::view(&s).await["status"], view["status"]);
            assert_eq!(tokens(&s), 0);
        }
    }

    fn durable(dir: &std::path::Path, limits: verifier_store::Limits) -> Shared {
        let (store, records) = Store::open_with_limits(dir, limits).unwrap();
        Arc::new((
            Config::new(KEY.into(), "127.0.0.1:1".into(), Duration::from_secs(20), limits, 64, 48, crate::relay::verifier::tls_config(rustls::RootCertStore::empty()).unwrap()),
            Mutex::new(Sessions::restore(store, records).unwrap()),
        ))
    }

    #[tokio::test]
    async fn a_64_mib_web_job_registers_under_the_default_limits() {
        let dir = Temp::new();
        let s = durable(&dir.0, verifier_store::Limits::default());
        let expires = now_ms() + 60_000;
        let page = |attempt: &str| CreateRequest { attempt: attempt.into(), ..job(payload("https://example.com/", 5), expires) };
        // Two reservations fit the default 192 MiB pool, a third does not.
        assert_eq!(create(State(s.clone()), headers(), Json(page("1"))).await.0, StatusCode::CREATED);
        assert_eq!(create(State(s.clone()), headers(), Json(page("2"))).await.0, StatusCode::CREATED);
        let (code, Json(refused)) = create(State(s.clone()), headers(), Json(page("3"))).await;
        assert_eq!((code, refused["error"].as_str()), (StatusCode::SERVICE_UNAVAILABLE, Some("verifier web capacity reached")));
        // A smaller page ceiling is refused, whatever the store holds.
        let mut small = payload("https://example.com/", 5);
        small["max_response_bytes"] = (10 << 20).into();
        assert_eq!(create(State(s.clone()), headers(), Json(CreateRequest { attempt: "4".into(), ..job(small, expires) })).await.0, StatusCode::BAD_REQUEST);
        // The receipt JSON of any valid job fits the smallest record limit; the page is a file.
        let job = webpolicy::validate_job(&payload("https://example.com/", 5)).unwrap();
        assert_eq!(web_json_bound(&job), 658_324);
        assert!(web_json_bound(&job) < 1 << 20);
    }

    #[tokio::test]
    async fn web_receipts_reserve_their_own_bound_and_leave_soon_after_expiry() {
        let dir = Temp::new();
        // A web pool of four pages, and room for one X or Codex reservation beside it.
        let pool = 4 * verifier_store::WEB_RESERVATION;
        let limits = verifier_store::Limits { max_records: 16, max_record_bytes: 64 << 20, max_web_bytes: pool, max_total_bytes: pool + (64 << 20) };
        let open = |dir: &std::path::Path| durable(dir, limits);
        let s = open(&dir.0);
        let expires = now_ms() + 60_000;
        let web = |attempt: u32| CreateRequest { attempt: attempt.to_string(), ..job(payload("https://example.com/", 5), expires) };
        for attempt in 1..=4 {
            assert_eq!(create(State(s.clone()), headers(), Json(web(attempt))).await.0, StatusCode::CREATED, "web {attempt}");
        }
        assert_eq!(create(State(s.clone()), headers(), Json(web(5))).await.0, StatusCode::SERVICE_UNAVAILABLE);
        // Web cannot take the X/Codex floor: a Codex job still registers, then the total is full.
        let codex = |attempt: &str| CreateRequest { attempt: attempt.into(), ..job(json!({"type":"response.create","model":"synthetic-model"}), expires) };
        assert_eq!(create(State(s.clone()), headers(), Json(codex("codex"))).await.0, StatusCode::CREATED);
        assert_eq!(create(State(s.clone()), headers(), Json(codex("codex2"))).await.0, StatusCode::SERVICE_UNAVAILABLE);
        // Expired web receipts stay ten minutes, then leave, in a purge or on restart.
        {
            let mut sessions = s.1.lock().unwrap();
            let age = |sessions: &mut Sessions, attempt: &str, age: u64| {
                let key = job_key("synthetic", attempt);
                sessions.by_job.get_mut(&key).unwrap().expires_ms = now_ms() - age;
                sessions.commit(&key).unwrap();
            };
            age(&mut sessions, "1", verifier_store::WEB_RETENTION_MS + 1);
            age(&mut sessions, "2", verifier_store::WEB_RETENTION_MS - 60_000);
            assert_eq!(sessions.purge().unwrap().len(), 1);
            assert!(!sessions.by_job.contains_key(&job_key("synthetic", "1")) && sessions.by_job.contains_key(&job_key("synthetic", "2")));
            const { assert!(verifier_store::WEB_RETENTION_MS < verifier_store::RETENTION_MS) };
            // Attempt 3 ages while the verifier is down and leaves on restart.
            age(&mut sessions, "3", verifier_store::WEB_RETENTION_MS + 1);
        }
        drop(s);
        let s = open(&dir.0);
        let sessions = s.1.lock().unwrap();
        assert!(!sessions.by_job.contains_key(&job_key("synthetic", "3")));
        assert!(sessions.by_job.contains_key(&job_key("synthetic", "2")) && sessions.by_job.contains_key(&job_key("synthetic", "4")));
    }

    /// `DELETE /v1/sessions/synthetic/{attempt}`: the status and the JSON body, if any.
    async fn revoke_attempt(s: &Shared, attempt: &str) -> (StatusCode, Value) {
        let response = revoke(State(s.clone()), headers(), Path(("synthetic".into(), attempt.into()))).await;
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        (parts.status, if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() })
    }

    /// The web pool's charges and whether one more page fits.
    fn web_pool(s: &Shared) -> (u64, bool) {
        let sessions = s.1.lock().unwrap();
        let pool = sessions.store.as_ref().unwrap().web_pool();
        (pool.reserved_bytes, pool.can_register)
    }

    #[tokio::test]
    async fn revoking_an_unrun_web_session_frees_its_pool_share_and_commits_first() {
        let dir = Temp::new();
        let s = durable(&dir.0, verifier_store::Limits::default());
        let (baseline, _) = web_pool(&s);
        let expires = now_ms() + 60_000;
        let page = |attempt: &str| CreateRequest { attempt: attempt.into(), ..job(payload("https://example.com/", 5), expires) };
        for attempt in ["1", "2"] {
            assert_eq!(create(State(s.clone()), headers(), Json(page(attempt))).await.0, StatusCode::CREATED);
        }
        // The default pool holds two pages: a third waits for one to go.
        assert_eq!(web_pool(&s), (baseline + 2 * verifier_store::WEB_RESERVATION, false));
        assert_eq!(create(State(s.clone()), headers(), Json(page("3"))).await.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(tokens(&s), 2);
        // A hedge loser's registration is revoked: its token is gone and its share free at once.
        assert_eq!(revoke_attempt(&s, "1").await, (StatusCode::NO_CONTENT, Value::Null));
        assert_eq!(tokens(&s), 1);
        let (reserved, can_register) = web_pool(&s);
        assert!(can_register);
        // What stays charged is the revoked receipt's own JSON, until it is purged.
        assert!(reserved > baseline + verifier_store::WEB_RESERVATION && reserved < baseline + verifier_store::WEB_RESERVATION + 4096, "{reserved}");
        let v = view(&s).await;
        assert_eq!(v["status"], "expired");
        assert!(v["expires_at_ms"].as_u64().unwrap() <= now_ms());
        assert_eq!(create(State(s.clone()), headers(), Json(page("3"))).await.0, StatusCode::CREATED);
        // Again: nothing more to do, and still no content.
        assert_eq!(revoke_attempt(&s, "1").await, (StatusCode::NO_CONTENT, Value::Null));
        // A revoked session cannot be registered back to life.
        let (code, Json(again)) = create(State(s.clone()), headers(), Json(page("1"))).await;
        assert_eq!((code, again["error"].as_str()), (StatusCode::CONFLICT, Some("session already exists for this attempt")));
        // The revocation was committed before the answer: it survives a restart.
        drop(s);
        let s = durable(&dir.0, verifier_store::Limits::default());
        {
            let sessions = s.1.lock().unwrap();
            assert!(!sessions.by_token.values().any(|key| key == &job_key("synthetic", "1")));
            assert_eq!(sessions.by_token.len(), 2);
        }
        assert!(web_pool(&s).0 < baseline + 2 * verifier_store::WEB_RESERVATION + 4096);
        // Every session revoked and purged: the pool is back to where it started.
        for attempt in ["2", "3"] {
            assert_eq!(revoke_attempt(&s, attempt).await.0, StatusCode::NO_CONTENT);
        }
        {
            let mut sessions = s.1.lock().unwrap();
            for attempt in ["1", "2", "3"] {
                let key = job_key("synthetic", attempt);
                sessions.by_job.get_mut(&key).unwrap().expires_ms = now_ms() - verifier_store::WEB_RETENTION_MS - 1;
                sessions.commit(&key).unwrap();
            }
            sessions.purge().unwrap();
            assert!(sessions.by_job.is_empty());
        }
        assert_eq!(web_pool(&s), (baseline, true));
        assert_eq!(revoke_attempt(&s, "1").await, (StatusCode::NOT_FOUND, json!({"error": "unknown session"})));
    }

    /// `GET /v1/events`: the status and the JSON body, if any.
    async fn read_events(s: &Shared, after: Option<&str>, wait: Option<&str>, epoch: Option<&str>) -> (StatusCode, Value) {
        let query = EventsQuery { after: after.map(Into::into), wait: wait.map(Into::into), epoch: epoch.map(Into::into) };
        let response = events(State(s.clone()), headers(), Query(query)).await;
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        (parts.status, if body.is_empty() { Value::Null } else { serde_json::from_slice(&body).unwrap() })
    }

    /// The (seq, attempt, kind) of each event after `after`.
    async fn events_after(s: &Shared, after: u64) -> Vec<(u64, String, String)> {
        let (code, reply) = read_events(s, Some(&after.to_string()), Some("1"), None).await;
        if code == StatusCode::NO_CONTENT {
            return Vec::new();
        }
        assert_eq!((code, reply["epoch"].as_str()), (StatusCode::OK, Some(s.0.events.epoch.as_str())));
        let events = reply["events"].as_array().unwrap();
        assert_eq!(reply["next"], events.last().unwrap()["seq"]);
        events
            .iter()
            .map(|e| {
                assert_eq!(e["job_id"], "synthetic");
                assert!(e["committed_at_ms"].as_u64().unwrap() <= now_ms());
                (e["seq"].as_u64().unwrap(), e["attempt"].as_str().unwrap().to_owned(), e["kind"].as_str().unwrap().to_owned())
            })
            .collect()
    }

    #[tokio::test]
    async fn only_terminal_web_commits_become_events() {
        const TOO_LARGE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 67108865\r\n\r\n";
        let origin = web_origin(
            routes(&[
                ("example.com/", b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.example.com/next\r\nContent-Length: 0\r\n\r\n", End::Wait),
                ("www.example.com/next", PAGE, End::Wait),
                ("example.com/large", TOO_LARGE, End::Wait),
            ]),
            false,
        )
        .await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5)).await;
        // A redirect hop is verified but the chain goes on: no event.
        hop(&s, &origin, &token, 0, "https://example.com/", None).await.0.unwrap();
        assert!(events_after(&s, 0).await.is_empty());
        // The final hop is: once its receipt and body are committed.
        hop(&s, &origin, &token, 1, "https://www.example.com/next", None).await.0.unwrap();
        assert_eq!(events_after(&s, 0).await, vec![(1, "1".to_owned(), "complete".to_owned())]);
        assert_eq!(stored(&s).await, &PAGE[PAGE.len() - 20..]);
        // A committed rejection is an event too.
        let (code, Json(created)) = create(State(s.clone()), headers(), Json(CreateRequest { attempt: "2".into(), ..job(payload("https://example.com/large", 5), now_ms() + 60_000) })).await;
        assert_eq!(code, StatusCode::CREATED);
        let large = created["token"].as_str().unwrap().to_owned();
        assert!(hop(&s, &origin, &large, 0, "https://example.com/large", None).await.0.is_err());
        assert_eq!(events_after(&s, 1).await, vec![(2, "2".to_owned(), "rejected".to_owned())]);
        // A busy refusal spends nothing and a revocation is the app's own act: neither is an event.
        let (_, Json(created)) = create(State(s.clone()), headers(), Json(CreateRequest { attempt: "3".into(), ..job(payload("https://example.com/", 5), now_ms() + 60_000) })).await;
        let busy = created["token"].as_str().unwrap().to_owned();
        let held = s.0.web_slots.clone().try_acquire_many_owned(48).unwrap();
        assert!(hop(&s, &origin, &busy, 0, "https://example.com/", None).await.0.is_err());
        drop(held);
        assert_eq!(revoke_attempt(&s, "3").await.0, StatusCode::NO_CONTENT);
        assert!(events_after(&s, 2).await.is_empty());
        assert_eq!(events_after(&s, 0).await.len(), 2);
    }

    #[tokio::test]
    async fn a_long_poll_wakes_at_the_next_commit_and_otherwise_ends_empty() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5)).await;
        let waiting = {
            let s = s.clone();
            tokio::spawn(async move {
                let asked = Instant::now();
                let reply = read_events(&s, Some("0"), Some("20"), None).await;
                (reply, asked.elapsed())
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!waiting.is_finished());
        hop(&s, &origin, &token, 0, "https://example.com/", None).await.0.unwrap();
        let ((code, reply), took) = tokio::time::timeout(Duration::from_secs(10), waiting).await.unwrap().unwrap();
        assert_eq!((code, reply["events"][0]["kind"].as_str(), reply["next"].as_u64()), (StatusCode::OK, Some("complete"), Some(1)));
        assert!(took < Duration::from_secs(10), "{took:?}");
        assert!(reply.get("reset").is_none());
        // Nothing new within the wait: 204, about when the wait ends.
        let asked = Instant::now();
        assert_eq!(read_events(&s, Some("1"), Some("1"), Some(&s.0.events.epoch)).await, (StatusCode::NO_CONTENT, Value::Null));
        assert!(asked.elapsed() >= Duration::from_millis(900));
        // Malformed positions and waits, and key auth.
        for (after, wait) in [(None, Some("1")), (Some("x"), Some("1")), (Some("-1"), Some("1")), (Some("1"), Some("0")), (Some("1"), Some("26")), (Some("1"), Some("1.5"))] {
            assert_eq!(read_events(&s, after, wait, None).await.0, StatusCode::BAD_REQUEST, "{after:?} {wait:?}");
        }
        let query = EventsQuery { after: Some("0".into()), wait: Some("1".into()), epoch: None };
        assert_eq!(events(State(s.clone()), HeaderMap::new(), Query(query)).await.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn positions_the_ring_cannot_continue_from_reset_to_the_newest_event() {
        let mut config = Config::new(KEY.into(), "127.0.0.1:1".into(), Duration::from_secs(20), verifier_store::Limits::default(), 64, 48, crate::relay::verifier::tls_config(rustls::RootCertStore::empty()).unwrap());
        config.events = crate::verifier_events::Feed::with_capacity(3);
        let s: Shared = Arc::new((config, Mutex::new(Sessions::default())));
        let reset = |next: u64| (StatusCode::OK, json!({"epoch": s.0.events.epoch, "events": [], "next": next, "reset": true}));
        // A consumer that remembers a position from before a restart.
        assert_eq!(read_events(&s, Some("7"), Some("1"), None).await, reset(0));
        for i in 1..=5 {
            s.0.events.append("synthetic", &i.to_string(), "complete", now_ms());
        }
        assert_eq!(events_after(&s, 2).await.len(), 3);
        // Events 1 and 2 are gone: a consumer at 0 or 1 missed some.
        assert_eq!(read_events(&s, Some("1"), Some("1"), None).await, reset(5));
        assert_eq!(read_events(&s, Some("0"), Some("1"), None).await, reset(5));
        // Another epoch's position, whatever its number.
        assert_eq!(read_events(&s, Some("4"), Some("1"), Some("00000000000000000000000000000000")).await, reset(5));
        assert_eq!(read_events(&s, Some("4"), Some("1"), Some(&s.0.events.epoch)).await.1["events"][0]["seq"], 5);
    }

    #[tokio::test]
    async fn a_revocation_that_cannot_be_committed_is_not_acknowledged() {
        if unsafe { libc::geteuid() } == 0 {
            return; // Permissions do not bind root.
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = Temp::new();
        let s = durable(&dir.0, verifier_store::Limits::default());
        let token = register(&s, payload("https://example.com/", 5)).await;
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o500)).unwrap();
        let answer = revoke_attempt(&s, "1").await;
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(answer, (StatusCode::SERVICE_UNAVAILABLE, json!({"error": "verifier state unavailable"})));
        // The verifier stops rather than run on a state it could not write.
        assert_eq!(revoke_attempt(&s, "1").await.0, StatusCode::SERVICE_UNAVAILABLE);
        drop(s);
        // Nothing was acknowledged, and on disk the session is still live.
        let s = durable(&dir.0, verifier_store::Limits::default());
        assert_eq!(s.1.lock().unwrap().by_token.get(&token), Some(&job_key("synthetic", "1")));
    }

    #[tokio::test]
    async fn sessions_with_a_running_hop_or_a_result_are_not_revoked() {
        // A hop in flight is refused, and so is its result once it has one.
        let stalled: Respond = Arc::new(|_: &[u8]| (Vec::new(), End::Wait));
        let origin = web_origin(stalled, false).await;
        let s = hurried(origin.roots.clone());
        let token = register(&s, payload("https://example.com/", 5)).await;
        let running = {
            let (s, origin, token) = (s.clone(), origin.addr, token.clone());
            tokio::spawn(async move {
                let origin = Server { addr: origin, roots: rustls::RootCertStore::empty(), seen: Arc::new(Mutex::new(None)) };
                hop(&s, &origin, &token, 0, "https://example.com/", None).await
            })
        };
        for _ in 0..500 {
            if s.1.lock().unwrap().by_job.get(&job_key("synthetic", "1")).is_some_and(|e| e.in_flight == 1) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(revoke_attempt(&s, "1").await, (StatusCode::CONFLICT, json!({"error": "session in flight"})));
        let (reported, verifier) = running.await.unwrap();
        verifier.unwrap();
        assert!(reported.is_err());
        // A rejected hop ended the job without a result: revoking it is a no-op that succeeds.
        assert_eq!(revoke_attempt(&s, "1").await.0, StatusCode::NO_CONTENT);
        match &s.1.lock().unwrap().by_job[&job_key("synthetic", "1")].status {
            Status::WebRead { rejections, .. } => assert_eq!(rejections, &["session_timeout"]),
            _ => panic!("not a web receipt"),
        }

        // A complete page is the caller's to ingest, and its body stays readable.
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5)).await;
        hop(&s, &origin, &token, 0, "https://example.com/", None).await.1.unwrap();
        assert_eq!(revoke_attempt(&s, "1").await, (StatusCode::CONFLICT, json!({"error": "session complete"})));
        assert_eq!(stored(&s).await, &PAGE[PAGE.len() - 20..]);
        assert_eq!(view(&s).await["complete"], true);

        // An unrun session's token is refused once revoked, before the target sees a request.
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5)).await;
        assert_eq!(revoke_attempt(&s, "1").await.0, StatusCode::NO_CONTENT);
        let (reported, verifier) = hop(&s, &origin, &token, 0, "https://example.com/", None).await;
        assert!(reported.is_err() && verifier.is_err());
        assert!(origin.seen.lock().unwrap().is_none());

        // X and Codex registrations revoke the same way; key auth applies.
        let x = json!({"type":"x.read","max_attempts":1,"exchanges":[{"operation":"UserByScreenName","query_id":"qid_1","variables":{"screen_name":"jack"},"features":{}}],"proof_mode":"relay","proof_policy":"x-relay-v1"});
        for (attempt, payload) in [("x", x), ("codex", json!({"type":"response.create","model":"synthetic-model"}))] {
            let (code, _) = create(State(s.clone()), headers(), Json(CreateRequest { attempt: attempt.into(), ..job(payload, now_ms() + 60_000) })).await;
            assert_eq!(code, StatusCode::CREATED);
            assert_eq!(revoke_attempt(&s, attempt).await.0, StatusCode::NO_CONTENT, "{attempt}");
            let (_, Json(v)) = status(State(s.clone()), headers(), Path(("synthetic".into(), attempt.into()))).await;
            assert_eq!(v["status"], "expired", "{attempt}");
        }
        assert_eq!(tokens(&s), 0);
        let response = revoke(State(s.clone()), HeaderMap::new(), Path(("synthetic".into(), "x".into()))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(revoke_attempt(&s, "nobody").await, (StatusCode::NOT_FOUND, json!({"error": "unknown session"})));
    }

    fn valid_hop(index: usize, url: &str, status: u16, location: Option<&str>, body: Option<&[u8]>) -> WebHop {
        let host = webpolicy::url_host(url).to_owned();
        WebHop {
            index,
            url: url.into(),
            status_code: status,
            location: location.map(Into::into),
            location_refused: None,
            head_base64: STANDARD.encode(format!("HTTP/1.1 {status} X\r\n\r\n")),
            body_stored: body.is_some(),
            body_bytes: body.map_or(0, <[u8]>::len),
            body_sha256: verifier_store::hash(body.unwrap_or_default()),
            response_sha256: hex(&Sha256::digest(b"r")),
            framing: "content_length".into(),
            sent_bytes: 100,
            received_bytes: 100,
            server_name: host,
            tls_version: WEB_TLS_VERSION.into(),
            cipher_suite: WEB_CIPHER_SUITE.into(),
            alpn: Some("http/1.1".into()),
            cert_chain_sha256: hex(&Sha256::digest(b"c")),
            leaf_cert_sha256: hex(&Sha256::digest(b"l")),
            started_at_ms: 1,
            duration_ms: 1,
            node_user_agent: None,
            node_cookie_names: None,
            node_cookie_sha256: None,
        }
    }

    #[test]
    fn malformed_web_receipts_cannot_restore() {
        let (kind, _) = kind(&payload("https://example.com/", 2), true).unwrap();
        let good = || Status::WebRead {
            remaining_sessions: 1,
            complete: true,
            next_url: None,
            hops: vec![valid_hop(0, "https://example.com/", 301, Some("https://www.example.com/"), None), valid_hop(1, "https://www.example.com/", 200, None, Some(b"page"))],
            rejections: vec![],
            rejection: None,
            body_released_at_ms: None,
        };
        assert!(validate_receipt(&kind, &good(), 0).is_ok());
        let pending = Status::WebRead {
            remaining_sessions: 2,
            complete: false,
            next_url: Some("https://www.example.com/".into()),
            hops: vec![valid_hop(0, "https://example.com/", 301, Some("https://www.example.com/"), None)],
            rejections: vec![],
            rejection: None,
            body_released_at_ms: None,
        };
        assert!(validate_receipt(&kind, &pending, 0).is_ok());
        let Status::WebRead { next_url, hops, .. } = &pending else { unreachable!() };
        let in_flight = Status::WebRead { remaining_sessions: 1, complete: false, next_url: next_url.clone(), hops: hops.clone(), rejections: vec![], rejection: None, body_released_at_ms: None };
        assert!(validate_receipt(&kind, &in_flight, 1).is_ok());
        // A released body is still a valid receipt.
        let mut released = good();
        if let Status::WebRead { body_released_at_ms, .. } = &mut released {
            *body_released_at_ms = Some(1);
        }
        assert!(validate_receipt(&kind, &released, 0).is_ok());
        fn edit(status: &mut Status) -> (&mut usize, &mut bool, &mut Option<String>, &mut Vec<WebHop>, &mut Vec<String>) {
            let Status::WebRead { remaining_sessions, complete, next_url, hops, rejections, .. } = status else { unreachable!() };
            (remaining_sessions, complete, next_url, hops, rejections)
        }
        fn extra(status: &mut Status) -> (&mut Option<Rejection>, &mut Option<u64>) {
            let Status::WebRead { rejection, body_released_at_ms, .. } = status else { unreachable!() };
            (rejection, body_released_at_ms)
        }
        let reject = |reason: &str| Rejection { reason: reason.into(), received_bytes: 10, entity_bytes: 4, declared_bytes: None };
        let mutations: Vec<(&str, Box<dyn Fn(&mut Status)>)> = vec![
            ("count", Box::new(|s| *edit(s).0 = 2)),
            ("broken chain", Box::new(|s| edit(s).3[1].url = "https://example.com/other".into())),
            ("index", Box::new(|s| edit(s).3[1].index = 2)),
            ("first url", Box::new(|s| edit(s).3[0].url = "https://example.com/x".into())),
            ("body on a redirect", Box::new(|s| edit(s).3[0].body_stored = true)),
            ("no final body", Box::new(|s| edit(s).3[1].body_stored = false)),
            ("body hash", Box::new(|s| edit(s).3[1].body_sha256 = "ZZ".repeat(32))),
            ("body over received", Box::new(|s| edit(s).3[1].body_bytes = 101)),
            ("body over the ceiling", Box::new(|s| {
                edit(s).3[1].body_bytes = webpolicy::PAGE_MAX + 1;
                edit(s).3[1].received_bytes = webpolicy::PAGE_MAX + 100;
            })),
            ("too large", Box::new(|s| edit(s).3[1].received_bytes = webpolicy::max_wire(webpolicy::PAGE_MAX) + 1)),
            ("released while incomplete", Box::new(|s| {
                let (remaining, complete, _, hops, _) = edit(s);
                (*remaining, *complete) = (2, false);
                hops.pop();
                *edit(s).2 = Some("https://www.example.com/".into());
                *extra(s).1 = Some(1);
            })),
            ("rejection without reason", Box::new(move |s| *extra(s).0 = Some(reject("tls_failed")))),
            ("not complete", Box::new(|s| *edit(s).1 = false)),
            ("next url", Box::new(|s| *edit(s).2 = Some("https://www.example.com/".into()))),
            ("redirect not followed", Box::new(|s| edit(s).3[0].location = None)),
            ("location on 200", Box::new(|s| edit(s).3[1].location = Some("https://example.com/".into()))),
            ("server name", Box::new(|s| edit(s).3[1].server_name = "example.com".into())),
            ("interim status", Box::new(|s| edit(s).3[1].status_code = 103)),
            ("hex", Box::new(|s| edit(s).3[1].leaf_cert_sha256 = "ZZ".repeat(32))),
            ("framing", Box::new(|s| edit(s).3[1].framing = "magic".into())),
            ("cipher", Box::new(|s| edit(s).3[1].cipher_suite = "TLS13_CHACHA20_POLY1305_SHA256".into())),
            ("refused on a 200", Box::new(|s| edit(s).3[1].location_refused = Some("insecure".into()))),
            ("unknown rejection", Box::new(move |s| {
                let (remaining, complete, _, hops, rejections) = edit(s);
                (*remaining, *complete) = (1, false);
                hops.pop();
                rejections.push("made_up".into());
                *extra(s).0 = Some(reject("made_up"));
            })),
            ("old reason", Box::new(move |s| {
                let (remaining, complete, _, hops, rejections) = edit(s);
                (*remaining, *complete) = (1, false);
                hops.pop();
                rejections.push("response_too_large".into());
                *extra(s).0 = Some(reject("response_too_large"));
            })),
            ("reason without rejection", Box::new(|s| {
                let (remaining, complete, _, hops, rejections) = edit(s);
                (*remaining, *complete) = (1, false);
                hops.pop();
                rejections.push("tls_failed".into());
            })),
            ("rejection of another reason", Box::new(move |s| {
                let (remaining, complete, _, hops, rejections) = edit(s);
                (*remaining, *complete) = (1, false);
                hops.pop();
                rejections.push("tls_failed".into());
                *extra(s).0 = Some(reject("page_too_large"));
            })),
            ("entity over received", Box::new(|s| {
                let (remaining, complete, _, hops, rejections) = edit(s);
                (*remaining, *complete) = (1, false);
                hops.pop();
                rejections.push("page_too_large".into());
                *extra(s).0 = Some(Rejection { reason: "page_too_large".into(), received_bytes: 1, entity_bytes: 2, declared_bytes: None });
            })),
            ("complete and rejected", Box::new(move |s| {
                *edit(s).0 = 0;
                edit(s).4.push("tls_failed".into());
                *extra(s).0 = Some(reject("tls_failed"));
            })),
        ];
        for (name, mutate) in mutations {
            let mut status = good();
            mutate(&mut status);
            assert!(validate_receipt(&kind, &status, 0).is_err(), "{name} accepted");
        }
        // The same shape with a known rejection is a valid ended job.
        let mut rejected = good();
        {
            let (remaining, complete, _, hops, rejections) = edit(&mut rejected);
            (*remaining, *complete) = (1, false);
            hops.pop();
            rejections.push("page_too_large".into());
            *extra(&mut rejected).0 = Some(Rejection { reason: "page_too_large".into(), received_bytes: 67_174_401, entity_bytes: 67_108_865, declared_bytes: None });
        }
        assert!(validate_receipt(&kind, &rejected, 0).is_ok());
        // A redirect that could not be followed ends the chain with its reason.
        let mut refused = valid_hop(0, "https://example.com/", 302, None, Some(b""));
        refused.location_refused = Some("insecure".into());
        let ended = |hop: WebHop| Status::WebRead { remaining_sessions: 2, complete: true, next_url: None, hops: vec![hop], rejections: vec![], rejection: None, body_released_at_ms: None };
        assert!(validate_receipt(&kind, &ended(refused.clone()), 0).is_ok());
        refused.location_refused = Some("because".into());
        assert!(validate_receipt(&kind, &ended(refused), 0).is_err());
        assert!(validate_receipt(&kind, &good(), 1).is_err());
        assert!(validate_receipt(&Kind::Codex, &good(), 0).is_err());
    }

    fn browser_hop(index: usize, url: &str, status: u16, location: Option<&str>, body: Option<&[u8]>, cookie: Option<&str>) -> WebHop {
        let node = webpolicy::NodeHeaders { user_agent: DARWIN_UA.into(), cookie: cookie.map(Into::into) };
        WebHop { node_user_agent: Some(node.user_agent.clone()), node_cookie_names: Some(node.cookie_names()), node_cookie_sha256: node.cookie_sha256(), ..valid_hop(index, url, status, location, body) }
    }

    #[test]
    fn browser_receipt_node_fields_follow_the_policy() {
        let (browser, _) = kind(&browser_payload("https://example.com/"), true).unwrap();
        let (relay, _) = kind(&payload("https://example.com/", 5), true).unwrap();
        let receipt = |hops: Vec<WebHop>| Status::WebRead { remaining_sessions: 6 - hops.len(), complete: true, next_url: None, hops, rejections: vec![], rejection: None, body_released_at_ms: None };
        let two = || vec![browser_hop(0, "https://example.com/", 302, Some("https://www.example.com/"), None, Some(CLEARANCE)), browser_hop(1, "https://www.example.com/", 200, None, Some(b"page"), None)];
        assert!(validate_receipt(&browser, &receipt(two()), 0).is_ok());
        // The same hops without the node fields are a relay receipt, and only that.
        let plain = || vec![valid_hop(0, "https://example.com/", 302, Some("https://www.example.com/"), None), valid_hop(1, "https://www.example.com/", 200, None, Some(b"page"))];
        assert!(validate_receipt(&relay, &receipt(plain()), 0).is_ok());
        assert!(validate_receipt(&browser, &receipt(plain()), 0).is_err());
        assert!(validate_receipt(&relay, &receipt(two()), 0).is_err());
        // A UA from before a pin bump still restores; anything else does not.
        let mut older = two();
        older[0].node_user_agent = Some(DARWIN_UA.replace("Chrome/155", "Chrome/154"));
        assert!(validate_receipt(&browser, &receipt(older), 0).is_ok());
        let mutations: Vec<(&str, Box<dyn Fn(&mut Vec<WebHop>)>)> = vec![
            ("no user agent", Box::new(|h| h[0].node_user_agent = None)),
            ("other user agent", Box::new(|h| h[0].node_user_agent = Some("Googlebot/2.1".into()))),
            ("no names", Box::new(|h| h[1].node_cookie_names = None)),
            ("session name", Box::new(|h| h[0].node_cookie_names = Some(vec!["cf_clearance".into(), "session".into()]))),
            ("names without a hash", Box::new(|h| h[0].node_cookie_sha256 = None)),
            ("hash without names", Box::new(|h| h[1].node_cookie_sha256 = Some(CLEARANCE_SHA256.into()))),
            ("hash not hex", Box::new(|h| h[0].node_cookie_sha256 = Some("Z".repeat(64)))),
            ("too many names", Box::new(|h| h[0].node_cookie_names = Some(vec!["_px1".into(); 51]))),
            ("relay hop in a browser job", Box::new(|h| h[1] = valid_hop(1, "https://www.example.com/", 200, None, Some(b"page")))),
        ];
        for (name, mutate) in mutations {
            let mut hops = two();
            mutate(&mut hops);
            assert!(validate_receipt(&browser, &receipt(hops), 0).is_err(), "{name} accepted");
        }
        let mut relay_with_ua = plain();
        relay_with_ua[1].node_user_agent = Some(DARWIN_UA.into());
        assert!(validate_receipt(&relay, &receipt(relay_with_ua), 0).is_err());
    }

    #[tokio::test]
    async fn a_browser_hop_records_what_the_node_sent_and_never_the_cookie_value() {
        let url = "https://example.com/";
        let job = webpolicy::validate_job(&browser_payload(url)).unwrap();
        for cookie in [Some(CLEARANCE), None] {
            let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
            let dir = Temp::new();
            let s = shared(origin.roots.clone(), Some(&dir.0));
            let token = register(&s, browser_payload(url)).await;
            let raw = webpolicy::request_with_node(url, &job.headers, DARWIN_UA, cookie);
            let (reported, verifier) = hop(&s, &origin, &token, 0, url, Some(raw.clone())).await;
            verifier.unwrap();
            assert!(reported.unwrap().is_final);
            // The origin got the node's headers, on the wire the verifier sealed.
            assert_eq!(origin.seen.lock().unwrap().as_deref(), Some(&raw[..]));
            let view = view(&s).await;
            assert_eq!(view["request_sha256"], "964f55b17be3ad0fb55ae96c3a1cdd36883b9a2f4833da2946c1eeefcdd62ba7");
            assert_eq!((view["complete"].as_bool(), view["rejections"].clone()), (Some(true), json!([])));
            let h = &view["hops"][0];
            assert_eq!((h["node_user_agent"].as_str(), h["sent_bytes"].as_u64()), (Some(DARWIN_UA), Some(raw.len() as u64)));
            match cookie {
                Some(_) => {
                    assert_eq!((h["node_cookie_names"].clone(), h["node_cookie_sha256"].as_str()), (json!(["cf_clearance", "__cf_bm"]), Some(CLEARANCE_SHA256)));
                    assert_eq!(h.as_object().unwrap().len(), 24);
                }
                None => {
                    assert_eq!((h["node_cookie_names"].clone(), h.get("node_cookie_sha256")), (json!([]), None));
                    assert_eq!(h.as_object().unwrap().len(), 23);
                }
            }
            // The cookie value is in no receipt byte: not the view, not the store.
            let mut receipts = vec![view.to_string().into_bytes()];
            for entry in fs::read_dir(&dir.0).unwrap() {
                receipts.push(fs::read(entry.unwrap().path()).unwrap());
            }
            assert!(receipts.len() > 1);
            for bytes in &receipts {
                for value in ["abc.DEF-123_456", "x1y2", "Cookie"] {
                    assert!(!bytes.windows(value.len()).any(|w| w == value.as_bytes()), "{value} stored");
                }
            }
            // The receipt restores with its node fields.
            drop(s);
            let s = shared(origin.roots.clone(), Some(&dir.0));
            assert_eq!(super::web_tests::view(&s).await["hops"][0]["node_user_agent"], DARWIN_UA);
        }
    }

    #[tokio::test]
    async fn a_browser_hop_outside_the_policy_is_rejected_before_it_reaches_the_origin() {
        let url = "https://example.com/";
        let job = webpolicy::validate_job(&browser_payload(url)).unwrap();
        let cases = [
            ("session cookie", webpolicy::request_with_node(url, &job.headers, DARWIN_UA, Some("cf_clearance=a; session=x"))),
            ("relay request", webpolicy::request(url, &job.headers)),
            ("unpinned user agent", webpolicy::request_with_node(url, &job.headers, &DARWIN_UA.replace("Chrome/155", "Chrome/156"), None)),
        ];
        for (case, raw) in cases {
            let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
            let s = shared(origin.roots.clone(), None);
            let token = register(&s, browser_payload(url)).await;
            let (reported, _) = hop(&s, &origin, &token, 0, url, Some(raw)).await;
            assert!(reported.is_err(), "{case}");
            assert!(origin.seen.lock().unwrap().is_none(), "{case}");
            let view = view(&s).await;
            assert_eq!((view["rejections"].clone(), view["hops"].as_array().unwrap().len()), (json!(["request_rejected"]), 0), "{case}");
            assert_eq!(tokens(&s), 0, "{case}");
        }
        // A relay job refuses the browser form just the same.
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload(url, 5)).await;
        let mut raw = webpolicy::request(url, &web_headers());
        let at = raw.windows(15).position(|w| w == b"Accept-Encoding").unwrap();
        raw.splice(at..at, format!("Cookie: {CLEARANCE}\r\n").into_bytes());
        assert!(hop(&s, &origin, &token, 0, url, Some(raw)).await.0.is_err());
        assert_eq!(view(&s).await["rejections"], json!(["request_rejected"]));
    }

    /// The whole `relay-web` path for a browser job's re-fetch: two hops
    /// through a CONNECT proxy, each with the node's User-Agent and the
    /// clearance cookies for its host.
    #[tokio::test]
    async fn relay_web_carries_clearance_cookies_over_two_hops() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let respond: Respond = Arc::new(move |request: &[u8]| {
            log.lock().unwrap().push(request.to_vec());
            if request.starts_with(b"GET / ") {
                (b"HTTP/1.1 302 Found\r\nLocation: https://www.example.com/next\r\nContent-Length: 0\r\n\r\n".to_vec(), End::Wait)
            } else {
                (PAGE.to_vec(), End::Wait)
            }
        });
        let origin = web_origin(respond, false).await;
        let first = "https://example.com/";
        let next = "https://www.example.com/next";
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, browser_payload(first)).await;
        let verifier = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let verifier_addr = verifier.local_addr().unwrap();
        let shared_verifier = s.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = verifier.accept().await {
                tokio::spawn(handle(shared_verifier.clone(), Box::new(socket), waiting(&shared_verifier), LOCAL));
            }
        });
        // The proxy tunnels every CONNECT to the local origin.
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let origin_addr = origin.addr;
        tokio::spawn(async move {
            while let Ok((mut client, _)) = proxy.accept().await {
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && client.read(&mut byte).await.unwrap() == 1 {
                        head.push(byte[0]);
                    }
                    let mut upstream = TcpStream::connect(origin_addr).await.unwrap();
                    client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        let other = "cf_clearance=www.Zz9";
        let input = |hop: u32, url: &str, cookie: &str| {
            json!({
                "verifier": verifier_addr.to_string(), "plaintext_fixture": true, "token": token, "hop": hop,
                "url": url, "ip": "93.184.215.14", "port": 443, "proxy": {"host": "127.0.0.1", "port": proxy_port},
                "payload": browser_payload(first), "node_headers": {"user_agent": DARWIN_UA, "cookie": cookie}, "timeout_ms": 20000
            })
        };
        let mut summaries = Vec::new();
        for (hop, url, cookie) in [(0, first, CLEARANCE), (1, next, other)] {
            match node::run_web(&serde_json::to_vec(&input(hop, url, cookie)).unwrap()).await {
                Ok(summary) => summaries.push(serde_json::to_value(summary).unwrap()),
                Err(failure) => panic!("hop {hop}: {}: {:#}", failure.class, failure.error),
            }
        }
        assert_eq!((summaries[0]["status_code"].as_u64(), summaries[0]["final"].as_bool(), summaries[0]["next_url"].as_str()), (Some(302), Some(false), Some(next)));
        assert_eq!((summaries[1]["status_code"].as_u64(), summaries[1]["final"].as_bool(), summaries[1]["url"].as_str()), (Some(200), Some(true), Some(next)));
        for summary in &summaries {
            let text = summary.to_string();
            assert!(!text.contains("abc.DEF") && !text.contains("x1y2") && !text.contains("Zz9") && !text.contains("hello"), "{text}");
        }
        // The origin saw each hop's own cookies, in the bytes the verifier authorized.
        let headers = webpolicy::validate_job(&browser_payload(first)).unwrap().headers;
        let expected = vec![webpolicy::request_with_node(first, &headers, DARWIN_UA, Some(CLEARANCE)), webpolicy::request_with_node(next, &headers, DARWIN_UA, Some(other))];
        assert_eq!(*seen.lock().unwrap(), expected);
        let view = view(&s).await;
        assert_eq!((view["complete"].as_bool(), view["remaining_sessions"].as_u64()), (Some(true), Some(4)));
        let hops = view["hops"].as_array().unwrap();
        assert_eq!((hops[0]["node_cookie_names"].clone(), hops[0]["node_cookie_sha256"].as_str()), (json!(["cf_clearance", "__cf_bm"]), Some(CLEARANCE_SHA256)));
        assert_eq!((hops[1]["node_cookie_names"].clone(), hops[1]["node_cookie_sha256"].as_str()), (json!(["cf_clearance"]), Some(verifier_store::hash(other.as_bytes()).as_str())));
        assert!(hops.iter().all(|h| h["node_user_agent"] == DARWIN_UA));
        assert!(!view.to_string().contains("Zz9") && !view.to_string().contains("abc.DEF"));
    }

    /// The whole `relay-web` input path: stdin JSON, a CONNECT proxy to the
    /// checked address, a plaintext loopback verifier, and the summary.
    #[tokio::test]
    async fn relay_web_runs_a_hop_through_a_connect_proxy() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5)).await;
        let verifier = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let verifier_addr = verifier.local_addr().unwrap();
        let shared_verifier = s.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = verifier.accept().await {
                tokio::spawn(handle(shared_verifier.clone(), Box::new(socket), waiting(&shared_verifier), LOCAL));
            }
        });
        // The proxy tunnels whatever it is asked for to the local origin, and
        // records the CONNECT line it was given.
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let connect = Arc::new(Mutex::new(String::new()));
        let log = connect.clone();
        let origin_addr = origin.addr;
        tokio::spawn(async move {
            let (mut client, _) = proxy.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && client.read(&mut byte).await.unwrap() == 1 {
                head.push(byte[0]);
            }
            *log.lock().unwrap() = String::from_utf8(head).unwrap();
            let mut upstream = TcpStream::connect(origin_addr).await.unwrap();
            client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        });
        let input = json!({
            "verifier": verifier_addr.to_string(), "plaintext_fixture": true, "token": token, "hop": 0,
            "url": "https://example.com/", "ip": "93.184.215.14", "port": 443,
            "proxy": {"host": "127.0.0.1", "port": proxy_port, "authorization": "Basic c2VjcmV0"},
            "payload": payload("https://example.com/", 5), "timeout_ms": 20000
        });
        let summary = match node::run_web(&serde_json::to_vec(&input).unwrap()).await {
            Ok(summary) => serde_json::to_value(summary).unwrap(),
            Err(failure) => panic!("{}: {:#}", failure.class, failure.error),
        };
        assert_eq!(*connect.lock().unwrap(), "CONNECT 93.184.215.14:443 HTTP/1.1\r\nHost: 93.184.215.14:443\r\nProxy-Authorization: Basic c2VjcmV0\r\n\r\n");
        assert_eq!((summary["status"].as_str(), summary["hop"].as_u64(), summary["status_code"].as_u64(), summary["final"].as_bool()), (Some("proof_sent"), Some(0), Some(200), Some(true)));
        assert!(summary.get("next_url").is_none());
        assert_eq!(summary["url"], "https://example.com/");
        assert_eq!(summary["verifier_transport_layer"], "tcp_payload");
        for counter in ["verifier_sent_bytes", "verifier_received_bytes", "target_sent_bytes", "target_received_bytes"] {
            assert!(summary[counter].as_u64().unwrap() > 0, "{counter}");
        }
        // Only integers, strings and booleans at the top level, besides the timings.
        for (key, value) in summary.as_object().unwrap() {
            assert!(key == "diagnostics" || value.is_u64() || value.is_string() || value.is_boolean(), "{key}");
        }
        let text = summary.to_string();
        for private in ["c2VjcmV0", "hello", "93.184.215.14"] {
            assert!(!text.contains(private), "{private} leaked into the summary");
        }
        let phases: Vec<&str> = summary["diagnostics"]["spans"].as_array().unwrap().iter().map(|s| s["phase"].as_str().unwrap()).collect();
        for phase in ["x_tcp_connect", "x_tls_ready", "relay_session", "request_sent", "response_first_byte", "response_complete", "opening_check"] {
            assert!(phases.contains(&phase), "{phase} missing from {phases:?}");
        }
        assert_eq!(view(&s).await["complete"], true);
    }

    /// Runs `serve` for `s` on a loopback port.
    async fn serve_verifier(s: &Shared) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, s.clone(), None));
        addr
    }

    /// One hop on `conn` with `token`: what the verifier reported, and
    /// whether it keeps the connection.
    async fn hop_on(conn: &mut node::RelayConn<TcpStream>, origin: &Server, token: &str, index: u32, url: &str) -> Result<(node::HopOutcome, bool)> {
        conn.present(token).await?;
        let tcp = TcpStream::connect(origin.addr).await?;
        let raw = webpolicy::request(url, &web_headers());
        tokio::time::timeout(Duration::from_secs(30), node::web_session_on(conn, tcp, &raw, webpolicy::url_host(url), index, url, &node::Sealing::default(), &Trace::new())).await?
    }

    /// Registers web job attempt `attempt` for `url` and returns its token.
    async fn register_attempt(s: &Shared, attempt: &str, url: &str) -> String {
        let (code, Json(created)) = create(State(s.clone()), headers(), Json(CreateRequest { attempt: attempt.into(), ..job(payload(url, 5), now_ms() + 60_000) })).await;
        assert_eq!(code, StatusCode::CREATED, "{created}");
        created["token"].as_str().unwrap().to_owned()
    }

    /// Whether the verifier closed `socket` within `within`.
    async fn closed_within(socket: &mut TcpStream, within: Duration) -> bool {
        let mut byte = [0u8; 1];
        matches!(tokio::time::timeout(within, socket.read(&mut byte)).await, Ok(Ok(0) | Err(_)))
    }

    #[tokio::test]
    async fn one_connection_serves_web_session_after_session_each_on_its_own_token() {
        const OTHER: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nother";
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait), ("www.example.com/", OTHER, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let first = register_attempt(&s, "1", "https://example.com/").await;
        let second = register_attempt(&s, "2", "https://www.example.com/").await;
        let mut conn = node::RelayConn::new(TcpStream::connect(verifier).await.unwrap());
        let (outcome, keep) = hop_on(&mut conn, &origin, &first, 0, "https://example.com/").await.unwrap();
        assert_eq!((outcome.status_code, keep), (200, true));
        // Between sessions the connection waits for a token: it holds a waiting place, no session slot.
        let c = capacity_view(&s).await;
        assert_eq!((c["pre_token"]["connections"].as_u64(), c["active_connections"].as_u64()), (Some(1), Some(0)));
        let (outcome, keep) = hop_on(&mut conn, &origin, &second, 0, "https://www.example.com/").await.unwrap();
        assert_eq!((outcome.url.as_str(), keep), ("https://www.example.com/", true));
        // Each job has its own receipt, complete, from its own session.
        for (attempt, url, bytes) in [("1", "https://example.com/", 20), ("2", "https://www.example.com/", 5)] {
            let (_, Json(v)) = status(State(s.clone()), headers(), Path(("synthetic".into(), attempt.into()))).await;
            assert_eq!((v["complete"].as_bool(), v["hops"][0]["url"].as_str(), v["hops"][0]["body_bytes"].as_u64()), (Some(true), Some(url), Some(bytes)), "{attempt}");
        }
        assert_eq!(tokens(&s), 0);
        // A used token is refused on the same connection, which then closes: nothing is spent.
        let third = register_attempt(&s, "3", "https://example.com/").await;
        assert!(hop_on(&mut conn, &origin, &first, 0, "https://example.com/").await.is_err());
        let mut fresh = node::RelayConn::new(TcpStream::connect(verifier).await.unwrap());
        assert_eq!(hop_on(&mut fresh, &origin, &third, 0, "https://example.com/").await.unwrap().0.status_code, 200);
        // A kept connection takes web tokens only: an X token closes it unspent.
        let x = json!({"type":"x.read","max_attempts":1,"exchanges":[{"operation":"UserByScreenName","query_id":"qid_1","variables":{"screen_name":"jack"},"features":{}}],"proof_mode":"relay","proof_policy":"x-relay-v1"});
        let (_, Json(created)) = create(State(s.clone()), headers(), Json(CreateRequest { attempt: "x".into(), fence: None, expires_at_ms: None, ttl_seconds: Some(60), ..job(x, 0) })).await;
        fresh.present(created["token"].as_str().unwrap()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(fresh.check_idle().is_err());
        let (_, Json(v)) = status(State(s.clone()), headers(), Path(("synthetic".into(), "x".into()))).await;
        assert_eq!((v["remaining_attempts"].as_u64(), tokens(&s)), (Some(1), 1));
    }

    #[tokio::test]
    async fn waiting_connections_are_capped_per_address_and_overall_and_hold_no_session_slot() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        // Two waiting connections per address.
        let s = shared_local(origin.roots.clone(), 2);
        let verifier = serve_verifier(&s).await;
        let mut first = TcpStream::connect(verifier).await.unwrap();
        let mut second = TcpStream::connect(verifier).await.unwrap();
        let mut third = TcpStream::connect(verifier).await.unwrap();
        assert!(closed_within(&mut third, Duration::from_secs(2)).await);
        assert!(!closed_within(&mut first, Duration::from_millis(100)).await && !closed_within(&mut second, Duration::from_millis(100)).await);
        let c = capacity_view(&s).await;
        assert_eq!((c["pre_token"]["connections"].as_u64(), c["pre_token"]["refused_per_address"].as_u64(), c["pre_token"]["per_address_limit"].as_u64()), (Some(2), Some(1), Some(2)));
        // A place frees when a waiting connection goes, or presents its token.
        drop(second);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut conn = node::RelayConn::new(TcpStream::connect(verifier).await.unwrap());
        assert_eq!(hop_on(&mut conn, &origin, &token, 0, "https://example.com/").await.unwrap(), (node_outcome(), true));
        drop((first, conn));

        // The overall cap counts every address.
        let mut config = Config::new(KEY.into(), "127.0.0.1:1".into(), Duration::from_secs(20), verifier_store::Limits::default(), 64, 48, crate::relay::verifier::tls_config(origin.roots.clone()).unwrap());
        config.pre_token = Arc::new(PreToken::new(3, 8));
        let s: Shared = Arc::new((config, Mutex::new(Sessions::default())));
        let verifier = serve_verifier(&s).await;
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(TcpStream::connect(verifier).await.unwrap());
        }
        let mut fourth = TcpStream::connect(verifier).await.unwrap();
        assert!(closed_within(&mut fourth, Duration::from_secs(2)).await);
        assert_eq!(capacity_view(&s).await["pre_token"]["refused_global"].as_u64(), Some(1));
        drop(held);

        // Waiting connections hold no session slot: 64 of them, and a session still runs.
        let s = shared_local(origin.roots.clone(), 128);
        let verifier = serve_verifier(&s).await;
        let mut idle = Vec::new();
        for _ in 0..64 {
            idle.push(TcpStream::connect(verifier).await.unwrap());
        }
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut conn = node::RelayConn::new(TcpStream::connect(verifier).await.unwrap());
        assert_eq!(hop_on(&mut conn, &origin, &token, 0, "https://example.com/").await.unwrap().0.status_code, 200);
        assert_eq!(capacity_view(&s).await["pre_token"]["connections"].as_u64(), Some(65));
    }

    fn node_outcome() -> node::HopOutcome {
        node::HopOutcome { hop: 0, url: "https://example.com/".into(), status_code: 200, is_final: true, next_url: None }
    }

    /// A verifier whose connections wait `token_wait` for a token, or
    /// `idle_wait` once they sent PING or finished a session.
    fn waits(roots: rustls::RootCertStore, token_wait: Duration, idle_wait: Duration) -> Shared {
        let mut config = Config::new(KEY.into(), "127.0.0.1:1".into(), Duration::from_secs(20), verifier_store::Limits::default(), 64, 48, crate::relay::verifier::tls_config(roots).unwrap());
        (config.token_wait, config.idle_wait) = (token_wait, idle_wait);
        Arc::new((config, Mutex::new(Sessions::default())))
    }

    #[tokio::test]
    async fn a_connection_waits_for_its_token_only_as_its_wait_allows() {
        use crate::relay::wire::{self, FROM_SERVER, PING, PONG};
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = waits(origin.roots.clone(), Duration::from_millis(300), Duration::from_millis(1200));
        let verifier = serve_verifier(&s).await;
        // Nothing sent: closed once the short wait ends.
        let started = Instant::now();
        let mut silent = TcpStream::connect(verifier).await.unwrap();
        assert!(closed_within(&mut silent, Duration::from_secs(3)).await);
        assert!(started.elapsed() >= Duration::from_millis(250), "{:?}", started.elapsed());
        // A PING is answered and earns the long wait, which still ends.
        let started = Instant::now();
        let mut pinged = TcpStream::connect(verifier).await.unwrap();
        wire::send(&mut pinged, PING, &[]).await.unwrap();
        assert_eq!(wire::recv(&mut pinged).await.unwrap(), (PONG, Vec::new()));
        tokio::time::sleep(Duration::from_millis(500)).await;
        wire::send(&mut pinged, PING, &[]).await.unwrap();
        assert_eq!(wire::recv(&mut pinged).await.unwrap(), (PONG, Vec::new()));
        assert!(closed_within(&mut pinged, Duration::from_secs(3)).await);
        assert!(started.elapsed() >= Duration::from_millis(1100), "{:?}", started.elapsed());
        // A token after a PING runs its session as any other.
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut conn = node::RelayConn::new(TcpStream::connect(verifier).await.unwrap());
        conn.ping(Duration::from_secs(2)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        let (_, keep) = hop_on(&mut conn, &origin, &token, 0, "https://example.com/").await.unwrap();
        assert!(keep);
        // After a session the long wait applies, and it ends too.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(conn.check_idle().is_err());
        // Anything but a token or PING ends a fresh connection at once:
        // garbage, a PING with a payload, a target's bytes, too many PINGs.
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("garbage", b"Z".to_vec()),
            ("upper-case token", format!("{}\n", "A".repeat(64)).into_bytes()),
            ("unterminated token", "a".repeat(65).into_bytes()),
            ("ping payload", vec![PING, 0, 0, 0, 1, 0]),
            ("target bytes", vec![FROM_SERVER, 0, 0, 0, 1, 0]),
            ("pings", [PING, 0, 0, 0, 0].repeat(17)),
        ];
        for (case, bytes) in cases {
            let mut socket = TcpStream::connect(verifier).await.unwrap();
            socket.write_all(&bytes).await.unwrap();
            let mut seen = Vec::new();
            let ended = tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut seen)).await;
            assert!(ended.is_ok(), "{case}: still open");
            assert!(seen.chunks(5).all(|frame| frame == [PONG, 0, 0, 0, 0]), "{case}");
        }
    }

    #[tokio::test]
    async fn a_connection_is_kept_after_a_session_only_while_a_waiting_place_is_free() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared_local(origin.roots.clone(), 1);
        let verifier = serve_verifier(&s).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let socket = TcpStream::connect(verifier).await.unwrap();
        let hop = {
            let origin_addr = origin.addr;
            tokio::spawn(async move {
                let origin = Server { addr: origin_addr, roots: rustls::RootCertStore::empty(), seen: Arc::new(Mutex::new(None)) };
                let mut conn = node::RelayConn::new(socket);
                let result = hop_on(&mut conn, &origin, &token, 0, "https://example.com/").await;
                (result, conn)
            })
        };
        // Once the token is admitted the connection's place is free; another connection from the address takes it.
        while s.1.lock().unwrap().by_job.get(&job_key("synthetic", "1")).is_none_or(|e| e.in_flight != 1) {
            tokio::task::yield_now().await;
        }
        let place = s.0.pre_token.take(LOCAL).expect("the place the session left");
        let (result, mut conn) = hop.await.unwrap();
        // The hop stands; the verifier just does not keep the connection.
        let (outcome, keep) = result.unwrap();
        assert_eq!((outcome.status_code, keep), (200, false));
        assert_eq!(view(&s).await["complete"], true);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(conn.check_idle().is_err());
        assert_eq!(capacity_view(&s).await["pre_token"]["refused_per_address"].as_u64(), Some(1));
        drop(place);
    }

    /// A CONNECT proxy that tunnels every connection to `origin`.
    async fn tunnel(origin: std::net::SocketAddr) -> u16 {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = proxy.accept().await {
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && client.read(&mut byte).await.unwrap_or(0) == 1 {
                        head.push(byte[0]);
                    }
                    let Ok(mut upstream) = TcpStream::connect(origin).await else { return };
                    let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        port
    }

    /// One whole `relay-web` hop 0 of `https://example.com/` through `serve`
    /// and a proxy: the summary, or the class and error the node reports.
    async fn relay_web(verifier: std::net::SocketAddr, proxy: u16, token: &str) -> Result<Value, (&'static str, String)> {
        let input = json!({
            "verifier": verifier.to_string(), "plaintext_fixture": true, "token": token, "hop": 0,
            "url": "https://example.com/", "ip": "93.184.215.14", "port": 443, "proxy": {"host": "127.0.0.1", "port": proxy},
            "payload": payload("https://example.com/", 5), "timeout_ms": 20000
        });
        match tokio::time::timeout(Duration::from_secs(30), node::run_web(&serde_json::to_vec(&input).unwrap())).await.unwrap() {
            Ok(summary) => Ok(serde_json::to_value(summary).unwrap()),
            Err(failure) => Err((failure.class, format!("{:#}", failure.error))),
        }
    }

    /// A CONNECT proxy to `origin` that counts the tunnels it opened.
    async fn counted_tunnel(origin: std::net::SocketAddr) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy.local_addr().unwrap().port();
        let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = opened.clone();
        tokio::spawn(async move {
            while let Ok((mut client, _)) = proxy.accept().await {
                let count = count.clone();
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") && client.read(&mut byte).await.unwrap_or(0) == 1 {
                        head.push(byte[0]);
                    }
                    if !head.ends_with(b"\r\n\r\n") {
                        return;
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                    let Ok(mut upstream) = TcpStream::connect(origin).await else { return };
                    let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (port, opened)
    }

    /// `relay-web` input for hop 0 of `https://example.com/` through `proxy`, without a token.
    fn predial_input(verifier: std::net::SocketAddr, proxy: u16, timeout_ms: u64) -> Value {
        json!({
            "verifier": verifier.to_string(), "plaintext_fixture": true, "predial": true, "hop": 0,
            "url": "https://example.com/", "ip": "93.184.215.14", "port": 443, "proxy": {"host": "127.0.0.1", "port": proxy},
            "payload": payload("https://example.com/", 5), "timeout_ms": timeout_ms
        })
    }

    /// Starts `relay-web` on a pipe and writes its first line; the returned
    /// writer is its stdin from there on.
    async fn start_relay_web(input: &Value) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<Result<node::RelayWeb, (&'static str, String)>>) {
        let (mut stdin, read_end) = tokio::io::duplex(1 << 20);
        let run = tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(read_end);
            node::relay_web(&mut reader).await.map_err(|failure| (failure.class, format!("{:#}", failure.error)))
        });
        stdin.write_all(&[serde_json::to_vec(input).unwrap(), b"\n".to_vec()].concat()).await.unwrap();
        (stdin, run)
    }

    /// The (phase, start, end) of each span of a summary's diagnostics.
    fn spans(diagnostics: &Value) -> Vec<(String, u64, u64)> {
        diagnostics["spans"].as_array().unwrap().iter().map(|s| (s["phase"].as_str().unwrap().to_owned(), s["start_ms"].as_u64().unwrap(), s["start_ms"].as_u64().unwrap() + s["duration_ms"].as_u64().unwrap())).collect()
    }

    #[tokio::test]
    async fn a_predialed_hop_dials_the_verifier_first_and_presents_its_token_only_when_given() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let (proxy, tunnels) = counted_tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let (mut stdin, run) = start_relay_web(&predial_input(verifier, proxy, 20_000)).await;
        // The verifier connection is up and waiting; nothing was presented and the target is untouched.
        for _ in 0..500 {
            if capacity_view(&s).await["pre_token"]["connections"] == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(capacity_view(&s).await["pre_token"]["connections"], 1);
        assert_eq!((tunnels.load(Ordering::SeqCst), tokens(&s), view(&s).await["remaining_sessions"].as_u64()), (0, 1, Some(6)));
        assert!(origin.seen.lock().unwrap().is_none() && !run.is_finished());
        // The accept returned the token.
        stdin.write_all(format!("{{\"token\":\"{token}\"}}\n").as_bytes()).await.unwrap();
        let node::RelayWeb::Hop(summary) = tokio::time::timeout(Duration::from_secs(30), run).await.unwrap().unwrap().unwrap() else { panic!("aborted") };
        let summary = serde_json::to_value(summary).unwrap();
        assert_eq!((summary["status"].as_str(), summary["status_code"].as_u64(), summary["final"].as_bool()), (Some("proof_sent"), Some(200), Some(true)));
        assert_eq!((tunnels.load(Ordering::SeqCst), view(&s).await["complete"].as_bool()), (1, Some(true)));
        // One dial, before the wait ended; the target connect after it.
        let spans = spans(&summary["diagnostics"]);
        let phase = |name: &str| spans.iter().filter(|(p, ..)| p == name).cloned().collect::<Vec<_>>();
        assert_eq!(phase("verifier_tcp_connect").len(), 1);
        let (_, _, waited) = phase("predial_wait")[0];
        let (_, dialed_at, _) = phase("verifier_tcp_connect")[0];
        let (_, target_at, _) = phase("x_tcp_connect")[0];
        assert!(dialed_at <= waited && target_at >= waited, "{spans:?}");
        assert!(summary["verifier_sent_bytes"].as_u64().unwrap() > 64);
    }

    #[tokio::test]
    async fn a_predial_ended_before_its_token_sends_nothing_and_reaches_nothing() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let (proxy, tunnels) = counted_tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        // The accept failed: the node closes stdin.
        let (stdin, run) = start_relay_web(&predial_input(verifier, proxy, 20_000)).await;
        for _ in 0..500 {
            if capacity_view(&s).await["pre_token"]["connections"] == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(stdin);
        let node::RelayWeb::Aborted(aborted) = tokio::time::timeout(Duration::from_secs(10), run).await.unwrap().unwrap().unwrap() else { panic!("ran a hop") };
        let aborted = serde_json::to_value(aborted).unwrap();
        assert_eq!(aborted["status"], "predial_aborted");
        assert_eq!(spans(&aborted["diagnostics"]).iter().filter(|(p, ..)| p == "predial_wait").count(), 1);
        for _ in 0..100 {
            if capacity_view(&s).await["pre_token"]["connections"] == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(capacity_view(&s).await["pre_token"]["connections"], 0);
        assert_eq!((tunnels.load(Ordering::SeqCst), tokens(&s), view(&s).await["remaining_sessions"].as_u64()), (0, 1, Some(6)));
        assert!(origin.seen.lock().unwrap().is_none());
        // A malformed token line, a token on the first line, a missing one, or no token in time: nothing is sent either.
        let (mut stdin, run) = start_relay_web(&predial_input(verifier, proxy, 20_000)).await;
        stdin.write_all(b"{\"token\":\"short\"}\n").await.unwrap();
        assert_eq!(tokio::time::timeout(Duration::from_secs(10), run).await.unwrap().unwrap().err().unwrap().0, "fetch_failed");
        let mut both = predial_input(verifier, proxy, 20_000);
        both["token"] = token.clone().into();
        let mut neither = predial_input(verifier, proxy, 20_000);
        neither["predial"] = false.into();
        for input in [both, neither] {
            let (_stdin, run) = start_relay_web(&input).await;
            assert_eq!(tokio::time::timeout(Duration::from_secs(10), run).await.unwrap().unwrap().err().unwrap().0, "fetch_failed");
        }
        let started = Instant::now();
        let (_stdin, run) = start_relay_web(&predial_input(verifier, proxy, 1000)).await;
        let (class, error) = tokio::time::timeout(Duration::from_secs(10), run).await.unwrap().unwrap().err().unwrap();
        assert_eq!(class, "fetch_failed");
        assert!(error.contains("no token before the hop deadline") && started.elapsed() < Duration::from_secs(5), "{error}");
        assert_eq!((tunnels.load(Ordering::SeqCst), tokens(&s), view(&s).await["remaining_sessions"].as_u64()), (0, 1, Some(6)));
    }

    #[tokio::test]
    async fn a_predial_keeps_its_connection_through_a_long_wait_or_dials_again() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        // The verifier gives a new connection 1 s, and 10 s after a PING.
        let s = waits(origin.roots.clone(), Duration::from_secs(1), Duration::from_secs(10));
        let verifier = serve_verifier(&s).await;
        let (proxy, _) = counted_tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let (mut stdin, run) = start_relay_web(&predial_input(verifier, proxy, 20_000)).await;
        // Past the short wait: the PING kept the pre-dialed connection.
        tokio::time::sleep(Duration::from_millis(1800)).await;
        stdin.write_all(format!("{{\"token\":\"{token}\"}}\n").as_bytes()).await.unwrap();
        let node::RelayWeb::Hop(summary) = tokio::time::timeout(Duration::from_secs(30), run).await.unwrap().unwrap().unwrap() else { panic!("aborted") };
        let summary = serde_json::to_value(summary).unwrap();
        assert_eq!(spans(&summary["diagnostics"]).iter().filter(|(p, ..)| p == "verifier_tcp_connect").count(), 1);

        // A pre-dialed connection the verifier closed while it waited (its wait
        // ended before the PING) is replaced by a fresh dial once the token comes.
        let s = waits(origin.roots.clone(), Duration::from_millis(100), Duration::from_millis(100));
        let verifier = serve_verifier(&s).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let (mut stdin, run) = start_relay_web(&predial_input(verifier, proxy, 20_000)).await;
        tokio::time::sleep(Duration::from_millis(1000)).await;
        stdin.write_all(format!("{{\"token\":\"{token}\"}}\n").as_bytes()).await.unwrap();
        let node::RelayWeb::Hop(summary) = tokio::time::timeout(Duration::from_secs(30), run).await.unwrap().unwrap().unwrap() else { panic!("aborted") };
        let summary = serde_json::to_value(summary).unwrap();
        assert_eq!((summary["status_code"].as_u64(), view(&s).await["complete"].as_bool()), (Some(200), Some(true)));
        assert_eq!(spans(&summary["diagnostics"]).iter().filter(|(p, ..)| p == "verifier_tcp_connect").count(), 2);
    }

    /// A `serve` hop's input for `url` through `proxy`, with `token` if given.
    fn daemon_input(verifier: std::net::SocketAddr, proxy: u16, hop: u32, url: &str, token: Option<&str>) -> Value {
        let mut input = json!({
            "verifier": verifier.to_string(), "plaintext_fixture": true, "hop": hop,
            "url": url, "ip": "93.184.215.14", "port": 443, "proxy": {"host": "127.0.0.1", "port": proxy},
            "payload": payload("https://example.com/", 5), "timeout_ms": 20_000
        });
        if let Some(token) = token {
            input["token"] = token.into();
        }
        input
    }

    /// The phases of a reply's diagnostics.
    fn phases(reply: &Value) -> Vec<String> {
        let diagnostics = if reply["type"] == "summary" { &reply["summary"]["diagnostics"] } else { &reply["diagnostics"] };
        spans(diagnostics).into_iter().map(|(phase, ..)| phase).collect()
    }

    async fn until_waiting(s: &Shared, connections: u64) {
        for _ in 0..500 {
            if capacity_view(s).await["pre_token"]["connections"].as_u64() == Some(connections) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the verifier never had {connections} waiting connections");
    }

    #[tokio::test]
    async fn the_daemon_runs_a_hop_on_a_warm_connection_and_presents_its_token_only_once_given() {
        use crate::serve::tests::Daemon;
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let (proxy, tunnels) = counted_tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut daemon = Daemon::start().await;
        daemon.send(json!({"type": "pool", "size": 2, "verifier": verifier.to_string(), "verifier_ca_file": null, "plaintext_fixture": true})).await;
        until_waiting(&s, 2).await;
        // Started before the accept: a warm connection is taken, and the pool is refilled.
        daemon.send(json!({"type": "hop", "id": "h1", "job": "j1", "input": daemon_input(verifier, proxy, 0, "https://example.com/", None)})).await;
        until_waiting(&s, 3).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!((tunnels.load(Ordering::SeqCst), tokens(&s), view(&s).await["remaining_sessions"].as_u64()), (0, 1, Some(6)));
        assert!(origin.seen.lock().unwrap().is_none());
        daemon.send(json!({"type": "token", "id": "h1", "token": token})).await;
        let (reply, presenting) = daemon.result("h1").await;
        assert!(presenting, "{reply}");
        assert_eq!((reply["type"].as_str(), reply["summary"]["status"].as_str(), reply["summary"]["final"].as_bool()), (Some("summary"), Some("proof_sent"), Some(true)));
        let phases = phases(&reply);
        assert!(phases.contains(&"pool_checkout_warm".into()) && phases.contains(&"predial_wait".into()), "{phases:?}");
        assert!(!phases.contains(&"verifier_tcp_connect".into()) && !phases.contains(&"pool_checkout_cold".into()), "{phases:?}");
        assert_eq!((tunnels.load(Ordering::SeqCst), view(&s).await["complete"].as_bool()), (1, Some(true)));
        // A hop's traffic counts only what it used of the connection.
        assert!(reply["summary"]["verifier_sent_bytes"].as_u64().unwrap() > 64);
        // The verifier kept the connection; the pool keeps two.
        until_waiting(&s, 2).await;
        assert!(daemon.close().await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn redirect_hops_reuse_the_connection_their_previous_hop_left() {
        use crate::serve::tests::Daemon;
        let origin = web_origin(
            routes(&[("example.com/", b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.example.com/next\r\nContent-Length: 0\r\n\r\n", End::Wait), ("www.example.com/next", PAGE, End::Wait)]),
            false,
        )
        .await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let (proxy, _) = counted_tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut daemon = Daemon::start().await;
        // No warm pool: hop 0 dials.
        daemon.send(json!({"type": "pool", "size": 0, "verifier": verifier.to_string(), "verifier_ca_file": null, "plaintext_fixture": true})).await;
        daemon.send(json!({"type": "hop", "id": "h0", "input": daemon_input(verifier, proxy, 0, "https://example.com/", Some(&token))})).await;
        let (reply, presenting) = daemon.result("h0").await;
        assert!(presenting);
        assert_eq!((reply["summary"]["final"].as_bool(), reply["summary"]["next_url"].as_str()), (Some(false), Some("https://www.example.com/next")));
        assert!(phases(&reply).contains(&"pool_checkout_cold".into()) && phases(&reply).contains(&"verifier_tcp_connect".into()));
        // The verifier kept the connection for the job's next hop, which takes it:
        // the hops share their token, which groups them.
        daemon.send(json!({"type": "hop", "id": "h1", "input": daemon_input(verifier, proxy, 1, "https://www.example.com/next", Some(&token))})).await;
        let (reply, _) = daemon.result("h1").await;
        assert_eq!((reply["summary"]["final"].as_bool(), reply["summary"]["status_code"].as_u64()), (Some(true), Some(200)));
        assert!(phases(&reply).contains(&"pool_checkout_warm".into()) && !phases(&reply).contains(&"verifier_tcp_connect".into()), "{:?}", phases(&reply));
        assert_eq!((view(&s).await["complete"].as_bool(), view(&s).await["hops"].as_array().map(Vec::len)), (Some(true), Some(2)));
        assert_eq!(stored(&s).await, &PAGE[PAGE.len() - 20..]);
    }

    #[tokio::test]
    async fn a_cancelled_or_unsent_hop_sends_no_token_and_returns_its_connection() {
        use crate::serve::tests::Daemon;
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let (proxy, tunnels) = counted_tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut daemon = Daemon::start().await;
        daemon.send(json!({"type": "pool", "size": 1, "verifier": verifier.to_string(), "verifier_ca_file": null, "plaintext_fixture": true})).await;
        until_waiting(&s, 1).await;
        // The accept failed: cancelled, nothing presented, no target, the connection back in the pool.
        daemon.send(json!({"type": "hop", "id": "h1", "input": daemon_input(verifier, proxy, 0, "https://example.com/", None)})).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        daemon.send(json!({"type": "cancel", "id": "h1"})).await;
        let (reply, presenting) = daemon.result("h1").await;
        assert_eq!((reply["type"].as_str(), presenting), (Some("cancelled"), false));
        assert!(phases(&reply).contains(&"predial_wait".into()));
        assert_eq!((tunnels.load(Ordering::SeqCst), tokens(&s), view(&s).await["remaining_sessions"].as_u64()), (0, 1, Some(6)));
        // A token after the cancel changes nothing.
        daemon.send(json!({"type": "token", "id": "h1", "token": token})).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!((tunnels.load(Ordering::SeqCst), tokens(&s)), (0, 1));
        until_waiting(&s, 1).await;
        // A target that cannot be reached fails the hop before its token: still unsent.
        let mut input = daemon_input(verifier, proxy, 0, "https://example.com/", Some(&token));
        input["proxy"]["port"] = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port().into();
        daemon.send(json!({"type": "hop", "id": "h2", "input": input})).await;
        let (reply, presenting) = daemon.result("h2").await;
        assert_eq!((reply["type"].as_str(), reply["class"].as_str(), reply["presented"].as_bool(), presenting), (Some("error"), Some("proxy_failed"), Some(false), false));
        assert_eq!((tokens(&s), view(&s).await["remaining_sessions"].as_u64()), (1, Some(6)));
        // Then the hop runs, on the connection the others gave back.
        daemon.send(json!({"type": "hop", "id": "h3", "input": daemon_input(verifier, proxy, 0, "https://example.com/", Some(&token))})).await;
        let (reply, presenting) = daemon.result("h3").await;
        assert!(presenting && reply["type"] == "summary", "{reply}");
        assert!(phases(&reply).contains(&"pool_checkout_warm".into()), "{:?}", phases(&reply));
    }

    #[tokio::test]
    async fn a_warm_connection_the_verifier_closed_is_replaced_before_the_token() {
        use crate::serve::tests::Daemon;
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        // The verifier drops waiting connections after 300 ms, PING or not.
        let s = waits(origin.roots.clone(), Duration::from_millis(300), Duration::from_millis(300));
        let verifier = serve_verifier(&s).await;
        let (proxy, _) = counted_tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut daemon = Daemon::start().await;
        daemon.send(json!({"type": "pool", "size": 1, "verifier": verifier.to_string(), "verifier_ca_file": null, "plaintext_fixture": true})).await;
        until_waiting(&s, 1).await;
        tokio::time::sleep(Duration::from_millis(600)).await;
        daemon.send(json!({"type": "hop", "id": "h1", "input": daemon_input(verifier, proxy, 0, "https://example.com/", Some(&token))})).await;
        let (reply, presenting) = daemon.result("h1").await;
        assert!(presenting && reply["type"] == "summary", "{reply}");
        assert!(phases(&reply).contains(&"verifier_tcp_connect".into()), "{:?}", phases(&reply));
        assert_eq!(view(&s).await["complete"], true);
    }

    #[tokio::test]
    async fn a_hop_whose_verifier_dial_fails_fast_dials_again_before_its_token() {
        // A verifier at its cap of waiting connections closes a new one at
        // accept, which fails the TLS handshake at once; here a verifier that
        // is not listening yet fails the dial as fast. Nothing was sent either way.
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let free = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let verifier = free.local_addr().unwrap();
        drop(free);
        let (proxy, _) = counted_tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut input = predial_input(verifier, proxy, 20_000);
        input["predial"] = false.into();
        input["token"] = token.into();
        let hop = tokio::spawn(async move { node::run_web(&serde_json::to_vec(&input).unwrap()).await.map_err(|failure| (failure.class, format!("{:#}", failure.error))) });
        tokio::time::sleep(Duration::from_millis(20)).await;
        tokio::spawn(serve(TcpListener::bind(verifier).await.unwrap(), s.clone(), None));
        let summary = tokio::time::timeout(Duration::from_secs(30), hop).await.unwrap().unwrap().unwrap();
        assert_eq!((summary.status_code, view(&s).await["complete"].as_bool()), (200, Some(true)));
        let dials = serde_json::to_value(&summary.diagnostics).unwrap()["spans"].as_array().unwrap().iter().filter(|span| span["phase"] == "verifier_tcp_connect").count();
        assert!(dials >= 2, "{dials}");
    }

    /// A CONNECT proxy that takes connections and never answers: to a hop it
    /// is a target that never answers its TCP connection.
    async fn silent_proxy() -> u16 {
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = proxy.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((client, _)) = proxy.accept().await {
                held.push(client);
            }
        });
        port
    }

    // Hang mode A (cross-binary e2e, 2026-10-12): a hop held a pre-token
    // verifier connection for 60 s and never answered, because nothing but
    // the hop's whole budget (up to 280 s) bounded its target connect.
    #[tokio::test]
    async fn a_hop_whose_target_never_answers_ends_unsent_within_its_connect_time() {
        use crate::serve::tests::Daemon;
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let (proxy, _) = counted_tunnel(origin.addr).await;
        let silent = silent_proxy().await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut daemon = Daemon::start().await;
        daemon.send(json!({"type": "pool", "size": 1, "verifier": verifier.to_string(), "verifier_ca_file": null, "plaintext_fixture": true})).await;
        until_waiting(&s, 1).await;
        // Pre-dialed on the warm connection; the token comes; the target never answers.
        daemon.send(json!({"type": "hop", "id": "h1", "input": daemon_input(verifier, silent, 0, "https://example.com/", None)})).await;
        daemon.send(json!({"type": "token", "id": "h1", "token": token})).await;
        let started = Instant::now();
        let (reply, presenting) = daemon.result("h1").await;
        // Its budget is 20 s; the connect gives up after 3 attempts of 1 s here (5, 10 and 10 s in production).
        assert!(started.elapsed() < Duration::from_secs(6), "{:?}", started.elapsed());
        assert_eq!((reply["type"].as_str(), reply["class"].as_str(), reply["presented"].as_bool(), presenting), (Some("error"), Some("proxy_failed"), Some(false), false), "{reply}");
        assert!(reply["error"].as_str().unwrap().contains("target connection timed out"), "{reply}");
        // Nothing was spent, and the connection it held went back to the pool.
        assert_eq!((tokens(&s), view(&s).await["remaining_sessions"].as_u64()), (1, Some(6)));
        until_waiting(&s, 1).await;
        // The same token then runs the hop to a target that answers.
        daemon.send(json!({"type": "hop", "id": "h2", "input": daemon_input(verifier, proxy, 0, "https://example.com/", Some(&token))})).await;
        let (reply, presenting) = daemon.result("h2").await;
        assert!(presenting && reply["type"] == "summary", "{reply}");
        assert_eq!(view(&s).await["complete"], true);
    }

    #[tokio::test]
    async fn a_hop_with_its_token_whose_target_never_answers_ends_unsent_too() {
        use crate::serve::tests::Daemon;
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let silent = silent_proxy().await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut daemon = Daemon::start().await;
        daemon.send(json!({"type": "pool", "size": 0, "verifier": verifier.to_string(), "verifier_ca_file": null, "plaintext_fixture": true})).await;
        let started = Instant::now();
        daemon.send(json!({"type": "hop", "id": "h1", "input": daemon_input(verifier, silent, 0, "https://example.com/", Some(&token))})).await;
        let (reply, presenting) = daemon.result("h1").await;
        assert!(started.elapsed() < Duration::from_secs(6), "{:?}", started.elapsed());
        assert_eq!((reply["type"].as_str(), reply["class"].as_str(), reply["presented"].as_bool(), presenting), (Some("error"), Some("proxy_failed"), Some(false), false), "{reply}");
        // Its cold dial is closed, not left waiting.
        until_waiting(&s, 0).await;
        assert_eq!(tokens(&s), 1);
    }

    #[tokio::test]
    async fn a_hop_whose_token_never_comes_ends_at_its_deadline_and_frees_its_connection() {
        use crate::serve::tests::Daemon;
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let (proxy, tunnels) = counted_tunnel(origin.addr).await;
        register(&s, payload("https://example.com/", 5)).await;
        let mut daemon = Daemon::start().await;
        daemon.send(json!({"type": "pool", "size": 0, "verifier": verifier.to_string(), "verifier_ca_file": null, "plaintext_fixture": true})).await;
        let mut input = daemon_input(verifier, proxy, 0, "https://example.com/", None);
        input["timeout_ms"] = 1500.into();
        let started = Instant::now();
        daemon.send(json!({"type": "hop", "id": "h1", "input": input})).await;
        until_waiting(&s, 1).await;
        let (reply, presenting) = daemon.result("h1").await;
        assert!((Duration::from_millis(1400)..Duration::from_secs(4)).contains(&started.elapsed()), "{:?}", started.elapsed());
        assert_eq!((reply["type"].as_str(), reply["presented"].as_bool(), presenting), (Some("error"), Some(false), false), "{reply}");
        assert!(reply["error"].as_str().unwrap().contains("no token before the hop deadline"), "{reply}");
        // Nothing was sent, no target reached, and the verifier no longer holds its connection.
        until_waiting(&s, 0).await;
        assert_eq!((tunnels.load(Ordering::SeqCst), tokens(&s)), (0, 1));
    }

    #[tokio::test]
    async fn every_hop_ends_in_a_reply_even_one_that_panics_or_stalls() {
        use crate::serve::tests::Daemon;
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let proxy = tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut daemon = Daemon::start().await;
        daemon.send(json!({"type": "pool", "size": 0, "verifier": verifier.to_string(), "verifier_ca_file": null, "plaintext_fixture": true})).await;
        // A hop task that panics is answered, not left silent.
        daemon.send(json!({"type": "hop", "id": "panics1", "input": daemon_input(verifier, proxy, 0, "https://example.com/", Some(&token))})).await;
        let (reply, presenting) = daemon.result("panics1").await;
        assert_eq!((reply["type"].as_str(), reply["class"].as_str(), reply["presented"].as_bool(), presenting), (Some("error"), Some("fetch_failed"), Some(false), false), "{reply}");
        // A hop stuck where no step of its own bounds it is answered a second after its deadline.
        let mut input = daemon_input(verifier, proxy, 0, "https://example.com/", Some(&token));
        input["timeout_ms"] = 1000.into();
        let started = Instant::now();
        daemon.send(json!({"type": "hop", "id": "stalls1", "input": input})).await;
        let (reply, _) = daemon.result("stalls1").await;
        assert!((Duration::from_secs(2)..Duration::from_secs(4)).contains(&started.elapsed()), "{:?}", started.elapsed());
        assert!(reply["type"] == "error" && reply["error"].as_str().unwrap().contains("overran its deadline"), "{reply}");
        // Neither spent the token, and the daemon goes on serving.
        daemon.send(json!({"type": "hop", "id": "h1", "input": daemon_input(verifier, proxy, 0, "https://example.com/", Some(&token))})).await;
        let (reply, presenting) = daemon.result("h1").await;
        assert!(presenting && reply["type"] == "summary", "{reply}");
    }

    // Hang mode B: the verifier rejects a page that is too large while the
    // target is still sending it; the daemon must answer with that rejection
    // at once, not after the page, and nothing of the hop may linger.
    #[tokio::test]
    async fn a_hop_the_verifier_rejects_mid_stream_answers_at_once() {
        use crate::serve::tests::Daemon;
        let huge: Respond = Arc::new(|_: &[u8]| {
            let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 104857600\r\n\r\n".to_vec();
            response.resize(response.len() + (16 << 20), b'x');
            (response, End::Wait)
        });
        let origin = web_origin(huge, false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let proxy = tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let mut daemon = Daemon::start().await;
        daemon.send(json!({"type": "pool", "size": 1, "verifier": verifier.to_string(), "verifier_ca_file": null, "plaintext_fixture": true})).await;
        until_waiting(&s, 1).await;
        daemon.send(json!({"type": "hop", "id": "h1", "input": daemon_input(verifier, proxy, 0, "https://example.com/", None)})).await;
        daemon.send(json!({"type": "token", "id": "h1", "token": token})).await;
        let started = Instant::now();
        let (reply, presenting) = daemon.result("h1").await;
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(presenting, "{reply}");
        assert_eq!((reply["type"].as_str(), reply["class"].as_str(), reply["presented"].as_bool()), (Some("error"), Some("page_too_large"), Some(true)), "{reply}");
        assert_eq!(view(&s).await["rejections"], json!(["page_too_large"]));
        // The hop is gone: the pool is refilled to its one connection and the
        // next hop's request is answered.
        until_waiting(&s, 1).await;
        daemon.send(json!({"type": "token", "id": "h1", "token": token})).await;
        daemon.send(json!({"type": "hop", "id": "h2", "input": daemon_input(verifier, proxy, 0, "https://example.com/", Some(&token))})).await;
        let (reply, _) = daemon.result("h2").await;
        assert_eq!(reply["type"], "error", "{reply}");
    }

    async fn capacity_view(s: &Shared) -> Value {
        let (_, Json(view)) = capacity(State(s.clone()), headers()).await;
        view
    }

    #[tokio::test]
    async fn a_stored_body_is_read_whole_or_by_range_and_released_once() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let dir = Temp::new();
        let s = shared(origin.roots.clone(), Some(&dir.0));
        let token = register(&s, payload("https://example.com/", 5)).await;
        hop(&s, &origin, &token, 0, "https://example.com/", None).await.1.unwrap();
        let body = &PAGE[PAGE.len() - 20..];
        let path = s.1.lock().unwrap().body_path(&job_key("synthetic", "1"));
        assert!(path.starts_with(&dir.0) && path.exists());
        let (code, h, read) = read_body(&s, "1", None).await;
        assert_eq!((code, read.as_slice()), (StatusCode::OK, body));
        assert_eq!((h["content-length"].to_str().unwrap(), h["accept-ranges"].to_str().unwrap(), h["content-type"].to_str().unwrap()), ("20", "bytes", "application/octet-stream"));
        let (code, h, read) = read_body(&s, "1", Some("bytes=0-9")).await;
        assert_eq!((code, read.as_slice(), h["content-range"].to_str().unwrap(), h["content-length"].to_str().unwrap()), (StatusCode::PARTIAL_CONTENT, &body[..10], "bytes 0-9/20", "10"));
        assert_eq!(h["x-body-sha256"].to_str().unwrap(), verifier_store::hash(body));
        let (code, _, read) = read_body(&s, "1", Some("bytes=15-")).await;
        assert_eq!((code, read.as_slice()), (StatusCode::PARTIAL_CONTENT, &body[15..]));
        let (code, h, _) = read_body(&s, "1", Some("bytes=12-999")).await;
        assert_eq!((code, h["content-range"].to_str().unwrap()), (StatusCode::PARTIAL_CONTENT, "bytes 12-19/20"));
        for bad in ["bytes=20-30", "bytes=5-2", "bytes=0-1,3-4", "items=0-1", "bytes=-5", "bytes=a-b"] {
            let (code, h, _) = read_body(&s, "1", Some(bad)).await;
            assert_eq!((code, h["content-range"].to_str().unwrap()), (StatusCode::RANGE_NOT_SATISFIABLE, "bytes */20"), "{bad}");
        }
        // Key auth, and receipts that hold no body.
        let response = get_body(State(s.clone()), HeaderMap::new(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = delete_body(State(s.clone()), HeaderMap::new(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(read_body(&s, "2", None).await.0, StatusCode::NOT_FOUND);
        let c = capacity_view(&s).await;
        assert_eq!((c["storage"]["body_files"].as_u64(), c["storage"]["body_bytes"].as_u64(), c["web"]["body_bytes"].as_u64()), (Some(1), Some(20), Some(20)));
        // The body survives a restart.
        drop(s);
        let s = shared(origin.roots.clone(), Some(&dir.0));
        assert_eq!(stored(&s).await, body);
        // Released once; later deletes are no-ops and reads are gone, also after a restart.
        let response = delete_body(State(s.clone()), headers(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        for _ in 0..50 {
            if !path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!path.exists());
        assert_eq!(read_body(&s, "1", None).await.0, StatusCode::GONE);
        assert_eq!(delete_body(State(s.clone()), headers(), Path(("synthetic".into(), "1".into()))).await.status(), StatusCode::NO_CONTENT);
        assert!(view(&s).await["body_released_at_ms"].as_u64().is_some());
        let c = capacity_view(&s).await;
        assert_eq!((c["storage"]["body_files"].as_u64(), c["web"]["body_bytes"].as_u64()), (Some(0), Some(0)));
        drop(s);
        let s = shared(origin.roots.clone(), Some(&dir.0));
        assert_eq!(read_body(&s, "1", None).await.0, StatusCode::GONE);
        // Purged with retention: gone, not unknown, while this process runs.
        {
            let mut sessions = s.1.lock().unwrap();
            let key = job_key("synthetic", "1");
            sessions.by_job.get_mut(&key).unwrap().expires_ms = now_ms() - verifier_store::WEB_RETENTION_MS - 1;
            sessions.commit(&key).unwrap();
            sessions.purge().unwrap();
        }
        assert_eq!(read_body(&s, "1", None).await.0, StatusCode::GONE);
        assert_eq!(delete_body(State(s.clone()), headers(), Path(("synthetic".into(), "1".into()))).await.status(), StatusCode::NO_CONTENT);
        assert_eq!(delete_body(State(s.clone()), headers(), Path(("synthetic".into(), "9".into()))).await.status(), StatusCode::NOT_FOUND);
        // A redirect-only receipt never stored a body.
        let origin = web_origin(routes(&[("example.com/", b"HTTP/1.1 301 Moved\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n", End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5)).await;
        hop(&s, &origin, &token, 0, "https://example.com/", None).await.0.unwrap();
        let response = delete_body(State(s.clone()), headers(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn relay_web_reports_page_too_large_and_verifier_busy() {
        const TOO_LARGE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 67108865\r\n\r\n";
        let origin = web_origin(routes(&[("example.com/", TOO_LARGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let proxy = tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let (class, error) = relay_web(verifier, proxy, &token).await.err().unwrap();
        assert_eq!(class, "page_too_large", "{error}");
        assert!(!error.contains(node::MISUSE) && !error.contains("example.com"), "{error}");
        let view = view(&s).await;
        assert_eq!((view["rejections"].clone(), view["rejection"]["declared_bytes"].as_u64()), (json!(["page_too_large"]), Some(67_108_865)));

        // At the web session limit the node is told so, and nothing is spent.
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let verifier = serve_verifier(&s).await;
        let proxy = tunnel(origin.addr).await;
        let token = register(&s, payload("https://example.com/", 5)).await;
        let held = s.0.web_slots.clone().try_acquire_many_owned(48).unwrap();
        for _ in 0..2 {
            let (class, error) = relay_web(verifier, proxy, &token).await.err().unwrap();
            assert_eq!(class, "verifier_busy", "{error}");
        }
        let view = super::web_tests::view(&s).await;
        assert_eq!((view["remaining_sessions"].as_u64(), view["rejections"].clone(), tokens(&s)), (Some(6), json!([]), 1));
        assert!(origin.seen.lock().unwrap().is_none());
        let c = capacity_view(&s).await;
        assert_eq!((c["web"]["busy_refusals"].as_u64(), c["web"]["active_sessions"].as_u64(), c["web"]["concurrency"].as_u64()), (Some(2), Some(48), Some(48)));
        drop(held);
        let summary = relay_web(verifier, proxy, &token).await.unwrap();
        assert_eq!((summary["status_code"].as_u64(), summary["final"].as_bool()), (Some(200), Some(true)));
        assert_eq!(stored(&s).await, &PAGE[PAGE.len() - 20..]);
    }

    #[test]
    fn the_hop_clock_holds_each_timing_rule() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let clock = || {
            let mut c = HopClock::new(Timing::WEB, at(280_000));
            c.request_sent(t0);
            c
        };
        // Runs `bytes(ms)` arrivals at every 100 ms tick from `first` (the
        // first response byte) and checks the clock at every tick and wake;
        // returns when and why it ended, if it did by `until`.
        let run = |first: u64, until: u64, bytes: &dyn Fn(u64) -> usize| -> Option<(u64, &'static str)> {
            let mut c = clock();
            let mut ms = 0;
            while ms <= until {
                if ms >= first {
                    if ms == first {
                        c.first_byte(at(ms));
                    }
                    let n = bytes(ms);
                    if n > 0 {
                        c.target(at(ms), n);
                    }
                }
                if let Err(rule) = c.check(at(ms)) {
                    return Some((ms, rule.0));
                }
                ms += 100;
            }
            None
        };
        // A 40 s hop at a steady 100 KiB/s.
        assert_eq!(run(1000, 41_000, &|_| 10 << 10), None);
        // 25 s to the first byte, then steady data: fine.
        assert_eq!(run(25_000, 70_000, &|_| 10 << 10), None);
        // 61 s to the first byte: ended at 60 s.
        assert_eq!(run(61_000, 70_000, &|_| 10 << 10), Some((60_000, "ttfb_timeout")));
        // Silence for 20 s after the first byte.
        assert_eq!(run(1000, 60_000, &|ms| if ms < 5000 { 10 << 10 } else { 0 }), Some((24_900, "idle_timeout")));
        // One byte every 19 s never trips idle, and the floor ends it within ~35 s of the first byte.
        let trickle = run(1000, 120_000, &|ms| usize::from((ms - 1000) % 19_000 == 0));
        assert_eq!(trickle.map(|(_, rule)| rule), Some("throughput_floor"));
        assert!(trickle.unwrap().0 <= 1000 + 35_000, "{trickle:?}");
        // A page that finishes inside 30 s is never held to the floor.
        assert_eq!(run(1000, 30_900, &|ms| usize::from(ms % 10_000 == 0)), None);
        // The hop limit, and the wake times the session sleeps until.
        let mut c = clock();
        assert_eq!(c.wake(), at(60_000));
        c.first_byte(at(500));
        assert_eq!(c.wake(), at(20_500));
        assert_eq!(c.check(at(280_000)), Err(TimedOut("hop_limit")));
        assert_eq!(Timing::WEB.floor_bytes(), 1_966_080);
    }

    /// A verifier for `roots` whose hops run on short, test-sized timing rules.
    fn hurried(roots: rustls::RootCertStore) -> Shared {
        let mut config = Config::new(KEY.into(), "127.0.0.1:1".into(), Duration::from_secs(20), verifier_store::Limits::default(), 64, 48, crate::relay::verifier::tls_config(roots).unwrap());
        config.web_timing = Timing { ttfb: Duration::from_millis(400), idle: Duration::from_millis(300), floor_after: Duration::from_secs(30), floor_window: Duration::from_secs(30), floor_rate: 1 };
        Arc::new((config, Mutex::new(Sessions::default())))
    }

    #[tokio::test]
    async fn a_slow_origin_is_ended_inside_the_session_and_the_node_learns_why() {
        let silent: Respond = Arc::new(|_: &[u8]| (Vec::new(), End::Wait));
        let stalled: Respond = Arc::new(|_: &[u8]| (b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nfirst".to_vec(), End::Wait));
        for (case, respond, entity) in [("ttfb", silent, 0), ("idle", stalled, 5)] {
            let origin = web_origin(respond, false).await;
            let s = hurried(origin.roots.clone());
            let token = register(&s, payload("https://example.com/", 5)).await;
            let started = Instant::now();
            let (reported, verifier) = hop(&s, &origin, &token, 0, "https://example.com/", None).await;
            assert!(started.elapsed() < Duration::from_secs(5), "{case}");
            verifier.unwrap();
            // The record was opened first, so this is a failure the node can report, not misuse.
            let error = reported.err().unwrap();
            assert_eq!(error.downcast_ref::<node::Refused>(), Some(&node::Refused("session_timeout")), "{case}: {error:#}");
            assert!(!format!("{error:#}").contains(node::MISUSE), "{case}");
            let view = view(&s).await;
            assert_eq!((view["rejections"].clone(), view["rejection"]["entity_bytes"].as_u64()), (json!(["session_timeout"]), Some(entity)), "{case}");
        }
    }

    /// As `shared` without state, with room for `per_address` waiting
    /// connections from 127.0.0.1, where every test connection comes from.
    fn shared_local(roots: rustls::RootCertStore, per_address: usize) -> Shared {
        let mut config = Config::new(KEY.into(), "127.0.0.1:1".into(), Duration::from_secs(20), verifier_store::Limits::default(), 64, 48, crate::relay::verifier::tls_config(roots).unwrap());
        config.pre_token = Arc::new(PreToken::new(PRE_TOKEN_LIMIT, per_address));
        Arc::new((config, Mutex::new(Sessions::default())))
    }

    #[tokio::test]
    async fn web_sessions_beyond_their_slots_are_refused_and_x_still_starts() {
        let s = shared_local(rustls::RootCertStore::empty(), 128);
        let verifier = serve_verifier(&s).await;
        let expires = now_ms() + 60_000;
        let mut tokens = Vec::new();
        for i in 0..64 {
            let (code, Json(created)) = create(State(s.clone()), headers(), Json(CreateRequest { attempt: format!("w{i}"), ..job(payload("https://example.com/", 5), expires) })).await;
            assert_eq!(code, StatusCode::CREATED);
            tokens.push(created["token"].as_str().unwrap().to_owned());
        }
        // 64 web sessions that present their token and hello, then stall.
        let mut open = Vec::new();
        for token in &tokens {
            let mut socket = TcpStream::connect(verifier).await.unwrap();
            socket.write_all(format!("{token}\n").as_bytes()).await.unwrap();
            crate::relay::wire::send(&mut socket, crate::relay::wire::HELLO, br#"{"version":1,"transfers":0,"transport":2}"#).await.unwrap();
            open.push(socket);
        }
        // 16 of them are turned away at once with FAILED verifier_busy; the
        // node closes those, as relay-web does.
        let mut stalled = Vec::new();
        for mut socket in open {
            let first = tokio::time::timeout(Duration::from_secs(5), crate::relay::wire::FrameReader::new(&mut socket).recv()).await.unwrap().unwrap();
            if first.0 == crate::relay::wire::FAILED {
                assert_eq!(first.1, br#"{"reason":"verifier_busy"}"#);
            } else {
                assert_eq!(first.0, crate::relay::wire::TO_SERVER);
                stalled.push(socket);
            }
        }
        assert_eq!(stalled.len(), 48);
        let c = capacity_view(&s).await;
        assert_eq!((c["web"]["active_sessions"].as_u64(), c["web"]["busy_refusals"].as_u64()), (Some(48), Some(16)));
        // An X session still gets a connection slot and starts.
        let x = json!({"type":"x.read","max_attempts":1,"exchanges":[{"operation":"UserByScreenName","query_id":"qid_1","variables":{"screen_name":"jack"},"features":{}}],"proof_mode":"relay","proof_policy":"x-relay-v1"});
        let (code, Json(created)) = create(State(s.clone()), headers(), Json(CreateRequest { attempt: "x".into(), fence: None, expires_at_ms: None, ttl_seconds: Some(60), ..job(x, 0) })).await;
        assert_eq!(code, StatusCode::CREATED, "{created}");
        let mut socket = TcpStream::connect(verifier).await.unwrap();
        socket.write_all(format!("{}\n", created["token"].as_str().unwrap()).as_bytes()).await.unwrap();
        let mut started = false;
        for _ in 0..500 {
            if s.1.lock().unwrap().by_job.get(&job_key("synthetic", "x")).is_some_and(|e| e.in_flight == 1) {
                started = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(started, "X session did not start");
        drop(stalled);
    }

    #[tokio::test]
    async fn a_slow_fsync_stalls_neither_capacity_nor_x_registrations() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let dir = Temp::new();
        let s = shared(origin.roots.clone(), Some(&dir.0));
        crate::body::SLOW_SYNC.lock().unwrap().push((dir.0.clone(), Duration::from_secs(2)));
        let token = register(&s, payload("https://example.com/", 5)).await;
        let started = Instant::now();
        let running = {
            let (s, token, addr) = (s.clone(), token.clone(), origin.addr);
            tokio::spawn(async move {
                let (mut node_end, verifier_end) = tokio::io::duplex(1 << 20);
                let session = tokio::spawn(handle(s.clone(), Box::new(verifier_end), waiting(&s), LOCAL));
                node_end.write_all(format!("{token}\n").as_bytes()).await.unwrap();
                let tcp = TcpStream::connect(addr).await.unwrap();
                let raw = webpolicy::request("https://example.com/", &web_headers());
                let result = node::web_session(node_end, tcp, &raw, "example.com", 0, "https://example.com/", &Trace::new()).await;
                (result.map(|o| o.is_final), session.await.unwrap().is_ok())
            })
        };
        // While the body's fsyncs sleep, the lock is free.
        tokio::time::sleep(Duration::from_millis(500)).await;
        for _ in 0..2 {
            let asked = Instant::now();
            assert_eq!(capacity_view(&s).await["healthy"], true);
            let x = CreateRequest {
                attempt: format!("x{}", rand::random::<u32>()),
                ..job(json!({"type":"x.read","max_attempts":1,"exchanges":[{"operation":"UserByScreenName","query_id":"qid_1","variables":{"screen_name":"jack"},"features":{}}],"proof_mode":"relay","proof_policy":"x-relay-v1"}), now_ms() + 60_000)
            };
            assert_eq!(create(State(s.clone()), headers(), Json(x)).await.0, StatusCode::CREATED);
            assert!(asked.elapsed() < Duration::from_millis(400), "{:?}", asked.elapsed());
        }
        let (result, verifier) = running.await.unwrap();
        crate::body::SLOW_SYNC.lock().unwrap().retain(|(d, _)| d != &dir.0);
        assert!(verifier && result.unwrap());
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert_eq!(stored(&s).await, &PAGE[PAGE.len() - 20..]);
    }

    /// api/fixtures/verifier: the contract's receipts, capacity and frames are what the code reads and writes.
    #[tokio::test]
    async fn contract_fixtures_match_the_code() {
        let fixture = |name: &str| -> Value {
            let raw = fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../api/fixtures/verifier").join(name)).unwrap();
            serde_json::from_slice(&raw).unwrap()
        };
        let registration = fixture("register-web.json");
        let request: CreateRequest = serde_json::from_value(registration.clone()).unwrap();
        let (kind, _) = kind(&request.payload, true).unwrap();
        let binding = ["durable", "job_id", "attempt", "fence", "expires_at_ms", "request_sha256"];
        for name in ["session-web-complete.json", "session-web-released.json", "session-web-rejected.json"] {
            let view = fixture(name);
            assert_eq!(view["request_sha256"], verifier_store::hash(&serde_json::to_vec(&request.payload).unwrap()), "{name}");
            assert_eq!((view["job_id"].clone(), view["attempt"].clone(), view["fence"].clone(), view["expires_at_ms"].clone()), (registration["job_id"].clone(), registration["attempt"].clone(), registration["fence"].clone(), registration["expires_at_ms"].clone()));
            let mut status = view.clone();
            binding.iter().for_each(|k| drop(status.as_object_mut().unwrap().remove(*k)));
            let parsed: Status = serde_json::from_value(status.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
            validate_receipt(&kind, &parsed, 0).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(serde_json::to_value(&parsed).unwrap(), status, "{name}");
        }
        // The body the complete receipt names.
        let complete = fixture("session-web-complete.json");
        let body = fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../api/fixtures/verifier/body-1.bin")).unwrap();
        let last = complete["hops"].as_array().unwrap().last().unwrap().clone();
        assert_eq!((last["body_sha256"].as_str().unwrap(), last["body_bytes"].as_u64().unwrap()), (verifier_store::hash(&body).as_str(), body.len() as u64));
        // A real receipt and capacity have exactly the fixtures' fields.
        fn keys(v: &Value) -> Vec<String> {
            let mut out = Vec::new();
            if let Some(map) = v.as_object() {
                for (k, child) in map {
                    out.push(k.clone());
                    out.extend(keys(child).into_iter().map(|c| format!("{k}.{c}")));
                }
            }
            out.sort();
            out
        }
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let dir = Temp::new();
        let s = shared(origin.roots.clone(), Some(&dir.0));
        let token = register(&s, payload("https://example.com/", 5)).await;
        hop(&s, &origin, &token, 0, "https://example.com/", None).await.0.unwrap();
        let real = view(&s).await;
        let mut expected = complete.clone();
        expected["hops"] = complete["hops"][1].clone();
        let mut got = real.clone();
        got["hops"] = real["hops"][0].clone();
        assert_eq!(keys(&got), keys(&expected));
        assert_eq!(keys(&capacity_view(&s).await), keys(&fixture("capacity.json")));
        // The FAILED payloads.
        for (name, reason) in [("relay-failed-busy.json", "verifier_busy"), ("relay-failed-page-too-large.json", "page_too_large")] {
            assert_eq!(fixture(name), json!({"reason": reason}));
        }
        // Transport 2 on the wire: a web hello, and DONE for a kept connection.
        assert_eq!(serde_json::from_slice::<Value>(&node::hello(0)).unwrap(), fixture("relay-hello.json"));
        assert_eq!(serde_json::from_slice::<Value>(crate::relay::verifier::DONE_KEEP).unwrap(), fixture("relay-done-keep.json"));
        // GET /v1/events: the complete hop above is the feed's first event.
        let (code, feed) = read_events(&s, Some("0"), Some("1"), None).await;
        assert_eq!(code, StatusCode::OK);
        let sample = fixture("events.json");
        assert_eq!(keys(&feed["events"][0]), keys(&sample["events"][0]));
        let mut shape = feed.clone();
        shape["events"] = json!([]);
        let mut expected = sample.clone();
        expected["events"] = json!([]);
        assert_eq!(keys(&shape), keys(&expected));
        assert!(sample["events"].as_array().unwrap().iter().all(|e| e["kind"] == "complete" || e["kind"] == "rejected"));
        assert_eq!((feed["events"][0]["kind"].as_str(), feed["events"][0]["attempt"].as_str()), (Some("complete"), Some("1")));
        let (_, reset) = read_events(&s, Some("9"), Some("1"), None).await;
        assert_eq!(keys(&reset), keys(&fixture("events-reset.json")));
        assert_eq!((reset["reset"].as_bool(), reset["events"].as_array().map(Vec::len)), (Some(true), Some(0)));
        // DELETE /v1/sessions/{job}/{attempt}: 204 has no body; the refusals are these.
        assert_eq!(revoke_attempt(&s, "1").await, (StatusCode::CONFLICT, fixture("revoke-complete.json")));
        assert_eq!(revoke_attempt(&s, "9").await, (StatusCode::NOT_FOUND, fixture("revoke-unknown.json")));
        let running = CreateRequest { attempt: "2".into(), ..job(payload("https://example.com/", 5), now_ms() + 60_000) };
        assert_eq!(create(State(s.clone()), headers(), Json(running)).await.0, StatusCode::CREATED);
        s.1.lock().unwrap().by_job.get_mut(&job_key("synthetic", "2")).unwrap().in_flight = 1;
        assert_eq!(revoke_attempt(&s, "2").await, (StatusCode::CONFLICT, fixture("revoke-in-flight.json")));
        s.1.lock().unwrap().by_job.get_mut(&job_key("synthetic", "2")).unwrap().in_flight = 0;
        assert_eq!(revoke_attempt(&s, "2").await, (StatusCode::NO_CONTENT, Value::Null));
    }
}

type Shared = Arc<(Config, Mutex<Sessions>)>;

fn bounded_env(name: &str, default: u64, min: u64, max: u64) -> Result<u64> {
    let value = match env::var(name) { Ok(raw) => raw.parse::<u64>().with_context(|| format!("invalid {name}"))?, Err(env::VarError::NotPresent) => default, Err(_) => bail!("invalid {name}") };
    if !(min..=max).contains(&value) { bail!("invalid {name}"); }
    Ok(value)
}
pub async fn run() -> Result<()> {
    let key = env::var("SCARLETT_VERIFIER_KEY").unwrap_or_default();
    if key.len() < 32 {
        bail!("SCARLETT_VERIFIER_KEY must be at least 32 characters");
    }
    let listen = env::var("SCARLETT_VERIFIER_LISTEN").unwrap_or_else(|_| "0.0.0.0:7047".into());
    let api = env::var("SCARLETT_VERIFIER_API").unwrap_or_else(|_| "127.0.0.1:7070".into());
    let upstream = env::var("UPSTREAM").unwrap_or_else(|_| format!("{}:443", policy::HOST));
    let limit = env::var("SESSION_TIMEOUT_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(300);
    let limits = verifier_store::Limits {
        max_records: bounded_env("SCARLETT_VERIFIER_MAX_RECORDS", 1024, 1, 1_000_000)? as usize,
        max_record_bytes: bounded_env("SCARLETT_VERIFIER_MAX_RECORD_BYTES", 64 << 20, 1 << 20, 64 << 20)?,
        max_total_bytes: bounded_env("SCARLETT_VERIFIER_MAX_TOTAL_BYTES", 256 << 20, 1 << 20, 1 << 40)?,
        max_web_bytes: bounded_env("SCARLETT_VERIFIER_MAX_WEB_BYTES", verifier_store::MAX_WEB_BYTES, verifier_store::WEB_RESERVATION, 1 << 40)?,
    };
    if limits.max_web_bytes + limits.max_record_bytes > limits.max_total_bytes {
        bail!("SCARLETT_VERIFIER_MAX_WEB_BYTES must leave a full receipt (SCARLETT_VERIFIER_MAX_RECORD_BYTES) in SCARLETT_VERIFIER_MAX_TOTAL_BYTES");
    }
    let limits = limits.validate()?;
    let concurrency = bounded_env("SCARLETT_VERIFIER_CONCURRENCY", 64, 1, 256)? as usize;
    let web_concurrency = bounded_env("SCARLETT_VERIFIER_WEB_CONCURRENCY", 48, 1, (256 - X_CODEX_SLOTS) as u64)? as usize;
    if web_concurrency + X_CODEX_SLOTS > concurrency {
        bail!("SCARLETT_VERIFIER_WEB_CONCURRENCY must leave {X_CODEX_SLOTS} of SCARLETT_VERIFIER_CONCURRENCY to X and Codex");
    }
    let sessions = if let Ok(dir) = env::var("SCARLETT_VERIFIER_STATE_DIR") {
        let (store, records) = Store::open_with_limits(std::path::Path::new(&dir), limits)?;
        Sessions::restore(store, records)?
    } else {
        Sessions::default()
    };
    if !api.parse::<std::net::SocketAddr>().is_ok_and(|a| a.ip().is_loopback()) {
        bail!("verifier API must bind loopback");
    }
    let cert = env::var("SCARLETT_VERIFIER_TLS_CERT").ok();
    let private_key = env::var("SCARLETT_VERIFIER_TLS_KEY").ok();
    let plaintext = env::var("SCARLETT_VERIFIER_PLAINTEXT_FIXTURE").as_deref() == Ok("1");
    let acceptor = match (cert, private_key) {
        (Some(cert), Some(key)) if !plaintext => Some(crate::control::acceptor(&cert, &key)?),
        (None, None) if plaintext && listen.parse::<std::net::SocketAddr>().is_ok_and(|a| a.ip().is_loopback()) => None,
        _ => bail!("verifier needs a TLS certificate/key or an explicit loopback plaintext fixture"),
    };
    let pre_token_limit = bounded_env("SCARLETT_VERIFIER_PRE_TOKEN_LIMIT", PRE_TOKEN_LIMIT as u64, 16, 65_536)? as usize;
    let pre_token_per_address = bounded_env("SCARLETT_VERIFIER_PRE_TOKEN_PER_ADDRESS", PRE_TOKEN_PER_ADDRESS as u64, 1, pre_token_limit as u64)? as usize;
    let relay_tls = crate::relay::verifier::tls_config(crate::relay::verifier::mozilla_roots()?)?;
    let mut config = Config::new(key, upstream, Duration::from_secs(limit), limits, concurrency, web_concurrency, relay_tls);
    config.pre_token = Arc::new(PreToken::new(pre_token_limit, pre_token_per_address));
    let shared: Shared = Arc::new((config, Mutex::new(sessions)));
    let cleanup = shared.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let purged = cleanup.1.lock().unwrap().purge();
            match purged {
                Ok(bodies) => unlink_later(bodies),
                Err(_) => eprintln!("verifier state unavailable"),
            }
        }
    });

    let router = Router::new()
        .route("/v1/sessions", post(create))
        .route("/v1/sessions/{job_id}/{attempt}", get(status).delete(revoke))
        .route("/v1/sessions/{job_id}/{attempt}/body", get(get_body).delete(delete_body))
        .route("/v1/capacity", get(capacity))
        .route("/v1/events", get(events))
        .with_state(shared.clone());
    let api_listener = TcpListener::bind(&api).await.with_context(|| format!("binding {api}"))?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(api_listener, router).await {
            eprintln!("verifier API stopped: {e}");
        }
    });

    let listener = TcpListener::bind(&listen).await.with_context(|| format!("binding {listen}"))?;
    println!("verifier: sessions on {listen} ({concurrency}, {web_concurrency} for web; {pre_token_limit} waiting, {pre_token_per_address} per address), API on {api}, upstream {}", shared.0.upstream);
    serve(listener, shared, acceptor).await
}

/// Accepts supplier connections. Each waits for its token among a bounded
/// number of waiting connections, at most `per_address` from one source
/// address; a connection that finds no place is closed at once (counted on
/// `GET /v1/capacity`). A session slot is taken only when the token arrives.
async fn serve(listener: TcpListener, shared: Shared, acceptor: Option<tokio_rustls::TlsAcceptor>) -> Result<()> {
    let mut refusals_noted = None::<Instant>;
    loop {
        let (socket, peer) = listener.accept().await?;
        let Some(waiting) = shared.0.pre_token.take(peer.ip()) else {
            // At most one line per 10 s; GET /v1/capacity counts them all.
            if refusals_noted.is_none_or(|at| at.elapsed() >= Duration::from_secs(10)) {
                refusals_noted = Some(Instant::now());
                let view = shared.0.pre_token.view();
                println!("verifier: refused a waiting connection from {} ({} waiting; refused so far: {} for its address, {} in all)", peer.ip(), view["connections"], view["refused_per_address"], view["refused_global"]);
            }
            continue;
        };
        let _ = socket.set_nodelay(true);
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let socket: crate::control::Socket = if let Some(acceptor) = acceptor {
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket)).await {
                    Ok(Ok(socket)) => Box::new(socket),
                    _ => return,
                }
            } else {
                Box::new(socket)
            };
            if let Err(e) = handle(shared, socket, waiting, peer.ip()).await {
                println!("verifier: session from {peer} ended without a result: {}", loggable(&e));
            }
        });
    }
}

/// Connections waiting for a token: those not yet in a session, and those
/// a transport 2 web session left open for the supplier's next token. They
/// hold none of the `concurrency` session slots, only a place here.
struct PreToken {
    places: Arc<tokio::sync::Semaphore>,
    limit: usize,
    per_address: usize,
    by_address: Mutex<HashMap<IpAddr, usize>>,
    refused_global: AtomicU64,
    refused_per_address: AtomicU64,
}

/// One connection's place among the waiting.
struct Waiting {
    pre_token: Arc<PreToken>,
    address: IpAddr,
    _place: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let mut by_address = self.pre_token.by_address.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = by_address.get_mut(&self.address) {
            *count -= 1;
            if *count == 0 {
                by_address.remove(&self.address);
            }
        }
    }
}

impl PreToken {
    fn new(limit: usize, per_address: usize) -> Self {
        Self { places: Arc::new(tokio::sync::Semaphore::new(limit)), limit, per_address, by_address: Mutex::new(HashMap::new()), refused_global: AtomicU64::new(0), refused_per_address: AtomicU64::new(0) }
    }

    /// The source a per-address count belongs to: an IPv4 address, or the
    /// /64 of an IPv6 address, which one host can fill with addresses.
    fn source(ip: IpAddr) -> IpAddr {
        match ip.to_canonical() {
            IpAddr::V6(v6) => IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & !((1u128 << 64) - 1))),
            v4 => v4,
        }
    }

    /// A place for one more waiting connection from `ip`, if there is one.
    fn take(self: &Arc<Self>, ip: IpAddr) -> Option<Waiting> {
        let Ok(place) = self.places.clone().try_acquire_owned() else {
            self.refused_global.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let address = Self::source(ip);
        let mut by_address = self.by_address.lock().unwrap_or_else(|e| e.into_inner());
        let count = by_address.entry(address).or_insert(0);
        if *count >= self.per_address {
            drop(by_address);
            self.refused_per_address.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        *count += 1;
        Some(Waiting { pre_token: self.clone(), address, _place: place })
    }

    fn view(&self) -> Value {
        serde_json::json!({
            "connections": self.limit - self.places.available_permits(), "limit": self.limit, "per_address_limit": self.per_address,
            "refused_global": self.refused_global.load(Ordering::Relaxed), "refused_per_address": self.refused_per_address.load(Ordering::Relaxed),
        })
    }
}

fn authorized(config: &Config, headers: &HeaderMap) -> bool {
    let given = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    given.len() == config.key.len() && given.bytes().zip(config.key.bytes()).fold(0, |acc, (a, b)| acc | (a ^ b)) == 0
}

fn job_key(job_id: &str, attempt: &str) -> String {
    format!("{job_id}\n{attempt}")
}

/// The attempt half of a receipt key.
fn attempt_of(key: &str) -> &str {
    key.split_once('\n').map_or("", |(_, attempt)| attempt)
}

#[derive(Deserialize)]
struct CreateRequest {
    job_id: String,
    attempt: String,
    payload: Value,
    ttl_seconds: Option<u64>,
    fence: Option<String>,
    expires_at_ms: Option<u64>,
}

async fn create(State(shared): State<Shared>, headers: HeaderMap, Json(request): Json<CreateRequest>) -> (StatusCode, Json<Value>) {
    let (config, sessions) = &*shared;
    if !authorized(config, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "verifier key required"})));
    }
    if !verifier_store::field(&request.job_id)
        || !verifier_store::field(&request.attempt)
        || request.fence.as_ref().is_some_and(|f| !verifier_store::field(f))
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid job or attempt"})));
    }
    let mut sessions = sessions.lock().unwrap();
    if sessions.failed {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"verifier state unavailable"})));
    }
    match sessions.purge() {
        Ok(bodies) => unlink_later(bodies),
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"verifier state unavailable"}))),
    }
    let durable = sessions.store.is_some();
    if durable && (request.fence.is_none() || request.expires_at_ms.is_none()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"durable sessions require a fence and absolute expiry"})));
    }
    let validated = kind(&request.payload, durable);
    let (kind, initial) = match validated {
        Ok(v) => v,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()})));
        }
    };
    // A receipt that cannot be stored would take the whole verifier down when
    // its hop commits, so a job whose receipt JSON could outgrow the record
    // limit is refused now. The page itself is a file of its own.
    if let Kind::Web(job) = &kind
        && durable
        && web_json_bound(job) > config.limits.max_record_bytes
    {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"verifier record limit is below this web job's receipt"})));
    }
    let now = now_ms();
    let expires_ms = request.expires_at_ms.unwrap_or(now.saturating_add(request.ttl_seconds.unwrap_or(300).min(600) * 1000));
    if expires_ms <= now || expires_ms > now.saturating_add(MAX_TTL.as_millis() as u64) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"invalid session expiry"})));
    }
    let ttl = Duration::from_millis(expires_ms - now);
    let token: String = rand::random::<[u8; 32]>().iter().map(|b| format!("{b:02x}")).collect();
    let key = job_key(&request.job_id, &request.attempt);
    if let Some(existing) = sessions.by_job.get(&key) {
        if durable
            && existing.payload == request.payload
            && existing.fence == request.fence.clone().unwrap_or_default()
            && existing.expires_ms == expires_ms
            && existing.in_flight == 0
            && let Some((token, _)) = sessions.by_token.iter().find(|(_, k)| *k == &key)
        {
            return (StatusCode::CREATED, Json(serde_json::json!({"token":token,"durable":true})));
        }
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "session already exists for this attempt"})));
    }
    // A web job reserves its own receipt and page in the web pool, which
    // always leaves an X or Codex receipt room in the total.
    if sessions.by_job.len() >= config.limits.max_records || sessions.store.as_ref().is_some_and(|store| !store.can_reserve(&request.payload)) {
        let pool_full = matches!(kind, Kind::Web(_)) && sessions.by_job.len() < config.limits.max_records && sessions.store.as_ref().is_some_and(|store| !store.web_pool().can_register);
        let error = if pool_full { "verifier web capacity reached" } else { "verifier session capacity reached" };
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": error})));
    }
    sessions.by_job.insert(
        key.clone(),
        Entry {
            payload: request.payload,
            kind,
            expires: Instant::now() + ttl,
            expires_ms,
            fence: request.fence.unwrap_or_default(),
            status: initial,
            in_flight: 0,
        },
    );
    sessions.by_token.insert(token.clone(), key.clone());
    if sessions.commit(&key).is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"verifier state unavailable"})));
    }
    (StatusCode::CREATED, Json(serde_json::json!({"token": token,"durable":durable})))
}

async fn capacity(State(shared): State<Shared>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    if !authorized(&shared.0, &headers) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"verifier key required"})));
    }
    let config = &shared.0;
    let sessions = shared.1.lock().unwrap();
    let storage = sessions.store.as_ref().map(Store::capacity);
    let pool = sessions.store.as_ref().map(Store::web_pool).unwrap_or(verifier_store::WebPool { can_register: true, reserved_bytes: 0, body_files: 0, body_bytes: 0, max_bytes: config.limits.max_web_bytes });
    let mut web = serde_json::to_value(pool).unwrap_or_default();
    web["concurrency"] = config.web_concurrency.into();
    web["active_sessions"] = (config.web_concurrency - config.web_slots.available_permits()).into();
    web["busy_refusals"] = config.busy_refusals.load(Ordering::Relaxed).into();
    (if sessions.failed { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::OK }, Json(serde_json::json!({
        "healthy": !sessions.failed, "durable": sessions.store.is_some(), "concurrency":config.concurrency,
        "records":sessions.by_job.len(), "storage":storage, "limits":config.limits, "web": web,
        "active_connections":config.concurrency - config.slots.available_permits(), "pre_token": config.pre_token.view(),
        "in_flight_proofs":sessions.by_job.values().map(|entry| entry.in_flight).sum::<usize>(),
        "pending_sessions":sessions.by_token.values().filter(|key| sessions.by_job.get(*key).is_some_and(|entry| entry.expires_ms > now_ms())).count()
    })))
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
    if sessions.failed {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"verifier state unavailable"})));
    }
    let Some(entry) = sessions.by_job.get(&job_key(&job_id, &attempt)) else {
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "unknown session"})));
    };
    let status = match entry.status {
        Status::Pending | Status::XRead { complete: false, .. } if Instant::now() >= entry.expires => Status::Expired,
        // Verified hops stay readable after expiry.
        Status::WebRead { ref hops, .. } if hops.is_empty() && Instant::now() >= entry.expires => Status::Expired,
        ref other => other.clone(),
    };
    let mut response = serde_json::to_value(status).unwrap_or_default();
    response["durable"] = sessions.store.is_some().into();
    response["job_id"] = job_id.into();
    response["attempt"] = attempt.into();
    response["fence"] = entry.fence.clone().into();
    response["expires_at_ms"] = entry.expires_ms.into();
    response["request_sha256"] = verifier_store::hash(&serde_json::to_vec(&entry.payload).unwrap_or_default()).into();
    (StatusCode::OK, Json(response))
}

#[derive(Deserialize)]
struct EventsQuery {
    after: Option<String>,
    wait: Option<String>,
    epoch: Option<String>,
}

/// `GET /v1/events?after=<seq>&wait=<1..25>[&epoch=<epoch>]`: web sessions'
/// terminal commits after `after`, as soon as there is one, or 204 once
/// `wait` seconds (default 20) pass without one. A position this process
/// cannot continue from, another epoch's or one behind what the ring holds,
/// answers at once with `"reset": true` and the newest seq as `next`. The
/// session lock is never held while waiting.
async fn events(State(shared): State<Shared>, headers: HeaderMap, Query(query): Query<EventsQuery>) -> Response {
    use crate::verifier_events::{MAX_REPLY, Read};
    let (config, sessions) = &*shared;
    if !authorized(config, &headers) {
        return error_response(StatusCode::UNAUTHORIZED, "verifier key required");
    }
    if sessions.lock().unwrap().failed {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "verifier state unavailable");
    }
    let number = |value: &str| (!value.is_empty() && value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit())).then(|| value.parse::<u64>().ok()).flatten();
    let Some(after) = query.after.as_deref().and_then(number) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid after");
    };
    let wait = match query.wait.as_deref().map(number) {
        None => 20,
        Some(Some(wait @ 1..=25)) => wait,
        Some(_) => return error_response(StatusCode::BAD_REQUEST, "invalid wait"),
    };
    let feed = &config.events;
    let reply = |events: Vec<crate::verifier_events::Event>, next: u64, reset: bool| {
        let mut body = serde_json::json!({"epoch": feed.epoch, "events": events, "next": next});
        if reset {
            body["reset"] = true.into();
        }
        (StatusCode::OK, Json(body)).into_response()
    };
    if query.epoch.as_deref().is_some_and(|epoch| epoch != feed.epoch) {
        return reply(Vec::new(), feed.head(), true);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait);
    // Subscribed before each read, so an event appended in between still wakes this.
    let mut appended = feed.subscribe();
    loop {
        match feed.read(after, MAX_REPLY) {
            Read::Reset { next } => return reply(Vec::new(), next, true),
            Read::Events(events, next) if !events.is_empty() => return reply(events, next, false),
            Read::Events(..) => {}
        }
        if !matches!(tokio::time::timeout_at(deadline, appended.changed()).await, Ok(Ok(()))) {
            return StatusCode::NO_CONTENT.into_response();
        }
    }
}

fn error_response(status: StatusCode, error: &str) -> Response {
    (status, Json(serde_json::json!({ "error": error }))).into_response()
}

/// One `Range: bytes=a-b` or `bytes=a-` within a body of `len` bytes, as
/// first and last byte; `Err` for anything else or nothing satisfiable.
fn byte_range(value: &HeaderValue, len: u64) -> Result<(u64, u64), ()> {
    let spec = value.to_str().map_err(drop)?.trim().strip_prefix("bytes=").ok_or(())?;
    let (first, last) = spec.split_once('-').ok_or(())?;
    let digits = |s: &str| !s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(first) || !(last.is_empty() || digits(last)) {
        return Err(());
    }
    let first: u64 = first.parse().map_err(drop)?;
    let last = if last.is_empty() { len.saturating_sub(1) } else { last.parse::<u64>().map_err(drop)?.min(len.saturating_sub(1)) };
    if first >= len || first > last {
        return Err(());
    }
    Ok((first, last))
}

/// `GET /v1/sessions/{job}/{attempt}/body`: a web receipt's stored page
/// body, whole or one byte range. The session lock is held only to look the
/// body up, never across its I/O.
async fn get_body(State(shared): State<Shared>, headers: HeaderMap, Path((job_id, attempt)): Path<(String, String)>) -> Response {
    let (config, sessions) = &*shared;
    if !authorized(config, &headers) {
        return error_response(StatusCode::UNAUTHORIZED, "verifier key required");
    }
    let found = {
        let sessions = sessions.lock().unwrap();
        if sessions.failed {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "verifier state unavailable");
        }
        sessions.body(&job_key(&job_id, &attempt))
    };
    let (path, bytes, sha256) = match found {
        Ok(found) => found,
        Err(NoBody::Unknown) => return error_response(StatusCode::NOT_FOUND, "unknown session"),
        Err(NoBody::None) => return error_response(StatusCode::NOT_FOUND, "no body"),
        Err(NoBody::Released) => return error_response(StatusCode::GONE, "body released"),
    };
    let range = match headers.get(header::RANGE).map(|value| byte_range(value, bytes)) {
        None => None,
        Some(Ok(range)) => Some(range),
        Some(Err(())) => {
            let mut response = error_response(StatusCode::RANGE_NOT_SATISFIABLE, "invalid range");
            response.headers_mut().insert(header::CONTENT_RANGE, HeaderValue::from_str(&format!("bytes */{bytes}")).expect("ascii"));
            return response;
        }
    };
    let mut file = match tokio::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&path).await {
        Ok(file) => file,
        // Released between the lookup and the open.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return error_response(StatusCode::GONE, "body released"),
        Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, "verifier state unavailable"),
    };
    if !file.metadata().await.is_ok_and(|m| m.is_file() && m.len() == bytes) {
        eprintln!("verifier: job {job_id} page body file does not match its receipt");
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "body does not match its receipt");
    }
    let (status, start, length) = match range {
        Some((first, last)) => (StatusCode::PARTIAL_CONTENT, first, last - first + 1),
        None => (StatusCode::OK, 0, bytes),
    };
    if start > 0 && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "verifier state unavailable");
    }
    let mut response = Body::from_stream(ReaderStream::with_capacity(file.take(length), 64 << 10)).into_response();
    *response.status_mut() = status;
    let set = response.headers_mut();
    set.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    set.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    set.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    set.insert("x-body-sha256", HeaderValue::from_str(&sha256).expect("hex"));
    set.insert("x-body-bytes", HeaderValue::from(bytes));
    if let Some((first, last)) = range {
        set.insert(header::CONTENT_RANGE, HeaderValue::from_str(&format!("bytes {first}-{last}/{bytes}")).expect("ascii"));
    }
    response
}

/// `DELETE /v1/sessions/{job}/{attempt}/body`: releases a stored page body.
/// The receipt records the release first, then the file is unlinked, so a
/// crash in between leaves only an orphan file that the next start deletes.
async fn delete_body(State(shared): State<Shared>, headers: HeaderMap, Path((job_id, attempt)): Path<(String, String)>) -> Response {
    let (config, sessions) = &*shared;
    if !authorized(config, &headers) {
        return error_response(StatusCode::UNAUTHORIZED, "verifier key required");
    }
    let key = job_key(&job_id, &attempt);
    let path = {
        let mut guard = sessions.lock().unwrap();
        let s = &mut *guard;
        if s.failed {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "verifier state unavailable");
        }
        let path = match s.body(&key) {
            Ok((path, ..)) => path,
            Err(NoBody::Released) => return StatusCode::NO_CONTENT.into_response(),
            Err(NoBody::Unknown) => return error_response(StatusCode::NOT_FOUND, "unknown session"),
            Err(NoBody::None) => return error_response(StatusCode::NOT_FOUND, "no body"),
        };
        if let Some(Entry { status: Status::WebRead { body_released_at_ms, .. }, .. }) = s.by_job.get_mut(&key) {
            *body_released_at_ms = Some(now_ms());
        }
        if s.commit(&key).is_err() {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "verifier state unavailable");
        }
        path
    };
    let removed = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => std::fs::File::open(path.parent().unwrap_or(std::path::Path::new("/")))?.sync_all(),
        }
    })
    .await;
    if !matches!(removed, Ok(Ok(()))) {
        // The receipt says released; the next start deletes the file.
        eprintln!("verifier: job {job_id} released page body could not be removed now");
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Why a session cannot be revoked: its result, or a running hop or proof,
/// is the caller's to handle.
#[derive(Debug, PartialEq, Eq)]
enum Unrevocable {
    InFlight,
    Complete,
}

impl Sessions {
    /// Revokes a session that is neither running nor finished with a result:
    /// its token is removed and its receipt expires now, which releases its
    /// reservation (a web job's web pool share with it). Verified hops and
    /// rejections stay in the receipt. Returns whether anything changed; the
    /// caller commits before it answers.
    fn revoke(&mut self, key: &str) -> Result<Option<bool>, Unrevocable> {
        let Some(entry) = self.by_job.get_mut(key) else { return Ok(None) };
        if entry.in_flight > 0 || matches!(entry.status, Status::Running) {
            return Err(Unrevocable::InFlight);
        }
        if matches!(entry.status, Status::Accepted { .. } | Status::WebRead { complete: true, .. } | Status::XRead { complete: true, .. }) {
            return Err(Unrevocable::Complete);
        }
        let mut changed = false;
        let now = now_ms();
        if entry.expires_ms > now {
            entry.expires_ms = now;
            entry.expires = entry.expires.min(Instant::now());
            changed = true;
        }
        let tokens = self.by_token.len();
        self.by_token.retain(|_, k| k.as_str() != key);
        Ok(Some(changed || self.by_token.len() != tokens))
    }
}

/// `DELETE /v1/sessions/{job}/{attempt}`: revokes a registered session
/// that has not run, such as a hedge loser's or a superseded attempt's, so
/// its token can never be presented and its reservation is free at once.
/// The revocation is committed before the answer. A session running a hop
/// or proof, or holding its result, is refused with 409.
async fn revoke(State(shared): State<Shared>, headers: HeaderMap, Path((job_id, attempt)): Path<(String, String)>) -> Response {
    let (config, sessions) = &*shared;
    if !authorized(config, &headers) {
        return error_response(StatusCode::UNAUTHORIZED, "verifier key required");
    }
    let key = job_key(&job_id, &attempt);
    let mut s = sessions.lock().unwrap();
    if s.failed {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "verifier state unavailable");
    }
    match s.revoke(&key) {
        Ok(None) => error_response(StatusCode::NOT_FOUND, "unknown session"),
        Err(Unrevocable::InFlight) => error_response(StatusCode::CONFLICT, "session in flight"),
        Err(Unrevocable::Complete) => error_response(StatusCode::CONFLICT, "session complete"),
        Ok(Some(changed)) => {
            if changed {
                if s.commit(&key).is_err() {
                    return error_response(StatusCode::SERVICE_UNAVAILABLE, "verifier state unavailable");
                }
                println!("verifier: job {job_id} session revoked");
            }
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

enum Job {
    Codex(Value),
    /// The pinned reads, how they are proven, and the reads already fulfilled
    /// when the session began.
    X(Arc<Vec<Spec>>, ProofMode, Vec<(usize, Exchange, Vec<String>)>),
    /// The job, the hop number and the URL this hop fetches.
    Web(Arc<webpolicy::Job>, usize, String),
}

/// Admission to a session for one presented token.
enum Admission {
    /// The token was spent (committed) and the session's slots are held.
    Admitted(Admitted),
    /// A web session found no session or web slot. The supplier is told
    /// `verifier_busy` and nothing is spent.
    Busy(String),
    /// An X or Codex session found no session slot; nothing is spent.
    Full,
}

struct Admitted {
    key: String,
    job: Job,
    expires: Instant,
    body_path: PathBuf,
    /// One of `concurrency` session slots, held for the session.
    _active: tokio::sync::OwnedSemaphorePermit,
    web_slot: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// Admits `token` under the session lock: a session slot (and a web slot
/// for a web hop) first, then the spent token or attempt is committed before
/// any provider work. A connection that already served a session (`reused`)
/// takes web tokens only, and refuses any other before spending it.
fn admit(shared: &Shared, token: &str, reused: bool) -> Result<Admission> {
    let (config, sessions) = &**shared;
    let mut guard = sessions.lock().unwrap();
    let s = &mut *guard;
    if s.failed {
        bail!("verifier state unavailable");
    }
    let key = s.by_token.get(token).cloned().context("unknown or used session token")?;
    let body_path = s.body_path(&key);
    let entry = s.by_job.get_mut(&key).context("session expired")?;
    if reused && !matches!(entry.kind, Kind::Web(_)) {
        bail!("a connection that served a session takes web sessions only");
    }
    if Instant::now() >= entry.expires {
        s.by_token.remove(token);
        // A web receipt keeps the hops it verified.
        if !matches!(entry.kind, Kind::Web(_)) {
            entry.status = Status::Expired;
        }
        s.commit(&key)?;
        bail!("session expired");
    }
    // Waiting connections hold no session slot; a session takes one now.
    let Ok(active) = config.slots.clone().try_acquire_owned() else {
        return Ok(if matches!(entry.kind, Kind::Web(_)) { Admission::Busy(key) } else { Admission::Full });
    };
    let mut web_slot = None;
    let job = match &entry.kind {
        Kind::Codex => {
            // Codex tokens are single use: removing it here blocks replays and parallel attempts.
            s.by_token.remove(token);
            entry.status = Status::Running;
            Job::Codex(entry.payload.clone())
        }
        Kind::X(specs, mode) => {
            let Status::XRead { remaining_attempts, complete, exchanges, .. } = &mut entry.status else {
                bail!("session is in an unexpected state")
            };
            let fulfilled = exchanges.iter().filter(|r| r.fulfilled).map(|r| (r.index, r.exchange.clone(), r.cursors.clone())).collect();
            if *remaining_attempts == 0 || *complete {
                s.by_token.remove(token);
                bail!("x.read session has no attempts left");
            }
            // Each connection spends one attempt; the token dies with the last one.
            *remaining_attempts -= 1;
            if *remaining_attempts == 0 {
                s.by_token.remove(token);
            }
            Job::X(specs.clone(), *mode, fulfilled)
        }
        Kind::Web(web) => {
            let Status::WebRead { remaining_sessions, complete, next_url, hops, rejections, .. } = &mut entry.status else {
                bail!("session is in an unexpected state")
            };
            // Hops run one at a time, and none after the job has ended.
            if entry.in_flight > 0 || *complete || !rejections.is_empty() || *remaining_sessions == 0 {
                bail!("web session cannot start a hop now");
            }
            // A hop takes a web slot, so X and Codex keep theirs. Without
            // one the session spends nothing and the node tries again.
            let Ok(slot) = config.web_slots.clone().try_acquire_owned() else {
                return Ok(Admission::Busy(key));
            };
            web_slot = Some(slot);
            let url = if hops.is_empty() { web.url.clone() } else { next_url.clone().context("web session has no authorized next hop")? };
            // Each connection spends one session; the token dies with the last one.
            *remaining_sessions -= 1;
            if *remaining_sessions == 0 {
                s.by_token.remove(token);
            }
            Job::Web(web.clone(), hops.len(), url)
        }
    };
    entry.in_flight += 1;
    let expires = entry.expires;
    // A durable spent token/attempt must exist before any provider session.
    s.commit(&key)?;
    Ok(Admission::Admitted(Admitted { key, job, expires, body_path, _active: active, web_slot }))
}

/// Serves one supplier connection. It waits for a token among the waiting
/// connections (`waiting`), then runs that token's session. A web session's
/// connection may wait for the supplier's next token after DONE (transport
/// 2), if it can take a place among the waiting again; it closes after any
/// failure. Every session presents its own token and starts from fresh
/// state; the last session's keys are wiped before the next token is read.
async fn handle(shared: Shared, socket: crate::control::Socket, waiting: Waiting, peer: IpAddr) -> Result<()> {
    let (config, sessions) = &*shared;
    let mut conn = Conn::new(socket);
    let mut wait = TokenWait::fresh(config.token_wait, config.idle_wait);
    let mut waiting = Some(waiting);
    let mut reused = false;
    loop {
        let Some(token) = conn.next_token(&mut wait, reused).await? else {
            // Closed before presenting a token: a cancelled pre-dial, a pool
            // connection retired, or a supplier done with its connection.
            return Ok(());
        };
        let Admitted { key, job, expires, body_path, _active, web_slot } = match admit(&shared, &token, reused)? {
            Admission::Admitted(admitted) => admitted,
            Admission::Busy(key) => {
                config.busy_refusals.fetch_add(1, Ordering::Relaxed);
                println!("verifier: job {} web session refused: verifier_busy", key.split('\n').next().unwrap_or_default());
                let _ = tokio::time::timeout(Duration::from_secs(5), conn.refuse("verifier_busy")).await;
                return Ok(());
            }
            Admission::Full => {
                println!("verifier: session from {peer} refused: no session slot");
                return Ok(());
            }
        };
        // In a session now: the connection no longer counts as waiting.
        drop(waiting.take());

        let started = Instant::now();
        let job_id = key.split('\n').next().unwrap_or_default().to_owned();
        let limit = config.session_limit.min(expires.saturating_duration_since(Instant::now()));
        match job {
            Job::Codex(payload) => {
                let status = match tokio::time::timeout(limit, verify(conn.into_inner()?, &payload, &config.upstream)).await {
                    Ok(Ok(verified)) => Status::Accepted { verified, duration_ms: started.elapsed().as_millis() as u64 },
                    Ok(Err(_)) => Status::Rejected { reason: "proof_rejected".into() },
                    Err(_) => Status::Rejected { reason: "session_timeout".into() },
                };
                match &status {
                    Status::Accepted { verified, .. } => {
                        println!("verifier: job {job_id} accepted, model {}", verified.model)
                    }
                    Status::Rejected { reason } => {
                        println!("verifier: job {job_id} rejected: {reason}")
                    }
                    _ => {}
                }
                let mut s = sessions.lock().unwrap();
                if s.failed {
                    bail!("verifier state unavailable");
                }
                if let Some(entry) = s.by_job.get_mut(&key) {
                    entry.in_flight = entry.in_flight.saturating_sub(1);
                    entry.status = if Instant::now() >= entry.expires { Status::Expired } else { status };
                    s.commit(&key)?;
                }
                return Ok(());
            }
            Job::X(specs, mode, fulfilled) => {
                let proof = async {
                    match mode {
                        ProofMode::Mpc => verify_x(conn.into_inner()?).await,
                        // The cause names only public job fields and protocol steps, never
                        // a hidden value, and is the one place a failed session can be diagnosed.
                        ProofMode::Relay => relay_x(&mut conn, config.relay_tls.clone(), &specs, &fulfilled).await.inspect_err(|e| println!("verifier: job {job_id} relay session failed: {}", loggable(e))),
                    }
                };
                let outcome = match tokio::time::timeout(limit, proof).await {
                    // Parse the response before taking the lock that every session shares.
                    Ok(Ok((exchange, sent_bytes, received_bytes))) => Ok((xpolicy::outcome(&exchange), exchange, sent_bytes, received_bytes)),
                    Ok(Err(_)) => Err("proof_rejected".into()),
                    Err(_) => Err("session_timeout".into()),
                };
                let mut guard = sessions.lock().unwrap();
                let s = &mut *guard;
                if s.failed {
                    bail!("verifier state unavailable");
                }
                if let Some(entry) = s.by_job.get_mut(&key) {
                    entry.in_flight = entry.in_flight.saturating_sub(1);
                    if Instant::now() >= entry.expires {
                        entry.status = Status::Expired;
                        s.by_token.retain(|_, k| *k != key);
                        s.commit(&key)?;
                        return Ok(());
                    }
                }
                let Some(Entry { status: Status::XRead { complete, pending, exchanges, rejections, .. }, .. }) = s.by_job.get_mut(&key) else {
                    return Ok(());
                };
                // Match under the lock, so concurrent proofs of one exchange cannot both fulfil it.
                let matched = outcome.and_then(|((fulfilled, cursors), exchange, sent_bytes, received_bytes)| {
                    let done: Vec<(usize, &Exchange, &[String])> =
                        exchanges.iter().filter(|r| r.fulfilled).map(|r| (r.index, &r.exchange, r.cursors.as_slice())).collect();
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
                        Err(_) => Err("exchange_mismatch".into()),
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
                s.commit(&key)?;
                return Ok(());
            }
            Job::Web(web, index, url) => {
                let hop = WebHopRun { key: &key, job_id: &job_id, web: &web, index, url: &url, body_path, started, limit };
                match web_hop(&shared, &mut conn, hop, web_slot, _active, peer).await? {
                    Some(next) => {
                        waiting = Some(next);
                        wait = TokenWait::after_session(config.idle_wait);
                        reused = true;
                    }
                    None => return Ok(()),
                }
            }
        }
    }
}

/// One admitted web hop, as `web_hop` runs it.
struct WebHopRun<'a> {
    key: &'a str,
    job_id: &'a str,
    web: &'a Arc<webpolicy::Job>,
    index: usize,
    url: &'a str,
    body_path: PathBuf,
    started: Instant,
    limit: Duration,
}

/// Runs one web hop and records it: the hop and its body are committed
/// before OUTCOME, a rejection before FAILED. After a verified hop the
/// session's slots are released and the connection may wait for the
/// supplier's next token (`Some`) if it can take a place among the waiting
/// connections; DONE tells the supplier which. After a failure it closes.
async fn web_hop(shared: &Shared, conn: &mut Conn<crate::control::Socket>, hop: WebHopRun<'_>, web_slot: Option<tokio::sync::OwnedSemaphorePermit>, active: tokio::sync::OwnedSemaphorePermit, peer: IpAddr) -> Result<Option<Waiting>> {
    let (config, sessions) = &**shared;
    let WebHopRun { key, job_id, web, index, url, body_path, started, limit } = hop;
    let host = webpolicy::url_host(url).to_owned();
    let authorize = |public: &[u8]| webpolicy::authorize(web, url, public).map(drop);
    let started_at_ms = now_ms();
    let hop_limit = limit.min(webpolicy::HOP_LIMIT);
    let mut reader = WebReader::new(Framer::for_hop(web.max_response_bytes, web.rule(url, index)), body_path);
    let mut clock = HopClock::new(config.web_timing, Instant::now() + hop_limit);
    // The clock ends the hop inside the session, so the node always
    // gets its record opened; this only bounds a session that stops
    // making progress some other way.
    let session = tokio::time::timeout(hop_limit + Duration::from_secs(10), web_session(conn, config.relay_tls.clone(), &host, authorize, &mut reader, &mut clock)).await;
    let duration_ms = started.elapsed().as_millis() as u64;
    let (reason, detail) = match session {
        // What the node chose for this hop, from the bytes just authorized.
        Ok(Ok(sealed)) => match (reader.finish().await, webpolicy::authorize(web, url, &sealed.sent)) {
            (Ok((response, stored)), Ok(node)) => {
                let is_final = !response.followable;
                let next_url = response.followable.then(|| response.location.clone()).flatten();
                let record = WebHop {
                    index,
                    url: url.to_owned(),
                    status_code: response.status,
                    location: response.location.clone(),
                    location_refused: response.location_refused.map(Into::into),
                    head_base64: STANDARD.encode(&response.head),
                    body_stored: is_final,
                    body_bytes: response.body_bytes,
                    body_sha256: hex(&response.body_sha256),
                    response_sha256: hex(&response.response_sha256),
                    framing: response.framing.name().into(),
                    sent_bytes: sealed.sent.len(),
                    received_bytes: response.received,
                    server_name: host.clone(),
                    tls_version: WEB_TLS_VERSION.into(),
                    cipher_suite: WEB_CIPHER_SUITE.into(),
                    alpn: sealed.tls.alpn.clone(),
                    cert_chain_sha256: hex(&sealed.tls.cert_chain_sha256),
                    leaf_cert_sha256: hex(&sealed.tls.leaf_cert_sha256),
                    started_at_ms,
                    duration_ms,
                    node_user_agent: node.as_ref().map(|n| n.user_agent.clone()),
                    node_cookie_names: node.as_ref().map(webpolicy::NodeHeaders::cookie_names),
                    node_cookie_sha256: node.as_ref().and_then(webpolicy::NodeHeaders::cookie_sha256),
                };
                let frame = serde_json::to_vec(&HopOutcome { hop: index, url, status_code: response.status, is_final, next_url: next_url.as_deref() })?;
                // The hop, and its body file, are durable before the node learns the next URL.
                {
                    let mut guard = sessions.lock().unwrap();
                    let s = &mut *guard;
                    if s.failed {
                        bail!("verifier state unavailable");
                    }
                    let Some(Entry { status: Status::WebRead { complete, next_url: pending, hops, .. }, in_flight, .. }) = s.by_job.get_mut(key) else {
                        bail!("web receipt is gone");
                    };
                    hops.push(record);
                    *pending = next_url;
                    *in_flight = 0;
                    if is_final {
                        *complete = true;
                        s.by_token.retain(|_, k| k != key);
                    }
                    s.commit(key)?;
                }
                if let Some(stored) = stored {
                    stored.commit();
                }
                // The final hop and its body are durable: the app may take the page now.
                if is_final {
                    config.events.append(job_id, attempt_of(key), "complete", now_ms());
                }
                println!("verifier: job {job_id} proved web hop {index} (HTTP {}, {} bytes, {duration_ms} ms)", response.status, response.body_bytes);
                // The session is over: its slots go back before the connection waits again.
                drop((web_slot, active));
                let next = config.pre_token.take(peer);
                return Ok(match tokio::time::timeout(Duration::from_secs(10), conn.done(Some(&frame), next.is_some())).await {
                    Ok(Ok(())) => next,
                    _ => None,
                });
            }
            (Err(e), _) | (_, Err(e)) => {
                println!("verifier: job {job_id} web hop {index} could not be recorded: {}", loggable(&e));
                (Failure::ProofRejected.reason(), None)
            }
        },
        // Only the reason is logged: never the URL, host or anything the page said.
        Ok(Err(e)) => (Failure::of(&e).reason(), e.downcast_ref::<TimedOut>().map(|t| t.0)),
        Err(_) => (Failure::SessionTimeout.reason(), Some("stalled")),
    };
    match detail {
        Some(detail) => println!("verifier: job {job_id} web hop {index} failed: {reason} ({detail})"),
        None => println!("verifier: job {job_id} web hop {index} failed: {reason}"),
    }
    let rejection = Rejection::new(reason, reader.counts());
    {
        let mut guard = sessions.lock().unwrap();
        let s = &mut *guard;
        if s.failed {
            bail!("verifier state unavailable");
        }
        if let Some(Entry { status: Status::WebRead { next_url, rejections, rejection: recorded, .. }, in_flight, .. }) = s.by_job.get_mut(key) {
            *in_flight = 0;
            *next_url = None;
            rejections.push(reason.into());
            *recorded = Some(rejection);
            s.by_token.retain(|_, k| k != key);
            s.commit(key)?;
            config.events.append(job_id, attempt_of(key), "rejected", now_ms());
        }
    }
    // The rejection is committed; now the node may learn why. The connection closes.
    drop((web_slot, active));
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.refuse(reason)).await;
    Ok(None)
}

/// The OUTCOME frame a supplier receives for a verified web hop.
#[derive(Serialize)]
struct HopOutcome<'a> {
    hop: usize,
    url: &'a str,
    status_code: u16,
    #[serde(rename = "final")]
    is_final: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_url: Option<&'a str>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn verify(socket: crate::control::Socket, job: &Value, upstream: &str) -> Result<Verified> {
    let (server_name, transcript) = prove_session(socket, Some(upstream)).await?;
    let sent_hidden: Vec<_> = transcript.sent_unauthed().iter().collect();
    let received_hidden: Vec<_> = transcript.received_unauthed().iter().collect();
    policy::check(&server_name, transcript.sent_unsafe(), &sent_hidden, transcript.received_unsafe(), &received_hidden, job)
}

/// An error as one bounded log line. Its text can quote what a supplier
/// sent, so nothing in it may start a line or run on.
fn loggable(error: &anyhow::Error) -> String {
    format!("{error:#}").escape_default().take(240).collect()
}

/// A relay session: the verifier is X's TLS peer through the supplier's
/// connection. It authorizes only a request for a read this job still wants,
/// and what it returns went through the same policy check as an MPC-TLS proof.
async fn relay_x(conn: &mut Conn<crate::control::Socket>, tls: Arc<rustls::ClientConfig>, specs: &[Spec], fulfilled: &[(usize, Exchange, Vec<String>)]) -> Result<(Exchange, usize, usize)> {
    let authorize = |sent: &[u8], hidden: &[std::ops::Range<usize>]| {
        let done: Vec<(usize, &Exchange, &[String])> = fulfilled.iter().map(|(index, exchange, cursors)| (*index, exchange, cursors.as_slice())).collect();
        xpolicy::assign_request(specs, &done, xpolicy::check_request(sent, hidden)?).map(|_| ())
    };
    let outcome = crate::relay::verifier::run(conn, tls, xpolicy::HOST, authorize).await?;
    let exchange = xpolicy::check(xpolicy::HOST, &outcome.sent, &outcome.hidden, &outcome.received, &[])?;
    Ok((exchange, outcome.sent.len(), outcome.received.len()))
}

/// Returns the verified exchange and the transcript's sent and received sizes.
async fn verify_x(socket: crate::control::Socket) -> Result<(Exchange, usize, usize)> {
    let (server_name, transcript) = prove_session(socket, None).await?;
    let sent_hidden: Vec<_> = transcript.sent_unauthed().iter().collect();
    let received_hidden: Vec<_> = transcript.received_unauthed().iter().collect();
    let (sent, received) = (transcript.sent_unsafe(), transcript.received_unsafe());
    let exchange = xpolicy::check(&server_name, sent, &sent_hidden, received, &received_hidden)?;
    Ok((exchange, sent.len(), received.len()))
}

/// Runs one TLSNotary session: proxy mode through `upstream` when given, else
/// MPC-TLS within the X size limits. Returns the proven server name and transcript.
struct CancelDriver(tokio::task::AbortHandle);
impl Drop for CancelDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn prove_session(socket: crate::control::Socket, upstream: Option<&str>) -> Result<(String, PartialTranscript)> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);
    // Cancelling a proof must also drop its session driver and transport.
    let _driver_guard = CancelDriver(driver_task.abort_handle());

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
