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
    extract::{Path, State},
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
    relay::verifier::{Conn, Failure, HopClock, TimedOut, Timing, WebReader, web_session},
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
        let session = tokio::spawn(handle(s.clone(), Box::new(verifier_end)));
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
        let session = tokio::spawn(handle(s.clone(), Box::new(verifier_end)));
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
        let session = tokio::spawn(handle(s.clone(), Box::new(verifier_end)));
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
            assert!(verifier_store::WEB_RETENTION_MS < verifier_store::RETENTION_MS);
            // Attempt 3 ages while the verifier is down and leaves on restart.
            age(&mut sessions, "3", verifier_store::WEB_RETENTION_MS + 1);
        }
        drop(s);
        let s = open(&dir.0);
        let sessions = s.1.lock().unwrap();
        assert!(!sessions.by_job.contains_key(&job_key("synthetic", "3")));
        assert!(sessions.by_job.contains_key(&job_key("synthetic", "2")) && sessions.by_job.contains_key(&job_key("synthetic", "4")));
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
                tokio::spawn(handle(shared_verifier.clone(), Box::new(socket)));
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
                tokio::spawn(handle(shared_verifier.clone(), Box::new(socket)));
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

    #[tokio::test]
    async fn web_sessions_beyond_their_slots_are_refused_and_x_still_starts() {
        let s = shared(rustls::RootCertStore::empty(), None);
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
            crate::relay::wire::send(&mut socket, crate::relay::wire::HELLO, br#"{"version":1,"transfers":0}"#).await.unwrap();
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
                let session = tokio::spawn(handle(s.clone(), Box::new(verifier_end)));
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
    let relay_tls = crate::relay::verifier::tls_config(crate::relay::verifier::mozilla_roots()?)?;
    let shared: Shared = Arc::new((Config::new(key, upstream, Duration::from_secs(limit), limits, concurrency, web_concurrency, relay_tls), Mutex::new(sessions)));
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
        .route("/v1/sessions/{job_id}/{attempt}", get(status))
        .route("/v1/sessions/{job_id}/{attempt}/body", get(get_body).delete(delete_body))
        .route("/v1/capacity", get(capacity))
        .with_state(shared.clone());
    let api_listener = TcpListener::bind(&api).await.with_context(|| format!("binding {api}"))?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(api_listener, router).await {
            eprintln!("verifier API stopped: {e}");
        }
    });

    let listener = TcpListener::bind(&listen).await.with_context(|| format!("binding {listen}"))?;
    println!("verifier: sessions on {listen} ({concurrency}, {web_concurrency} for web), API on {api}, upstream {}", shared.0.upstream);
    serve(listener, shared, acceptor).await
}

/// Accepts supplier connections, each into one of the connection slots;
/// a connection that finds none is closed at once.
async fn serve(listener: TcpListener, shared: Shared, acceptor: Option<tokio_rustls::TlsAcceptor>) -> Result<()> {
    let slots = shared.0.slots.clone();
    loop {
        let (socket, peer) = listener.accept().await?;
        let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
        let _ = socket.set_nodelay(true);
        let shared = shared.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let socket: crate::control::Socket = if let Some(acceptor) = acceptor {
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(socket)).await {
                    Ok(Ok(socket)) => Box::new(socket),
                    _ => return,
                }
            } else {
                Box::new(socket)
            };
            if handle(shared, socket).await.is_err() {
                println!("verifier: session from {peer} ended without a result");
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
        "active_connections":config.concurrency - config.slots.available_permits(),
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

enum Job {
    Codex(Value),
    /// The pinned reads, how they are proven, and the reads already fulfilled
    /// when the session began.
    X(Arc<Vec<Spec>>, ProofMode, Vec<(usize, Exchange, Vec<String>)>),
    /// The job, the hop number and the URL this hop fetches.
    Web(Arc<webpolicy::Job>, usize, String),
}

async fn handle(shared: Shared, mut socket: crate::control::Socket) -> Result<()> {
    let (config, sessions) = &*shared;
    let mut line = [0u8; 65];
    tokio::time::timeout(Duration::from_secs(10), socket.read_exact(&mut line)).await.context("no session token")??;
    if line[64] != b'\n' {
        bail!("malformed session token");
    }
    let token = std::str::from_utf8(&line[..64])?;
    // Err(key): the job's web session must wait for a web slot.
    let admitted = 'admit: {
        let mut guard = sessions.lock().unwrap();
        let s = &mut *guard;
        if s.failed {
            bail!("verifier state unavailable");
        }
        let key = s.by_token.get(token).cloned().context("unknown or used session token")?;
        let body_path = s.body_path(&key);
        let mut web_slot = None;
        let entry = s.by_job.get_mut(&key).context("session expired")?;
        if Instant::now() >= entry.expires {
            s.by_token.remove(token);
            // A web receipt keeps the hops it verified.
            if !matches!(entry.kind, Kind::Web(_)) {
                entry.status = Status::Expired;
            }
            s.commit(&key)?;
            bail!("session expired");
        }
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
                    break 'admit Err(key);
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
        Ok((key, job, expires, web_slot, body_path))
    };
    let (key, job, expires, web_slot, body_path) = match admitted {
        Ok(admitted) => admitted,
        Err(key) => {
            config.busy_refusals.fetch_add(1, Ordering::Relaxed);
            println!("verifier: job {} web session refused: verifier_busy", key.split('\n').next().unwrap_or_default());
            let _ = tokio::time::timeout(Duration::from_secs(5), Conn::new(socket).refuse("verifier_busy")).await;
            return Ok(());
        }
    };

    let started = Instant::now();
    let job_id = key.split('\n').next().unwrap_or_default().to_owned();
    let limit = config.session_limit.min(expires.saturating_duration_since(Instant::now()));
    match job {
        Job::Codex(payload) => {
            let status = match tokio::time::timeout(limit, verify(socket, &payload, &config.upstream)).await {
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
        }
        Job::X(specs, mode, fulfilled) => {
            let proof = async {
                match mode {
                    ProofMode::Mpc => verify_x(socket).await,
                    // The cause names only public job fields and protocol steps, never
                    // a hidden value, and is the one place a failed session can be diagnosed.
                    ProofMode::Relay => relay_x(socket, config.relay_tls.clone(), &specs, &fulfilled).await.inspect_err(|e| println!("verifier: job {job_id} relay session failed: {}", loggable(e))),
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
        }
        Job::Web(web, index, url) => {
            let _web_slot = web_slot;
            let host = webpolicy::url_host(&url).to_owned();
            let authorize = |public: &[u8]| webpolicy::authorize(&web, &url, public).map(drop);
            let started_at_ms = now_ms();
            let hop_limit = limit.min(webpolicy::HOP_LIMIT);
            let mut conn = Conn::new(socket);
            let mut reader = WebReader::new(Framer::for_hop(web.max_response_bytes, web.rule(&url, index)), body_path);
            let mut clock = HopClock::new(config.web_timing, Instant::now() + hop_limit);
            // The clock ends the hop inside the session, so the node always
            // gets its record opened; this only bounds a session that stops
            // making progress some other way.
            let session = tokio::time::timeout(hop_limit + Duration::from_secs(10), web_session(&mut conn, config.relay_tls.clone(), &host, authorize, &mut reader, &mut clock)).await;
            let duration_ms = started.elapsed().as_millis() as u64;
            let (reason, detail) = match session {
                // What the node chose for this hop, from the bytes just authorized.
                Ok(Ok(sealed)) => match (reader.finish().await, webpolicy::authorize(&web, &url, &sealed.sent)) {
                    (Ok((response, stored)), Ok(node)) => {
                        let is_final = !response.followable;
                        let next_url = response.followable.then(|| response.location.clone()).flatten();
                        let hop = WebHop {
                            index,
                            url: url.clone(),
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
                        let frame = serde_json::to_vec(&HopOutcome { hop: index, url: &url, status_code: response.status, is_final, next_url: next_url.as_deref() })?;
                        // The hop, and its body file, are durable before the node learns the next URL.
                        {
                            let mut guard = sessions.lock().unwrap();
                            let s = &mut *guard;
                            if s.failed {
                                bail!("verifier state unavailable");
                            }
                            let Some(Entry { status: Status::WebRead { complete, next_url: pending, hops, .. }, in_flight, .. }) = s.by_job.get_mut(&key) else {
                                bail!("web receipt is gone");
                            };
                            hops.push(hop);
                            *pending = next_url;
                            *in_flight = 0;
                            if is_final {
                                *complete = true;
                                s.by_token.retain(|_, k| *k != key);
                            }
                            s.commit(&key)?;
                        }
                        if let Some(stored) = stored {
                            stored.commit();
                        }
                        println!("verifier: job {job_id} proved web hop {index} (HTTP {}, {} bytes, {duration_ms} ms)", response.status, response.body_bytes);
                        let _ = tokio::time::timeout(Duration::from_secs(10), conn.done(Some(&frame))).await;
                        return Ok(());
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
                if let Some(Entry { status: Status::WebRead { next_url, rejections, rejection: recorded, .. }, in_flight, .. }) = s.by_job.get_mut(&key) {
                    *in_flight = 0;
                    *next_url = None;
                    rejections.push(reason.into());
                    *recorded = Some(rejection);
                    s.by_token.retain(|_, k| *k != key);
                    s.commit(&key)?;
                }
            }
            // The rejection is committed; now the node may learn why.
            let _ = tokio::time::timeout(Duration::from_secs(5), conn.refuse(reason)).await;
        }
    }
    Ok(())
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
async fn relay_x(socket: crate::control::Socket, tls: Arc<rustls::ClientConfig>, specs: &[Spec], fulfilled: &[(usize, Exchange, Vec<String>)]) -> Result<(Exchange, usize, usize)> {
    let authorize = |sent: &[u8], hidden: &[std::ops::Range<usize>]| {
        let done: Vec<(usize, &Exchange, &[String])> = fulfilled.iter().map(|(index, exchange, cursors)| (*index, exchange, cursors.as_slice())).collect();
        xpolicy::assign_request(specs, &done, xpolicy::check_request(sent, hidden)?).map(|_| ())
    };
    let outcome = crate::relay::verifier::run(socket, tls, xpolicy::HOST, authorize).await?;
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
