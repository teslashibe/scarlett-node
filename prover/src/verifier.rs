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
//! and one failed session ends the job (see webpolicy.rs).
//!
//! Environment: SCARLETT_VERIFIER_KEY (required, 32+ chars),
//! SCARLETT_VERIFIER_LISTEN (default 0.0.0.0:7047), SCARLETT_VERIFIER_API
//! (default 127.0.0.1:7070), UPSTREAM (default chatgpt.com:443),
//! SESSION_TIMEOUT_SECS (default 300). Optional SCARLETT_VERIFIER_STATE_DIR
//! enables private durable receipts and requires absolute expiry/fence bindings.

use std::{
    collections::HashMap,
    env,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
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
    relay::verifier::{Failure, WebOutcome},
    verifier_store::{self, Record, Store},
    webpolicy,
    xpolicy::{self, Exchange, ProofMode, Spec},
    xprove::{MAX_RECV, MAX_SENT},
};

const MAX_TTL: Duration = Duration::from_secs(600);

struct Config {
    key: String,
    upstream: String,
    session_limit: Duration,
    limits: verifier_store::Limits,
    concurrency: usize,
    slots: Arc<tokio::sync::Semaphore>,
    /// TLS client settings for relay sessions, where the verifier is X's TLS peer.
    relay_tls: Arc<rustls::ClientConfig>,
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
    },
}

/// One verified web hop.
#[derive(Clone, Serialize, Deserialize)]
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
    /// The entity body, dechunked but still content-encoded; final hop only.
    body_base64: Option<String>,
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
}

/// The reasons a web hop can be rejected for.
const WEB_REJECTIONS: [&str; 8] = ["tls_failed", "request_rejected", "response_too_large", "response_invalid", "server_closed", "session_timeout", "execution_uncertain", "proof_rejected"];
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

#[derive(Default)]
struct Sessions {
    by_job: HashMap<String, Entry>,
    by_token: HashMap<String, String>,
    store: Option<Store>,
    failed: bool,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}
fn kind(payload: &Value, durable: bool) -> Result<(Kind, Status)> {
    if payload["type"] == "x.read" {
        let (specs, max) = xpolicy::validate_job(payload)?;
        let mode = xpolicy::proof_mode(payload)?;
        if durable && (specs.len() > 3 || max != specs.len()) {
            bail!("durable X jobs require 1-3 exchanges with one attempt each");
        }
        let pending = (0..specs.len()).collect();
        Ok((
            Kind::X(Arc::new(specs), mode),
            Status::XRead { remaining_attempts: max, complete: false, pending, exchanges: Vec::new(), rejections: Vec::new() },
        ))
    } else if payload["type"] == webpolicy::PAYLOAD_TYPE {
        let job = webpolicy::validate_job(payload)?;
        let sessions = job.max_redirects + 1;
        Ok((Kind::Web(Arc::new(job)), Status::WebRead { remaining_sessions: sessions, complete: false, next_url: None, hops: Vec::new(), rejections: Vec::new() }))
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
        (Kind::Web(job), Status::WebRead { remaining_sessions, complete, next_url, hops, rejections }) => {
            if in_flight > 1
                || remaining_sessions.checked_add(hops.len()).and_then(|n| n.checked_add(rejections.len())).and_then(|n| n.checked_add(in_flight)) != Some(job.max_redirects + 1)
                || rejections.len() > 1
                || rejections.iter().any(|r| !WEB_REJECTIONS.contains(&r.as_str()))
                || ((in_flight > 0 || *complete) && !rejections.is_empty())
                || (in_flight > 0 && *complete)
            {
                bail!("invalid web receipt session count");
            }
            let is_final = |hop: &WebHop| hop.location.is_none() || hop.index == job.max_redirects;
            for (i, hop) in hops.iter().enumerate() {
                let url = if i == 0 { Some(&job.url) } else { hops[i - 1].location.as_ref() };
                let last = i + 1 == hops.len();
                if hop.index != i || Some(&hop.url) != url || (!last && is_final(hop)) || hop.body_base64.is_some() != (last && *complete) {
                    bail!("invalid web receipt chain");
                }
                valid_web_hop(job, hop)?;
            }
            let followable = hops.last().and_then(|hop| hop.location.as_ref()).filter(|_| !*complete && rejections.is_empty());
            if *complete != hops.last().is_some_and(is_final) || next_url.as_ref() != followable {
                bail!("invalid web receipt completion");
            }
            Ok(())
        }
        _ => bail!("receipt status does not match the job"),
    }
}

/// The most a web receipt can hold (verifier_store::web_receipt_bound).
fn web_receipt_bound(job: &webpolicy::Job) -> u64 {
    verifier_store::web_receipt_bound(job.max_response_bytes, job.max_redirects)
}

fn valid_web_hop(job: &webpolicy::Job, hop: &WebHop) -> Result<()> {
    let hex = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let canonical = |url: &str| webpolicy::canonical_url(url).ok().as_deref() == Some(url);
    let redirect = webpolicy::REDIRECTS.contains(&hop.status_code);
    let head = STANDARD.decode(&hop.head_base64).ok().filter(|head| head.len() <= webpolicy::MAX_HEAD);
    let body_ok = match &hop.body_base64 {
        None => true,
        Some(body) => STANDARD.decode(body).is_ok_and(|body| body.len() == hop.body_bytes && verifier_store::hash(&body) == hop.body_sha256),
    };
    if !canonical(&hop.url)
        || hop.server_name != webpolicy::url_host(&hop.url)
        || !(200..=999).contains(&hop.status_code)
        || hop.location.as_deref().is_some_and(|next| !redirect || !canonical(next) || hop.location_refused.is_some())
        || hop.location_refused.as_deref().is_some_and(|reason| !redirect || !webpolicy::UrlError::ALL.iter().any(|e| e.code() == reason))
        || head.is_none()
        || !body_ok
        || hop.body_bytes > hop.received_bytes
        || hop.received_bytes > job.max_response_bytes
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
        let mut s = Self { store: Some(store), ..Self::default() };
        let now = now_ms();
        for r in records {
            if r.expires_ms > now.saturating_add(MAX_TTL.as_millis() as u64) {
                bail!("verifier receipt expiry exceeds the session bound");
            }
            if r.in_flight == 0 && r.status["reason"] != "execution_uncertain" && now > r.expires_ms.saturating_add(verifier_store::retention_ms(&r.payload)) {
                s.store.as_mut().unwrap().remove(&r.job_id, &r.attempt)?;
                continue;
            }
            let (kind, _) = kind(&r.payload, true)?;
            let mut status: Status = serde_json::from_value(r.status)?;
            validate_receipt(&kind, &status, r.in_flight)?;
            let mut token = r.token;
            if r.in_flight > 0 || matches!(status, Status::Running) {
                if let Status::WebRead { rejections, next_url, .. } = &mut status {
                    // A web receipt keeps the hops it verified; the interrupted one ends the job.
                    rejections.push("execution_uncertain".into());
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
    fn purge(&mut self) -> Result<()> {
        let now = now_ms();
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
        for key in stale {
            if let Some(store) = self.store.as_mut() {
                let (job, attempt) = key.split_once('\n').context("invalid receipt key")?;
                if let Err(e) = store.remove(job, attempt) {
                    self.failed = true;
                    return Err(e);
                }
            }
            self.by_job.remove(&key);
            self.by_token.retain(|_, k| k != &key);
        }
        Ok(())
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
            Config {
                key: "synthetic-fixture-key-never-used-remotely".into(),
                upstream: "127.0.0.1:1".into(),
                session_limit: Duration::from_secs(30),
                limits: verifier_store::Limits::default(),
                concurrency: 64,
                slots: Arc::new(tokio::sync::Semaphore::new(64)),
                relay_tls: crate::relay::verifier::tls_config(rustls::RootCertStore::empty()).unwrap(),
            },
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
            Config {
                key: KEY.into(),
                upstream: "127.0.0.1:1".into(),
                session_limit: Duration::from_secs(20),
                limits: verifier_store::Limits::default(),
                concurrency: 64,
                slots: Arc::new(tokio::sync::Semaphore::new(64)),
                relay_tls: crate::relay::verifier::tls_config(roots).unwrap(),
            },
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
            Config {
                key: KEY.into(),
                upstream: "127.0.0.1:1".into(),
                session_limit: Duration::from_secs(20),
                limits: verifier_store::Limits::default(),
                concurrency: 64,
                slots: Arc::new(tokio::sync::Semaphore::new(64)),
                relay_tls: crate::relay::verifier::tls_config(roots).unwrap(),
            },
            Mutex::new(sessions),
        ))
    }
    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", format!("Bearer {KEY}").parse().unwrap());
        h
    }
    fn payload(url: &str, max_redirects: u64, max_bytes: u64) -> Value {
        json!({"type":"web.fetch","proof_mode":"relay","proof_policy":"web-relay-v1","url":url,"max_redirects":max_redirects,"max_response_bytes":max_bytes,"headers":web_headers()})
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

    const PAGE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 20\r\n\r\n<title>hello</title>";

    #[tokio::test]
    async fn a_single_hop_records_the_page_and_ends_the_job() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5, 10 << 20)).await;
        let (reported, verifier) = hop(&s, &origin, &token, 0, "https://example.com/", None).await;
        verifier.unwrap();
        let reported = reported.unwrap();
        assert_eq!((reported.hop, reported.status_code, reported.is_final, reported.next_url), (0, 200, true, None));
        let request = webpolicy::request("https://example.com/", &web_headers());
        assert_eq!(origin.seen.lock().unwrap().as_deref(), Some(&request[..]));
        let view = view(&s).await;
        assert_eq!((view["status"].as_str(), view["complete"].as_bool(), view["remaining_sessions"].as_u64()), (Some("web_read"), Some(true), Some(5)));
        assert_eq!((view["next_url"].clone(), view["rejections"].clone()), (Value::Null, json!([])));
        assert_eq!(view["request_sha256"], verifier_store::hash(&serde_json::to_vec(&payload("https://example.com/", 5, 10 << 20)).unwrap()));
        let h = &view["hops"][0];
        let head_end = PAGE.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert_eq!((h["index"].as_u64(), h["url"].as_str(), h["status_code"].as_u64()), (Some(0), Some("https://example.com/"), Some(200)));
        assert_eq!((h["location"].clone(), h["location_refused"].clone()), (Value::Null, Value::Null));
        assert_eq!(decode(&h["head_base64"]), &PAGE[..head_end]);
        assert_eq!(decode(&h["body_base64"]), &PAGE[head_end..]);
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
        let token = register(&s, payload("https://example.com/a/b?x=1", 5, 10 << 20)).await;
        let (first, verifier) = hop(&s, &origin, &token, 0, "https://example.com/a/b?x=1", None).await;
        verifier.unwrap();
        let first = first.unwrap();
        let next = "https://www.example.com/next?q=%7e";
        assert_eq!((first.status_code, first.is_final, first.next_url.as_deref()), (301, false, Some(next)));
        let view = view(&s).await;
        assert_eq!((view["complete"].as_bool(), view["next_url"].as_str(), view["remaining_sessions"].as_u64()), (Some(false), Some(next), Some(5)));
        assert_eq!(view["hops"][0]["body_base64"], Value::Null);
        assert_eq!(view["hops"][0]["body_sha256"], verifier_store::hash(b"moved"));
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
        assert_eq!(decode(&hops[1]["body_base64"]), b"\x1f\x8b\x08\x00zz");
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
            let token = register(&s, payload("https://example.com/", 5, 10 << 20)).await;
            let (reported, _) = hop(&s, &origin, &token, 0, "https://example.com/", None).await;
            assert!(reported.unwrap().is_final);
            let view = view(&s).await;
            let h = &view["hops"][0];
            assert_eq!((view["complete"].as_bool(), h["location"].clone(), h["location_refused"].as_str()), (Some(true), Value::Null, Some(reason)), "{location}");
            assert_eq!(decode(&h["body_base64"]), b"body");
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
        let token = register(&s, payload("https://example.com/a", 1, 10 << 20)).await;
        assert_eq!(hop(&s, &origin, &token, 0, "https://example.com/a", None).await.0.unwrap().next_url.as_deref(), Some("https://example.com/b"));
        let last = hop(&s, &origin, &token, 1, "https://example.com/b", None).await.0.unwrap();
        assert!(last.is_final && last.next_url.is_none());
        let view = view(&s).await;
        assert_eq!((view["complete"].as_bool(), view["remaining_sessions"].as_u64()), (Some(true), Some(0)));
        // The followable location is still recorded, so the buyer sees where it pointed.
        assert_eq!(view["hops"][1]["location"], "https://example.com/c");
        assert_eq!(decode(&view["hops"][1]["body_base64"]), b"");
        assert_eq!(tokens(&s), 0);
        assert!(hop(&s, &origin, &token, 2, "https://example.com/c", None).await.0.is_err());
    }

    #[tokio::test]
    async fn a_failed_hop_ends_the_job_revokes_the_token_and_names_the_reason() {
        let url = "https://example.com/";
        let mut tampered = webpolicy::request(url, &web_headers());
        tampered[5] = b'x';
        let cases: Vec<(&str, &'static [(&str, &[u8], End)], bool, u64, Option<Vec<u8>>, &str)> = vec![
            ("tampered", &[("example.com/", PAGE, End::Wait)], false, 10 << 20, Some(tampered), "request_rejected"),
            ("tls 1.2", &[("example.com/", PAGE, End::Wait)], true, 10 << 20, None, "tls_failed"),
            ("too large", &[("example.com/", PAGE, End::Wait)], false, 64, None, "response_too_large"),
            ("bad framing", &[("example.com/", b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", End::Wait)], false, 10 << 20, None, "response_invalid"),
            ("cut short", &[("example.com/", b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort", End::Close)], false, 10 << 20, None, "server_closed"),
        ];
        for (case, table, tls12, max, raw, reason) in cases {
            let origin = web_origin(routes(table), tls12).await;
            let s = shared(origin.roots.clone(), None);
            let token = register(&s, payload(url, 5, max)).await;
            let (reported, _) = hop(&s, &origin, &token, 0, url, raw).await;
            assert!(reported.is_err(), "{case}");
            let view = view(&s).await;
            assert_eq!(view["rejections"], json!([reason]), "{case}");
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
        let token = register(&s, payload("https://example.com/", 5, 10 << 20)).await;
        hop(&s, &origin, &token, 0, "https://example.com/", None).await.0.unwrap();
        let (reported, _) = hop(&s, &origin, &token, 1, "https://example.com/other", None).await;
        assert!(reported.is_err());
        assert_ne!(origin.seen.lock().unwrap().as_deref().map(|r| r.starts_with(b"GET /other")), Some(true));
        let view = view(&s).await;
        assert_eq!((view["rejections"].clone(), view["next_url"].clone(), view["hops"].as_array().unwrap().len()), (json!(["request_rejected"]), Value::Null, 1));
        assert_eq!(tokens(&s), 0);
    }

    #[tokio::test]
    async fn a_second_concurrent_session_is_refused_without_spending_one() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5, 10 << 20)).await;
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
        let (code, Json(created)) = create(State(s.clone()), headers(), Json(job(payload("https://example.com/", 5, 10 << 20), expires))).await;
        assert_eq!(code, StatusCode::CREATED);
        // Registration is idempotent for the same binding.
        let (_, Json(again)) = create(State(s.clone()), headers(), Json(job(payload("https://example.com/", 5, 10 << 20), expires))).await;
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
        assert_eq!((view["hops"].as_array().unwrap().len(), view["remaining_sessions"].as_u64()), (1, Some(4)));
        assert_eq!(tokens(&s), 0);
        assert_eq!(create(State(s.clone()), headers(), Json(job(payload("https://example.com/", 5, 10 << 20), expires))).await.0, StatusCode::CONFLICT);
        // The finished receipt no longer reserves a full record.
        let capacity = s.1.lock().unwrap().store.as_ref().unwrap().capacity();
        assert_eq!(capacity.reserved_bytes, capacity.bytes);
    }

    #[tokio::test]
    async fn expiry_keeps_verified_hops_readable() {
        let origin = web_origin(routes(&[("example.com/", b"HTTP/1.1 301 Moved\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n", End::Wait)]), false).await;
        for verified in [false, true] {
            let s = shared(origin.roots.clone(), None);
            let token = register(&s, payload("https://example.com/", 5, 10 << 20)).await;
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

    #[tokio::test]
    async fn a_web_job_whose_receipt_could_outgrow_the_record_limit_is_refused() {
        let dir = Temp::new();
        let limits = verifier_store::Limits { max_records: 8, max_record_bytes: 4 << 20, max_total_bytes: 64 << 20 };
        let (store, records) = Store::open_with_limits(&dir.0, limits).unwrap();
        let s: Shared = Arc::new((
            Config {
                key: KEY.into(),
                upstream: "127.0.0.1:1".into(),
                session_limit: Duration::from_secs(20),
                limits,
                concurrency: 64,
                slots: Arc::new(tokio::sync::Semaphore::new(64)),
                relay_tls: crate::relay::verifier::tls_config(rustls::RootCertStore::empty()).unwrap(),
            },
            Mutex::new(Sessions::restore(store, records).unwrap()),
        ));
        let expires = now_ms() + 60_000;
        assert_eq!(create(State(s.clone()), headers(), Json(job(payload("https://example.com/", 5, 10 << 20), expires))).await.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(create(State(s.clone()), headers(), Json(job(payload("https://example.com/", 5, 2 << 20), expires))).await.0, StatusCode::CREATED);
        // The default job fits the default record limit with room to spare.
        let default = webpolicy::validate_job(&payload("https://example.com/", 5, 10 << 20)).unwrap();
        assert!(web_receipt_bound(&default) <= 24 << 20 && web_receipt_bound(&default) > 10 << 20);
    }

    #[tokio::test]
    async fn web_receipts_reserve_their_own_bound_and_leave_soon_after_expiry() {
        let dir = Temp::new();
        // Room for one X or Codex reservation (the full record limit) or four
        // default web jobs (about 14 MiB each).
        let limits = verifier_store::Limits { max_records: 16, max_record_bytes: 64 << 20, max_total_bytes: 64 << 20 };
        let open = |dir: &std::path::Path| -> Shared {
            let (store, records) = Store::open_with_limits(dir, limits).unwrap();
            Arc::new((
                Config {
                    key: KEY.into(),
                    upstream: "127.0.0.1:1".into(),
                    session_limit: Duration::from_secs(20),
                    limits,
                    concurrency: 64,
                    slots: Arc::new(tokio::sync::Semaphore::new(64)),
                    relay_tls: crate::relay::verifier::tls_config(rustls::RootCertStore::empty()).unwrap(),
                },
                Mutex::new(Sessions::restore(store, records).unwrap()),
            ))
        };
        let s = open(&dir.0);
        let expires = now_ms() + 60_000;
        let web = |attempt: u32| CreateRequest { attempt: attempt.to_string(), ..job(payload("https://example.com/", 5, 10 << 20), expires) };
        for attempt in 1..=4 {
            assert_eq!(create(State(s.clone()), headers(), Json(web(attempt))).await.0, StatusCode::CREATED, "web {attempt}");
        }
        assert_eq!(create(State(s.clone()), headers(), Json(web(5))).await.0, StatusCode::SERVICE_UNAVAILABLE);
        let codex = CreateRequest { attempt: "codex".into(), ..job(json!({"type":"response.create","model":"synthetic-model"}), expires) };
        assert_eq!(create(State(s.clone()), headers(), Json(codex)).await.0, StatusCode::SERVICE_UNAVAILABLE);
        // Expired web receipts stay ten minutes, then leave, in a purge or on restart.
        {
            let mut sessions = s.1.lock().unwrap();
            let mut age = |sessions: &mut Sessions, attempt: &str, age: u64| {
                let key = job_key("synthetic", attempt);
                sessions.by_job.get_mut(&key).unwrap().expires_ms = now_ms() - age;
                sessions.commit(&key).unwrap();
            };
            age(&mut sessions, "1", verifier_store::WEB_RETENTION_MS + 1);
            age(&mut sessions, "2", verifier_store::WEB_RETENTION_MS - 60_000);
            sessions.purge().unwrap();
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
            body_base64: body.map(|b| STANDARD.encode(b)),
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
        }
    }

    #[test]
    fn malformed_web_receipts_cannot_restore() {
        let (kind, _) = kind(&payload("https://example.com/", 2, 1000), true).unwrap();
        let good = || Status::WebRead {
            remaining_sessions: 1,
            complete: true,
            next_url: None,
            hops: vec![valid_hop(0, "https://example.com/", 301, Some("https://www.example.com/"), None), valid_hop(1, "https://www.example.com/", 200, None, Some(b"page"))],
            rejections: vec![],
        };
        assert!(validate_receipt(&kind, &good(), 0).is_ok());
        let pending = Status::WebRead { remaining_sessions: 2, complete: false, next_url: Some("https://www.example.com/".into()), hops: vec![valid_hop(0, "https://example.com/", 301, Some("https://www.example.com/"), None)], rejections: vec![] };
        assert!(validate_receipt(&kind, &pending, 0).is_ok());
        let Status::WebRead { next_url, hops, .. } = &pending else { unreachable!() };
        let in_flight = Status::WebRead { remaining_sessions: 1, complete: false, next_url: next_url.clone(), hops: hops.clone(), rejections: vec![] };
        assert!(validate_receipt(&kind, &in_flight, 1).is_ok());
        fn edit(status: &mut Status) -> (&mut usize, &mut bool, &mut Option<String>, &mut Vec<WebHop>, &mut Vec<String>) {
            let Status::WebRead { remaining_sessions, complete, next_url, hops, rejections } = status else { unreachable!() };
            (remaining_sessions, complete, next_url, hops, rejections)
        }
        let mutations: Vec<(&str, Box<dyn Fn(&mut Status)>)> = vec![
            ("count", Box::new(|s| *edit(s).0 = 2)),
            ("broken chain", Box::new(|s| edit(s).3[1].url = "https://example.com/other".into())),
            ("index", Box::new(|s| edit(s).3[1].index = 2)),
            ("first url", Box::new(|s| edit(s).3[0].url = "https://example.com/x".into())),
            ("body on a redirect", Box::new(|s| edit(s).3[0].body_base64 = Some(String::new()))),
            ("no final body", Box::new(|s| edit(s).3[1].body_base64 = None)),
            ("body hash", Box::new(|s| edit(s).3[1].body_sha256 = hex(&Sha256::digest(b"other")))),
            ("body size", Box::new(|s| edit(s).3[1].body_bytes = 5)),
            ("too large", Box::new(|s| edit(s).3[1].received_bytes = 1001)),
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
            ("unknown rejection", Box::new(|s| {
                let (remaining, complete, _, hops, rejections) = edit(s);
                (*remaining, *complete) = (1, false);
                hops.pop();
                rejections.push("made_up".into());
            })),
            ("complete and rejected", Box::new(|s| {
                *edit(s).0 = 0;
                edit(s).4.push("tls_failed".into());
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
            rejections.push("tls_failed".into());
        }
        assert!(validate_receipt(&kind, &rejected, 0).is_ok());
        // A redirect that could not be followed ends the chain with its reason.
        let mut refused = valid_hop(0, "https://example.com/", 302, None, Some(b""));
        refused.location_refused = Some("insecure".into());
        let ended = |hop: WebHop| Status::WebRead { remaining_sessions: 2, complete: true, next_url: None, hops: vec![hop], rejections: vec![] };
        assert!(validate_receipt(&kind, &ended(refused.clone()), 0).is_ok());
        refused.location_refused = Some("because".into());
        assert!(validate_receipt(&kind, &ended(refused), 0).is_err());
        assert!(validate_receipt(&kind, &good(), 1).is_err());
        assert!(validate_receipt(&Kind::Codex, &good(), 0).is_err());
    }

    /// The whole `relay-web` input path: stdin JSON, a CONNECT proxy to the
    /// checked address, a plaintext loopback verifier, and the summary.
    #[tokio::test]
    async fn relay_web_runs_a_hop_through_a_connect_proxy() {
        let origin = web_origin(routes(&[("example.com/", PAGE, End::Wait)]), false).await;
        let s = shared(origin.roots.clone(), None);
        let token = register(&s, payload("https://example.com/", 5, 10 << 20)).await;
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
            "payload": payload("https://example.com/", 5, 10 << 20), "timeout_ms": 20000
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
    }.validate()?;
    let concurrency = bounded_env("SCARLETT_VERIFIER_CONCURRENCY", 64, 1, 256)? as usize;
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
    let shared: Shared = Arc::new((Config { key, upstream, session_limit: Duration::from_secs(limit), limits, concurrency, slots: Arc::new(tokio::sync::Semaphore::new(concurrency)), relay_tls }, Mutex::new(sessions)));
    let cleanup = shared.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            if cleanup.1.lock().unwrap().purge().is_err() {
                eprintln!("verifier state unavailable");
            }
        }
    });

    let router =
        Router::new().route("/v1/sessions", post(create)).route("/v1/sessions/{job_id}/{attempt}", get(status)).route("/v1/capacity", get(capacity)).with_state(shared.clone());
    let api_listener = TcpListener::bind(&api).await.with_context(|| format!("binding {api}"))?;
    tokio::spawn(async move {
        if let Err(e) = axum::serve(api_listener, router).await {
            eprintln!("verifier API stopped: {e}");
        }
    });

    let listener = TcpListener::bind(&listen).await.with_context(|| format!("binding {listen}"))?;
    println!("verifier: sessions on {listen}, API on {api}, upstream {}", shared.0.upstream);
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
    if sessions.failed || sessions.purge().is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"verifier state unavailable"})));
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
    // its hop commits, so a job that could outgrow the record limit is refused now.
    if let Kind::Web(job) = &kind
        && durable
        && web_receipt_bound(job) > config.limits.max_record_bytes
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
    // A web job reserves its own receipt bound, so web registrations are not
    // limited by the larger reservation X and Codex receipts need.
    if sessions.by_job.len() >= config.limits.max_records || sessions.store.as_ref().is_some_and(|store| !store.can_reserve(&request.payload)) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"verifier session capacity reached"})));
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
    let sessions = shared.1.lock().unwrap();
    let storage = sessions.store.as_ref().map(Store::capacity);
    (if sessions.failed { StatusCode::SERVICE_UNAVAILABLE } else { StatusCode::OK }, Json(serde_json::json!({
        "healthy": !sessions.failed, "durable": sessions.store.is_some(), "concurrency":shared.0.concurrency,
        "records":sessions.by_job.len(), "storage":storage, "limits":shared.0.limits,
        "active_connections":shared.0.concurrency - shared.0.slots.available_permits(),
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
    let (key, job, expires) = {
        let mut guard = sessions.lock().unwrap();
        let s = &mut *guard;
        if s.failed {
            bail!("verifier state unavailable");
        }
        let key = s.by_token.get(token).cloned().context("unknown or used session token")?;
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
                let Status::WebRead { remaining_sessions, complete, next_url, hops, rejections } = &mut entry.status else {
                    bail!("session is in an unexpected state")
                };
                // Hops run one at a time, and none after the job has ended.
                if entry.in_flight > 0 || *complete || !rejections.is_empty() || *remaining_sessions == 0 {
                    bail!("web session cannot start a hop now");
                }
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
        (key, job, expires)
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
            let host = webpolicy::url_host(&url).to_owned();
            let request = webpolicy::request(&url, &web.headers);
            let started_at_ms = now_ms();
            let concluded = AtomicBool::new(false);
            // Runs once the supplier holds the record opening: the hop is
            // durable before the supplier learns the next URL.
            let conclude = |outcome: &WebOutcome| -> Result<Vec<u8>> {
                let response = &outcome.response;
                let (location, location_refused) = match response.location() {
                    Some(location) if webpolicy::REDIRECTS.contains(&response.status) => match location.and_then(|l| webpolicy::resolve_location(&url, l)) {
                        Ok(next) => (Some(next), None),
                        Err(refused) => (None, Some(refused.code().to_owned())),
                    },
                    _ => (None, None),
                };
                let is_final = location.is_none() || index == web.max_redirects;
                let hop = WebHop {
                    index,
                    url: url.clone(),
                    status_code: response.status,
                    location: location.clone(),
                    location_refused,
                    head_base64: STANDARD.encode(&response.head),
                    body_base64: is_final.then(|| STANDARD.encode(&response.body)),
                    body_bytes: response.body.len(),
                    body_sha256: verifier_store::hash(&response.body),
                    response_sha256: hex(&response.response_sha256),
                    framing: response.framing.name().into(),
                    sent_bytes: outcome.sent.len(),
                    received_bytes: response.received,
                    server_name: host.clone(),
                    tls_version: WEB_TLS_VERSION.into(),
                    cipher_suite: WEB_CIPHER_SUITE.into(),
                    alpn: outcome.tls.alpn.clone(),
                    cert_chain_sha256: hex(&outcome.tls.cert_chain_sha256),
                    leaf_cert_sha256: hex(&outcome.tls.leaf_cert_sha256),
                    started_at_ms,
                    duration_ms: started.elapsed().as_millis() as u64,
                };
                let next_url = (!is_final).then_some(location).flatten();
                let frame = serde_json::to_vec(&HopOutcome { hop: index, url: &url, status_code: response.status, is_final, next_url: next_url.as_deref() })?;
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
                concluded.store(true, Ordering::SeqCst);
                println!("verifier: job {job_id} proved web hop {index} (HTTP {})", response.status);
                Ok(frame)
            };
            let hop = crate::relay::verifier::run_web(socket, config.relay_tls.clone(), &host, &request, web.max_response_bytes, conclude);
            let result = tokio::time::timeout(limit.min(webpolicy::HOP_LIMIT), hop).await;
            if concluded.load(Ordering::SeqCst) {
                return Ok(());
            }
            // Only the reason is logged: never the URL, host or anything the page said.
            let reason = match &result {
                Ok(Err(e)) => Failure::of(e).reason(),
                Ok(Ok(_)) => Failure::ProofRejected.reason(),
                Err(_) => "session_timeout",
            };
            println!("verifier: job {job_id} web hop {index} failed: {reason}");
            let mut guard = sessions.lock().unwrap();
            let s = &mut *guard;
            if s.failed {
                bail!("verifier state unavailable");
            }
            if let Some(Entry { status: Status::WebRead { next_url, rejections, .. }, in_flight, .. }) = s.by_job.get_mut(&key) {
                *in_flight = 0;
                *next_url = None;
                rejections.push(reason.into());
                s.by_token.retain(|_, k| *k != key);
                s.commit(&key)?;
            }
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
