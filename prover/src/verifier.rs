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
//! SESSION_TIMEOUT_SECS (default 300). Optional SCARLETT_VERIFIER_STATE_DIR
//! enables private durable receipts and requires absolute expiry/fence bindings.

use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
    verifier_store::{self, Record, Store},
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
}

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
        _ => bail!("receipt status does not match the job"),
    }
}
impl Sessions {
    fn restore(store: Store, records: Vec<Record>) -> Result<Self> {
        let mut s = Self { store: Some(store), ..Self::default() };
        let now = now_ms();
        for r in records {
            if r.expires_ms > now.saturating_add(MAX_TTL.as_millis() as u64) {
                bail!("verifier receipt expiry exceeds the session bound");
            }
            if r.in_flight == 0 && r.status["reason"] != "execution_uncertain" && now > r.expires_ms.saturating_add(verifier_store::RETENTION_MS) {
                s.store.as_mut().unwrap().remove(&r.job_id, &r.attempt)?;
                continue;
            }
            let (kind, _) = kind(&r.payload, true)?;
            let mut status: Status = serde_json::from_value(r.status)?;
            validate_receipt(&kind, &status, r.in_flight)?;
            let mut token = r.token;
            if r.in_flight > 0 || matches!(status, Status::Running) {
                status = Status::Rejected { reason: "execution_uncertain".into() };
                token = None;
            }
            if let Status::XRead { exchanges, .. } = &mut status {
                for record in exchanges.iter_mut().filter(|r| r.fulfilled) {
                    record.cursors = xpolicy::outcome(&record.exchange).1;
                }
            }
            let reusable = matches!(&status, Status::Pending | Status::XRead { remaining_attempts: 1.., complete: false, .. });
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
        let retention = if self.store.is_some() { verifier_store::RETENTION_MS } else { MAX_TTL.as_millis() as u64 };
        let stale: Vec<_> = self
            .by_job
            .iter()
            .filter(|(_, e)| e.in_flight == 0 && !matches!(&e.status, Status::Rejected { reason } if reason == "execution_uncertain") && now > e.expires_ms.saturating_add(retention))
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
        let result = tokio::time::timeout(Duration::from_secs(30), crate::relay::node::session(node_end, tcp, &request())).await.unwrap();
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
    async fn a_job_must_name_the_relay_policy_exactly() {
        let x = server(response(), |_| {}).await;
        for mode in [("relay", None), ("relay", Some("x-relay-v2")), ("mpc", Some(crate::relay::POLICY)), ("proxy", None)] {
            let s = shared(x.roots.clone());
            assert_eq!(create(State(s), headers(), Json(job("jack", Some(mode)))).await.0, StatusCode::BAD_REQUEST, "{mode:?}");
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
    if sessions.by_job.len() >= config.limits.max_records || sessions.store.as_ref().is_some_and(|store| !store.capacity().can_register) {
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
            entry.status = Status::Expired;
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
                    ProofMode::Relay => relay_x(socket, config.relay_tls.clone(), &specs, &fulfilled).await.inspect_err(|e| println!("verifier: job {job_id} relay session failed: {e:#}")),
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
    }
    Ok(())
}

async fn verify(socket: crate::control::Socket, job: &Value, upstream: &str) -> Result<Verified> {
    let (server_name, transcript) = prove_session(socket, Some(upstream)).await?;
    let sent_hidden: Vec<_> = transcript.sent_unauthed().iter().collect();
    let received_hidden: Vec<_> = transcript.received_unauthed().iter().collect();
    policy::check(&server_name, transcript.sent_unsafe(), &sent_hidden, transcript.received_unsafe(), &received_hidden, job)
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
