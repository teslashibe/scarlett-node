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
    xpolicy::{self, Exchange, Spec, ProofMode},
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
    x_proxy_experiment: bool,
    x_batch_experiment: bool,
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
    X(Arc<Vec<Spec>>),
}

struct Entry {
    payload: Value,
    kind: Kind,
    expires: Instant,
    status: Status,
    expires_ms: u64,
    fence: String,
    /// Logical attempts reserved before execution; a batch connection owns two.
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
        if durable && (specs.len() > 3 || max != specs.len()) {
            bail!("durable X jobs require 1-3 exchanges with one attempt each");
        }
        let pending = (0..specs.len()).collect();
        Ok((
            Kind::X(Arc::new(specs)),
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
        (Kind::X(specs), Status::XRead { remaining_attempts, complete, pending, exchanges, rejections }) => {
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

fn validate_batch_receipt(payload: &Value, status: &Status, in_flight: usize) -> Result<()> {
    if !xpolicy::batch(payload) { return Ok(()); }
    let Status::XRead { remaining_attempts, exchanges, rejections, .. } = status else {
        if matches!(status, Status::Expired) && in_flight == 0 { return Ok(()); }
        bail!("invalid batch receipt state");
    };
    match (*remaining_attempts, in_flight, exchanges.len() + rejections.len()) {
        (2, 0, 0) | (0, 2, 0) | (0, 0, 2) => Ok(()),
        _ => bail!("invalid batch logical attempt reservation"),
    }
}

fn reserve_x(entry: &mut Entry, batch: bool) -> Result<usize> {
    let reads = if batch { xpolicy::BATCH_READS } else { 1 };
    let Status::XRead { remaining_attempts, complete, .. } = &mut entry.status else { bail!("session is in an unexpected state"); };
    if *complete || *remaining_attempts < reads || batch && entry.in_flight != 0 { bail!("x.read session has no attempts left"); }
    *remaining_attempts -= reads;
    entry.in_flight += reads;
    Ok(reads)
}

/// Atomic completion of exactly the two reserved reads. Transcript failure
/// rejects both; HTTP failures or exact-request mismatches remain per read.
fn finish_x_batch(entry: &mut Entry, specs: &[Spec], result: Result<Vec<(Exchange, usize, usize)>, String>, duration_ms: u64) -> Result<()> {
    validate_batch_receipt(&entry.payload, &entry.status, entry.in_flight)?;
    if entry.in_flight != xpolicy::BATCH_READS { bail!("batch reservation missing"); }
    let Status::XRead { complete, pending, exchanges, rejections, .. } = &mut entry.status else { bail!("batch status missing"); };
    let outcomes = match result {
        Ok(values) if values.len() == xpolicy::BATCH_READS => values.into_iter().map(Ok).collect(),
        Ok(_) => vec![Err("proof_rejected".into()); xpolicy::BATCH_READS],
        Err(reason) => vec![Err(reason); xpolicy::BATCH_READS],
    };
    for (expected, value) in outcomes.into_iter().enumerate() {
        let matched = value.and_then(|(exchange, sent_bytes, received_bytes)| {
            let (fulfilled, cursors) = xpolicy::outcome(&exchange);
            let done: Vec<_> = exchanges.iter().filter(|r| r.fulfilled).map(|r| (r.index, &r.exchange, r.cursors.as_slice())).collect();
            let index = xpolicy::assign(specs, &done, &exchange).map_err(|_| "exchange_mismatch".to_owned())?;
            if index != expected { return Err("exchange_mismatch".into()); }
            Ok(XRecord { index, fulfilled, exchange, cursors, sent_bytes, received_bytes, duration_ms })
        });
        match matched {
            Ok(record) => {
                if record.fulfilled { pending.retain(|&i| i != record.index); }
                exchanges.push(record);
            }
            Err(reason) => rejections.push(reason),
        }
    }
    *complete = pending.is_empty();
    entry.in_flight = 0;
    validate_receipt(&entry.kind, &entry.status, 0)?;
    validate_batch_receipt(&entry.payload, &entry.status, 0)
}
impl Sessions {
    fn restore(store: Store, records: Vec<Record>) -> Result<Self> {
        let mut s = Self { store: Some(store), ..Self::default() };
        let now = now_ms();
        for r in records {
            if r.expires_ms > now.saturating_add(MAX_TTL.as_millis() as u64) {
                bail!("verifier receipt expiry exceeds the session bound");
            }
            if r.in_flight == 0 && r.status["reason"] != "execution_uncertain" && !r.status["rejections"].as_array().is_some_and(|v| v.iter().any(|reason| reason == "execution_uncertain")) && now > r.expires_ms.saturating_add(verifier_store::RETENTION_MS) {
                s.store.as_mut().unwrap().remove(&r.job_id, &r.attempt)?;
                continue;
            }
            let (kind, _) = kind(&r.payload, true)?;
            let mut status: Status = serde_json::from_value(r.status)?;
            validate_receipt(&kind, &status, r.in_flight)?;
            validate_batch_receipt(&r.payload, &status, r.in_flight)?;
            let mut token = r.token;
            if r.in_flight > 0 || matches!(status, Status::Running) {
                if xpolicy::batch(&r.payload) {
                    let Status::XRead { rejections, .. } = &mut status else { bail!("invalid batch recovery state"); };
                    // Each reserved read stays spent. No proof result exists after
                    // an interrupted connection, so neither read can be fulfilled.
                    rejections.extend((0..r.in_flight).map(|_| "execution_uncertain".into()));
                    validate_receipt(&kind, &status, 0)?;
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
            .filter(|(_, e)| e.in_flight == 0 && !matches!(&e.status, Status::Rejected { reason } if reason == "execution_uncertain") && !matches!(&e.status, Status::XRead { rejections, .. } if rejections.iter().any(|r| r == "execution_uncertain")) && now > e.expires_ms.saturating_add(retention))
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
                x_proxy_experiment: false,
                x_batch_experiment: false,
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
    fn batch_request(expires: u64) -> CreateRequest {
        let mut r = request(expires);
        r.payload = json!({"type":"x.read", "proof_mode":"mpc", "proof_policy":xpolicy::BATCH_EXPERIMENT_POLICY, "max_attempts":2, "exchanges":[
            {"operation":"UserByScreenName","query_id":"fixture_profile","variables":{"screen_name":"jack"},"features":{}},
            {"operation":"TweetResultByRestId","query_id":"fixture_post","variables":{"tweetId":"20"},"features":{}}
        ]});
        r
    }
    fn batch_values(specs: &[Spec]) -> Vec<(Exchange, usize, usize)> {
        specs.iter().map(|s| (Exchange { operation:s.operation.clone(), query_id:s.query_id.clone(), variables:s.variables.clone(), features:Some(s.features.clone()), field_toggles:s.field_toggles.clone(), http_status:200, body:"{\"data\":{\"synthetic\":true}}".into() }, 100, 100)).collect()
    }
    #[test]
    fn batch_receipt_rejects_a_half_reserved_connection() {
        let payload=batch_request(now_ms()+30_000).payload;
        let (kind,mut status)=kind(&payload,true).unwrap();
        let Status::XRead { remaining_attempts,.. }=&mut status else { panic!("X required") };
        *remaining_attempts=1;
        // The ordinary conserved count alone cannot bind one connection to two reads.
        validate_receipt(&kind,&status,1).unwrap();
        assert!(validate_batch_receipt(&payload,&status,1).is_err());
    }
    #[tokio::test]
    async fn batch_requires_server_flag_and_durable_store() {
        let dir = Temp::new();
        let mut s = shared(&dir.0);
        assert_eq!(create(State(s.clone()), headers(), Json(batch_request(now_ms()+30_000))).await.0, StatusCode::BAD_REQUEST);
        Arc::get_mut(&mut s).unwrap().0.x_batch_experiment = true;
        assert_eq!(create(State(s.clone()), headers(), Json(batch_request(now_ms()+30_000))).await.0, StatusCode::CREATED);
        let (_, Json(view)) = status(State(s.clone()), headers(), Path(("synthetic".into(),"1".into()))).await;
        assert_eq!(view["proof_mode"], "mpc");
        assert_eq!(view["proof_policy"], xpolicy::BATCH_EXPERIMENT_POLICY);
        assert_eq!(view["remaining_attempts"], 2);
        assert!(s.1.lock().unwrap().by_token.len() == 1);
        // Even an enabled experimental flag cannot make volatile accounting eligible.
        let volatile_dir = Temp::new();
        let mut volatile = shared(&volatile_dir.0);
        Arc::get_mut(&mut volatile).unwrap().0.x_batch_experiment = true;
        volatile.1.lock().unwrap().store = None;
        assert_eq!(create(State(volatile), headers(), Json(batch_request(now_ms()+30_000))).await.0, StatusCode::BAD_REQUEST);
    }
    #[tokio::test]
    async fn batch_reserves_both_reads_before_execution_and_crash_spends_both() {
        let dir = Temp::new();
        let mut s = shared(&dir.0);
        Arc::get_mut(&mut s).unwrap().0.x_batch_experiment = true;
        let (_, Json(created)) = create(State(s.clone()), headers(), Json(batch_request(now_ms()+30_000))).await;
        let token = created["token"].as_str().unwrap().to_owned();
        let key = job_key("synthetic","1");
        {
            let mut sessions = s.1.lock().unwrap();
            let entry = sessions.by_job.get_mut(&key).unwrap();
            assert_eq!(reserve_x(entry, true).unwrap(),2);
            assert!(reserve_x(entry, true).is_err(), "concurrent batch reused reservation");
            validate_receipt(&entry.kind, &entry.status, 2).unwrap();
            sessions.by_token.remove(&token);
            sessions.commit(&key).unwrap();
        }
        drop(s);
        let s = shared(&dir.0);
        {
            let sessions = s.1.lock().unwrap();
            assert!(sessions.by_token.is_empty());
            let entry = &sessions.by_job[&key];
            validate_receipt(&entry.kind, &entry.status, 0).unwrap();
            assert!(matches!(&entry.status, Status::XRead { complete:false, remaining_attempts:0, rejections, exchanges, .. } if rejections == &["execution_uncertain","execution_uncertain"] && exchanges.is_empty()));
        }
        {
            let mut sessions=s.1.lock().unwrap();
            let entry=sessions.by_job.get_mut(&key).unwrap();
            entry.expires=Instant::now();
            entry.expires_ms=now_ms()-verifier_store::RETENTION_MS-1;
            sessions.commit(&key).unwrap();
            sessions.purge().unwrap();
            assert_eq!(sessions.by_job.len(),1,"uncertain batch receipt was discarded");
        }
        let (_,Json(view))=status(State(s.clone()),headers(),Path(("synthetic".into(),"1".into()))).await;
        assert_eq!(view["rejections"],json!(["execution_uncertain","execution_uncertain"]));
        drop(s);
        let mut s = shared(&dir.0);
        Arc::get_mut(&mut s).unwrap().0.x_batch_experiment = true;
        assert!(s.1.lock().unwrap().by_token.is_empty(), "second restart restored spent token");
        assert_eq!(create(State(s), headers(), Json(batch_request(now_ms()+30_000))).await.0, StatusCode::CONFLICT);
    }
    #[tokio::test]
    async fn batch_conserves_partial_http_failure_mismatch_and_protocol_failure() {
        for failure in ["none","http","mismatch","protocol","truncated"] {
            let dir = Temp::new();
            let mut s = shared(&dir.0);
            Arc::get_mut(&mut s).unwrap().0.x_batch_experiment = true;
            assert_eq!(create(State(s.clone()), headers(), Json(batch_request(now_ms()+30_000))).await.0, StatusCode::CREATED);
            let key = job_key("synthetic","1");
            {
                let mut sessions = s.1.lock().unwrap();
                let entry = sessions.by_job.get_mut(&key).unwrap();
                let Kind::X(specs) = &entry.kind else { panic!("expected X"); };
                let specs = specs.clone();
                reserve_x(entry,true).unwrap();
                sessions.by_token.clear();
                sessions.commit(&key).unwrap();
                let mut values = batch_values(&specs);
                if failure == "http" { values[1].0.http_status=429; }
                if failure == "mismatch" { values[1].0.variables["tweetId"]=json!("21"); }
                if failure == "truncated" { values.pop(); }
                let result = if failure == "protocol" { Err("proof_rejected".into()) } else { Ok(values) };
                let entry = sessions.by_job.get_mut(&key).unwrap();
                finish_x_batch(entry,&specs,result,1).unwrap();
                let Status::XRead { complete, remaining_attempts, exchanges,rejections,.. } = &entry.status else { panic!("expected X status"); };
                assert_eq!(*remaining_attempts,0);
                assert_eq!(exchanges.len()+rejections.len(),2);
                assert_eq!(*complete,failure == "none");
                if failure == "http" { assert_eq!(exchanges.len(),2); assert!(!exchanges[1].fulfilled); }
                if failure == "mismatch" { assert_eq!(exchanges.len(),1); assert_eq!(rejections.len(),1); }
                if failure == "protocol" || failure == "truncated" { assert_eq!(rejections.len(),2); }
                sessions.commit(&key).unwrap();
            }
            drop(s);
            let s=shared(&dir.0);
            let sessions=s.1.lock().unwrap();
            let entry=&sessions.by_job[&key];
            validate_receipt(&entry.kind,&entry.status,0).unwrap();
            validate_batch_receipt(&entry.payload,&entry.status,0).unwrap();
            assert!(sessions.by_token.is_empty());
        }
    }
    #[tokio::test]
    async fn batch_connection_failure_spends_two_and_token_replay_fails() {
        use tokio::io::AsyncWriteExt;
        let dir=Temp::new();
        let mut s=shared(&dir.0);
        Arc::get_mut(&mut s).unwrap().0.x_batch_experiment=true;
        Arc::get_mut(&mut s).unwrap().0.session_limit=Duration::from_secs(1);
        let (_,Json(created))=create(State(s.clone()),headers(),Json(batch_request(now_ms()+30_000))).await;
        let token=created["token"].as_str().unwrap();
        let (socket,mut peer)=tokio::io::duplex(128);
        peer.write_all(format!("{token}\n").as_bytes()).await.unwrap();
        peer.write_all(xpolicy::BATCH_PREFACE).await.unwrap();
        let task=tokio::spawn(handle(s.clone(),Box::new(socket)));
        let mut ack=vec![0;xpolicy::BATCH_ACK.len()];
        tokio::time::timeout(Duration::from_secs(5),peer.read_exact(&mut ack)).await.unwrap().unwrap();
        assert_eq!(ack,xpolicy::BATCH_ACK);
        // Acknowledgement follows the durable reservation, before crypto starts.
        let name=format!("{}.json",verifier_store::hash(b"synthetic\n1"));
        let stored:Record=serde_json::from_slice(&fs::read(dir.0.join(name)).unwrap()).unwrap();
        assert_eq!(stored.in_flight,2);
        assert_eq!(stored.status["remaining_attempts"],0);
        assert!(stored.token.is_none());
        let (_,Json(capacity))=capacity(State(s.clone()),headers()).await;
        assert_eq!(capacity["in_flight_proofs"],1);
        assert_eq!(capacity["in_flight_attempts"],2);
        drop(peer);
        task.await.unwrap().unwrap();
        let (_,Json(view))=status(State(s.clone()),headers(),Path(("synthetic".into(),"1".into()))).await;
        assert_eq!(view["remaining_attempts"],0);
        let rejected=view["rejections"].as_array().unwrap();
        assert_eq!(rejected.len(),2);
        assert_eq!(rejected[0],rejected[1]);
        assert!(rejected[0]=="proof_rejected" || rejected[0]=="session_timeout");
        assert_eq!(view["complete"],false);
        let (socket,mut peer)=tokio::io::duplex(128);
        peer.write_all(format!("{token}\n").as_bytes()).await.unwrap();
        assert!(handle(s,Box::new(socket)).await.is_err());
    }
    #[tokio::test]
    async fn failed_batch_reservation_never_acknowledges_and_storage_failure_hides_success() {
        use tokio::io::AsyncWriteExt;
        for fail_at_reservation in [true,false] {
            let dir=Temp::new();
            let mut s=shared(&dir.0);
            Arc::get_mut(&mut s).unwrap().0.x_batch_experiment=true;
            let (_,Json(created))=create(State(s.clone()),headers(),Json(batch_request(now_ms()+30_000))).await;
            let key=job_key("synthetic","1");
            if fail_at_reservation {
                fs::rename(&dir.0,dir.0.with_extension("moved")).unwrap();
                let (socket,mut peer)=tokio::io::duplex(128);
                peer.write_all(format!("{}\n",created["token"].as_str().unwrap()).as_bytes()).await.unwrap();
                peer.write_all(xpolicy::BATCH_PREFACE).await.unwrap();
                assert!(handle(s.clone(),Box::new(socket)).await.is_err());
                let mut ack=[0;1];
                assert_eq!(peer.read(&mut ack).await.unwrap(),0,"failed reservation acknowledged provider eligibility");
            } else {
                let mut sessions=s.1.lock().unwrap();
                reserve_x(sessions.by_job.get_mut(&key).unwrap(),true).unwrap();
                sessions.by_token.clear();
                sessions.commit(&key).unwrap();
                let entry=sessions.by_job.get_mut(&key).unwrap();
                let Kind::X(specs)=&entry.kind else {panic!("X required")};
                let specs=specs.clone();
                finish_x_batch(entry,&specs,Ok(batch_values(&specs)),1).unwrap();
                fs::rename(&dir.0,dir.0.with_extension("moved")).unwrap();
                assert!(sessions.commit(&key).is_err());
            }
            assert_eq!(status(State(s.clone()),headers(),Path(("synthetic".into(),"1".into()))).await.0,StatusCode::SERVICE_UNAVAILABLE);
            fs::rename(dir.0.with_extension("moved"),&dir.0).unwrap();
        }
    }
    #[tokio::test]
    async fn x_proxy_registration_is_explicitly_gated_and_bound_to_receipt() {
        let dir = Temp::new();
        let mut s = shared(&dir.0);
        let expires = now_ms() + 30_000;
        let mut r = request(expires);
        let lease: Value = serde_json::from_str(include_str!("../../api/fixtures/lease-x.json")).unwrap();
        r.payload = lease["x_payload"].clone();
        r.payload["proof_mode"] = json!("proxy");
        r.payload["proof_policy"] = json!(xpolicy::PROXY_EXPERIMENT_POLICY);
        let expected_hash = verifier_store::hash(&serde_json::to_vec(&r.payload).unwrap());
        assert_eq!(create(State(s.clone()), headers(), Json(r)).await.0, StatusCode::BAD_REQUEST);
        assert!(s.1.lock().unwrap().by_job.is_empty());
        Arc::get_mut(&mut s).unwrap().0.x_proxy_experiment = true;
        let mut r = request(expires);
        r.payload = lease["x_payload"].clone();
        r.payload["proof_mode"] = json!("proxy");
        r.payload["proof_policy"] = json!(xpolicy::PROXY_EXPERIMENT_POLICY);
        assert_eq!(create(State(s.clone()), headers(), Json(r)).await.0, StatusCode::CREATED);
        let (code, Json(receipt)) = status(State(s), headers(), Path(("synthetic".into(), "1".into()))).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(receipt["proof_mode"], "proxy");
        assert_eq!(receipt["proof_policy"], xpolicy::PROXY_EXPERIMENT_POLICY);
        assert_eq!(receipt["request_sha256"], expected_hash);
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
    let x_proxy_experiment = bounded_env("SCARLETT_VERIFIER_X_PROXY_EXPERIMENT", 0, 0, 1)? == 1;
    let x_batch_experiment = bounded_env("SCARLETT_VERIFIER_X_BATCH_EXPERIMENT", 0, 0, 1)? == 1;
    let sessions = if let Ok(dir) = env::var("SCARLETT_VERIFIER_STATE_DIR") {
        let (store, records) = Store::open_with_limits(std::path::Path::new(&dir), limits)?;
        Sessions::restore(store, records)?
    } else {
        Sessions::default()
    };
    if !x_proxy_experiment && sessions.by_job.values().any(|entry| entry.payload["type"] == "x.read" && xpolicy::proof_mode(&entry.payload).ok() == Some(ProofMode::Proxy)) {
        bail!("experimental X Proxy receipts require the experiment verifier");
    }
    if !x_batch_experiment && sessions.by_job.values().any(|entry| xpolicy::batch(&entry.payload)) {
        bail!("experimental X batch receipts require the experiment verifier");
    }
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
    let shared: Shared = Arc::new((Config { key, upstream, session_limit: Duration::from_secs(limit), limits, concurrency, slots: Arc::new(tokio::sync::Semaphore::new(concurrency)), x_proxy_experiment, x_batch_experiment }, Mutex::new(sessions)));
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
    if request.payload["type"] == "x.read" && xpolicy::proof_mode(&request.payload).ok() == Some(ProofMode::Proxy) && !config.x_proxy_experiment {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"X Proxy experiments are disabled"})));
    }
    if xpolicy::batch(&request.payload) && (!config.x_batch_experiment || !durable) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"X batch experiments require an enabled durable verifier"})));
    }
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
        "in_flight_proofs":sessions.by_job.values().map(|entry| if xpolicy::batch(&entry.payload) { entry.in_flight / xpolicy::BATCH_READS } else { entry.in_flight }).sum::<usize>(),
        "in_flight_attempts":sessions.by_job.values().map(|entry| entry.in_flight).sum::<usize>(),
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
        Status::Pending if Instant::now() >= entry.expires => Status::Expired,
        Status::XRead { complete: false, remaining_attempts, .. } if Instant::now() >= entry.expires && (!xpolicy::batch(&entry.payload) || remaining_attempts > 0) => Status::Expired,
        ref other => other.clone(),
    };
    let mut response = serde_json::to_value(status).unwrap_or_default();
    response["durable"] = sessions.store.is_some().into();
    response["job_id"] = job_id.into();
    response["attempt"] = attempt.into();
    response["fence"] = entry.fence.clone().into();
    response["expires_at_ms"] = entry.expires_ms.into();
    response["request_sha256"] = verifier_store::hash(&serde_json::to_vec(&entry.payload).unwrap_or_default()).into();
    if entry.payload["type"] == "x.read" && xpolicy::proof_mode(&entry.payload).ok() == Some(ProofMode::Proxy) {
        response["proof_mode"] = "proxy".into();
        response["proof_policy"] = xpolicy::PROXY_EXPERIMENT_POLICY.into();
    }
    if xpolicy::batch(&entry.payload) {
        response["proof_mode"] = "mpc".into();
        response["proof_policy"] = xpolicy::BATCH_EXPERIMENT_POLICY.into();
    }
    (StatusCode::OK, Json(response))
}

enum Job {
    Codex(Value),
    X(Arc<Vec<Spec>>, ProofMode, bool),
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
        let durable = s.store.is_some();
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
                entry.in_flight += 1;
                Job::Codex(entry.payload.clone())
            }
            Kind::X(specs) => {
                let mode = xpolicy::proof_mode(&entry.payload)?;
                if mode == ProofMode::Proxy && !config.x_proxy_experiment { bail!("X Proxy experiments are disabled"); }
                let batch = xpolicy::batch(&entry.payload);
                if batch && (!config.x_batch_experiment || !durable) { bail!("X batch experiments are disabled"); }
                let specs = specs.clone();
                reserve_x(entry, batch)?;
                if matches!(entry.status, Status::XRead { remaining_attempts: 0, .. }) {
                    s.by_token.remove(token);
                }
                Job::X(specs, mode, batch)
            }
        };
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
        Job::X(specs, mode, batch) => {
            if batch {
                let result = match tokio::time::timeout(limit, verify_x_batch(socket)).await {
                    Ok(Ok(values)) => Ok(values),
                    Ok(Err(_)) => Err("proof_rejected".into()),
                    Err(_) => Err("session_timeout".into()),
                };
                let mut s = sessions.lock().unwrap();
                if s.failed { bail!("verifier state unavailable"); }
                let entry = s.by_job.get_mut(&key).context("batch session missing")?;
                let result = if Instant::now() >= entry.expires { Err("session_expired".into()) } else { result };
                finish_x_batch(entry, &specs, result, started.elapsed().as_millis() as u64)?;
                s.by_token.retain(|_, value| value != &key);
                s.commit(&key)?;
                return Ok(());
            }
            let outcome = match tokio::time::timeout(limit, verify_x(socket, mode)).await {
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

/// Returns the verified exchange and the transcript's sent and received sizes.
async fn verify_x(socket: crate::control::Socket, mode: ProofMode) -> Result<(Exchange, usize, usize)> {
    // Proxy's destination is fixed here, never accepted from supplier input.
    let upstream = (mode == ProofMode::Proxy).then_some("x.com:443");
    let (server_name, transcript) = prove_session(socket, upstream).await?;
    let sent_hidden: Vec<_> = transcript.sent_unauthed().iter().collect();
    let received_hidden: Vec<_> = transcript.received_unauthed().iter().collect();
    let (sent, received) = (transcript.sent_unsafe(), transcript.received_unsafe());
    if sent.len() > MAX_SENT || received.len() > MAX_RECV { bail!("X transcript exceeds its limits"); }
    let exchange = xpolicy::check(&server_name, sent, &sent_hidden, received, &received_hidden)?;
    Ok((exchange, sent.len(), received.len()))
}

async fn verify_x_batch(socket: crate::control::Socket) -> Result<Vec<(Exchange, usize, usize)>> {
    let mut socket = socket;
    let mut preface = vec![0; xpolicy::BATCH_PREFACE.len()];
    socket.read_exact(&mut preface).await?;
    if preface != xpolicy::BATCH_PREFACE { bail!("missing experimental batch preface"); }
    tokio::io::AsyncWriteExt::write_all(&mut socket, xpolicy::BATCH_ACK).await?;
    let (server_name, transcript) = prove_session(socket, None).await?;
    let sent_hidden: Vec<_> = transcript.sent_unauthed().iter().collect();
    let received_hidden: Vec<_> = transcript.received_unauthed().iter().collect();
    let (sent, received) = (transcript.sent_unsafe(), transcript.received_unsafe());
    if sent.len() > MAX_SENT || received.len() > MAX_RECV { bail!("X batch transcript exceeds its limits"); }
    xpolicy::check_batch(&server_name, sent, &sent_hidden, received, &received_hidden)
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
