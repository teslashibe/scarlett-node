//! Supplier side for X reads: send the exact request bytes to x.com over
//! MPC-TLS, so the node's own connection (and IP) reaches X while the assigned
//! verifier jointly holds the session keys. Only the session cookie and CSRF
//! token values are hidden.

use std::{
    future::IntoFuture,
    io,
    ops::Range,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{self, Poll, Waker},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};
use tlsn::{
    Session,
    config::{prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig, tls_commit::{mpc::{MpcTlsConfig, NetworkSetting}, proxy::ProxyTlsConfig}},
    connection::{DnsName, ServerName},
    webpki::RootCertStore,
};
use tokio::{
    io::{AsyncWriteExt as _, ReadBuf},
    net::TcpStream,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{
    policy::find,
    prove::Driver,
    xpolicy::{self, HOST, ProofMode},
};

/// Default and verifier-enforced ceiling on the bytes X may return.
pub const MAX_RECV: usize = 256 << 10;
pub const MAX_SENT: usize = 16 << 10;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MpcNetwork {
    ReduceBandwidth,
    ReduceRoundtrips,
}

impl MpcNetwork {
    fn setting(self) -> NetworkSetting {
        match self {
            Self::ReduceBandwidth => NetworkSetting::Latency,
            Self::ReduceRoundtrips => NetworkSetting::Bandwidth,
        }
    }
}

#[derive(Deserialize)]
pub struct Request {
    pub verifier: String,
    pub verifier_ca_file: Option<String>,
    pub verifier_server_name: Option<String>,
    #[serde(default)]
    pub plaintext_fixture: bool,
    pub token: String,
    /// Base64 of the complete HTTP/1.1 request, which must ask X to close the connection.
    pub request: String,
    pub max_recv: Option<usize>,
    #[serde(default)]
    pub proof_mode: ProofMode,
    pub max_sent_records: Option<usize>,
    pub max_recv_records_online: Option<usize>,
    /// Opt-in use of the pinned SDK's existing network tradeoff. Omission
    /// preserves its default low-bandwidth configuration.
    pub mpc_network: Option<MpcNetwork>,
    /// Known-job simulation only: fresh commit is kept alive before logical demand.
    #[serde(default)]
    pub prepare_hold_ms: u64,
    #[serde(default)]
    pub response_ready_event: bool,
    /// Opt-in private pipe delivery for an isolated buyer experiment. This is
    /// explicitly unverified data and never substitutes for the final proof.
    #[serde(default)]
    pub provisional_response: bool,
    /// Explicit isolated pipeline; the registered verifier policy owns eligibility.
    #[serde(default)]
    pub batch_reads: usize,
}

#[derive(Default, Serialize)]
pub struct Timings {
    pub control_connect: u128,
    pub commit: u128,
    pub request_write: u128,
    pub response_read: u128,
    pub tls_finish: u128,
    pub prove: u128,
    pub finalize: u128,
    pub total: u128,
}

#[derive(Serialize)]
pub struct Summary {
    /// Untrusted operational TCP payload counters, never billing or proof evidence.
    #[serde(flatten)]
    pub verifier_transport: crate::control::TrafficSnapshot,
    pub status: &'static str,
    /// Base64 of X's complete HTTP response as received over the proven session.
    pub response: String,
    pub sent_bytes: usize,
    pub received_bytes: usize,
    pub duration_ms: u128,
    pub proof_mode: ProofMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpc_network: Option<MpcNetwork>,
    pub timings_ms: Timings,
    pub execution_ms: u128,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub batch_exchanges: Vec<BatchExchange>,
}

#[derive(Serialize)]
pub struct BatchExchange {
    pub response: String,
    pub sent_bytes: usize,
    pub received_bytes: usize,
}

fn validate_experiment(request: &Request) -> Result<()> {
    if request.batch_reads != 0 && (request.batch_reads != xpolicy::BATCH_READS || request.proof_mode != ProofMode::Mpc) {
        bail!("batch_reads requires exactly two MPC reads");
    }
    if request.provisional_response && request.batch_reads != 0 {
        bail!("provisional delivery requires one independent read");
    }
    if request.prepare_hold_ms > 30_000 {
        bail!("prepare_hold_ms exceeds 30000");
    }
    for records in [request.max_sent_records, request.max_recv_records_online].into_iter().flatten() {
        // Explicit limits include the protocol records in this pinned fork.
        if !(3..=32).contains(&records) {
            bail!("experimental record limits must be 3-32 including protocol records");
        }
    }
    if request.proof_mode == ProofMode::Proxy
        && (request.max_sent_records.is_some() || request.max_recv_records_online.is_some() || request.prepare_hold_ms != 0 || request.mpc_network.is_some())
    {
        bail!("MPC tuning options are not valid in Proxy mode");
    }
    Ok(())
}

fn provisional_response(response: &[u8], elapsed_ms: u128) -> Result<Option<serde_json::Value>> {
    let (status, body) = xpolicy::response_body(response)?;
    if status != 200 { return Ok(None); }
    let parsed: serde_json::Value = serde_json::from_str(&body)?;
    if parsed.get("data").and_then(|data| data.as_object()).is_none_or(|data| data.is_empty()) {
        return Ok(None);
    }
    // Only the decoded body crosses this optional pipe. Headers can contain
    // cookies, and the received bytes have not yet been proven to the verifier.
    Ok(Some(serde_json::json!({"phase":"response_provisional", "state":"unverified", "verified":false, "settled":false, "http_status":status, "body":body, "elapsed_ms":elapsed_ms})))
}

async fn batch_handshake(socket: &mut crate::control::Socket) -> Result<()> {
    socket.write_all(xpolicy::BATCH_PREFACE).await?;
    let mut ack = vec![0; xpolicy::BATCH_ACK.len()];
    tokio::time::timeout(Duration::from_secs(10), tokio::io::AsyncReadExt::read_exact(socket, &mut ack)).await.context("batch acknowledgement timed out")??;
    if ack != xpolicy::BATCH_ACK { bail!("verifier did not acknowledge the batch policy"); }
    Ok(())
}

pub async fn run(request: Request) -> Result<Summary> {
    validate_experiment(&request)?;
    let raw = STANDARD.decode(request.request.as_bytes()).context("request is not base64")?;
    if raw.len() > MAX_SENT || !raw.starts_with(b"GET /i/api/graphql/") {
        bail!("request must be an X GraphQL GET of at most {MAX_SENT} bytes");
    }
    let request_ranges = if request.batch_reads == xpolicy::BATCH_READS {
        let ranges = xpolicy::batch_request_ranges(&raw)?;
        // Validate both reads before opening any provider connection. The
        // fixture response is used only for local request policy parsing.
        for range in &ranges {
            xpolicy::check(HOST, &raw[range.clone()], &[], b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", &[])?;
        }
        ranges
    } else {
        vec![0..raw.len()]
    };
    let complete = |response: &[u8]| if request.batch_reads != 0 { xpolicy::batch_response_ranges(response).is_ok() } else { xpolicy::response_complete(response) };
    if request.token.len() != 64 || !request.token.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("verifier token must be 64 hex characters");
    }
    let max_recv = request.max_recv.unwrap_or(MAX_RECV).min(MAX_RECV);
    let started = Instant::now();
    let mut timings = Timings::default();

    let (mut socket, traffic) = crate::control::connect_named(&request.verifier, request.verifier_ca_file.as_deref(), request.plaintext_fixture, request.verifier_server_name.as_deref()).await?;
    socket.write_all(format!("{}\n", request.token).as_bytes()).await?;
    if request.batch_reads != 0 { batch_handshake(&mut socket).await?; }
    timings.control_connect = started.elapsed().as_millis();
    let (driver, mut handle) = Session::new(socket.compat()).split();
    let mut session = Driver::new(tokio::spawn(driver));
    let work = async {
        let phase = Instant::now();
        let prover = handle.new_prover(ProverConfig::builder().build()?)?;
        let tls_config = TlsClientConfig::builder().server_name(ServerName::Dns(HOST.try_into()?)).root_store(RootCertStore::mozilla()).build()?;
        // Both protocol variants finish as the same committed-prover type.
        let (mut tls, prover_task, end, execution_started) = match request.proof_mode {
            ProofMode::Mpc => {
                let mut config = MpcTlsConfig::builder().max_sent_data(raw.len()).max_recv_data(max_recv);
                if let Some(n) = request.max_sent_records { config = config.max_sent_records(n); }
                if let Some(n) = request.max_recv_records_online { config = config.max_recv_records_online(n); }
                if let Some(network) = request.mpc_network { config = config.network(network.setting()); }
                let prover = prover.commit(config.build()?).await?;
                timings.commit = phase.elapsed().as_millis();
                if request.prepare_hold_ms != 0 { tokio::time::sleep(Duration::from_millis(request.prepare_hold_ms)).await; }
                let execution_started = Instant::now();
                let tcp = TcpStream::connect((HOST, 443)).await.context("x.com unreachable")?;
                tcp.set_nodelay(true)?;
                let end = Arc::new(End::default());
                let (tls, prover) = prover.connect(tls_config, Server { tcp, end: end.clone() }.compat())?;
                (tls, tokio::spawn(prover.into_future()), Some(end), execution_started)
            }
            ProofMode::Proxy => {
                let prover = prover.commit(ProxyTlsConfig::builder().server_name(DnsName::try_from(HOST)?).build()?).await?;
                timings.commit = phase.elapsed().as_millis();
                let execution_started = Instant::now();
                let (tls, prover) = prover.connect(tls_config)?;
                (tls, tokio::spawn(prover.into_future()), None, execution_started)
            }
        };
        let phase = Instant::now();
        tls.write_all(&raw).await?;
        tls.flush().await?;
        timings.request_write = phase.elapsed().as_millis();
        // X does not always close after `Connection: close`, so stop at the end of
        // the framed response rather than waiting for the connection to end.
        let mut response = Vec::new();
        let phase = Instant::now();
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut chunk = [0u8; 16 << 10];
            while !complete(&response) {
                let n = tls.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                if response.len().saturating_add(n) > max_recv { bail!("X response exceeds receive limit"); }
                response.extend_from_slice(&chunk[..n]);
            }
            anyhow::Ok(())
        })
        .await
        .context("timed out waiting for X")??;
        timings.response_read = phase.elapsed().as_millis();
        if !complete(&response) { bail!("X response framing incomplete"); }
        if request.response_ready_event {
            eprintln!("{}", serde_json::json!({"phase":"response_ready", "elapsed_ms":started.elapsed().as_millis()}));
        }
        if request.provisional_response {
            if let Some(event) = provisional_response(&response, started.elapsed().as_millis())? {
                use std::io::Write;
                println!("{event}");
                std::io::stdout().flush()?;
            }
        }
        // tlsn finalizes only once the server stream ends, and X may hold the
        // connection open indefinitely, so end it here.
        let phase = Instant::now();
        if let Some(end) = end { end.finish(); }
        drop(tls);

        let mut prover = tokio::time::timeout(Duration::from_secs(120), prover_task).await.context("TLS finalization timeout")???;
        timings.tls_finish = phase.elapsed().as_millis();
        let sent = prover.transcript().sent().to_vec();
        let received_bytes = prover.transcript().received().len();
        let mut builder = ProveConfig::builder(prover.transcript());
        builder.server_identity();
        for range in reveal_requests(&sent, request.batch_reads != 0)? {
            builder.reveal_sent(&range)?;
        }
        builder.reveal_recv(&(0..received_bytes))?;
        let phase = Instant::now();
        prover.prove(&builder.build()?).await?;
        timings.prove = phase.elapsed().as_millis();
        anyhow::Ok((prover, response, sent.len(), received_bytes, execution_started))
    };
    let (prover, response, sent_bytes, received_bytes, execution_started) = session.step(work).await?;
    let phase = Instant::now();
    session.finish(async { Ok(prover.close().await?) }, || handle.close()).await?;
    timings.finalize = phase.elapsed().as_millis();
    timings.total = started.elapsed().as_millis();

    let batch_exchanges = if request.batch_reads != 0 {
        let responses = xpolicy::batch_response_ranges(&response)?;
        request_ranges.into_iter().zip(responses).map(|(sent, recv)| BatchExchange { response: STANDARD.encode(&response[recv.clone()]), sent_bytes: sent.len(), received_bytes: recv.len() }).collect()
    } else { Vec::new() };

    Ok(Summary {
        verifier_transport: traffic.snapshot(),
        status: "proof_sent",
        response: STANDARD.encode(&response),
        sent_bytes,
        received_bytes,
        duration_ms: started.elapsed().as_millis(),
        proof_mode: request.proof_mode,
        mpc_network: request.mpc_network,
        timings_ms: timings,
        execution_ms: execution_started.elapsed().as_millis(),
        batch_exchanges,
    })
}

/// The x.com connection, whose reads report end of stream once `End::finish` is called.
struct Server {
    tcp: TcpStream,
    end: Arc<End>,
}

#[derive(Default)]
struct End {
    finished: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl End {
    fn finish(&self) {
        self.finished.store(true, Ordering::SeqCst);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

impl tokio::io::AsyncRead for Server {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        *self.end.waker.lock().unwrap() = Some(cx.waker().clone());
        if self.end.finished.load(Ordering::SeqCst) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Server {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tcp).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

/// Everything in the request except the secret cookie values and the CSRF token.
fn reveal(sent: &[u8]) -> Result<Vec<Range<usize>>> {
    let head_end = find(sent, b"\r\n\r\n").context("request has no header terminator")?;
    let (mut ranges, mut at) = (Vec::new(), 0);
    for span in xpolicy::secret_spans(sent, head_end)? {
        ranges.push(at..span.start);
        at = span.end;
    }
    ranges.push(at..sent.len());
    Ok(ranges.into_iter().filter(|r| !r.is_empty()).collect())
}

fn reveal_requests(sent: &[u8], batch: bool) -> Result<Vec<Range<usize>>> {
    if !batch { return reveal(sent); }
    let mut ranges = Vec::new();
    for request in xpolicy::batch_request_ranges(sent)? {
        ranges.extend(reveal(&sent[request.clone()])?.into_iter().map(|r| r.start + request.start..r.end + request.start));
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provisional_data_is_unverified_and_excludes_headers() {
        let body = r#"{"data":{"fixture":"synthetic"}}"#;
        let raw = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nSet-Cookie: PRIVATE_SESSION\r\n\r\n{body}", body.len());
        let event = provisional_response(raw.as_bytes(), 123).unwrap().unwrap();
        assert_eq!(event["state"], "unverified");
        assert_eq!(event["verified"], false);
        assert_eq!(event["settled"], false);
        assert_eq!(event["elapsed_ms"], 123);
        assert_eq!(event["body"], body);
        assert!(!event.to_string().contains("PRIVATE_SESSION"));
        assert!(provisional_response(b"HTTP/1.1 429 Rate Limited\r\nContent-Length: 2\r\n\r\n{}", 1).unwrap().is_none());
        assert!(provisional_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", 1).unwrap().is_none());
        assert!(provisional_response(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n{}", 1).is_err());
        let value = serde_json::json!({"verifier":"localhost:1", "token":"a".repeat(64), "request":"", "batch_reads":2, "provisional_response":true});
        assert!(validate_experiment(&serde_json::from_value(value).unwrap()).is_err());
    }

    #[tokio::test]
    async fn batch_handshake_requires_the_exact_policy_acknowledgement() {
        for valid in [true,false] {
            let (socket,mut peer)=tokio::io::duplex(128);
            let mut socket: crate::control::Socket=Box::new(socket);
            let server=tokio::spawn(async move {
                let mut preface=vec![0;xpolicy::BATCH_PREFACE.len()];
                tokio::io::AsyncReadExt::read_exact(&mut peer,&mut preface).await.unwrap();
                assert_eq!(preface,xpolicy::BATCH_PREFACE);
                let mut ack=xpolicy::BATCH_ACK.to_vec();
                if !valid { ack[0]=b'!'; }
                peer.write_all(&ack).await.unwrap();
            });
            assert_eq!(batch_handshake(&mut socket).await.is_ok(),valid);
            server.await.unwrap();
        }
    }

    #[test]
    fn tuning_is_bounded_and_mpc_only() {
        let mut value = serde_json::json!({"verifier":"localhost:1", "token":"a".repeat(64), "request":""});
        let request = |v: &serde_json::Value| serde_json::from_value::<Request>(v.clone()).unwrap();
        assert!(validate_experiment(&request(&value)).is_ok());
        value["max_sent_records"] = serde_json::json!(3);
        value["max_recv_records_online"] = serde_json::json!(3);
        value["prepare_hold_ms"] = serde_json::json!(30_000);
        assert!(validate_experiment(&request(&value)).is_ok());
        value["prepare_hold_ms"] = serde_json::json!(30_001);
        assert!(validate_experiment(&request(&value)).is_err());
        value["prepare_hold_ms"] = serde_json::json!(0);
        value["max_sent_records"] = serde_json::json!(2);
        assert!(validate_experiment(&request(&value)).is_err());
        value["max_sent_records"] = serde_json::json!(3);
        value["proof_mode"] = serde_json::json!("proxy");
        assert!(validate_experiment(&request(&value)).is_err());
        value.as_object_mut().unwrap().remove("max_sent_records");
        value.as_object_mut().unwrap().remove("max_recv_records_online");
        assert!(validate_experiment(&request(&value)).is_ok());
        value["mpc_network"] = serde_json::json!("reduce_roundtrips");
        assert!(validate_experiment(&request(&value)).is_err());
        value["proof_mode"] = serde_json::json!("mpc");
        assert!(validate_experiment(&request(&value)).is_ok());
        value["mpc_network"] = serde_json::json!("unknown");
        assert!(serde_json::from_value::<Request>(value).is_err());
    }

    #[test]
    fn reveals_everything_but_the_session_values() {
        let sent = b"GET /i/api/graphql/q/Viewer HTTP/1.1\r\nHost: x.com\r\nX-Csrf-Token: CSRF\r\nCookie: auth_token=SECRET; ct0=CSRF; twid=u%3D1; kdt=KDT\r\n\r\n";
        let shown: Vec<u8> = reveal(sent).unwrap().into_iter().flat_map(|r| sent[r].to_vec()).collect();
        let shown = String::from_utf8(shown).unwrap();
        assert!(!shown.contains("CSRF") && !shown.contains("SECRET") && !shown.contains("KDT"));
        assert_eq!(shown, "GET /i/api/graphql/q/Viewer HTTP/1.1\r\nHost: x.com\r\nX-Csrf-Token: \r\nCookie: auth_token=; ct0=; twid=u%3D1; kdt=\r\n\r\n");
        let long = format!("GET / HTTP/1.1\r\nCookie: auth_token={}\r\n\r\n", "a".repeat(65));
        assert!(reveal(long.as_bytes()).is_err(), "an overlong secret was hidden");
    }

    #[test]
    fn batch_redaction_never_reveals_request_two_secrets() {
        let first = b"GET /i/api/graphql/q/Viewer?variables=%7B%7D&features=%7B%7D HTTP/1.1\r\nHost: x.com\r\nConnection: keep-alive\r\nX-Csrf-Token: FIRST_CSRF\r\nCookie: auth_token=FIRST_AUTH; ct0=FIRST_CSRF; kdt=FIRST_KDT\r\n\r\n";
        let second = b"GET /i/api/graphql/q/TweetResultByRestId?variables=%7B%22tweetId%22%3A%2220%22%7D&features=%7B%7D HTTP/1.1\r\nHost: x.com\r\nConnection: close\r\nX-Csrf-Token: SECOND_CSRF\r\nCookie: auth_token=SECOND_AUTH; ct0=SECOND_CSRF; kdt=SECOND_KDT\r\n\r\n";
        let sent = [first.as_slice(), second.as_slice()].concat();
        let ranges = reveal_requests(&sent, true).unwrap();
        let shown: Vec<u8> = ranges.iter().flat_map(|r| sent[r.clone()].to_vec()).collect();
        assert!(!String::from_utf8(shown).unwrap().contains("FIRST_"));
        let shown: Vec<u8> = ranges.iter().flat_map(|r| sent[r.clone()].to_vec()).collect();
        assert!(!String::from_utf8(shown).unwrap().contains("SECOND_"));
        let mut blank = sent.clone();
        let hidden: Vec<_> = (0..sent.len()).filter(|i| !ranges.iter().any(|r| r.contains(i))).map(|i| { blank[i] = 0; i..i+1 }).collect();
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n{\"data\":{}}";
        assert!(xpolicy::check_batch(HOST, &blank, &hidden, &[response.as_slice(),response.as_slice()].concat(), &[]).is_ok());
    }
}
