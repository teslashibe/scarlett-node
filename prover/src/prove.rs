//! Supplier side: run one Codex job through TLSNotary proxy mode so the
//! assigned verifier sees OpenAI's response. Only the login token is hidden.

use std::{
    env,
    future::IntoFuture,
    ops::Range,
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tlsn::{
    Session,
    config::{prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig, tls_commit::proxy::ProxyTlsConfig},
    connection::{DnsName, ServerName},
    webpki::{CertificateDer, RootCertStore},
};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::policy::{HOST, PATH, find, validate_job};

#[derive(Deserialize)]
pub struct Request {
    pub verifier: String,
    pub verifier_ca_file: Option<String>,
    pub verifier_server_name: Option<String>,
    #[serde(default)]
    pub plaintext_fixture: bool,
    pub token: String,
    pub payload: Value,
    #[serde(default)]
    pub close_strategy: CloseStrategy,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseStrategy {
    #[default]
    Normal,
    TlsAfterCompleted,
}

#[derive(Serialize)]
pub struct Summary {
    /// Untrusted operational TCP payload counters, never billing or proof evidence.
    #[serde(flatten)]
    pub verifier_transport: crate::control::TrafficSnapshot,
    pub status: &'static str,
    pub proof_mode: &'static str,
    pub close_strategy: CloseStrategy,
    pub duration_ms: u128,
    pub codex_ms: u128,
    pub sent_bytes: usize,
    pub received_bytes: usize,
    pub timings_ms: Timings,
}

/// Local monotonic measurements for experiments, never authenticated usage.
#[derive(Default, Serialize)]
pub struct Timings {
    pub control_connect: u128,
    pub commit: u128,
    pub websocket_handshake: u128,
    pub response_read: u128,
    pub tls_finish: u128,
    pub prove: u128,
    pub finalize: u128,
    pub total: u128,
}

// Provider errors can contain prompts, authentication headers, and account IDs.
// Inspect bounded error fields locally and return only one of these finite labels.
// Never serialize the provider event, its message, code, or response headers.
fn provider_error_kind(event: &Value) -> &'static str {
    let error = if event["type"] == "response.failed" { &event["response"]["error"] } else { &event["error"] };
    let code = error["code"].as_str().or_else(|| event["code"].as_str()).unwrap_or_default();
    match code {
        "model_not_found" | "model_not_supported" | "unsupported_model" | "model_unavailable" | "model_access_denied" => return "model_unavailable",
        "invalid_api_key" | "authentication_error" | "unauthorized" | "invalid_authentication_token" | "token_expired" | "expired_token" => return "unauthenticated",
        "rate_limit_exceeded" | "rate_limit_error" | "requests_per_minute_exceeded" | "tokens_per_minute_exceeded" | "insufficient_quota" => return "rate_limited",
        "unsupported_parameter" | "unknown_parameter" | "invalid_parameter" => return "unsupported_request",
        _ => {}
    }
    if code == "unsupported_value" && error["param"] == "model" {
        return "model_unavailable";
    }
    // Some Codex WebSocket errors provide only a message. The entire bounded
    // message stays private; only recognized conditions produce a fixed label.
    let message = error["message"].as_str().or_else(|| event["message"].as_str()).unwrap_or_default();
    if message.len() <= 4096 {
        let message = message.to_ascii_lowercase();
        if message.contains("unsupported parameter") || message.contains("unsupported value") || message.contains("unknown parameter") || message.contains("unrecognized request argument") || message.contains("reasoning") && message.contains("not supported") {
            return "unsupported_request";
        }
        if message.contains("model") && (message.contains("not supported") || message.contains("not available") || message.contains("do not have access") || message.contains("does not exist") || message.contains("unsupported model")) {
            return "model_unavailable";
        }
        if message.contains("authentication token has expired") || message.contains("invalid authentication token") || message.contains("invalid api key") || message.contains("authentication required") {
            return "unauthenticated";
        }
        if message.contains("rate limit") || message.contains("usage limit") || message.contains("insufficient quota") {
            return "rate_limited";
        }
    }
    match error["type"].as_str().unwrap_or_default() {
        "authentication_error" => "unauthenticated",
        "rate_limit_error" => "rate_limited",
        "invalid_request_error" => "unsupported_request",
        _ => match code { "invalid_request_error" | "unsupported_value" => "unsupported_request", _ => "provider_error" },
    }
}

// Reviewed against OpenAI codex rust-v0.159.2: model-provider-info/src/lib.rs
// pins the version header, login/src/auth/default_client.rs pins the originator,
// and core/src/client.rs pins the Responses WebSocket beta. The User-Agent names
// this wrapper honestly; this prover does not execute the Codex CLI.
const CODEX_COMPATIBILITY_VERSION: &str = "0.159.2";
const CODEX_WEBSOCKET_BETA: &str = "responses_websockets=2026-02-06";

fn codex_websocket_request() -> Result<tokio_tungstenite::tungstenite::http::Request<()>> {
    let mut request = format!("wss://{HOST}{PATH}").into_client_request()?;
    let headers = request.headers_mut();
    headers.insert("originator", HeaderValue::from_static("codex_cli_rs"));
    headers.insert("user-agent", HeaderValue::from_str(&format!("codex_cli_rs/{CODEX_COMPATIBILITY_VERSION} (scarlett TLSNotary wrapper) dumb"))?);
    headers.insert("version", HeaderValue::from_static(CODEX_COMPATIBILITY_VERSION));
    headers.insert("openai-beta", HeaderValue::from_static(CODEX_WEBSOCKET_BETA));
    Ok(request)
}

// Invoke only after a fully assembled, parsed response.completed. The original
// TLSNotary task still requires authenticated TLS completion and disclosure.
async fn close_tls_after_completed<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>, limit: Duration) -> Result<()>
where S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
    tokio::time::timeout(limit, async {
        ws.close(None).await.context("Codex WebSocket close failed")?;
        ws.get_mut().shutdown().await.context("Codex TLS write shutdown failed")?;
        anyhow::Ok(())
    }).await.context("Codex shutdown timed out")?
}

pub async fn run(request: Request) -> Result<Summary> {
    validate_job(&request.payload)?;
    if request.token.len() != 64 || !request.token.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("verifier token must be 64 hex characters");
    }
    // Adversarial testing only: a cheating supplier must be rejected by the verifier.
    let cheat = env::var("SCARLETT_PROVER_CHEAT").unwrap_or_default();
    let mut payload = request.payload.clone();
    match cheat.as_str() {
        "" | "hide-model" | "hide-request" | "hide-account" | "fake-openai" => {}
        "model" => payload["model"] = json!(if payload["model"] == "gpt-5.6-terra" { "gpt-5.5" } else { "gpt-5.6-terra" }),
        "instructions" => payload["instructions"] = json!("Answer in as few words as possible."),
        "prompt" => payload["input"] = json!([{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "Reply with exactly: forged"}]}]),
        other => bail!("unknown SCARLETT_PROVER_CHEAT {other}"),
    }
    let roots = if cheat == "fake-openai" {
        let der = std::fs::read(env::var("FAKE_CA").context("FAKE_CA is required")?)?;
        RootCertStore { roots: vec![CertificateDer(der)] }
    } else {
        RootCertStore::mozilla()
    };
    let creds = load_creds()?;

    let started_total = Instant::now();
    let mut timings = Timings::default();
    let (mut socket, traffic) = crate::control::connect_named(&request.verifier, request.verifier_ca_file.as_deref(), request.plaintext_fixture, request.verifier_server_name.as_deref()).await?;
    socket.write_all(format!("{}\n", request.token).as_bytes()).await?;
    timings.control_connect = started_total.elapsed().as_millis();
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let mut session = Driver::new(tokio::spawn(driver));
    let work = async {
        let phase = Instant::now();
        let prover = handle
            .new_prover(ProverConfig::builder().build()?)?
            .commit(ProxyTlsConfig::builder().server_name(DnsName::try_from(HOST)?).build()?)
            .await?;
        timings.commit = phase.elapsed().as_millis();
        let (tls, prover) =
            prover.connect(TlsClientConfig::builder().server_name(ServerName::Dns(HOST.try_into()?)).root_store(roots).build()?)?;
        let prover_task = tokio::spawn(prover.into_future());

        let started = Instant::now();
        let mut ws_request = codex_websocket_request()?;
        let headers = ws_request.headers_mut();
        headers.insert("authorization", HeaderValue::from_str(&format!("Bearer {}", creds.access_token))?);
        headers.insert("chatgpt-account-id", HeaderValue::from_str(&creds.account_id)?);

        let (mut ws, _) = tokio_tungstenite::client_async(ws_request, tls.compat())
            .await
            .context("Codex WebSocket handshake failed")?;
        timings.websocket_handshake = started.elapsed().as_millis();
        let phase = Instant::now();
        ws.send(Message::text(payload.to_string())).await?;
        loop {
            let message = tokio::time::timeout(Duration::from_secs(240), ws.next())
                .await
                .context("timed out waiting for Codex")?
                .ok_or_else(|| anyhow!("Codex closed the stream before completing"))??;
            let Message::Text(text) = message else { continue };
            let event: Value = serde_json::from_str(&text)?;
            match event["type"].as_str() {
                Some("response.completed") => break,
                Some("response.failed" | "error") => bail!("Codex provider error: {}", provider_error_kind(&event)),
                _ => {}
            }
        }
        timings.response_read = phase.elapsed().as_millis();
        let codex_ms = started.elapsed().as_millis();
        let phase = Instant::now();
        match request.close_strategy {
            CloseStrategy::Normal => {
                let _ = ws.close(None).await;
                while let Ok(Some(Ok(_))) = tokio::time::timeout(Duration::from_secs(5), ws.next()).await {}
            }
            CloseStrategy::TlsAfterCompleted => close_tls_after_completed(&mut ws, Duration::from_secs(5)).await?,
        }
        drop(ws);

        let mut prover =
            tokio::time::timeout(Duration::from_secs(30), prover_task).await.context("TLS connection did not close")???;
        timings.tls_finish = phase.elapsed().as_millis();
        let phase = Instant::now();
        let sent = prover.transcript().sent().to_vec();
        let received = prover.transcript().received().to_vec();
        let mut hide_sent = occurrences(&sent, creds.access_token.as_bytes());
        if hide_sent.is_empty() {
            bail!("login token not found in the request; refusing to guess what to hide");
        }
        let mut hide_recv = Vec::new();
        match cheat.as_str() {
            "hide-model" => hide_recv = occurrences(&received, request.payload["model"].as_str().unwrap_or_default().as_bytes()),
            "hide-account" => hide_sent.extend(occurrences(&sent, creds.account_id.as_bytes())),
            "hide-request" => {
                let body = find(&sent, b"\r\n\r\n").context("no request header")? + 4;
                hide_sent.push(body + 8..(body + 40).min(sent.len()));
            }
            _ => {}
        }

        let mut builder = ProveConfig::builder(prover.transcript());
        builder.server_identity();
        for range in complement(sent.len(), hide_sent) {
            builder.reveal_sent(&range)?;
        }
        for range in complement(received.len(), hide_recv) {
            builder.reveal_recv(&range)?;
        }
        let config = builder.build()?;
        prover.prove(&config).await?;
        timings.prove = phase.elapsed().as_millis();
        anyhow::Ok((prover, codex_ms, sent.len(), received.len()))
    };
    let (prover, codex_ms, sent_bytes, received_bytes) = session.step(work).await?;
    let phase = Instant::now();
    session.finish(async { Ok(prover.close().await?) }, || handle.close()).await?;
    timings.finalize = phase.elapsed().as_millis();
    timings.total = started_total.elapsed().as_millis();

    Ok(Summary { status: "proof_sent", proof_mode: "proxy", close_strategy: request.close_strategy,
        duration_ms: timings.total, codex_ms, sent_bytes, received_bytes,
        timings_ms: timings, verifier_transport: traffic.snapshot() })
}

/// The task driving a TLSNotary session. A protocol handle may stay pending
/// after the transport ends, so both participants race their work against it.
pub struct Driver<S, E> {
    task: tokio::task::JoinHandle<Result<S, E>>,
    ended: bool,
}

impl<S, E: Into<anyhow::Error>> Driver<S, E> {
    pub fn new(task: tokio::task::JoinHandle<Result<S, E>>) -> Self {
        Self { task, ended: false }
    }

    /// Runs `step`, failing as soon as the session ends first.
    pub async fn step<T>(&mut self, step: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::select! {
            biased;
            done = step => done,
            ended = &mut self.task => {
                self.ended = true;
                match ended {
                    Ok(Ok(_)) => bail!("TLSNotary session closed"),
                    Ok(Err(e)) => Err(e.into().context("TLSNotary session failed")),
                    Err(e) => Err(anyhow::Error::from(e).context("TLSNotary session failed")),
                }
            }
        }
    }

    /// Closes the prover and then the session once the proof is sent. The
    /// verifier may hang up as soon as it has the proof, which is not a failure.
    pub async fn finish(mut self, close_prover: impl Future<Output = Result<()>>, close_session: impl FnOnce()) -> Result<()> {
        tokio::select! {
            biased;
            closed = close_prover => closed?,
            _ = &mut self.task => self.ended = true,
        }
        close_session();
        if !self.ended {
            self.task.await?.map_err(Into::into)?;
        }
        Ok(())
    }
}

struct Creds {
    access_token: String,
    account_id: String,
}

/// Reads the Codex login without refreshing it; run `codex login` when it expires.
fn load_creds() -> Result<Creds> {
    let home = match env::var("CODEX_HOME") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => PathBuf::from(env::var("HOME").context("HOME is not set")?).join(".codex"),
    };
    let path = home.join("auth.json");
    let auth: Value = serde_json::from_slice(&std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?)?;
    let field = |name: &str| {
        auth["tokens"][name]
            .as_str()
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("auth.json has no tokens.{name}"))
    };
    Ok(Creds { access_token: field("access_token")?, account_id: field("account_id")? })
}

fn occurrences(data: &[u8], needle: &[u8]) -> Vec<Range<usize>> {
    if needle.is_empty() {
        return Vec::new();
    }
    data.windows(needle.len()).enumerate().filter(|(_, w)| *w == needle).map(|(i, _)| i..i + needle.len()).collect()
}

/// `0..len` minus `hidden`.
fn complement(len: usize, mut hidden: Vec<Range<usize>>) -> Vec<Range<usize>> {
    hidden.sort_by_key(|r| r.start);
    let (mut reveal, mut at) = (Vec::new(), 0);
    for range in hidden {
        if range.start > at {
            reveal.push(at..range.start);
        }
        at = at.max(range.end);
    }
    if at < len {
        reveal.push(at..len);
    }
    reveal
}

#[cfg(test)]
mod provider_error_tests {
    use super::*;

    #[tokio::test]
    async fn explicit_tls_shutdown_flushes_close_then_finishes_without_remote_ws_ack() {
        use tokio::io::AsyncReadExt;
        use tokio_tungstenite::tungstenite::protocol::Role;
        let (client, mut remote) = tokio::io::duplex(4096);
        let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let peer = tokio::spawn(async move {
            let mut bytes = Vec::new();
            remote.read_to_end(&mut bytes).await.unwrap();
            bytes
        });
        close_tls_after_completed(&mut ws, Duration::from_secs(1)).await.unwrap();
        let sent = tokio::time::timeout(Duration::from_secs(1), peer).await.unwrap().unwrap();
        assert_eq!(sent[0], 0x88); // complete WebSocket Close frame precedes write EOF
        assert_eq!(sent.len(), 6); // masked empty client Close, no extra application data
    }

    #[tokio::test]
    async fn explicit_tls_shutdown_times_out_when_close_cannot_flush() {
        use tokio_tungstenite::tungstenite::protocol::Role;
        let (client, _unread_remote) = tokio::io::duplex(1);
        let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        let error = close_tls_after_completed(&mut ws, Duration::from_millis(20)).await.unwrap_err();
        assert_eq!(error.to_string(), "Codex shutdown timed out");
    }

    #[test]
    fn current_compatibility_headers_keep_fixed_provider_route_and_honest_identity() {
        let request = codex_websocket_request().unwrap();
        assert_eq!(request.uri().scheme_str(), Some("wss"));
        assert_eq!(request.uri().host(), Some("chatgpt.com"));
        assert_eq!(request.uri().path(), "/backend-api/codex/responses");
        let headers = request.headers();
        assert_eq!(headers["originator"], "codex_cli_rs");
        assert_eq!(headers["version"], "0.159.2");
        assert_eq!(headers["user-agent"], "codex_cli_rs/0.159.2 (scarlett TLSNotary wrapper) dumb");
        assert_eq!(headers["openai-beta"], "responses_websockets=2026-02-06");
        assert!(!headers.contains_key("authorization"));
        assert!(!headers.contains_key("chatgpt-account-id"));
        assert!(!headers.contains_key("x-openai-internal-codex-responses-lite"));
        assert!(!headers.contains_key("service-tier"));
        for value in headers.values() {
            assert!(!value.as_bytes().windows(7).any(|bytes| bytes == b"0.144.1"));
        }
    }

    #[test]
    fn classifies_nested_and_direct_errors_without_echoing_provider_fields() {
        for (code, expected) in [
            ("model_not_found", "model_unavailable"),
            ("model_not_supported", "model_unavailable"),
            ("invalid_authentication_token", "unauthenticated"),
            ("token_expired", "unauthenticated"),
            ("rate_limit_exceeded", "rate_limited"),
            ("insufficient_quota", "rate_limited"),
            ("unsupported_value", "unsupported_request"),
            ("unknown_parameter", "unsupported_request"),
        ] {
            for event in [
                json!({"type":"error", "error":{"code":code, "message":"SECRET_PROMPT SECRET_TOKEN", "headers":{"authorization":"SECRET_TOKEN"}}}),
                json!({"type":"error", "code":code, "message":"SECRET_PROMPT SECRET_TOKEN"}),
                json!({"type":"response.failed", "response":{"error":{"code":code, "message":"SECRET_PROMPT SECRET_TOKEN"}, "output":"SECRET_OUTPUT"}}),
            ] {
                assert_eq!(provider_error_kind(&event), expected);
                let diagnostic = format!("Codex provider error: {}", provider_error_kind(&event));
                assert!(!diagnostic.contains("SECRET"));
            }
        }
    }

    #[test]
    fn message_only_conditions_return_finite_labels_without_messages() {
        for (message, expected) in [
            ("The 'SECRET_MODEL' model is not supported when using Codex with a ChatGPT account", "model_unavailable"),
            ("You do not have access to model SECRET_MODEL", "model_unavailable"),
            ("Unsupported value: SECRET_PROMPT is not supported with this model", "unsupported_request"),
            ("Unsupported parameter: SECRET_PARAMETER", "unsupported_request"),
            ("Your authentication token has expired SECRET_TOKEN", "unauthenticated"),
            ("Rate limit reached for SECRET_ACCOUNT", "rate_limited"),
            ("Unexpected provider response SECRET_TOKEN", "provider_error"),
        ] {
            let event = json!({"type":"error", "error":{"message":message}});
            assert_eq!(provider_error_kind(&event), expected);
            assert!(!format!("Codex provider error: {}", provider_error_kind(&event)).contains("SECRET"));
        }
    }

    #[test]
    fn unsupported_values_distinguish_model_access_from_reasoning_controls() {
        let model = json!({"type":"error", "error":{"code":"unsupported_value", "param":"model", "message":"SECRET"}});
        assert_eq!(provider_error_kind(&model), "model_unavailable");
        let model_message = json!({"type":"error", "error":{"code":"unsupported_value", "message":"This model is not supported when using Codex with a ChatGPT account"}});
        assert_eq!(provider_error_kind(&model_message), "model_unavailable");
        let reasoning = json!({"type":"error", "error":{"code":"unsupported_value", "param":"reasoning.effort", "message":"Unsupported value: SECRET is not supported with this model"}});
        assert_eq!(provider_error_kind(&reasoning), "unsupported_request");
    }

    #[test]
    fn unknown_malformed_and_oversize_provider_fields_stay_generic() {
        for event in [
            json!({"type":"error", "error":{"code":"SECRET_TOKEN", "message":"SECRET_PROMPT", "type":"SECRET_ACCOUNT"}}),
            json!({"type":"error", "error":{"code":["model_not_found"], "message":{}, "type":true}}),
            json!({"type":"response.failed", "response":{"error":{"message":format!("model not supported {}", "SECRET".repeat(1000))}}}),
            json!({"type":"error"}),
        ] {
            assert_eq!(provider_error_kind(&event), "provider_error");
        }
    }
}
