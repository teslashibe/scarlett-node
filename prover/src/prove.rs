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
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::policy::{HOST, PATH, find, validate_job};

#[derive(Deserialize)]
pub struct Request {
    pub verifier: String,
    pub token: String,
    pub payload: Value,
}

#[derive(Serialize)]
pub struct Summary {
    pub status: &'static str,
    pub codex_ms: u128,
    pub sent_bytes: usize,
    pub received_bytes: usize,
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

    let mut socket = TcpStream::connect(&request.verifier).await.context("verifier unreachable")?;
    socket.write_all(format!("{}\n", request.token).as_bytes()).await?;
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(ProxyTlsConfig::builder().server_name(DnsName::try_from(HOST)?).build()?)
        .await?;
    let (tls, prover) =
        prover.connect(TlsClientConfig::builder().server_name(ServerName::Dns(HOST.try_into()?)).root_store(roots).build()?)?;
    let prover_task = tokio::spawn(prover.into_future());

    let started = Instant::now();
    let mut ws_request = format!("wss://{HOST}{PATH}").into_client_request()?;
    let headers = ws_request.headers_mut();
    headers.insert("authorization", HeaderValue::from_str(&format!("Bearer {}", creds.access_token))?);
    headers.insert("chatgpt-account-id", HeaderValue::from_str(&creds.account_id)?);
    headers.insert("originator", HeaderValue::from_static("codex_cli_rs"));
    headers.insert("user-agent", HeaderValue::from_static("codex_cli_rs/0.144.1 (api wrapper) dumb"));
    headers.insert("version", HeaderValue::from_static("0.144.1"));
    headers.insert("openai-beta", HeaderValue::from_static("responses_websockets=2026-02-06"));

    let (mut ws, _) = tokio_tungstenite::client_async(ws_request, tls.compat())
        .await
        .context("Codex WebSocket handshake failed")?;
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
            Some("response.failed" | "error") => bail!("Codex returned {}", event["type"]),
            _ => {}
        }
    }
    let codex_ms = started.elapsed().as_millis();
    let _ = ws.close(None).await;
    while let Ok(Some(Ok(_))) = tokio::time::timeout(Duration::from_secs(5), ws.next()).await {}
    drop(ws);

    let mut prover =
        tokio::time::timeout(Duration::from_secs(30), prover_task).await.context("TLS connection did not close")???;
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
    prover.close().await?;
    handle.close();
    driver_task.await??;

    Ok(Summary { status: "proof_sent", codex_ms, sent_bytes: sent.len(), received_bytes: received.len() })
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
