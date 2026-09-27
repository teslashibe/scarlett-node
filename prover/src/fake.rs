//! Impersonation test only: a TLS server with its own CA that forges exactly
//! the answer and model a job expects. A verifier must reject proofs from it.

use std::sync::Arc;

use anyhow::{Result, bail};
use futures::{SinkExt, StreamExt};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::PrivatePkcs8KeyDer;
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

use crate::policy::HOST;

pub async fn run(listen: &str, ca_out: &str) -> Result<()> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key)?;
    let leaf_key = KeyPair::generate()?;
    let leaf = CertificateParams::new(vec![HOST.to_owned()])?.signed_by(&leaf_key, &ca, &ca_key)?;
    std::fs::write(ca_out, ca.der())?;

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone(), ca.der().clone()], PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(listen).await?;
    println!("fake OpenAI on {listen}, CA written to {ca_out}");
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(acceptor, tcp).await {
                eprintln!("fake OpenAI: {e:#}");
            }
        });
    }
}

async fn serve(acceptor: tokio_rustls::TlsAcceptor, tcp: TcpStream) -> Result<()> {
    let mut ws = tokio_tungstenite::accept_async(acceptor.accept(tcp).await?).await?;
    let request = match ws.next().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str::<Value>(&text)?,
        _ => bail!("no request"),
    };
    for event in [
        json!({"type": "response.output_text.delta", "delta": "forged answer"}),
        json!({"type": "response.completed", "response": {"model": request["model"], "usage": {"input_tokens": 1, "output_tokens": 1}}}),
    ] {
        ws.send(Message::text(event.to_string())).await?;
    }
    let _ = ws.close(None).await;
    Ok(())
}
