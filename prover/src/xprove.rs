//! Supplier side for X reads: send the exact request bytes to x.com over
//! MPC-TLS, so the node's own connection (and IP) reaches X while the assigned
//! verifier jointly holds the session keys. Only the session cookie and CSRF
//! token values are hidden.

use std::{future::IntoFuture, ops::Range, time::Instant};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};
use tlsn::{
    Session,
    config::{prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig, tls_commit::mpc::MpcTlsConfig},
    connection::ServerName,
    webpki::RootCertStore,
};
use tokio::{io::AsyncWriteExt as _, net::TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{
    policy::find,
    xpolicy::{self, HOST},
};

/// Default and verifier-enforced ceiling on the bytes X may return.
pub const MAX_RECV: usize = 256 << 10;
pub const MAX_SENT: usize = 16 << 10;

#[derive(Deserialize)]
pub struct Request {
    pub verifier: String,
    pub token: String,
    /// Base64 of the complete HTTP/1.1 request, which must ask X to close the connection.
    pub request: String,
    pub max_recv: Option<usize>,
}

#[derive(Serialize)]
pub struct Summary {
    pub status: &'static str,
    /// Base64 of X's complete HTTP response as received over the proven session.
    pub response: String,
    pub sent_bytes: usize,
    pub received_bytes: usize,
    pub duration_ms: u128,
}

pub async fn run(request: Request) -> Result<Summary> {
    let raw = STANDARD.decode(request.request.as_bytes()).context("request is not base64")?;
    if raw.len() > MAX_SENT || !raw.starts_with(b"GET /i/api/graphql/") {
        bail!("request must be an X GraphQL GET of at most {MAX_SENT} bytes");
    }
    if request.token.len() != 64 || !request.token.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("verifier token must be 64 hex characters");
    }
    let max_recv = request.max_recv.unwrap_or(MAX_RECV).min(MAX_RECV);
    let started = Instant::now();

    let mut socket = TcpStream::connect(&request.verifier).await.context("verifier unreachable")?;
    socket.set_nodelay(true)?;
    socket.write_all(format!("{}\n", request.token).as_bytes()).await?;
    let (driver, mut handle) = Session::new(socket.compat()).split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(MpcTlsConfig::builder().max_sent_data(raw.len()).max_recv_data(max_recv).build()?)
        .await?;
    let server = TcpStream::connect((HOST, 443)).await.context("x.com unreachable")?;
    server.set_nodelay(true)?;
    let (mut tls, prover) = prover.connect(
        TlsClientConfig::builder().server_name(ServerName::Dns(HOST.try_into()?)).root_store(RootCertStore::mozilla()).build()?,
        server.compat(),
    )?;
    let prover_task = tokio::spawn(prover.into_future());
    tls.write_all(&raw).await?;
    tls.flush().await?;
    // X does not always close after `Connection: close`, so stop at the end of
    // the framed response rather than waiting for the connection to end.
    let mut response = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(120), async {
        let mut chunk = [0u8; 16 << 10];
        while !xpolicy::response_complete(&response) {
            let n = tls.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..n]);
        }
        anyhow::Ok(())
    })
    .await
    .context("timed out waiting for X")??;
    tls.close().await?;
    drop(tls);

    let mut prover = prover_task.await??;
    let sent = prover.transcript().sent().to_vec();
    let received_bytes = prover.transcript().received().len();
    let mut builder = ProveConfig::builder(prover.transcript());
    builder.server_identity();
    for range in reveal(&sent)? {
        builder.reveal_sent(&range)?;
    }
    builder.reveal_recv(&(0..received_bytes))?;
    prover.prove(&builder.build()?).await?;
    prover.close().await?;
    handle.close();
    driver_task.await??;

    Ok(Summary {
        status: "proof_sent",
        response: STANDARD.encode(&response),
        sent_bytes: sent.len(),
        received_bytes,
        duration_ms: started.elapsed().as_millis(),
    })
}

/// Everything in the request except the Cookie and X-Csrf-Token values.
fn reveal(sent: &[u8]) -> Result<Vec<Range<usize>>> {
    let head_end = find(sent, b"\r\n\r\n").context("request has no header terminator")?;
    let (mut ranges, mut at, mut start) = (Vec::new(), 0, 0);
    while start < head_end {
        let line_end = start + find(&sent[start..head_end + 2], b"\r\n").context("bad header line")?;
        let line = &sent[start..line_end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line[..colon]).trim().to_ascii_lowercase();
            if name == "cookie" || name == "x-csrf-token" {
                let value = start + colon + 1 + line[colon + 1..].iter().take_while(|&&b| b == b' ').count();
                ranges.push(at..value);
                at = line_end;
            }
        }
        start = line_end + 2;
    }
    ranges.push(at..sent.len());
    Ok(ranges.into_iter().filter(|r| !r.is_empty()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reveals_everything_but_the_session_values() {
        let sent = b"GET /i/api/graphql/q/Viewer HTTP/1.1\r\nHost: x.com\r\nX-Csrf-Token: CSRF\r\nCookie: auth_token=S; ct0=CSRF\r\n\r\n";
        let shown: Vec<u8> = reveal(sent).unwrap().into_iter().flat_map(|r| sent[r].to_vec()).collect();
        let shown = String::from_utf8(shown).unwrap();
        assert!(!shown.contains("CSRF") && !shown.contains("auth_token"));
        assert!(shown.contains("X-Csrf-Token: ") && shown.contains("Cookie: ") && shown.ends_with("\r\n\r\n"));
    }
}
