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
    time::Instant,
};

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
use tokio::{
    io::{AsyncWriteExt as _, ReadBuf},
    net::TcpStream,
};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{
    policy::find,
    prove::Driver,
    xpolicy::{self, HOST},
};

/// Default and verifier-enforced ceiling on the bytes X may return.
pub const MAX_RECV: usize = 256 << 10;
pub const MAX_SENT: usize = 16 << 10;

#[derive(Deserialize)]
pub struct Request {
    pub verifier: String,
    pub verifier_ca_file: Option<String>,
    #[serde(default)]
    pub plaintext_fixture: bool,
    pub token: String,
    /// Base64 of the complete HTTP/1.1 request, which must ask X to close the connection.
    pub request: String,
    pub max_recv: Option<usize>,
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

    let (mut socket, traffic) = crate::control::connect(&request.verifier, request.verifier_ca_file.as_deref(), request.plaintext_fixture).await?;
    socket.write_all(format!("{}\n", request.token).as_bytes()).await?;
    let (driver, mut handle) = Session::new(socket.compat()).split();
    let mut session = Driver::new(tokio::spawn(driver));
    let work = async {
        let prover = handle
            .new_prover(ProverConfig::builder().build()?)?
            .commit(MpcTlsConfig::builder().max_sent_data(raw.len()).max_recv_data(max_recv).build()?)
            .await?;
        let tcp = TcpStream::connect((HOST, 443)).await.context("x.com unreachable")?;
        tcp.set_nodelay(true)?;
        let end = Arc::new(End::default());
        let (mut tls, prover) = prover.connect(
            TlsClientConfig::builder().server_name(ServerName::Dns(HOST.try_into()?)).root_store(RootCertStore::mozilla()).build()?,
            Server { tcp, end: end.clone() }.compat(),
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
        // tlsn finalizes only once the server stream ends, and X may hold the
        // connection open indefinitely, so end it here.
        end.finish();
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
        anyhow::Ok((prover, response, sent.len(), received_bytes))
    };
    let (prover, response, sent_bytes, received_bytes) = session.step(work).await?;
    session.finish(async { Ok(prover.close().await?) }, || handle.close()).await?;

    Ok(Summary {
        verifier_transport: traffic.snapshot(),
        status: "proof_sent",
        response: STANDARD.encode(&response),
        sent_bytes,
        received_bytes,
        duration_ms: started.elapsed().as_millis(),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
