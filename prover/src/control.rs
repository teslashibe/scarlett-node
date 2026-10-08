//! Encrypted supplier/verifier control transport, configured on the local host.
use anyhow::{Context, Result, bail};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use std::{
    fs::OpenOptions,
    io::{self, IoSlice, Read},
    pin::Pin,
    path::Path,
    sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}},
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use crate::diagnostics::{Phase, Trace};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(windows)]
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use rustls::{ServerConfig, pki_types::PrivateKeyDer};
#[cfg(unix)]
use tokio_rustls::TlsAcceptor;

pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
pub type Socket = Box<dyn Transport>;

// These supplier-reported counters are operational telemetry only. They count
// successful TCP payload reads/writes below outer TLS, including its handshake
// and records; they exclude IP/TCP headers, acknowledgements and retransmissions.
// Saturation never changes transport behavior, billing, or proof eligibility.
const MAX_METERED_BYTES: u64 = 1 << 40;

#[derive(Clone, Default)]
pub struct Traffic {
    sent: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    saturated: Arc<AtomicBool>,
}

#[derive(serde::Serialize)]
pub struct TrafficSnapshot {
    pub verifier_sent_bytes: u64,
    pub verifier_received_bytes: u64,
    pub verifier_transport_layer: &'static str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub verifier_bytes_saturated: bool,
}

impl Traffic {
    fn add(&self, counter: &AtomicU64, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let previous = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| Some(old.saturating_add(bytes).min(MAX_METERED_BYTES))).unwrap();
        if bytes > MAX_METERED_BYTES - previous {
            self.saturated.store(true, Ordering::Relaxed);
        }
    }
    /// Bytes written and read so far.
    pub fn bytes(&self) -> (u64, u64) {
        (self.sent.load(Ordering::Relaxed), self.received.load(Ordering::Relaxed))
    }
    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            verifier_sent_bytes: self.sent.load(Ordering::Relaxed),
            verifier_received_bytes: self.received.load(Ordering::Relaxed),
            verifier_transport_layer: "tcp_payload",
            verifier_bytes_saturated: self.saturated.load(Ordering::Relaxed),
        }
    }
}

pub struct Metered<S> {
    inner: S,
    traffic: Traffic,
}

/// Counts the payload bytes `inner` carries in each direction.
pub fn metered<S>(inner: S) -> (Metered<S>, Traffic) {
    let traffic = Traffic::default();
    (Metered { inner, traffic: traffic.clone() }, traffic)
}
impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let previous = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = result {
            self.traffic.add(&self.traffic.received, buf.filled().len() - previous);
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(bytes)) = result { self.traffic.add(&self.traffic.sent, bytes); }
        result
    }
    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, bufs: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(bytes)) = result { self.traffic.add(&self.traffic.sent, bytes); }
        result
    }
    fn is_write_vectored(&self) -> bool { self.inner.is_write_vectored() }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// This exception exists only for the unpaid loopback/Docker fixtures. A DNS
// name cannot resolve into eligibility for a plaintext connection.
pub fn fixture_address(address: &str) -> bool {
    address.parse::<std::net::SocketAddr>().is_ok_and(|a| a.ip().is_loopback()) || address == "verifier:7047"
}
fn pem(path: &Path, private: bool) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("TLS file must have an absolute path");
    }
    #[cfg(unix)]
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).context("opening TLS file")?;
    #[cfg(windows)]
    let file = {
        // Windows hosts the supplier client only; no private verifier key is read.
        if private { bail!("private verifier keys are unsupported on Windows"); }
        OpenOptions::new().read(true).custom_flags(0x00200000).open(path).context("opening TLS CA file")?
    };
    let info = file.metadata()?;
    if !info.is_file() || info.len() > 1 << 20 {
        bail!("invalid TLS file permissions or size");
    }
    #[cfg(unix)]
    if private && (info.mode() & 0o077 != 0 || info.uid() != unsafe { libc::geteuid() }) {
        bail!("invalid TLS file permissions or size");
    }
    #[cfg(windows)]
    if info.file_attributes() & 0x00000400 != 0 {
        bail!("TLS CA file must not be a reparse point");
    }
    let mut bytes = Vec::new();
    file.take((1 << 20) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1 << 20 {
        bail!("TLS file too large");
    }
    Ok(bytes)
}
fn client(ca: Option<&str>) -> Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    // Use the pinned Mozilla roots already bundled for TLSNotary. A local CA
    // adds trust only to this control connection, never to provider proofs.
    for root in tlsn::webpki::RootCertStore::mozilla().roots {
        roots.add(CertificateDer::from(root.0))?;
    }
    if let Some(ca) = ca {
        let raw = pem(Path::new(ca), false)?;
        let certs = CertificateDer::pem_slice_iter(&raw).collect::<Result<Vec<_>, _>>()?;
        if certs.is_empty() {
            bail!("TLS CA file contains no certificates");
        }
        for cert in certs {
            roots.add(cert)?;
        }
    }
    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}
#[cfg(test)]
pub async fn connect(address: &str, ca: Option<&str>, plaintext_fixture: bool) -> Result<(Socket, Traffic)> {
    connect_observed(address, ca, plaintext_fixture, None).await
}

pub async fn connect_observed(address: &str, ca: Option<&str>, plaintext_fixture: bool, trace: Option<&Trace>) -> Result<(Socket, Traffic)> {
    let configure = || -> Result<_> {
        if plaintext_fixture && (!fixture_address(address) || ca.is_some()) {
            bail!("plaintext is restricted to explicit unpaid fixtures");
        }
        let connector = if plaintext_fixture { None } else { Some(client(ca)?) };
        // Bracket an IPv6 literal only for parsing; certificate validation uses its IP.
        let host = if let Ok(parsed) = address.parse::<std::net::SocketAddr>() {
            parsed.ip().to_string()
        } else {
            let (host, port) = address.rsplit_once(':').context("verifier must be host:port")?;
            let port: u16 = port.parse()?;
            if host.is_empty() || port == 0 {
                bail!("invalid verifier address");
            }
            host.to_owned()
        };
        Ok((connector, host))
    };
    let (connector, host) = match trace {
        Some(trace) => trace.measure_sync(Phase::ControlConfig, configure)?,
        None => configure()?,
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let dial = async { TcpStream::connect(address).await.context("verifier unreachable") };
        let socket = match trace {
            Some(trace) => trace.measure(Phase::VerifierTcpConnect, dial).await?,
            None => dial.await?,
        };
        socket.set_nodelay(true)?;
        let traffic = Traffic::default();
        let socket = Metered { inner: socket, traffic: traffic.clone() };
        if let Some(connector) = connector {
            let name = ServerName::try_from(host).context("invalid verifier TLS name")?;
            let handshake = async { connector.connect(name, socket).await.context("verifier TLS verification failed") };
            let socket = match trace {
                Some(trace) => trace.measure(Phase::VerifierTls, handshake).await?,
                None => handshake.await?,
            };
            Ok((Box::new(socket) as Socket, traffic))
        } else {
            Ok((Box::new(socket) as Socket, traffic))
        }
    })
    .await
    .context("verifier connection timed out")?
}
#[cfg(unix)]
pub fn acceptor(cert: &str, key: &str) -> Result<TlsAcceptor> {
    let raw = pem(Path::new(cert), false)?;
    let chain = CertificateDer::pem_slice_iter(&raw).collect::<Result<Vec<_>, _>>()?;
    if chain.is_empty() {
        bail!("TLS certificate chain is empty");
    }
    let key = PrivateKeyDer::from_pem_slice(&pem(Path::new(key), true)?)?;
    let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    #[test]
    fn ca_reads_are_absolute_regular_bounded_and_public_only() {
        let path = std::env::temp_dir().join(format!("scarlett-ca-{}", rand::random::<u128>()));
        std::fs::write(&path, b"synthetic public CA fixture").unwrap();
        assert!(pem(&path, false).is_ok());
        assert!(pem(&path, true).is_err());
        assert!(pem(Path::new("relative-ca.pem"), false).is_err());
        assert!(pem(&std::env::temp_dir(), false).is_err());
        std::fs::write(&path, vec![0; (1 << 20) + 1]).unwrap();
        assert!(pem(&path, false).is_err());
        std::fs::remove_file(path).unwrap();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    use std::{
        fs,
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        path::PathBuf,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("scarlett-control-{}", rand::random::<u128>()));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
        fn file(&self, name: &str, raw: &[u8]) -> String {
            let path = self.0.join(name);
            fs::write(&path, raw).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            path.to_str().unwrap().to_owned()
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn certificate(dir: &Temp, expired: bool) -> (String, String, String) {
        let ca_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        if expired {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        }
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        (
            dir.file("cert.pem", cert.pem().as_bytes()),
            dir.file("key.pem", key.serialize_pem().as_bytes()),
            dir.file("ca.pem", ca.pem().as_bytes()),
        )
    }
    async fn endpoint(acceptor: TlsAcceptor) -> (u16, tokio::task::JoinHandle<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let Ok(mut socket) = acceptor.accept(socket).await else { return false };
            let mut token = [0; 5];
            if socket.read_exact(&mut token).await.is_err() {
                return false;
            }
            token == *b"token"
        });
        (port, server)
    }
    #[tokio::test]
    async fn verified_tls_accepts_local_ca_and_sends_bytes_only_after_handshake() {
        let dir = Temp::new();
        let (cert, key, ca) = certificate(&dir, false);
        let (port, server) = endpoint(acceptor(&cert, &key).unwrap()).await;
        let (mut socket, traffic) = connect(&format!("localhost:{port}"), Some(&ca), false).await.unwrap();
        let handshake = traffic.snapshot();
        assert!(handshake.verifier_sent_bytes > 5 && handshake.verifier_received_bytes > 5);
        socket.write_all(b"token").await.unwrap();
        assert!(server.await.unwrap());
        assert!(traffic.snapshot().verifier_sent_bytes > handshake.verifier_sent_bytes + 5);
    }
    #[tokio::test]
    async fn observed_control_tls_records_a_fixture_delay_without_changing_transport() {
        let dir = Temp::new();
        let (cert, key, ca) = certificate(&dir, false);
        let acceptor = acceptor(&cert, &key).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // Wait for the ClientHello so the observed TLS span has begun.
            let mut hello = [0; 1];
            assert_eq!(tcp.peek(&mut hello).await.unwrap(), 1);
            tokio::time::sleep(Duration::from_millis(25)).await;
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut bytes = [0; 5];
            tls.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, *b"token");
        });
        let trace = Trace::new();
        let (mut socket, _) = connect_observed(&format!("localhost:{port}"), Some(&ca), false, Some(&trace)).await.unwrap();
        socket.write_all(b"token").await.unwrap();
        server.await.unwrap();
        let snapshot = serde_json::to_value(trace.snapshot()).unwrap();
        let spans = snapshot["spans"].as_array().unwrap();
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[0]["phase"], "control_config");
        assert_eq!(spans[1]["phase"], "verifier_tcp_connect");
        assert_eq!(spans[2]["phase"], "verifier_tls");
        assert!(spans[2]["duration_ms"].as_u64().unwrap() >= 25);
        assert!(spans.iter().all(|span| span["outcome"] == "success"));
    }
    #[tokio::test]
    async fn wrong_hostname_untrusted_root_and_expired_certificate_reject_before_token() {
        for failure in ["hostname", "root", "expiry"] {
            let dir = Temp::new();
            let (cert, key, ca) = certificate(&dir, failure == "expiry");
            let (port, server) = endpoint(acceptor(&cert, &key).unwrap()).await;
            let host = if failure == "hostname" { "127.0.0.1" } else { "localhost" };
            assert!(
                connect(&format!("{host}:{port}"), if failure == "root" { None } else { Some(&ca) }, false).await.is_err(),
                "{failure}"
            );
            assert!(!server.await.unwrap());
        }
    }
    #[tokio::test]
    async fn plaintext_requires_an_explicit_local_fixture_and_never_falls_back() {
        assert!(connect("example.invalid:7047", None, true).await.is_err());
        assert!(connect("localhost:7047", None, true).await.is_err());
        assert!(connect("127.0.0.1:7047", Some("/test-ca.pem"), true).await.is_err());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 5];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"token");
        });
        let (mut socket, traffic) = connect(&address, None, true).await.unwrap();
        socket.write_all(b"token").await.unwrap();
        server.await.unwrap();
        assert_eq!(traffic.snapshot().verifier_sent_bytes, 5);
    }
    #[test]
    fn tls_files_reject_relative_paths_empty_ca_public_keys_symlinks_and_fifos() {
        use std::os::unix::fs::symlink;
        let dir = Temp::new();
        let (cert, key, _) = certificate(&dir, false);
        assert!(client(Some("relative.pem")).is_err());
        assert!(client(Some(&dir.file("empty.pem", b""))).is_err());
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(acceptor(&cert, &key).is_err());
        let link = dir.0.join("link.pem");
        symlink(&cert, &link).unwrap();
        assert!(pem(&link, false).is_err());
        let fifo = dir.0.join("fifo.pem");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(pem(&fifo, false).is_err());
    }
}

#[cfg(test)]
mod traffic_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn duplex_counts_only_accepted_partial_reads_and_writes() {
        let (socket, mut peer) = tokio::io::duplex(3);
        let vectored = socket.is_write_vectored();
        let traffic = Traffic::default();
        let mut socket = Metered { inner: socket, traffic: traffic.clone() };
        assert_eq!(socket.is_write_vectored(), vectored);
        assert_eq!(socket.write(b"abcdef").await.unwrap(), 3);
        assert_eq!(traffic.snapshot().verifier_sent_bytes, 3);
        assert!(tokio::time::timeout(Duration::from_millis(5), socket.write(b"ignored")).await.is_err());
        assert_eq!(traffic.snapshot().verifier_sent_bytes, 3);
        let mut taken = [0; 3];
        peer.read_exact(&mut taken).await.unwrap();
        assert_eq!(&taken, b"abc");
        assert_eq!(socket.write_vectored(&[IoSlice::new(b"def"), IoSlice::new(b"ghi")]).await.unwrap(), 3);
        peer.read_exact(&mut taken).await.unwrap();
        assert_eq!(&taken, b"def");
        assert_eq!(traffic.snapshot().verifier_sent_bytes, 6);
        peer.write_all(b"xyz").await.unwrap();
        let mut bytes = [0; 8];
        let mut read = ReadBuf::new(&mut bytes);
        read.put_slice(b"!");
        std::future::poll_fn(|cx| Pin::new(&mut socket).poll_read(cx, &mut read)).await.unwrap();
        assert_eq!(read.filled(), b"!xyz");
        assert_eq!(traffic.snapshot().verifier_received_bytes, 3);
        assert!(tokio::time::timeout(Duration::from_millis(5), socket.read(&mut bytes)).await.is_err());
        assert_eq!(traffic.snapshot().verifier_received_bytes, 3);
        drop(peer);
        assert!(socket.write(b"not accepted").await.is_err());
        assert_eq!(socket.read(&mut bytes).await.unwrap(), 0);
        socket.flush().await.unwrap();
        socket.shutdown().await.unwrap();
        assert_eq!(serde_json::to_value(traffic.snapshot()).unwrap(), serde_json::json!({
            "verifier_sent_bytes":6, "verifier_received_bytes":3, "verifier_transport_layer":"tcp_payload"
        }));
    }

    #[test]
    fn byte_counters_saturate_without_wrapping_and_mark_incomplete_telemetry() {
        let traffic = Traffic::default();
        traffic.add(&traffic.sent, MAX_METERED_BYTES as usize);
        assert!(!traffic.snapshot().verifier_bytes_saturated);
        traffic.add(&traffic.sent, 1);
        traffic.add(&traffic.sent, usize::MAX);
        traffic.add(&traffic.received, usize::MAX);
        let snapshot = traffic.snapshot();
        assert_eq!(snapshot.verifier_sent_bytes, MAX_METERED_BYTES);
        assert_eq!(snapshot.verifier_received_bytes, MAX_METERED_BYTES);
        assert!(snapshot.verifier_bytes_saturated);
        assert_eq!(serde_json::to_value(snapshot).unwrap()["verifier_bytes_saturated"], true);
    }
}
