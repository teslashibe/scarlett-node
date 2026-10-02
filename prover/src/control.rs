//! Encrypted supplier/verifier control transport, configured on the local host.
use anyhow::{Context, Result, bail};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}
pub type Socket = Box<dyn Transport>;

// This exception exists only for the unpaid loopback/Docker fixtures. A DNS
// name cannot resolve into eligibility for a plaintext connection.
pub fn fixture_address(address: &str) -> bool {
    address.parse::<std::net::SocketAddr>().is_ok_and(|a| a.ip().is_loopback()) || address == "verifier:7047"
}
fn pem(path: &Path, private: bool) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("TLS file must have an absolute path");
    }
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).context("opening TLS file")?;
    let info = file.metadata()?;
    if !info.is_file() || info.len() > 1 << 20 || private && (info.mode() & 0o077 != 0 || info.uid() != unsafe { libc::geteuid() }) {
        bail!("invalid TLS file permissions or size");
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
pub async fn connect(address: &str, ca: Option<&str>, plaintext_fixture: bool) -> Result<Socket> {
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
    tokio::time::timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect(address).await.context("verifier unreachable")?;
        socket.set_nodelay(true)?;
        if let Some(connector) = connector {
            let name = ServerName::try_from(host).context("invalid verifier TLS name")?;
            Ok(Box::new(connector.connect(name, socket).await.context("verifier TLS verification failed")?) as Socket)
        } else {
            Ok(Box::new(socket) as Socket)
        }
    })
    .await
    .context("verifier connection timed out")?
}
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

#[cfg(test)]
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
        let mut socket = connect(&format!("localhost:{port}"), Some(&ca), false).await.unwrap();
        socket.write_all(b"token").await.unwrap();
        assert!(server.await.unwrap());
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
        let mut socket = connect(&address, None, true).await.unwrap();
        socket.write_all(b"token").await.unwrap();
        server.await.unwrap();
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
