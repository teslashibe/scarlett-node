//! The supplier's TCP connection to a web target. The node resolves the
//! name and checks the address before the prover runs, so the prover only
//! ever dials that literal address: straight from this host, or through a
//! local HTTP CONNECT proxy that tunnels it. TLS stays end to end between
//! the verifier and the target, so only a non-intercepting tunnel works.
//!
//! Proxy settings are local configuration. Nothing here prints the proxy's
//! address or credentials.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

/// Largest CONNECT reply head accepted from the proxy.
const MAX_REPLY: usize = 8 << 10;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proxy {
    pub host: String,
    pub port: u16,
    /// The exact `Proxy-Authorization` value, when the proxy needs one.
    pub authorization: Option<String>,
}

/// Why the target could not be reached.
pub enum Error {
    /// The direct TCP connection failed.
    Connect(anyhow::Error),
    /// The proxy could not be reached or would not open the tunnel.
    Proxy(anyhow::Error),
}

impl Proxy {
    fn validate(&self) -> Result<()> {
        let printable = |s: &str| s.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if self.host.is_empty() || self.host.len() > 253 || !printable(&self.host) || self.port == 0 {
            bail!("invalid egress proxy address");
        }
        if let Some(value) = &self.authorization
            && (value.is_empty() || value.len() > 4096 || !value.bytes().all(|b| (0x20..=0x7e).contains(&b)))
        {
            bail!("invalid egress proxy authorization");
        }
        Ok(())
    }
}

/// Opens a TCP connection to `ip:port`, through `proxy` when one is configured.
pub async fn target(ip: IpAddr, port: u16, proxy: Option<&Proxy>) -> Result<TcpStream, Error> {
    let stream = match proxy {
        None => TcpStream::connect(SocketAddr::new(ip, port)).await.context("target unreachable").map_err(Error::Connect)?,
        Some(proxy) => tunnel(proxy, SocketAddr::new(ip, port)).await.map_err(Error::Proxy)?,
    };
    stream.set_nodelay(true).map_err(|e| Error::Connect(e.into()))?;
    Ok(stream)
}

async fn tunnel(proxy: &Proxy, target: SocketAddr) -> Result<TcpStream> {
    proxy.validate()?;
    let mut stream = TcpStream::connect((proxy.host.as_str(), proxy.port)).await.context("egress proxy unreachable")?;
    // SocketAddr brackets an IPv6 address, as the authority form requires.
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(value) = &proxy.authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.context("egress proxy write failed")?;
    let mut reply = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await.context("egress proxy read failed")?;
        if n == 0 {
            bail!("egress proxy closed before replying");
        }
        let from = reply.len().saturating_sub(3);
        reply.extend_from_slice(&chunk[..n]);
        if let Some(at) = reply[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            // The target speaks only after the verifier's ClientHello, so
            // anything here came from the proxy, not through the tunnel.
            if from + at + 4 != reply.len() {
                bail!("egress proxy sent bytes after its reply");
            }
            break;
        }
        if reply.len() > MAX_REPLY {
            bail!("egress proxy reply is too large");
        }
    }
    let status = reply.strip_prefix(b"HTTP/1.1 ").or_else(|| reply.strip_prefix(b"HTTP/1.0 ")).and_then(|rest| rest.get(..3)).context("egress proxy reply is not HTTP")?;
    if !status.iter().all(u8::is_ascii_digit) || !matches!(reply.get(12), Some(b' ' | b'\r')) {
        bail!("egress proxy reply is not HTTP");
    }
    if status != b"200" {
        bail!("egress proxy refused the tunnel with HTTP {}", String::from_utf8_lossy(status));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    const SECRET: &str = "Basic c3ludGhldGljOnByb3h5LXNlY3JldA==";

    /// A one-shot proxy that records the request head and answers with `reply`.
    /// After a 200 it echoes, standing in for the tunnelled target.
    async fn proxy(reply: &'static [u8]) -> (Proxy, Arc<Mutex<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && tcp.read(&mut byte).await.unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            *log.lock().unwrap() = head;
            tcp.write_all(reply).await.unwrap();
            let mut buf = [0u8; 64];
            while let Ok(n @ 1..) = tcp.read(&mut buf).await {
                if tcp.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        (Proxy { host: "127.0.0.1".into(), port, authorization: Some(SECRET.into()) }, seen)
    }

    fn message(error: Error) -> (bool, String) {
        match error {
            Error::Proxy(e) => (true, format!("{e:#}")),
            Error::Connect(e) => (false, format!("{e:#}")),
        }
    }

    #[tokio::test]
    async fn a_proxy_tunnel_carries_the_checked_address_and_credentials() {
        let (config, seen) = proxy(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
        let mut stream = target("93.184.215.14".parse().unwrap(), 443, Some(&config)).await.ok().unwrap();
        assert_eq!(*seen.lock().unwrap(), format!("CONNECT 93.184.215.14:443 HTTP/1.1\r\nHost: 93.184.215.14:443\r\nProxy-Authorization: {SECRET}\r\n\r\n").into_bytes());
        stream.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");

        let (mut config, seen) = proxy(b"HTTP/1.0 200 OK\r\nVia: test\r\n\r\n").await;
        config.authorization = None;
        assert!(target("2606:2800:220:1::1".parse().unwrap(), 443, Some(&config)).await.is_ok());
        assert_eq!(*seen.lock().unwrap(), b"CONNECT [2606:2800:220:1::1]:443 HTTP/1.1\r\nHost: [2606:2800:220:1::1]:443\r\n\r\n");
    }

    #[tokio::test]
    async fn refusals_extra_bytes_and_bad_replies_are_proxy_failures_without_credentials() {
        for reply in [
            &b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"[..],
            b"HTTP/1.1 403 Forbidden\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\nunexpected",
            b"SSH-2.0-OpenSSH\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
        ] {
            let (config, _) = proxy(reply).await;
            let (is_proxy, text) = message(target("93.184.215.14".parse().unwrap(), 443, Some(&config)).await.err().unwrap());
            assert!(is_proxy, "{text}");
            assert!(!text.contains("c3ludGhldGlj") && !text.contains("127.0.0.1"), "{text}");
        }
        // A proxy that never stops sending a head.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let _ = tcp.write_all(&vec![b'a'; 3 * MAX_REPLY]).await;
        });
        let config = Proxy { host: "127.0.0.1".into(), port, authorization: None };
        assert!(matches!(target("93.184.215.14".parse().unwrap(), 443, Some(&config)).await, Err(Error::Proxy(_))));
        // Invalid local settings fail before any connection.
        for (host, auth) in [("", None), ("bad host", None), ("127.0.0.1", Some("a\r\nX-Injected: 1"))] {
            let config = Proxy { host: host.into(), port: 1, authorization: auth.map(Into::into) };
            let (is_proxy, text) = message(target("93.184.215.14".parse().unwrap(), 443, Some(&config)).await.err().unwrap());
            assert!(is_proxy && !text.contains("Injected"), "{text}");
        }
    }

    #[tokio::test]
    async fn an_unreachable_proxy_or_target_is_classified() {
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        let config = Proxy { host: "127.0.0.1".into(), port: closed, authorization: None };
        assert!(matches!(target("93.184.215.14".parse().unwrap(), 443, Some(&config)).await, Err(Error::Proxy(_))));
        assert!(matches!(target("127.0.0.1".parse().unwrap(), closed, None).await, Err(Error::Connect(_))));
        let open = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(target("127.0.0.1".parse().unwrap(), open.local_addr().unwrap().port(), None).await.is_ok());
    }
}
