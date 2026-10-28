//! The supplier's TCP connection to a web target. The node resolves the
//! name and checks the address before the prover runs, so the prover only
//! ever dials that literal address: straight from this host, or through an
//! HTTP CONNECT proxy that tunnels it. The node resolves and checks the
//! proxy's own name too and hands over its address, so nothing here asks
//! DNS. TLS stays end to end between the verifier and the target, so only a
//! non-intercepting tunnel works.
//!
//! Proxy settings are local configuration. Nothing here prints the proxy's
//! address or credentials.

use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{Context, Result, anyhow, bail};
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
    /// The proxy's address as an IP literal, which the node checked.
    pub host: String,
    pub port: u16,
    /// The exact `Proxy-Authorization` value, when the proxy needs one: for a
    /// Webshare proxy, the job's own session.
    pub authorization: Option<String>,
}

/// Why the target could not be reached.
pub enum Error {
    /// The direct TCP connection failed.
    Connect(anyhow::Error),
    /// The proxy could not be reached or would not open the tunnel: with the
    /// status of its CONNECT reply when it answered one other than 200, and
    /// `None` when it was unreachable or did not answer as HTTP.
    Proxy(Option<u16>, anyhow::Error),
}

impl Proxy {
    /// The checked socket address to dial. A link-local, unspecified or
    /// multicast address is never a proxy, whatever the node sent.
    fn address(&self) -> Result<SocketAddr> {
        let ip: IpAddr = self.host.parse().ok().context("egress proxy host must be an IP address literal")?;
        let unusable = match ip.to_canonical() {
            IpAddr::V4(v4) => v4.is_link_local() || v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast(),
            IpAddr::V6(v6) => v6.is_unicast_link_local() || v6.is_unspecified() || v6.is_multicast(),
        };
        if unusable || self.port == 0 {
            bail!("invalid egress proxy address");
        }
        if let Some(value) = &self.authorization
            && (value.is_empty() || value.len() > 4096 || !value.bytes().all(|b| (0x20..=0x7e).contains(&b)))
        {
            bail!("invalid egress proxy authorization");
        }
        Ok(SocketAddr::new(ip, self.port))
    }
}

/// Opens a TCP connection to `ip:port`, through `proxy` when one is
/// configured. `reached` is set once the proxy's own TCP connection is up, so
/// that a caller whose time ran out can tell a proxy it never reached from a
/// tunnel the proxy never opened.
pub async fn target(ip: IpAddr, port: u16, proxy: Option<&Proxy>, reached: &AtomicBool) -> Result<TcpStream, Error> {
    let stream = match proxy {
        None => TcpStream::connect(SocketAddr::new(ip, port)).await.context("target unreachable").map_err(Error::Connect)?,
        Some(proxy) => tunnel(proxy, SocketAddr::new(ip, port), reached).await?,
    };
    stream.set_nodelay(true).map_err(|e| Error::Connect(e.into()))?;
    Ok(stream)
}

async fn tunnel(proxy: &Proxy, target: SocketAddr, reached: &AtomicBool) -> Result<TcpStream, Error> {
    let unreachable = |error| Error::Proxy(None, error);
    let address = proxy.address().map_err(unreachable)?;
    let mut stream = TcpStream::connect(address).await.context("egress proxy unreachable").map_err(unreachable)?;
    reached.store(true, Ordering::Relaxed);
    // SocketAddr brackets an IPv6 address, as the authority form requires.
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(value) = &proxy.authorization {
        request.push_str("Proxy-Authorization: ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.context("egress proxy write failed").map_err(unreachable)?;
    let status = reply_status(&mut stream).await.map_err(unreachable)?;
    if status != 200 {
        return Err(Error::Proxy(Some(status), anyhow!("egress proxy refused the tunnel with HTTP {status}")));
    }
    Ok(stream)
}

/// Reads the proxy's CONNECT reply head and returns its status.
async fn reply_status(stream: &mut TcpStream) -> Result<u16> {
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
    Ok(status.iter().fold(0, |n, d| n * 10 + u16::from(d - b'0')))
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

    async fn dial(proxy: Option<&Proxy>) -> (Result<TcpStream, Error>, bool) {
        let reached = AtomicBool::new(false);
        let result = target("93.184.215.14".parse().unwrap(), 443, proxy, &reached).await;
        (result, reached.load(Ordering::Relaxed))
    }

    /// A proxy failure's status and message.
    fn message(error: Error) -> (Option<Option<u16>>, String) {
        match error {
            Error::Proxy(status, e) => (Some(status), format!("{e:#}")),
            Error::Connect(e) => (None, format!("{e:#}")),
        }
    }

    #[tokio::test]
    async fn a_proxy_tunnel_carries_the_checked_address_and_credentials() {
        let (config, seen) = proxy(b"HTTP/1.1 200 Connection established\r\n\r\n").await;
        let (result, reached) = dial(Some(&config)).await;
        let mut stream = result.ok().unwrap();
        assert!(reached);
        assert_eq!(*seen.lock().unwrap(), format!("CONNECT 93.184.215.14:443 HTTP/1.1\r\nHost: 93.184.215.14:443\r\nProxy-Authorization: {SECRET}\r\n\r\n").into_bytes());
        stream.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");

        let (mut config, seen) = proxy(b"HTTP/1.0 200 OK\r\nVia: test\r\n\r\n").await;
        config.authorization = None;
        assert!(target("2606:2800:220:1::1".parse().unwrap(), 443, Some(&config), &AtomicBool::new(false)).await.is_ok());
        assert_eq!(*seen.lock().unwrap(), b"CONNECT [2606:2800:220:1::1]:443 HTTP/1.1\r\nHost: [2606:2800:220:1::1]:443\r\n\r\n");
    }

    /// The CONNECT status reaches the caller, which the node maps to a class.
    #[tokio::test]
    async fn a_refused_tunnel_carries_its_status() {
        for (reply, status) in [
            (&b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n"[..], 407),
            (b"HTTP/1.1 402 Payment Required\r\n\r\n", 402),
            (b"HTTP/1.1 403 Forbidden\r\n\r\n", 403),
            (b"HTTP/1.1 429 Too Many Requests\r\n\r\n", 429),
            (b"HTTP/1.1 502 Bad Gateway\r\n\r\n", 502),
            (b"HTTP/1.0 504\r\n\r\n", 504),
        ] {
            let (config, _) = proxy(reply).await;
            let (result, reached) = dial(Some(&config)).await;
            let (got, text) = message(result.err().unwrap());
            assert_eq!(got, Some(Some(status)), "{text}");
            assert!(reached && !text.contains("c3ludGhldGlj") && !text.contains("127.0.0.1"), "{text}");
        }
    }

    #[tokio::test]
    async fn extra_bytes_and_bad_replies_are_proxy_failures_without_a_status_or_credentials() {
        for reply in [&b"HTTP/1.1 200 OK\r\n\r\nunexpected"[..], b"SSH-2.0-OpenSSH\r\n\r\n", b"HTTP/1.1 2000 OK\r\n\r\n", b"HTTP/1.1 20x OK\r\n\r\n"] {
            let (config, _) = proxy(reply).await;
            let (got, text) = message(dial(Some(&config)).await.0.err().unwrap());
            assert_eq!(got, Some(None), "{text}");
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
        assert!(matches!(dial(Some(&config)).await.0, Err(Error::Proxy(None, _))));
        // Invalid local settings fail before any connection: the proxy is a
        // checked IP literal, never a name, link-local or unspecified.
        for (host, auth) in [("", None), ("bad host", None), ("localhost", None), ("p.webshare.io", None), ("169.254.169.254", None), ("fe80::1", None), ("0.0.0.0", None), ("224.0.0.1", None), ("127.0.0.1", Some("a\r\nX-Injected: 1"))] {
            let config = Proxy { host: host.into(), port: 1, authorization: auth.map(Into::into) };
            let (result, reached) = dial(Some(&config)).await;
            let (got, text) = message(result.err().unwrap());
            assert!(got == Some(None) && !reached && !text.contains("Injected"), "{host}: {text}");
        }
    }

    #[tokio::test]
    async fn an_unreachable_proxy_or_target_is_classified() {
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
        let config = Proxy { host: "127.0.0.1".into(), port: closed, authorization: None };
        let (result, reached) = dial(Some(&config)).await;
        assert!(matches!(result, Err(Error::Proxy(None, _))) && !reached);
        assert!(matches!(target("127.0.0.1".parse().unwrap(), closed, None, &AtomicBool::new(false)).await, Err(Error::Connect(_))));
        let open = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(target("127.0.0.1".parse().unwrap(), open.local_addr().unwrap().port(), None, &AtomicBool::new(false)).await.is_ok());
    }
}
