//! End-to-end relay sessions against a local TLS 1.3 server, including a
//! supplier, a network path and a verifier that each try to cheat.

use std::{
    net::SocketAddr,
    ops::Range,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::{RootCertStore, pki_types::PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream},
    net::{TcpListener, TcpStream},
};

use super::{node, ot::NodeOt, record, tag, verifier, wire};
use crate::xpolicy;

pub(crate) const AUTH: &str = "0123456789abcdef0123456789abcdef01234567";
pub(crate) const RESPONSE_BODY: &str = r#"{"data":{"user":{"result":{"rest_id":"12","legacy":{"screen_name":"jack"}}}}}"#;

fn csrf() -> String {
    "c0ffee1234".repeat(16)
}

pub(crate) fn request() -> Vec<u8> {
    format!(
        "GET /i/api/graphql/qid_1/UserByScreenName?features=%7B%7D&variables=%7B%22screen_name%22%3A%22jack%22%7D HTTP/1.1\r\nHost: x.com\r\nAuthorization: Bearer PUBLIC\r\nX-Csrf-Token: {csrf}\r\nCookie: auth_token={AUTH}; ct0={csrf}; twid=u%3D1\r\nConnection: close\r\n\r\n",
        csrf = csrf()
    )
    .into_bytes()
}

pub(crate) fn response() -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{RESPONSE_BODY}", RESPONSE_BODY.len()).into_bytes()
}

pub(crate) struct Server {
    pub(crate) addr: SocketAddr,
    pub(crate) roots: RootCertStore,
    /// The request the server decrypted, once it has one.
    pub(crate) seen: Arc<Mutex<Option<Vec<u8>>>>,
}

/// A TLS server for x.com under a private CA that answers one request.
pub(crate) async fn server(response: Vec<u8>, mut config: impl FnMut(&mut rustls::ServerConfig) + Send + 'static) -> Server {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![xpolicy::HOST.to_owned()]).unwrap().signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into())
        .unwrap();
    config(&mut tls);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(None));
    let record = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, response, record) = (acceptor.clone(), response.clone(), record.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(n) if n > 0 => request.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                *record.lock().unwrap() = Some(request);
                let _ = tls.write_all(&response).await;
                let _ = tls.flush().await;
                // Like X, keep the connection open after the response.
                let _ = tls.read(&mut chunk).await;
            });
        }
    });
    Server { addr, roots, seen }
}

/// What a tampering party does to one item passing through it.
enum Verdict {
    Pass,
    Replace(Vec<u8>),
    /// Forward this, then stop forwarding in that direction.
    Last(Vec<u8>),
}

/// Relays TLS records between the supplier and the server, letting `tamper`
/// alter them. `client` counts records from the supplier, `server` from X.
fn path<F>(server: TcpStream, mut tamper: F) -> DuplexStream
where
    F: FnMut(bool, usize, &[u8]) -> Verdict + Send + 'static,
{
    let (near, far) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let (mut from_node, mut to_node) = tokio::io::split(far);
        let (mut from_server, mut to_server) = server.into_split();
        let (mut up, mut down) = (Vec::new(), Vec::new());
        let (mut up_count, mut down_count) = (0, 0);
        let (mut a, mut b) = ([0u8; 8192], [0u8; 8192]);
        let (mut up_open, mut down_open) = (true, true);
        while up_open || down_open {
            tokio::select! {
                n = from_node.read(&mut a), if up_open => {
                    let n = n.unwrap_or(0);
                    if n == 0 { up_open = false; let _ = to_server.shutdown().await; continue; }
                    up.extend_from_slice(&a[..n]);
                    while let Ok(Some((_, record))) = record::take(&mut up) {
                        let verdict = tamper(true, up_count, &record);
                        up_count += 1;
                        match verdict {
                            Verdict::Pass => { let _ = to_server.write_all(&record).await; }
                            Verdict::Replace(bytes) => { let _ = to_server.write_all(&bytes).await; }
                            Verdict::Last(bytes) => { let _ = to_server.write_all(&bytes).await; let _ = to_server.shutdown().await; up_open = false; }
                        }
                    }
                }
                n = from_server.read(&mut b), if down_open => {
                    let n = n.unwrap_or(0);
                    if n == 0 { down_open = false; let _ = to_node.shutdown().await; continue; }
                    down.extend_from_slice(&b[..n]);
                    while let Ok(Some((_, record))) = record::take(&mut down) {
                        let verdict = tamper(false, down_count, &record);
                        down_count += 1;
                        match verdict {
                            Verdict::Pass => { let _ = to_node.write_all(&record).await; }
                            Verdict::Replace(bytes) => { let _ = to_node.write_all(&bytes).await; }
                            Verdict::Last(bytes) => { let _ = to_node.write_all(&bytes).await; let _ = to_node.shutdown().await; down_open = false; }
                        }
                    }
                }
            }
        }
    });
    near
}

/// Relays frames between the supplier and the verifier, letting `tamper`
/// alter them. The flag is true for frames from the supplier.
fn link<F>(mut tamper: F) -> (DuplexStream, DuplexStream)
where
    F: FnMut(bool, u8, &[u8]) -> Verdict + Send + 'static,
{
    let (node_end, node_far) = tokio::io::duplex(1 << 20);
    let (verifier_end, verifier_far) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let (mut from_node, mut to_node) = tokio::io::split(node_far);
        let (mut from_verifier, mut to_verifier) = tokio::io::split(verifier_far);
        loop {
            tokio::select! {
                frame = wire::recv(&mut from_node) => {
                    let Ok((kind, payload)) = frame else { let _ = to_verifier.shutdown().await; break };
                    match tamper(true, kind, &payload) {
                        Verdict::Pass => { let _ = wire::send(&mut to_verifier, kind, &payload).await; }
                        Verdict::Replace(bytes) | Verdict::Last(bytes) => { let _ = wire::send(&mut to_verifier, kind, &bytes).await; }
                    }
                }
                frame = wire::recv(&mut from_verifier) => {
                    let Ok((kind, payload)) = frame else { let _ = to_node.shutdown().await; break };
                    match tamper(false, kind, &payload) {
                        Verdict::Pass => { let _ = wire::send(&mut to_node, kind, &payload).await; }
                        Verdict::Replace(bytes) | Verdict::Last(bytes) => { let _ = wire::send(&mut to_node, kind, &bytes).await; }
                    }
                }
            }
        }
    });
    (node_end, verifier_end)
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(20), future).await.expect("session hung")
}

/// Runs an honest supplier and verifier over the given link and server path.
async fn run<V, X>(roots: RootCertStore, node_end: V, verifier_end: DuplexStream, to_server: X) -> (Result<Vec<u8>>, Result<verifier::Outcome>)
where
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    X: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = verifier::tls_config(roots).unwrap();
    let raw = request();
    let node = tokio::spawn(async move { node::session(node_end, to_server, &raw).await });
    let outcome = within(verifier::run(verifier_end, config, xpolicy::HOST, verifier::authorize_x)).await;
    // A verifier that gives up closes its side, which is how the supplier learns of it.
    let response = within(node).await.unwrap();
    (response, outcome)
}

fn hidden_values(raw: &[u8]) -> Vec<Range<usize>> {
    let text = String::from_utf8_lossy(raw);
    let csrf = csrf();
    let first = text.find(&csrf).unwrap();
    let second = first + csrf.len() + text[first + csrf.len()..].find(&csrf).unwrap();
    let auth = text.find(AUTH).unwrap();
    vec![first..first + csrf.len(), auth..auth + AUTH.len(), second..second + csrf.len()]
}

#[tokio::test]
async fn honest_session_proves_the_read_and_the_verifier_never_sees_a_secret() {
    let server = server(response(), |_| {}).await;
    let seen_by_verifier = Arc::new(Mutex::new(Vec::new()));
    let log = seen_by_verifier.clone();
    let (node_end, verifier_end) = link(move |from_node, _, payload| {
        if from_node {
            log.lock().unwrap().extend_from_slice(payload);
        }
        Verdict::Pass
    });
    let tcp = TcpStream::connect(server.addr).await.unwrap();
    let (response_at_node, outcome) = run(server.roots.clone(), node_end, verifier_end, tcp).await;
    let outcome = outcome.unwrap();

    // X received the real request, secrets included, in one record that authenticated.
    assert_eq!(server.seen.lock().unwrap().as_deref(), Some(&request()[..]));
    // Both sides hold X's response; the verifier's copy is the one it decrypted.
    assert_eq!(outcome.received, response());
    assert_eq!(response_at_node.unwrap(), response());
    // The verifier's view of the request has zeros where the secrets are, and nothing else differs.
    let raw = request();
    assert_eq!(outcome.hidden, hidden_values(&raw));
    let mut blank = raw.clone();
    outcome.hidden.iter().for_each(|r| blank[r.clone()].fill(0));
    assert_eq!(outcome.sent, blank);
    // The existing X policy accepts it exactly as it accepts an MPC-TLS transcript.
    let exchange = xpolicy::check(xpolicy::HOST, &outcome.sent, &outcome.hidden, &outcome.received, &[]).unwrap();
    assert_eq!((exchange.operation.as_str(), exchange.http_status, exchange.body.as_str()), ("UserByScreenName", 200, RESPONSE_BODY));
    // Nothing the supplier sent the verifier contains a secret value.
    let seen = seen_by_verifier.lock().unwrap();
    for secret in [AUTH.as_bytes(), csrf().as_bytes(), &AUTH.as_bytes()[..8], &csrf().as_bytes()[..8]] {
        assert!(!seen.windows(secret.len()).any(|w| w == secret), "a secret reached the verifier");
    }
}

#[tokio::test]
async fn altered_dropped_or_truncated_server_records_are_rejected() {
    for attack in ["flip", "truncate", "drop", "garbage"] {
        let server = server(response(), |_| {}).await;
        let tcp = TcpStream::connect(server.addr).await.unwrap();
        let mut request_seen = false;
        let to_server = path(tcp, move |from_node, index, record| {
            // The supplier's request is its second protected record, after the Finished.
            if from_node {
                request_seen |= index >= 3;
                return Verdict::Pass;
            }
            if !request_seen || record[0] != record::APPLICATION_DATA {
                return Verdict::Pass;
            }
            let mut bytes = record.to_vec();
            match attack {
                "flip" => {
                    bytes[7] ^= 1;
                    Verdict::Replace(bytes)
                }
                "truncate" => Verdict::Last(bytes[..bytes.len() / 2].to_vec()),
                "drop" => Verdict::Last(Vec::new()),
                _ => Verdict::Replace([&record::aad(40)[..], &[0x5a; 56]].concat()),
            }
        });
        let (node_end, verifier_end) = link(|_, _, _| Verdict::Pass);
        let (response_at_node, outcome) = run(server.roots.clone(), node_end, verifier_end, to_server).await;
        assert!(outcome.is_err(), "{attack}: verifier accepted a tampered response");
        assert!(response_at_node.is_err(), "{attack}: supplier reported a result");
    }
}

#[tokio::test]
async fn altering_the_sealed_request_on_the_wire_gets_no_response() {
    let server = server(response(), |_| {}).await;
    let tcp = TcpStream::connect(server.addr).await.unwrap();
    let to_server = path(tcp, |from_node, index, record| {
        if from_node && index == 3 {
            // One public ciphertext bit: the supplier has no tag share for it.
            let mut bytes = record.to_vec();
            bytes[5 + 4] ^= 0x20;
            return Verdict::Replace(bytes);
        }
        Verdict::Pass
    });
    let (node_end, verifier_end) = link(|_, _, _| Verdict::Pass);
    let (response_at_node, outcome) = run(server.roots.clone(), node_end, verifier_end, to_server).await;
    assert!(outcome.is_err() && response_at_node.is_err());
    assert!(server.seen.lock().unwrap().is_none(), "server accepted an altered request");
}

#[tokio::test]
async fn a_server_without_the_pinned_identity_or_cipher_is_refused() {
    // Unknown CA: the verifier's roots do not include it.
    let server_a = server(response(), |_| {}).await;
    let other = server(response(), |_| {}).await;
    let tcp = TcpStream::connect(server_a.addr).await.unwrap();
    let (node_end, verifier_end) = link(|_, _, _| Verdict::Pass);
    let (response_at_node, outcome) = run(other.roots.clone(), node_end, verifier_end, tcp).await;
    assert!(outcome.is_err() && response_at_node.is_err());
    assert!(server_a.seen.lock().unwrap().is_none());

    // TLS 1.2 only: the relay has no split tag for it and must not fall back.
    let old = server(response(), |tls| {
        *tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(tls.cert_resolver.clone());
    })
    .await;
    let tcp = TcpStream::connect(old.addr).await.unwrap();
    let (node_end, verifier_end) = link(|_, _, _| Verdict::Pass);
    let (response_at_node, outcome) = run(old.roots.clone(), node_end, verifier_end, tcp).await;
    assert!(outcome.is_err() && response_at_node.is_err());
    assert!(old.seen.lock().unwrap().is_none());
}

#[tokio::test]
async fn a_request_outside_policy_gets_no_key_material() {
    for case in ["post", "hide_path", "nonzero_hidden", "two_requests", "wrong_transfers"] {
        let server = server(response(), |_| {}).await;
        let (mut node_end, verifier_end) = tokio::io::duplex(1 << 20);
        let config = verifier::tls_config(server.roots.clone()).unwrap();
        let verifier = tokio::spawn(async move { within(verifier::run(verifier_end, config, xpolicy::HOST, verifier::authorize_x)).await });

        let raw = request();
        let (public, hidden): (Vec<u8>, Vec<Range<usize>>) = match case {
            "post" => (String::from_utf8(raw.clone()).unwrap().replacen("GET ", "POST ", 1).into_bytes(), vec![]),
            // Hiding part of the request line is not one of the allowed values.
            "hide_path" => {
                let mut public = raw.clone();
                public[20..28].fill(0);
                (public, vec![20..28])
            }
            // A hidden range that still carries bytes would be sealed as public.
            "nonzero_hidden" => (raw.clone(), hidden_values(&raw)[..1].to_vec()),
            _ => {
                let mut public = raw.clone();
                hidden_values(&raw).iter().for_each(|r| public[r.clone()].fill(0));
                (public, hidden_values(&raw))
            }
        };
        let bits = hidden.iter().map(|r| r.len() * 8).sum::<usize>();
        let transfers = if case == "wrong_transfers" { bits - 8 } else { bits };
        wire::send(&mut node_end, wire::HELLO, format!("{{\"version\":1,\"transfers\":{transfers}}}").as_bytes()).await.unwrap();
        // The verifier's ClientHello arrives first; this supplier never forwards it.
        let mut corrections = Vec::new();
        if transfers > 0 {
            let (mut ot, (kind, setup)) = NodeOt::start(transfers).unwrap();
            wire::send(&mut node_end, kind, &setup).await.unwrap();
            loop {
                let (kind, payload) = wire::recv(&mut node_end).await.unwrap();
                match kind {
                    wire::CO_CHOOSE => {
                        for (kind, frame) in ot.on_choose(&payload).unwrap() {
                            wire::send(&mut node_end, kind, &frame).await.unwrap();
                        }
                    }
                    wire::KOS_CHI => {
                        let (kind, check) = ot.on_chi(&payload).unwrap();
                        wire::send(&mut node_end, kind, &check).await.unwrap();
                        break;
                    }
                    _ => {}
                }
            }
            corrections = vec![false; bits];
        }
        let mut payload = (public.len() as u32).to_be_bytes().to_vec();
        payload.extend_from_slice(&public);
        payload.extend_from_slice(&(hidden.len() as u16).to_be_bytes());
        for r in &hidden {
            payload.extend_from_slice(&(r.start as u32).to_be_bytes());
            payload.extend_from_slice(&(r.end as u32).to_be_bytes());
        }
        payload.extend_from_slice(&vec![0u8; corrections.len().div_ceil(8)]);
        let _ = wire::send(&mut node_end, wire::REQUEST, &payload).await;
        if case == "two_requests" {
            let _ = wire::send(&mut node_end, wire::REQUEST, &payload).await;
        }
        // Whatever else arrives, it is never request material.
        let mut got_material = false;
        while let Ok(Ok((kind, _))) = tokio::time::timeout(Duration::from_secs(5), wire::recv(&mut node_end)).await {
            got_material |= kind == wire::MATERIAL;
        }
        assert!(!got_material, "{case}: verifier released key material");
        drop(node_end);
        assert!(verifier.await.unwrap().is_err(), "{case}: verifier accepted");
    }
}

#[tokio::test]
async fn a_verifier_that_cheats_on_the_tag_gets_nothing_from_the_server() {
    for attack in ["masked", "share", "ciphertext"] {
        let server = server(response(), |_| {}).await;
        let (node_end, verifier_end) = link(move |from_node, kind, payload| {
            if from_node || kind != wire::MATERIAL {
                return Verdict::Pass;
            }
            let mut bytes = payload.to_vec();
            let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
            match attack {
                // Probe one hidden bit: the tag is now wrong exactly when that bit is set.
                "masked" => bytes[4 + len + 16 + 16 * 3] ^= 1,
                "share" => bytes[4 + len] ^= 1,
                _ => bytes[4 + 2] ^= 1,
            }
            Verdict::Replace(bytes)
        });
        let tcp = TcpStream::connect(server.addr).await.unwrap();
        let (response_at_node, outcome) = run(server.roots.clone(), node_end, verifier_end, tcp).await;
        // "masked" flips a bit the supplier only uses when its hidden bit is 1; either
        // way the server must never accept a request the verifier distorted.
        if server.seen.lock().unwrap().is_some() {
            assert_eq!(attack, "masked", "{attack}: server accepted a distorted request");
            assert_eq!(server.seen.lock().unwrap().as_deref(), Some(&request()[..]));
        } else {
            assert!(response_at_node.is_err() && outcome.is_err(), "{attack}");
        }
    }
}

#[tokio::test]
async fn the_verifier_cannot_use_the_connection_after_the_request_or_get_a_second_record() {
    for attack in ["late_bytes", "second_material"] {
        let server = server(response(), |_| {}).await;
        let (node_end, mut verifier_side) = tokio::io::duplex(1 << 20);
        let tcp = TcpStream::connect(server.addr).await.unwrap();
        let raw = request();
        let node = tokio::spawn(async move { node::session(node_end, tcp, &raw).await });
        // A scripted verifier: complete the transfers honestly, then misbehave.
        let (_, hello) = wire::recv(&mut verifier_side).await.unwrap();
        let transfers = serde_json::from_slice::<serde_json::Value>(&hello).unwrap()["transfers"].as_u64().unwrap() as usize;
        let mut ot = super::ot::VerifierOt::new(transfers);
        let public_len;
        loop {
            let (kind, payload) = wire::recv(&mut verifier_side).await.unwrap();
            match kind {
                wire::CO_SETUP => {
                    let (kind, reply) = ot.on_setup(&payload).unwrap();
                    wire::send(&mut verifier_side, kind, &reply).await.unwrap();
                }
                wire::CO_PAYLOAD => ot.on_payload(&payload).unwrap(),
                wire::KOS_EXTEND => {
                    if let Some((kind, chi)) = ot.on_extend(&payload).unwrap() {
                        wire::send(&mut verifier_side, kind, &chi).await.unwrap();
                    }
                }
                wire::KOS_CHECK => ot.on_check(&payload).unwrap(),
                wire::REQUEST => {
                    public_len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
                    break;
                }
                _ => {}
            }
        }
        let mut material = ((public_len + 1) as u32).to_be_bytes().to_vec();
        material.extend_from_slice(&vec![0x11; public_len + 1 + 16 + 16 * transfers]);
        wire::send(&mut verifier_side, wire::MATERIAL, &material).await.unwrap();
        match attack {
            "late_bytes" => wire::send(&mut verifier_side, wire::TO_SERVER, b"GET /anything HTTP/1.1\r\n\r\n").await.unwrap(),
            _ => wire::send(&mut verifier_side, wire::MATERIAL, &material).await.unwrap(),
        }
        assert!(within(node).await.unwrap().is_err(), "{attack}: supplier went along");
    }
}

#[tokio::test]
async fn a_response_cannot_be_carried_into_another_session() {
    // Record everything X sent in one session and replay it to a second verifier.
    let server = server(response(), |_| {}).await;
    let recorded = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let log = recorded.clone();
    let tcp = TcpStream::connect(server.addr).await.unwrap();
    let to_server = path(tcp, move |from_node, _, record| {
        if !from_node {
            log.lock().unwrap().push(record.to_vec());
        }
        Verdict::Pass
    });
    let (node_end, verifier_end) = link(|_, _, _| Verdict::Pass);
    let (first, outcome) = run(server.roots.clone(), node_end, verifier_end, to_server).await;
    assert!(first.is_ok() && outcome.is_ok());

    let replay: Vec<u8> = recorded.lock().unwrap().concat();
    let (mut node_end, verifier_end) = tokio::io::duplex(1 << 20);
    let config = verifier::tls_config(server.roots.clone()).unwrap();
    let verifier = tokio::spawn(async move { within(verifier::run(verifier_end, config, xpolicy::HOST, verifier::authorize_x)).await });
    wire::send(&mut node_end, wire::HELLO, b"{\"version\":1,\"transfers\":0}").await.unwrap();
    for chunk in replay.chunks(wire::CHUNK) {
        if wire::send(&mut node_end, wire::FROM_SERVER, chunk).await.is_err() {
            break;
        }
    }
    assert!(verifier.await.unwrap().is_err(), "verifier accepted another session's records");
}

#[tokio::test]
async fn malformed_or_oversized_hellos_and_stray_frames_end_the_session() {
    let server = server(response(), |_| {}).await;
    for hello in [&b"{\"version\":2,\"transfers\":0}"[..], b"{\"version\":1,\"transfers\":999999}", b"{\"version\":1}", b"not json", b"{\"version\":1,\"transfers\":0,\"extra\":1}"] {
        let (mut node_end, verifier_end) = tokio::io::duplex(1 << 16);
        wire::send(&mut node_end, wire::HELLO, hello).await.unwrap();
        let config = verifier::tls_config(server.roots.clone()).unwrap();
        assert!(within(verifier::run(verifier_end, config, xpolicy::HOST, verifier::authorize_x)).await.is_err());
    }
    for stray in [wire::KOS_CHECK, wire::CO_PAYLOAD, wire::KOS_EXTEND, wire::CO_SETUP, wire::SERVER_EOF, wire::MATERIAL] {
        let (mut node_end, verifier_end) = tokio::io::duplex(1 << 16);
        wire::send(&mut node_end, wire::HELLO, b"{\"version\":1,\"transfers\":0}").await.unwrap();
        wire::send(&mut node_end, stray, &[]).await.unwrap();
        let config = verifier::tls_config(server.roots.clone()).unwrap();
        assert!(within(verifier::run(verifier_end, config, xpolicy::HOST, verifier::authorize_x)).await.is_err(), "frame {stray}");
    }
    // A session that never says hello is refused on its first frame.
    let (mut node_end, verifier_end) = tokio::io::duplex(1 << 16);
    wire::send(&mut node_end, wire::REQUEST, &[0; 8]).await.unwrap();
    let config = verifier::tls_config(server.roots.clone()).unwrap();
    assert!(within(verifier::run(verifier_end, config, xpolicy::HOST, verifier::authorize_x)).await.is_err());
}

#[test]
fn split_tag_inputs_are_bound_to_the_request_layout() {
    // The supplier's own checks: material for a different length or bit count is refused.
    let material = tag::Material { ciphertext: vec![0; 10], masked: vec![[0; 16]; 8], tag_share: [0; 16] };
    assert!(tag::node_record(&material, &[2..3], b"x", &[[0; 16]; 8]).is_ok());
    assert!(tag::node_record(&material, &[2..3], b"xy", &[[0; 16]; 8]).is_err());
    assert!(tag::node_record(&material, &[2..4], b"xy", &[[0; 16]; 8]).is_err());
    assert!(tag::node_record(&material, &[9..10], b"x", &[[0; 16]; 8]).is_err());
}
