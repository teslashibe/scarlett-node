//! Supplier side of a relay session: `scarlett-prover relay-x`.
//!
//! The supplier opens the TCP connection to X, so X sees its address, and
//! carries the verifier's TLS session over it. It holds no session key. Its
//! only cryptographic act is to place its cookie and CSRF values into the one
//! request record the verifier sealed and finish that record's tag.

use std::{ops::Range, time::Instant};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};

use super::{
    MAX_REQUEST, VERSION,
    ot::NodeOt,
    tag,
    wire::{self, CHUNK},
};
use crate::{
    policy::find,
    xpolicy::{self, HOST},
    xprove::{MAX_RECV, Request},
};

/// Bytes of the verifier's handshake the supplier will forward to X. After
/// the request record nothing more is forwarded.
const MAX_HANDSHAKE: usize = 64 << 10;

#[derive(Serialize)]
pub struct Summary {
    /// Untrusted operational TCP payload counters, never billing or proof evidence.
    #[serde(flatten)]
    pub verifier_transport: crate::control::TrafficSnapshot,
    pub status: &'static str,
    /// Base64 of X's complete HTTP response as the verifier decrypted it.
    pub response: String,
    pub sent_bytes: usize,
    pub received_bytes: usize,
    pub duration_ms: u128,
}

pub async fn run(request: Request) -> Result<Summary> {
    let raw = STANDARD.decode(request.request.as_bytes()).context("request is not base64")?;
    if raw.len() > MAX_REQUEST || !raw.starts_with(b"GET /i/api/graphql/") {
        bail!("request must be an X GraphQL GET of at most {MAX_REQUEST} bytes");
    }
    if request.token.len() != 64 || !request.token.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("verifier token must be 64 hex characters");
    }
    let started = Instant::now();
    let (mut socket, traffic) = crate::control::connect(&request.verifier, request.verifier_ca_file.as_deref(), request.plaintext_fixture).await?;
    socket.write_all(format!("{}\n", request.token).as_bytes()).await?;
    let server = TcpStream::connect((HOST, 443)).await.context("x.com unreachable")?;
    server.set_nodelay(true)?;
    let response = tokio::time::timeout(std::time::Duration::from_secs(120), session(socket, server, &raw)).await.context("relay session timed out")??;
    Ok(Summary {
        verifier_transport: traffic.snapshot(),
        status: "proof_sent",
        received_bytes: response.len(),
        response: STANDARD.encode(&response),
        sent_bytes: raw.len(),
        duration_ms: started.elapsed().as_millis(),
    })
}

/// The hidden ranges of a request and the bytes in them.
fn secrets(raw: &[u8]) -> Result<(Vec<Range<usize>>, Vec<u8>)> {
    let head_end = find(raw, b"\r\n\r\n").context("request has no header terminator")?;
    let hidden = xpolicy::secret_spans(raw, head_end)?.into_iter().filter(|range| !range.is_empty()).collect::<Vec<_>>();
    let secret = hidden.iter().flat_map(|range| raw[range.clone()].to_vec()).collect();
    Ok((hidden, secret))
}

enum Event {
    Frame(u8, Vec<u8>),
    Server(Vec<u8>),
    ServerEof,
    Failed(anyhow::Error),
}

/// Runs the session over an established verifier socket and server
/// connection, and returns the response the verifier decrypted.
pub async fn session<V, X>(verifier: V, server: X, raw: &[u8]) -> Result<Vec<u8>>
where
    V: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    X: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (hidden, secret) = secrets(raw)?;
    let bits = tag::hidden_bits(raw.len(), &hidden)?;
    let mut public = raw.to_vec();
    hidden.iter().for_each(|range| public[range.clone()].fill(0));

    let (mut from_verifier, mut to_verifier) = tokio::io::split(verifier);
    let (mut from_server, mut to_server) = tokio::io::split(server);
    let (events, mut inbox) = mpsc::channel(16);
    let frames = events.clone();
    let frame_reader = tokio::spawn(async move {
        loop {
            let event = match wire::recv(&mut from_verifier).await {
                Ok((kind, payload)) => Event::Frame(kind, payload),
                Err(e) => Event::Failed(e.context("verifier connection ended")),
            };
            let stop = matches!(event, Event::Failed(_));
            if frames.send(event).await.is_err() || stop {
                break;
            }
        }
    });
    let server_reader = tokio::spawn(async move {
        let mut chunk = vec![0u8; CHUNK];
        loop {
            let event = match from_server.read(&mut chunk).await {
                Ok(0) | Err(_) => Event::ServerEof,
                Ok(n) => Event::Server(chunk[..n].to_vec()),
            };
            let stop = matches!(event, Event::ServerEof);
            if events.send(event).await.is_err() || stop {
                break;
            }
        }
    });
    let _readers = Abort(vec![frame_reader.abort_handle(), server_reader.abort_handle()]);

    wire::send(&mut to_verifier, wire::HELLO, format!("{{\"version\":{VERSION},\"transfers\":{bits}}}").as_bytes()).await?;
    let mut ot = None;
    let mut received = None;
    if bits > 0 {
        let (state, (kind, setup)) = NodeOt::start(bits)?;
        wire::send(&mut to_verifier, kind, &setup).await?;
        ot = Some(state);
    } else {
        send_request(&mut to_verifier, &public, &hidden, &[]).await?;
        received = Some(Vec::new());
    }

    let mut forwarded = 0usize;
    let mut record_sent = false;
    let mut response = Vec::new();
    while let Some(event) = inbox.recv().await {
        match event {
            Event::Failed(e) => return Err(e),
            Event::Server(bytes) => wire::send(&mut to_verifier, wire::FROM_SERVER, &bytes).await?,
            Event::ServerEof => wire::send(&mut to_verifier, wire::SERVER_EOF, &[]).await?,
            Event::Frame(wire::CO_CHOOSE, payload) => {
                for (kind, frame) in ot.as_mut().context("unexpected base-OT choice")?.on_choose(&payload)? {
                    wire::send(&mut to_verifier, kind, &frame).await?;
                }
            }
            Event::Frame(wire::KOS_CHI, payload) => {
                let ot = ot.as_mut().context("unexpected OT challenge")?;
                let (kind, check) = ot.on_chi(&payload)?;
                wire::send(&mut to_verifier, kind, &check).await?;
                let (choices, blocks) = ot.take(bits)?;
                send_request(&mut to_verifier, &public, &hidden, &tag::corrections(&secret, &choices)?).await?;
                received = Some(blocks);
            }
            Event::Frame(wire::TO_SERVER, payload) => {
                forwarded += payload.len();
                // Only the handshake travels this way. Once the request record
                // is out the verifier gets no further use of this connection.
                if record_sent || forwarded > MAX_HANDSHAKE {
                    bail!("verifier tried to send more than its handshake");
                }
                to_server.write_all(&payload).await?;
            }
            Event::Frame(wire::MATERIAL, payload) => {
                let blocks = received.take().context("verifier sent request material twice or before the request")?;
                let material = parse_material(&payload, public.len(), bits)?;
                let record = tag::node_record(&material, &hidden, &secret, &blocks)?;
                to_server.write_all(&record).await?;
                to_server.flush().await?;
                record_sent = true;
            }
            Event::Frame(wire::PLAIN, payload) => {
                if !record_sent || response.len() + payload.len() > MAX_RECV {
                    bail!("verifier returned an unexpected or oversized response");
                }
                response.extend_from_slice(&payload);
            }
            Event::Frame(wire::DONE, _) => {
                if !record_sent {
                    bail!("verifier finished before the request was sent");
                }
                return Ok(response);
            }
            Event::Frame(kind, _) => bail!("unexpected relay frame {kind}"),
        }
    }
    bail!("relay session ended without a result")
}

struct Abort(Vec<tokio::task::AbortHandle>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.iter().for_each(tokio::task::AbortHandle::abort);
    }
}

async fn send_request<W: AsyncWrite + Unpin>(writer: &mut W, public: &[u8], hidden: &[Range<usize>], corrections: &[bool]) -> Result<()> {
    let mut payload = Vec::with_capacity(public.len() + 64 + corrections.len() / 8);
    payload.extend_from_slice(&(public.len() as u32).to_be_bytes());
    payload.extend_from_slice(public);
    payload.extend_from_slice(&(hidden.len() as u16).to_be_bytes());
    for range in hidden {
        payload.extend_from_slice(&(range.start as u32).to_be_bytes());
        payload.extend_from_slice(&(range.end as u32).to_be_bytes());
    }
    let mut packed = vec![0u8; corrections.len().div_ceil(8)];
    for (k, _) in corrections.iter().enumerate().filter(|(_, bit)| **bit) {
        packed[k / 8] |= 0x80 >> (k % 8);
    }
    payload.extend_from_slice(&packed);
    wire::send(writer, wire::REQUEST, &payload).await
}

fn parse_material(payload: &[u8], request_len: usize, bits: usize) -> Result<tag::Material> {
    let len = payload.get(..4).map(|b| u32::from_be_bytes(b.try_into().expect("four bytes")) as usize).context("truncated request material")?;
    // The sealed request is exactly our request plus its content-type byte.
    if len != request_len + 1 || payload.len() != 4 + len + 16 + 16 * bits {
        bail!("verifier material does not match the request");
    }
    let ciphertext = payload[4..4 + len].to_vec();
    let tag_share = payload[4 + len..4 + len + 16].try_into().expect("sixteen bytes");
    let masked = payload[4 + len + 16..].chunks_exact(16).map(|block| block.try_into().expect("sixteen bytes")).collect();
    Ok(tag::Material { ciphertext, masked, tag_share })
}
