//! Verifier side of a relay session.
//!
//! The verifier runs the TLS 1.3 handshake itself through the supplier's
//! tunnel, validates X's certificate, and keeps both traffic keys. It then
//! authorizes exactly one request record: the supplier's public request
//! bytes, checked against the X policy, with the supplier's hidden values
//! joined in through the split tag. It opens X's records itself, so the
//! response it returns is what X sent on this connection.

use std::{io, ops::Range, sync::Arc};

use anyhow::{Context, Result, bail};
use rustls::{ClientConfig, ClientConnection, ConnectionTrafficSecrets, RootCertStore, pki_types::ServerName};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{
    MAX_HIDDEN_BITS, MAX_REQUEST, VERSION,
    ot::VerifierOt,
    record::{self, Keys},
    tag,
    wire::{self, CHUNK},
};
use crate::{xpolicy, xprove::MAX_RECV};

/// Handshake bytes the verifier will accept from, or send to, the server.
const MAX_HANDSHAKE: usize = 64 << 10;

/// What the session established, in the shape the X policy checks.
pub struct Outcome {
    /// The request as the verifier saw it: hidden bytes are zero.
    pub sent: Vec<u8>,
    pub hidden: Vec<Range<usize>>,
    /// X's response, decrypted by the verifier.
    pub received: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    version: u8,
    transfers: usize,
}

struct Request {
    public: Vec<u8>,
    hidden: Vec<Range<usize>>,
    corrections: Vec<bool>,
}

/// TLS 1.3 with AES-128-GCM only: the one suite the split tag covers.
pub fn tls_config(roots: RootCertStore) -> Result<Arc<ClientConfig>> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites.retain(|suite| suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider)).with_protocol_versions(&[&rustls::version::TLS13])?.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_secret_extraction = true;
    Ok(Arc::new(config))
}

/// The pinned Mozilla roots TLSNotary proofs already trust.
pub fn mozilla_roots() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for root in tlsn::webpki::RootCertStore::mozilla().roots {
        roots.add(rustls::pki_types::CertificateDer::from(root.0))?;
    }
    Ok(roots)
}

fn parse_request(payload: &[u8], transfers: usize) -> Result<Request> {
    let take = |at: &mut usize, n: usize| -> Result<&[u8]> {
        let slice = payload.get(*at..*at + n).context("truncated relay request")?;
        *at += n;
        Ok(slice)
    };
    let mut at = 0;
    let len = u32::from_be_bytes(take(&mut at, 4)?.try_into()?) as usize;
    if len == 0 || len > MAX_REQUEST {
        bail!("request must be 1-{MAX_REQUEST} bytes");
    }
    let public = take(&mut at, len)?.to_vec();
    let ranges = u16::from_be_bytes(take(&mut at, 2)?.try_into()?) as usize;
    let mut hidden = Vec::with_capacity(ranges.min(8));
    for _ in 0..ranges {
        let start = u32::from_be_bytes(take(&mut at, 4)?.try_into()?) as usize;
        let end = u32::from_be_bytes(take(&mut at, 4)?.try_into()?) as usize;
        hidden.push(start..end);
    }
    let bits = tag::hidden_bits(public.len(), &hidden)?;
    if bits != transfers {
        bail!("request hides {bits} bits but the session prepared {transfers} transfers");
    }
    let packed = take(&mut at, bits.div_ceil(8))?;
    if at != payload.len() {
        bail!("trailing bytes after relay request");
    }
    // A hidden position that still carried a byte would be sealed as public.
    if hidden.iter().flat_map(|range| &public[range.clone()]).any(|&byte| byte != 0) {
        bail!("hidden request bytes must be zero in the public view");
    }
    let corrections = (0..bits).map(|k| packed[k / 8] & (0x80 >> (k % 8)) != 0).collect();
    Ok(Request { public, hidden, corrections })
}

/// Runs one relay session with a supplier and returns what X answered.
///
/// `authorize` sees the public request and its hidden ranges before any key
/// material is used for it, and must reject anything the job does not allow.
pub async fn run<S>(socket: S, config: Arc<ClientConfig>, server_name: &str, authorize: impl Fn(&[u8], &[Range<usize>]) -> Result<()>) -> Result<Outcome>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(socket);
    let (kind, payload) = wire::recv(&mut reader).await?;
    if kind != wire::HELLO {
        bail!("relay session must start with a hello");
    }
    let hello: Hello = serde_json::from_slice(&payload).context("invalid relay hello")?;
    if hello.version != VERSION || hello.transfers > MAX_HIDDEN_BITS {
        bail!("unsupported relay hello");
    }
    let mut ot = (hello.transfers > 0).then(|| VerifierOt::new(hello.transfers));

    let mut tls = Some(ClientConnection::new(config, ServerName::try_from(server_name.to_owned())?)?);
    let mut to_server = 0usize;
    let mut from_server = 0usize;
    let mut keys: Option<(([u8; 16], [u8; 12], u64), Keys)> = None;
    let mut inbound = Vec::new();
    let mut request: Option<Request> = None;
    let mut sent: Option<(Vec<u8>, Vec<Range<usize>>)> = None;
    let mut received = Vec::new();

    // The ClientHello does not depend on the server, so it goes out first.
    flush_handshake(tls.as_mut().expect("handshake is in progress"), &mut writer, &mut to_server).await?;

    // Whatever ends the session after a record was sealed, success or any
    // failure, the supplier gets the client key and so can always check what
    // it was made to send. A verifier that sealed and then went quiet would
    // otherwise be indistinguishable from one hiding a request of its own.
    let outcome: Result<()> = async {
    loop {
        let (kind, payload) = wire::recv(&mut reader).await?;
        match kind {
            wire::CO_SETUP => {
                let (kind, reply) = ot.as_mut().context("session prepared no transfers")?.on_setup(&payload)?;
                wire::send(&mut writer, kind, &reply).await?;
            }
            wire::CO_PAYLOAD => ot.as_mut().context("session prepared no transfers")?.on_payload(&payload)?,
            wire::KOS_EXTEND => {
                if let Some((kind, chi)) = ot.as_mut().context("session prepared no transfers")?.on_extend(&payload)? {
                    wire::send(&mut writer, kind, &chi).await?;
                }
            }
            wire::KOS_CHECK => ot.as_mut().context("session prepared no transfers")?.on_check(&payload)?,
            wire::REQUEST => {
                if request.is_some() || sent.is_some() {
                    bail!("a relay session authorizes one request");
                }
                let parsed = parse_request(&payload, hello.transfers)?;
                authorize(&parsed.public, &parsed.hidden)?;
                request = Some(parsed);
            }
            wire::FROM_SERVER => {
                inbound.extend_from_slice(&payload);
                while let Some((outer, record)) = record::take(&mut inbound)? {
                    if let Some(conn) = tls.as_mut() {
                        from_server += record.len();
                        if from_server > MAX_HANDSHAKE {
                            bail!("server handshake is too large");
                        }
                        // One record at a time, so nothing past the handshake is ever inside the TLS library.
                        // The library takes a bounded amount per call, so a large
                        // record needs several.
                        let mut cursor = io::Cursor::new(&record);
                        while (cursor.position() as usize) < record.len() {
                            if conn.read_tls(&mut cursor)? == 0 {
                                bail!("TLS library refused handshake bytes");
                            }
                            conn.process_new_packets().context("TLS handshake with the server failed")?;
                        }
                        flush_handshake(conn, &mut writer, &mut to_server).await?;
                        if !conn.is_handshaking() {
                            keys = Some(traffic_keys(tls.take().expect("handshake just completed"))?);
                        }
                        continue;
                    }
                    let (_, server) = keys.as_mut().expect("keys exist once the handshake is done");
                    if outer != record::APPLICATION_DATA {
                        bail!("server sent an unprotected record after the handshake");
                    }
                    match server.open(&record)? {
                        (record::APPLICATION_DATA, data) => {
                            if sent.is_none() {
                                bail!("server sent application data before the request");
                            }
                            if received.len() + data.len() > MAX_RECV {
                                bail!("response exceeds {MAX_RECV} bytes");
                            }
                            for chunk in data.chunks(CHUNK) {
                                wire::send(&mut writer, wire::PLAIN, chunk).await?;
                            }
                            received.extend_from_slice(&data);
                            // X closes right behind a `Connection: close` response, and
                            // that alert can share a frame with the last data record.
                            // Stop at the response's own end rather than reading on.
                            if xpolicy::response_complete(&received) {
                                break;
                            }
                        }
                        // Session tickets are the only post-handshake message a plain read expects.
                        (record::HANDSHAKE, message) if message.first() == Some(&4) => {}
                        (record::HANDSHAKE, _) => bail!("unsupported post-handshake message"),
                        (record::ALERT, alert) if alert == [1, 0] => bail!("server closed before the response was complete"),
                        (record::ALERT, _) => bail!("server sent a TLS alert"),
                        _ => bail!("unexpected TLS content type"),
                    }
                }
            }
            wire::SERVER_EOF => bail!("server connection ended before the response was complete"),
            _ => bail!("unexpected relay frame {kind}"),
        }

        if sent.is_none()
            && let (Some(parsed), Some(((key, iv, seq), _))) = (request.as_ref(), keys.as_ref())
            && ot.as_ref().is_none_or(VerifierOt::ready)
        {
            let transfers = match ot.as_mut() {
                Some(ot) => ot.take(hello.transfers)?,
                None => Vec::new(),
            };
            let material = tag::verifier_material(key, iv, *seq, &parsed.public, &parsed.hidden, &parsed.corrections, &transfers)?;
            // From here this key and sequence number are spent: there is no
            // second material for this record, whatever happens next.
            let parsed = request.take().expect("request was just read");
            sent = Some((parsed.public, parsed.hidden));
            let mut payload = Vec::with_capacity(4 + material.ciphertext.len() + 16 + 16 * material.masked.len());
            payload.extend_from_slice(&(material.ciphertext.len() as u32).to_be_bytes());
            payload.extend_from_slice(&material.ciphertext);
            payload.extend_from_slice(&material.tag_share);
            material.masked.iter().for_each(|block| payload.extend_from_slice(block));
            wire::send(&mut writer, wire::MATERIAL, &payload).await?;
        }
        if sent.is_some() && xpolicy::response_complete(&received) {
            break;
        }
    }
    Ok(())
    }
    .await;
    // The client key has no further use to us once a record is sealed:
    // there is no second material for it. Hand it over, on success or
    // failure, so the supplier can check that the record it completed was
    // its own request and nothing else. Best effort on failure: the supplier
    // treats a sealed record that is never opened as misuse.
    if sent.is_some()
        && let Some(((key, iv, seq), _)) = keys.as_ref()
    {
        let opening = wire::send(&mut writer, wire::OPENING, &[&key[..], &iv[..], &seq.to_be_bytes()[..]].concat()).await;
        if outcome.is_ok() {
            opening?;
        }
    }
    outcome?;
    wire::send(&mut writer, wire::DONE, b"{\"status\":\"complete\"}").await?;
    // The supplier may still be forwarding X's close. Dropping the socket
    // with those frames unread can reset it, and a reset discards OPENING and
    // DONE if the supplier has not read them yet: it then has to treat the
    // sealed record as misuse and halts relay. So close our half and wait for
    // the supplier to close its own, which it does once it has checked the
    // opening, for up to CLOSE_DRAIN.
    let _ = writer.shutdown().await;
    let _ = tokio::time::timeout(CLOSE_DRAIN, async {
        let mut sink = [0u8; 4096];
        while matches!(reader.read(&mut sink).await, Ok(n) if n > 0) {}
    })
    .await;
    let (sent, hidden) = sent.expect("loop ends only after a request was sent");
    Ok(Outcome { sent, hidden, received })
}

/// How long a finished session waits for the supplier to close after DONE.
/// An honest supplier closes within milliseconds of reading DONE; two seconds
/// was not always enough on a busy home connection (one false relay halt in
/// about 1,300 production sessions on 2026-10-07).
const CLOSE_DRAIN: std::time::Duration = std::time::Duration::from_secs(15);

/// Forwards whatever the handshake wants to write. Nothing is written
/// through the TLS library after the handshake.
async fn flush_handshake<W: AsyncWrite + Unpin>(conn: &mut ClientConnection, writer: &mut W, total: &mut usize) -> Result<()> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out)?;
    }
    *total += out.len();
    if *total > MAX_HANDSHAKE {
        bail!("client handshake is too large");
    }
    for chunk in out.chunks(CHUNK) {
        wire::send(writer, wire::TO_SERVER, chunk).await?;
    }
    Ok(())
}

type ClientKey = ([u8; 16], [u8; 12], u64);

/// Takes both application traffic keys out of the finished handshake.
fn traffic_keys(conn: ClientConnection) -> Result<(ClientKey, Keys)> {
    if conn.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        bail!("server did not negotiate TLS 1.3");
    }
    let secrets = conn.dangerous_extract_secrets().context("extracting TLS traffic keys")?;
    let part = |(seq, secrets): (u64, ConnectionTrafficSecrets)| -> Result<ClientKey> {
        let ConnectionTrafficSecrets::Aes128Gcm { key, iv } = secrets else { bail!("server did not negotiate AES-128-GCM") };
        Ok((key.as_ref().try_into().context("unexpected traffic key length")?, iv.as_ref().try_into().context("unexpected traffic IV length")?, seq))
    };
    let client = part(secrets.tx)?;
    let (key, iv, seq) = part(secrets.rx)?;
    Ok((client, Keys::new(&key, iv, seq)?))
}

/// The X policy's request check alone, for tests that have no job.
#[cfg(test)]
pub fn authorize_x(public: &[u8], hidden: &[Range<usize>]) -> Result<()> {
    xpolicy::check_request(public, hidden).map(|_| ())
}
