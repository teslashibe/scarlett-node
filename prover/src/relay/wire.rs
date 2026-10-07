//! Frames between a supplier and the verifier during a relay session: one
//! kind byte, a big-endian length and the payload. Each kind has its own
//! size ceiling, so neither side can make the other buffer more than a
//! session legitimately needs.

use anyhow::{Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{MAX_HIDDEN_BITS, MAX_RECORD, MAX_REQUEST};

/// Supplier to verifier.
pub const HELLO: u8 = 1;
pub const CO_SETUP: u8 = 2;
pub const CO_PAYLOAD: u8 = 4;
pub const KOS_EXTEND: u8 = 5;
pub const KOS_CHECK: u8 = 7;
pub const FROM_SERVER: u8 = 10;
pub const SERVER_EOF: u8 = 11;
pub const REQUEST: u8 = 12;
/// Verifier to supplier.
pub const CO_CHOOSE: u8 = 3;
pub const KOS_CHI: u8 = 6;
pub const TO_SERVER: u8 = 20;
pub const MATERIAL: u8 = 21;
pub const PLAIN: u8 = 22;
pub const DONE: u8 = 23;
/// The client write key, IV and sequence number of the request record, sent
/// once the response is complete so the supplier can check what it was made to send.
pub const OPENING: u8 = 24;
/// Web sessions only, after OPENING: the hop's status and the URL the
/// verifier authorizes next. The supplier learns nothing else of the page.
pub const OUTCOME: u8 = 25;

/// Largest tunnel chunk either side forwards in one frame.
pub const CHUNK: usize = 32 << 10;

fn limit(kind: u8) -> Option<usize> {
    Some(match kind {
        HELLO | DONE => 1 << 10,
        // Two URLs of at most 2048 bytes each, plus the fields around them.
        OUTCOME => 8 << 10,
        CO_SETUP | KOS_CHI | OPENING => 1 << 8,
        CO_CHOOSE | CO_PAYLOAD | KOS_CHECK => 32 << 10,
        // The KOS matrix is 16 bytes per transfer, plus its padding rows.
        KOS_EXTEND => 16 * (MAX_HIDDEN_BITS + 1024) + 64,
        FROM_SERVER | TO_SERVER | PLAIN => CHUNK,
        SERVER_EOF => 0,
        REQUEST => MAX_REQUEST + MAX_HIDDEN_BITS / 8 + 256,
        MATERIAL => MAX_RECORD + 16 * MAX_HIDDEN_BITS + 256,
        _ => return None,
    })
}

pub async fn send<W: AsyncWrite + Unpin>(w: &mut W, kind: u8, payload: &[u8]) -> Result<()> {
    match limit(kind) {
        Some(max) if payload.len() <= max => {}
        _ => bail!("relay frame {kind} of {} bytes is not sendable", payload.len()),
    }
    let mut head = [0u8; 5];
    head[0] = kind;
    head[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&head).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

pub async fn recv<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut head = [0u8; 5];
    r.read_exact(&mut head).await?;
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    match limit(head[0]) {
        Some(max) if len <= max => {}
        _ => bail!("relay frame {} of {len} bytes is not acceptable", head[0]),
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok((head[0], payload))
}

/// Encodes one of the OT library's messages.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(bincode::serialize(value)?)
}

/// Decodes one of the OT library's messages. The whole frame must be the
/// message, and no length inside it can ask for more than the frame holds.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    use bincode::Options;
    Ok(bincode::options().with_fixint_encoding().with_limit(bytes.len() as u64).reject_trailing_bytes().deserialize(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_and_reject_oversize_or_unknown_kinds() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        send(&mut a, PLAIN, b"hello").await.unwrap();
        assert_eq!(recv(&mut b).await.unwrap(), (PLAIN, b"hello".to_vec()));
        assert!(send(&mut a, PLAIN, &vec![0; CHUNK + 1]).await.is_err());
        assert!(send(&mut a, 99, b"").await.is_err());
        // A peer that ignores the sender-side check is still refused on receipt.
        a.write_all(&[SERVER_EOF, 0, 0, 0, 1, 0]).await.unwrap();
        assert!(recv(&mut b).await.is_err());
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[99, 0, 0, 0, 0]).await.unwrap();
        assert!(recv(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn outcome_frames_carry_two_maximal_urls_and_no_more() {
        let url = format!("https://example.com/{}", "a".repeat(2048 - 20));
        let outcome = serde_json::to_vec(&serde_json::json!({"hop":4,"url":url,"status_code":308,"final":false,"next_url":url})).unwrap();
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        send(&mut a, OUTCOME, &outcome).await.unwrap();
        assert_eq!(recv(&mut b).await.unwrap(), (OUTCOME, outcome));
        assert!(send(&mut a, OUTCOME, &vec![b' '; (8 << 10) + 1]).await.is_err());
        a.write_all(&[OUTCOME, 0, 0, 0x20, 1]).await.unwrap();
        assert!(recv(&mut b).await.is_err());
    }

    #[test]
    fn decoding_rejects_trailing_bytes_and_oversized_lengths() {
        let bytes = encode(&vec![1u8, 2, 3]).unwrap();
        assert_eq!(decode::<Vec<u8>>(&bytes).unwrap(), vec![1, 2, 3]);
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode::<Vec<u8>>(&extra).is_err());
        // A length prefix far beyond the frame cannot trigger a large allocation.
        let mut huge = (u64::MAX / 2).to_le_bytes().to_vec();
        huge.extend_from_slice(&[0; 8]);
        assert!(decode::<Vec<u8>>(&huge).is_err());
    }
}
