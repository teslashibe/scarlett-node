//! The TLS 1.3 record layer for AES-128-GCM, used once the handshake library
//! has handed over the application traffic keys. Only the verifier holds
//! keys, so only the verifier opens records.

use anyhow::{Result, bail};
use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

pub const CHANGE_CIPHER_SPEC: u8 = 20;
pub const ALERT: u8 = 21;
pub const HANDSHAKE: u8 = 22;
pub const APPLICATION_DATA: u8 = 23;

/// Largest ciphertext a TLS 1.3 record may carry (RFC 8446, section 5.2).
const MAX_CIPHERTEXT: usize = (1 << 14) + 256;

/// The additional data of a protected record: its own header.
pub fn aad(inner_len: usize) -> [u8; 5] {
    let len = (inner_len + 16) as u16;
    [APPLICATION_DATA, 3, 3, (len >> 8) as u8, len as u8]
}

/// The per-record nonce: the write IV with the sequence number folded in.
pub fn nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    nonce[4..].iter_mut().zip(seq.to_be_bytes()).for_each(|(n, s)| *n ^= s);
    nonce
}

/// Takes one whole record off the front of `buffer`, if one has arrived.
/// Returns its outer type and the complete record, header included.
pub fn take(buffer: &mut Vec<u8>) -> Result<Option<(u8, Vec<u8>)>> {
    if buffer.len() < 5 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
    if !matches!(buffer[0], CHANGE_CIPHER_SPEC | ALERT | HANDSHAKE | APPLICATION_DATA) || buffer[1] != 3 || len > MAX_CIPHERTEXT {
        bail!("malformed TLS record header");
    }
    if buffer.len() < 5 + len {
        return Ok(None);
    }
    let record: Vec<u8> = buffer.drain(..5 + len).collect();
    Ok(Some((record[0], record)))
}

/// One direction's traffic key and position.
pub struct Keys {
    key: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
}

impl Keys {
    pub fn new(key: &[u8; 16], iv: [u8; 12], seq: u64) -> Result<Self> {
        Ok(Self { key: LessSafeKey::new(UnboundKey::new(&AES_128_GCM, key).map_err(|_| anyhow::anyhow!("invalid record key"))?), iv, seq })
    }

    /// Opens the next protected record. Returns its inner content type and
    /// content. A record that does not authenticate ends the session: the
    /// sequence number is not advanced and the caller must stop.
    pub fn open(&mut self, record: &[u8]) -> Result<(u8, Vec<u8>)> {
        if record.len() < 5 + 16 || record[0] != APPLICATION_DATA {
            bail!("expected a protected TLS record");
        }
        let header: [u8; 5] = record[..5].try_into().expect("length was checked");
        let mut body = record[5..].to_vec();
        let seq = self.seq;
        let plain_len = self
            .key
            .open_in_place(Nonce::assume_unique_for_key(nonce(&self.iv, seq)), Aad::from(header), &mut body)
            .map_err(|_| anyhow::anyhow!("TLS record failed authentication"))?
            .len();
        self.seq = seq.checked_add(1).ok_or_else(|| anyhow::anyhow!("TLS sequence number exhausted"))?;
        body.truncate(plain_len);
        // Inner plaintext is content, type, then optional zero padding.
        while body.last() == Some(&0) {
            body.pop();
        }
        let Some(kind) = body.pop() else { bail!("TLS record has no content type") };
        Ok((kind, body))
    }

    /// Seals a record as the key holder would. Tests use it to play the server.
    #[cfg(test)]
    pub fn seal(&mut self, kind: u8, content: &[u8]) -> Result<Vec<u8>> {
        let mut inner = content.to_vec();
        inner.push(kind);
        let header = aad(inner.len());
        let seq = self.seq;
        self.seq = seq.checked_add(1).ok_or_else(|| anyhow::anyhow!("TLS sequence number exhausted"))?;
        let tag = self
            .key
            .seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce(&self.iv, seq)), Aad::from(header), &mut inner)
            .map_err(|_| anyhow::anyhow!("sealing a TLS record failed"))?;
        Ok([&header[..], &inner, tag.as_ref()].concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(seq: u64) -> Keys {
        Keys::new(b"0123456789abcdef", *b"abcdefghijkl", seq).unwrap()
    }

    #[test]
    fn nonce_folds_the_sequence_into_the_low_bytes() {
        assert_eq!(nonce(&[0; 12], 1), [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(nonce(&[0xff; 12], 0x0102), [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xfd]);
    }

    #[test]
    fn records_open_in_order_only_and_tampering_is_fatal() {
        let (mut writer, mut reader) = (keys(0), keys(0));
        let first = writer.seal(APPLICATION_DATA, b"first").unwrap();
        let second = writer.seal(ALERT, &[1, 0]).unwrap();
        // Out of order, replayed and altered records all fail and do not advance.
        assert!(reader.open(&second).is_err());
        assert_eq!(reader.open(&first).unwrap(), (APPLICATION_DATA, b"first".to_vec()));
        assert!(reader.open(&first).is_err());
        let mut altered = second.clone();
        *altered.last_mut().unwrap() ^= 1;
        assert!(reader.open(&altered).is_err());
        let mut relabelled = second.clone();
        relabelled[4] ^= 1;
        assert!(reader.open(&relabelled).is_err());
        assert_eq!(reader.open(&second).unwrap(), (ALERT, vec![1, 0]));
    }

    #[test]
    fn padding_is_stripped_and_an_all_zero_record_is_refused() {
        let writer = keys(5);
        // Seal content "hi", type, then two padding zeros by hand.
        let mut inner = b"hi".to_vec();
        inner.extend_from_slice(&[APPLICATION_DATA, 0, 0]);
        let padded = {
            let header = aad(inner.len());
            let tag = writer.key.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce(&writer.iv, 5)), Aad::from(header), &mut inner).unwrap();
            [&header[..], &inner, tag.as_ref()].concat()
        };
        assert_eq!(keys(5).open(&padded).unwrap(), (APPLICATION_DATA, b"hi".to_vec()));
        let mut zeros = vec![0u8; 4];
        let header = aad(zeros.len());
        let tag = writer.key.seal_in_place_separate_tag(Nonce::assume_unique_for_key(nonce(&writer.iv, 6)), Aad::from(header), &mut zeros).unwrap();
        assert!(keys(6).open(&[&header[..], &zeros, tag.as_ref()].concat()).is_err());
    }

    #[test]
    fn take_waits_for_whole_records_and_rejects_bad_headers() {
        let mut buffer = keys(0).seal(APPLICATION_DATA, b"abc").unwrap();
        let whole = buffer.clone();
        buffer.extend_from_slice(&[APPLICATION_DATA, 3, 3, 0]);
        assert_eq!(take(&mut buffer).unwrap(), Some((APPLICATION_DATA, whole)));
        assert_eq!(take(&mut buffer).unwrap(), None);
        assert!(take(&mut vec![99, 3, 3, 0, 0]).is_err());
        assert!(take(&mut vec![APPLICATION_DATA, 3, 3, 0xff, 0xff]).is_err());
        assert!(take(&mut vec![APPLICATION_DATA, 2, 3, 0, 0]).is_err());
    }
}
