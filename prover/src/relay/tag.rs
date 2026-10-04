//! The split AES-GCM tag.
//!
//! The verifier holds the client write key. It seals the request with every
//! hidden byte set to zero, which gives the ciphertext `C_pub` and its tag
//! `T_pub`. The real ciphertext differs from `C_pub` only in the hidden bytes,
//! and GHASH is linear, so the real tag is
//!
//! ```text
//! T = T_pub + sum over hidden bits b of  b * (unit(b) * H^e(b))
//! ```
//!
//! where `unit(b)` is the block with only that bit set and `H^e(b)` the power
//! of the hash key GHASH applies to that bit's block. Each hidden bit is one
//! random oblivious transfer: the supplier learns `r + b * a` for its bit `b`
//! and the verifier's correlation `a`, the verifier keeps `r`. The supplier
//! never sees `T_pub`, `H` or any `a`; the verifier never sees a hidden bit.
//!
//! The supplier can therefore complete exactly one record: the public bytes
//! the verifier sealed, with its own bits in the hidden positions only.

use std::ops::Range;

use aes::cipher::{BlockEncrypt, KeyInit};
use anyhow::{Result, bail};
use mpz_fields::gf2_128::Gf2_128;
use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use super::{MAX_HIDDEN_BITS, MAX_REQUEST, record};

/// What the verifier sends for one request record.
pub struct Material {
    /// `C_pub`: the sealed public plaintext. At hidden positions this is keystream.
    pub ciphertext: Vec<u8>,
    /// One masked correlation per hidden bit.
    pub masked: Vec<[u8; 16]>,
    /// `T_pub` plus the verifier's shares. Reveals neither.
    pub tag_share: [u8; 16],
}

fn xor(a: &mut [u8; 16], b: &[u8; 16]) {
    a.iter_mut().zip(b).for_each(|(a, b)| *a ^= b);
}

/// A GCM block as a field element, and back. GCM numbers bits in the
/// opposite order to the polynomial representation.
fn field(block: [u8; 16]) -> Gf2_128 {
    Gf2_128::new(u128::from_be_bytes(block).reverse_bits())
}
fn block(value: Gf2_128) -> [u8; 16] {
    value.to_inner().reverse_bits().to_be_bytes()
}

/// Checks hidden ranges are sorted, disjoint, inside the request and within
/// the bit budget, and returns their total bit count.
pub fn hidden_bits(len: usize, hidden: &[Range<usize>]) -> Result<usize> {
    let mut at = 0;
    let mut bytes = 0usize;
    for range in hidden {
        if range.start < at || range.start >= range.end || range.end > len {
            bail!("hidden ranges must be sorted, disjoint, non-empty and inside the request");
        }
        at = range.end;
        bytes += range.len();
    }
    if bytes * 8 > MAX_HIDDEN_BITS {
        bail!("request hides more than {MAX_HIDDEN_BITS} bits");
    }
    Ok(bytes * 8)
}

/// Every hidden bit as (byte offset, mask), in the order both sides use:
/// ranges in order, bytes ascending, most significant bit first.
fn positions(hidden: &[Range<usize>]) -> impl Iterator<Item = (usize, u8)> + '_ {
    hidden.iter().flat_map(|range| range.clone()).flat_map(|at| (0..8).map(move |bit| (at, 0x80u8 >> bit)))
}

/// The correlation of each hidden bit: its unit block times the power of `h`
/// GHASH applies to that block, for a ciphertext of `len` bytes.
fn correlations(h: [u8; 16], len: usize, hidden: &[Range<usize>]) -> Vec<[u8; 16]> {
    let blocks = len.div_ceil(16);
    // GHASH multiplies ciphertext block j (from zero) by H^(blocks - j + 1):
    // the length block follows the ciphertext and takes H^1.
    let h = field(h);
    // powers[k] is H^(k+1).
    let mut powers = Vec::with_capacity(blocks + 1);
    let mut power = h;
    powers.push(power);
    for _ in 0..blocks {
        power = power * h;
        powers.push(power);
    }
    positions(hidden)
        .map(|(at, mask)| {
            let mut unit = [0u8; 16];
            unit[at % 16] = mask;
            block(field(unit) * powers[blocks - at / 16])
        })
        .collect()
}

/// Verifier: seals the public request for record `seq` and prepares the
/// supplier's share of the tag.
///
/// `public` is the request with every hidden byte zero. `corrections[k]` is
/// the supplier's random choice for transfer `k` XOR its hidden bit, and
/// `transfers[k]` both random blocks of that transfer. The caller must never
/// call this twice for one `(key, seq)`.
pub fn verifier_material(key: &[u8; 16], iv: &[u8; 12], seq: u64, public: &[u8], hidden: &[Range<usize>], corrections: &[bool], transfers: &[[[u8; 16]; 2]]) -> Result<Material> {
    if public.is_empty() || public.len() > MAX_REQUEST {
        bail!("request must be 1-{MAX_REQUEST} bytes");
    }
    let bits = hidden_bits(public.len(), hidden)?;
    if corrections.len() != bits || transfers.len() != bits {
        bail!("request needs {bits} oblivious transfers");
    }
    if hidden.iter().flat_map(|range| &public[range.clone()]).any(|&byte| byte != 0) {
        bail!("hidden request bytes must be zero in the public view");
    }
    // TLS 1.3 inner plaintext: the content, then its type.
    let mut ciphertext = public.to_vec();
    ciphertext.push(record::APPLICATION_DATA);
    let sealing = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, key).map_err(|_| anyhow::anyhow!("invalid record key"))?);
    let aad = record::aad(ciphertext.len());
    let tag = sealing
        .seal_in_place_separate_tag(Nonce::assume_unique_for_key(record::nonce(iv, seq)), Aad::from(aad), &mut ciphertext)
        .map_err(|_| anyhow::anyhow!("sealing the request failed"))?;
    let mut tag_share: [u8; 16] = tag.as_ref().try_into().expect("GCM tags are 16 bytes");

    let mut h = [0u8; 16];
    aes::Aes128::new(key.into()).encrypt_block((&mut h).into());
    let mut masked = correlations(h, ciphertext.len(), hidden);
    for ((masked, &correction), [zero, one]) in masked.iter_mut().zip(corrections).zip(transfers) {
        // The supplier holds block `choice`. Our share is block `correction`:
        // the supplier's own block when its bit is 0, the other when it is 1.
        xor(&mut tag_share, if correction { one } else { zero });
        xor(masked, zero);
        xor(masked, one);
    }
    Ok(Material { ciphertext, masked, tag_share })
}

/// Supplier: the correction bit of each transfer for its hidden bytes.
/// `secret` is the hidden bytes in range order.
pub fn corrections(secret: &[u8], choices: &[bool]) -> Result<Vec<bool>> {
    if choices.len() != secret.len() * 8 {
        bail!("{} hidden bytes need {} oblivious transfers", secret.len(), secret.len() * 8);
    }
    Ok(secret.iter().flat_map(|&byte| (0..8).map(move |bit| byte & (0x80 >> bit) != 0)).zip(choices).map(|(bit, &choice)| bit ^ choice).collect())
}

/// Supplier: completes the record from the verifier's material, placing its
/// hidden bytes and finishing the tag. Returns the full TLS record.
pub fn node_record(material: &Material, hidden: &[Range<usize>], secret: &[u8], received: &[[u8; 16]]) -> Result<Vec<u8>> {
    let len = material.ciphertext.len();
    if len < 2 || len > MAX_REQUEST + 1 {
        bail!("verifier sent an invalid request ciphertext");
    }
    let bits = hidden_bits(len - 1, hidden)?;
    if secret.len() * 8 != bits || material.masked.len() != bits || received.len() != bits {
        bail!("verifier material does not match the hidden request bytes");
    }
    let mut record = Vec::with_capacity(5 + len + 16);
    record.extend_from_slice(&record::aad(len));
    record.extend_from_slice(&material.ciphertext);
    let mut tag = material.tag_share;
    let mut secret_bytes = secret.iter();
    let mut k = 0;
    for range in hidden {
        for at in range.clone() {
            let byte = *secret_bytes.next().expect("length was checked");
            record[5 + at] ^= byte;
            for bit in 0..8 {
                // Add the masked correlation only when the bit is set, without branching on it.
                let keep = 0u8.wrapping_sub((byte >> (7 - bit)) & 1);
                let mut share = received[k];
                share.iter_mut().zip(&material.masked[k]).for_each(|(s, m)| *s ^= m & keep);
                xor(&mut tag, &share);
                k += 1;
            }
        }
    }
    record.extend_from_slice(&tag);
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::ot;

    const KEY: [u8; 16] = *b"relay-test-key-1";
    const IV: [u8; 12] = *b"relay-iv-012";

    /// The record a single party holding the key would produce.
    fn reference(seq: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut inner = plaintext.to_vec();
        inner.push(record::APPLICATION_DATA);
        let aad = record::aad(inner.len());
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &KEY).unwrap());
        let tag = key.seal_in_place_separate_tag(Nonce::assume_unique_for_key(record::nonce(&IV, seq)), Aad::from(aad), &mut inner).unwrap();
        [&aad[..], &inner, tag.as_ref()].concat()
    }

    fn split(seq: u64, plaintext: &[u8], hidden: &[Range<usize>]) -> (Material, Vec<u8>) {
        let secret: Vec<u8> = hidden.iter().flat_map(|r| plaintext[r.clone()].to_vec()).collect();
        let mut public = plaintext.to_vec();
        hidden.iter().for_each(|r| public[r.clone()].fill(0));
        let bits = secret.len() * 8;
        let (mut node, mut verifier) = ot::pair(bits.max(1));
        let (choices, received) = node.take(bits).unwrap();
        let corrections = corrections(&secret, &choices).unwrap();
        let material = verifier_material(&KEY, &IV, seq, &public, hidden, &corrections, &verifier.take(bits).unwrap()).unwrap();
        let record = node_record(&material, hidden, &secret, &received).unwrap();
        (material, record)
    }

    #[test]
    fn split_record_equals_the_single_party_record() {
        let request = b"GET /i/api/graphql/q/Viewer?variables=%7B%7D HTTP/1.1\r\nHost: x.com\r\nX-Csrf-Token: 0123456789abcdef\r\nCookie: auth_token=fedcba9876543210; ct0=0123456789abcdef; twid=u%3D1\r\n\r\n";
        let text = std::str::from_utf8(request).unwrap();
        let at = |needle: &str| text.find(needle).unwrap() + needle.len();
        // Hidden values that start and end mid-block, as real ones do.
        let hidden = [at("X-Csrf-Token: ")..at("X-Csrf-Token: ") + 16, at("auth_token=")..at("auth_token=") + 16, at("ct0=")..at("ct0=") + 16];
        for seq in [0, 1, 7] {
            let (_, record) = split(seq, request, &hidden);
            assert_eq!(record, reference(seq, request), "record {seq}");
        }
    }

    #[test]
    fn every_length_and_position_matches_the_reference() {
        // Block boundaries, a final partial block, and hidden bytes at either edge.
        for len in [1usize, 15, 16, 17, 31, 32, 33, 64, 100, 257] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            for hidden in [vec![], vec![0..1], vec![len - 1..len], vec![0..len.min(20)], vec![len / 2..len]] {
                let (_, record) = split(3, &plaintext, &hidden);
                assert_eq!(record, reference(3, &plaintext), "len {len} hidden {hidden:?}");
            }
        }
    }

    #[test]
    fn a_request_with_nothing_hidden_needs_no_transfers_and_exposes_only_the_final_tag() {
        let (material, record) = split(0, b"GET / HTTP/1.1\r\n\r\n", &[]);
        assert!(material.masked.is_empty());
        assert_eq!(record, reference(0, b"GET / HTTP/1.1\r\n\r\n"));
    }

    #[test]
    fn supplier_cannot_change_a_public_byte() {
        let plaintext = b"GET /wanted HTTP/1.1\r\nCookie: ct0=SECRETSECRETSECRE\r\n\r\n".to_vec();
        let hidden = [33..49];
        let (_, mut record) = split(0, &plaintext, &hidden);
        assert_eq!(record, reference(0, &plaintext));
        // Flipping a ciphertext bit outside the hidden range leaves the tag wrong:
        // the supplier has no share for that position.
        record[5 + 5] ^= 0x01;
        let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &KEY).unwrap());
        let mut body = record[5..].to_vec();
        let aad: [u8; 5] = record[..5].try_into().unwrap();
        assert!(key.open_in_place(Nonce::assume_unique_for_key(record::nonce(&IV, 0)), Aad::from(aad), &mut body).is_err());
    }

    #[test]
    fn tag_share_alone_is_not_the_public_tag() {
        // T_pub and the real tag under one nonce would expose the hash key, so
        // the share must differ from T_pub whenever anything is hidden.
        let plaintext = b"GET / HTTP/1.1\r\nCookie: ct0=abcdefgh\r\n\r\n".to_vec();
        let hidden = [28..36];
        let (material, _) = split(0, &plaintext, &hidden);
        let mut public = plaintext.clone();
        public[28..36].fill(0);
        let public_record = reference(0, &public);
        assert_ne!(&material.tag_share[..], &public_record[public_record.len() - 16..]);
    }

    #[test]
    fn inputs_that_do_not_fit_are_refused() {
        let transfers = vec![[[0u8; 16]; 2]; 8];
        let ok = |public: &[u8], hidden: &[Range<usize>], corrections: &[bool]| verifier_material(&KEY, &IV, 0, public, hidden, corrections, &transfers[..corrections.len()]).is_ok();
        assert!(ok(b"a\0c", &[1..2], &[false; 8]));
        // A non-zero byte in a hidden position would be sealed as public and leak the tag relation.
        assert!(!ok(b"abc", &[1..2], &[false; 8]));
        assert!(!ok(b"a\0c", &[1..2], &[false; 7]));
        assert!(!ok(b"a\0c", &[1..4], &[false; 8]));
        assert!(!ok(b"", &[], &[]));
        assert!(hidden_bits(10, &[2..4, 3..5]).is_err());
        assert!(hidden_bits(10, &[4..4]).is_err());
        assert!(hidden_bits(MAX_HIDDEN_BITS, &[0..MAX_HIDDEN_BITS / 8 + 1]).is_err());
        assert!(corrections(b"ab", &[false; 15]).is_err());
    }
}
