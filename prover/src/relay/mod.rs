//! Keyed relay for X reads.
//!
//! The verifier is the TLS client. Its handshake and records travel through
//! the supplier, which opens the TCP connection, so X sees the supplier's
//! address. The supplier never holds a session key. It adds only its session
//! cookie and CSRF values to a request the verifier has otherwise sealed, by
//! finishing the record's authentication tag jointly (see `tag`). The
//! verifier decrypts X's response itself and records it under the same
//! policy as an MPC-TLS proof.
//!
//! What this keeps from MPC-TLS: the supplier cannot forge or alter a
//! response, and cannot send any request byte the verifier did not seal
//! outside the hidden values.
//!
//! What it gives up: the supplier has to trust the verifier with its X
//! session for the length of a relay session. Only the verifier holds the
//! client key, so the verifier decides what plaintext is sealed. A dishonest
//! verifier can seal a different request of the same length around the
//! hidden positions, and the supplier will complete a valid record for it
//! with its real cookie and CSRF values: one request of the verifier's
//! choosing, as the supplier's account, per session. It needs no access to
//! the supplier's traffic for that, and it reads the response. It can also
//! learn a chosen hidden bit, or a parity of several, from whether X accepts
//! a record whose correlations it altered. With the supplier's traffic to X
//! it could read the hidden values outright. Nothing short of proving the
//! sealing to the supplier prevents the first of these; the supplier only
//! detects it afterwards, when the verifier opens the record (`node::MISUSE`).
//!
//! Hidden bytes are not checked for content, as under MPC-TLS: the verifier
//! cannot see them, so a supplier can put any bytes there, line breaks
//! included, within the allowed lengths.
//!
//! Verifiers are operator-run; the policy name pins that assumption.
//!
//! Web fetches (policy `web-relay-v1`, see webpolicy.rs) use the same
//! session for any public https host with nothing hidden, so there is no OT
//! and no secret for a verifier to misuse. The supplier still checks the
//! opened record, which shows the verifier used its address for exactly
//! the canonical request of the hop and nothing else.

pub mod node;
pub mod ot;
pub mod record;
pub mod tag;
#[cfg(all(test, unix))]
pub(crate) mod tests;
#[cfg(unix)]
pub mod verifier;
pub mod wire;

/// Proof policy a relay job must name.
pub const POLICY: &str = "x-relay-v1";
pub const VERSION: u8 = 1;
/// One TLS record carries the whole request with its content type.
pub const MAX_REQUEST: usize = (1 << 14) - 1;
pub const MAX_RECORD: usize = MAX_REQUEST + 1;
/// The hidden values the X policy allows: auth_token, ct0, kdt and the CSRF header.
pub const MAX_HIDDEN_BITS: usize = 8 * (64 + 160 + 64 + 160);
