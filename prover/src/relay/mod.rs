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
//! outside the hidden values. What it gives up: the verifier knows the client
//! key, so a verifier that could also capture the supplier's traffic to X
//! could read the hidden values. Verifiers are operator-run; the policy name
//! pins that assumption.

pub mod node;
pub mod ot;
pub mod record;
pub mod tag;
#[cfg(all(test, unix))]
mod tests;
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
