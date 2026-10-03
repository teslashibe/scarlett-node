//! Random oblivious transfers for the split tag. The supplier is the receiver:
//! each transfer gives it one random choice bit and one of the verifier's two
//! random blocks. Nothing here is new cryptography; these are the mpz
//! Chou-Orlandi and KOS15 state machines, driven over relay frames instead of
//! an mpz context.
//!
//! KOS15 lets a cheating receiver guess a few bits of the sender's correlation
//! at the price of being caught with matching probability. A failed check ends
//! the session; the correlation is fresh for every session.

use anyhow::{Context, Result, bail};
use itybity::IntoBits;
use mpz_common::future::Output;
use mpz_core::Block;
use mpz_ot_core::{
    chou_orlandi::{self, receiver_state as co_receiver, sender_state as co_sender},
    kos::{self, receiver_state as kos_receiver, sender_state as kos_sender},
    ot::{OTReceiver, OTSender},
    rcot::{RCOTReceiver, RCOTSender},
    rot::{ROTReceiver, ROTSender, RandomizeRCOTReceiver, RandomizeRCOTSender},
};

use super::wire::{self, decode, encode};

type Frame = (u8, Vec<u8>);

enum NodeState {
    BaseOt { base: chou_orlandi::Sender<co_sender::Setup>, seeds: Box<[[Block; 2]; kos::CSP]> },
    Extending(kos::Receiver<kos_receiver::Extension>),
    Ready(RandomizeRCOTReceiver<kos::Receiver<kos_receiver::Extension>>),
    Failed,
}

/// Supplier side: base-OT sender, extension receiver.
pub struct NodeOt {
    state: NodeState,
    count: usize,
}

impl NodeOt {
    /// Starts the setup for `count` transfers and returns the first frame.
    pub fn start(count: usize) -> Result<(Self, Frame)> {
        let (setup, base) = chou_orlandi::Sender::new().setup();
        let seeds: [[Block; 2]; kos::CSP] = std::array::from_fn(|_| [Block::random(&mut rand::rng()), Block::random(&mut rand::rng())]);
        Ok((Self { state: NodeState::BaseOt { base, seeds: Box::new(seeds) }, count }, (wire::CO_SETUP, encode(&setup)?)))
    }

    /// Answers the verifier's base-OT choices and sends the extension matrix.
    pub fn on_choose(&mut self, payload: &[u8]) -> Result<Vec<Frame>> {
        let NodeState::BaseOt { mut base, seeds } = std::mem::replace(&mut self.state, NodeState::Failed) else {
            bail!("unexpected base-OT choice");
        };
        // The output only says the transfer was sent; the seeds are ours.
        let _ = base.queue_send_ot(&seeds[..]).map_err(|e| anyhow::anyhow!("base OT: {e}"))?;
        let payload = base.send(decode(payload)?).map_err(|e| anyhow::anyhow!("base OT: {e}"))?;
        let mut frames = vec![(wire::CO_PAYLOAD, encode(&payload)?)];
        let mut receiver = kos::Receiver::new(kos::ReceiverConfig::default()).setup(*seeds);
        receiver.alloc(self.count).map_err(|e| anyhow::anyhow!("OT extension: {e}"))?;
        while receiver.wants_extend() {
            let extend = receiver.extend().map_err(|e| anyhow::anyhow!("OT extension: {e}"))?;
            frames.push((wire::KOS_EXTEND, encode(&extend)?));
        }
        self.state = NodeState::Extending(receiver);
        Ok(frames)
    }

    /// Answers the verifier's consistency challenge.
    pub fn on_chi(&mut self, payload: &[u8]) -> Result<Frame> {
        let NodeState::Extending(mut receiver) = std::mem::replace(&mut self.state, NodeState::Failed) else {
            bail!("unexpected OT challenge");
        };
        let check = receiver.check(decode(payload)?).map_err(|e| anyhow::anyhow!("OT extension: {e}"))?;
        self.state = NodeState::Ready(RandomizeRCOTReceiver::new(receiver));
        Ok((wire::KOS_CHECK, encode(&check)?))
    }

    pub fn ready(&self) -> bool {
        matches!(self.state, NodeState::Ready(_))
    }

    /// Consumes `n` transfers: the random choice bits and the chosen blocks.
    pub fn take(&mut self, n: usize) -> Result<(Vec<bool>, Vec<[u8; 16]>)> {
        let NodeState::Ready(rot) = &mut self.state else { bail!("oblivious transfers are not ready") };
        let out = rot.try_recv_rot(n).map_err(|e| anyhow::anyhow!("OT extension: {e}"))?;
        Ok((out.choices, out.msgs.into_iter().map(Block::to_bytes).collect()))
    }
}

enum VerifierState {
    Start(chou_orlandi::Receiver),
    BaseOt { base: chou_orlandi::Receiver<co_receiver::Setup>, seeds: <chou_orlandi::Receiver<co_receiver::Setup> as OTReceiver<bool, Block>>::Future },
    Extending(kos::Sender<kos_sender::Extension>),
    Checking(kos::Sender<kos_sender::Extension>),
    Ready(RandomizeRCOTSender<kos::Sender<kos_sender::Extension>>),
    Failed,
}

/// Verifier side: base-OT receiver, extension sender.
pub struct VerifierOt {
    state: VerifierState,
    delta: Block,
    count: usize,
}

impl VerifierOt {
    pub fn new(count: usize) -> Self {
        Self { state: VerifierState::Start(chou_orlandi::Receiver::new()), delta: Block::random(&mut rand::rng()), count }
    }

    /// Chooses base OTs with the bits of this session's correlation.
    pub fn on_setup(&mut self, payload: &[u8]) -> Result<Frame> {
        let VerifierState::Start(base) = std::mem::replace(&mut self.state, VerifierState::Failed) else {
            bail!("unexpected base-OT setup");
        };
        let mut base = base.setup(decode(payload)?);
        let choices = self.delta.into_lsb0_vec();
        let seeds = base.queue_recv_ot(&choices).map_err(|e| anyhow::anyhow!("base OT: {e}"))?;
        let choose = base.choose();
        self.state = VerifierState::BaseOt { base, seeds };
        Ok((wire::CO_CHOOSE, encode(&choose)?))
    }

    pub fn on_payload(&mut self, payload: &[u8]) -> Result<()> {
        let VerifierState::BaseOt { mut base, mut seeds } = std::mem::replace(&mut self.state, VerifierState::Failed) else {
            bail!("unexpected base-OT payload");
        };
        base.receive(decode(payload)?).map_err(|e| anyhow::anyhow!("base OT: {e}"))?;
        let seeds = seeds.try_recv().ok().flatten().context("base OT did not complete")?.msgs;
        let seeds: [Block; kos::CSP] = seeds.try_into().ok().context("base OT returned the wrong number of seeds")?;
        let mut sender = kos::Sender::new(kos::SenderConfig::default(), self.delta).setup(seeds);
        sender.alloc(self.count).map_err(|e| anyhow::anyhow!("OT extension: {e}"))?;
        self.state = VerifierState::Extending(sender);
        Ok(())
    }

    /// Takes one extension frame. Returns the consistency challenge once the
    /// whole matrix has arrived, never before.
    pub fn on_extend(&mut self, payload: &[u8]) -> Result<Option<Frame>> {
        let VerifierState::Extending(mut sender) = std::mem::replace(&mut self.state, VerifierState::Failed) else {
            bail!("unexpected OT extension");
        };
        sender.extend(decode(payload)?).map_err(|e| anyhow::anyhow!("OT extension: {e}"))?;
        if sender.wants_extend() {
            self.state = VerifierState::Extending(sender);
            return Ok(None);
        }
        let chi = sender.check_start();
        self.state = VerifierState::Checking(sender);
        Ok(Some((wire::KOS_CHI, encode(&chi)?)))
    }

    /// Verifies the supplier's consistency check. A failure is final.
    pub fn on_check(&mut self, payload: &[u8]) -> Result<()> {
        let VerifierState::Checking(mut sender) = std::mem::replace(&mut self.state, VerifierState::Failed) else {
            bail!("unexpected OT check");
        };
        sender.check(decode(payload)?).map_err(|e| anyhow::anyhow!("OT consistency check failed: {e}"))?;
        self.state = VerifierState::Ready(RandomizeRCOTSender::new(sender));
        Ok(())
    }

    pub fn ready(&self) -> bool {
        matches!(self.state, VerifierState::Ready(_))
    }

    /// Consumes `n` transfers: both random blocks of each.
    pub fn take(&mut self, n: usize) -> Result<Vec<[[u8; 16]; 2]>> {
        let VerifierState::Ready(rot) = &mut self.state else { bail!("oblivious transfers are not ready") };
        let out = rot.try_send_rot(n).map_err(|e| anyhow::anyhow!("OT extension: {e}"))?;
        Ok(out.keys.into_iter().map(|[a, b]| [a.to_bytes(), b.to_bytes()]).collect())
    }
}

#[cfg(test)]
pub(crate) fn pair(count: usize) -> (NodeOt, VerifierOt) {
    let (mut node, setup) = NodeOt::start(count).unwrap();
    let mut verifier = VerifierOt::new(count);
    let choose = verifier.on_setup(&setup.1).unwrap();
    let mut chi = None;
    for (kind, payload) in node.on_choose(&choose.1).unwrap() {
        match kind {
            wire::CO_PAYLOAD => verifier.on_payload(&payload).unwrap(),
            _ => chi = verifier.on_extend(&payload).unwrap().or(chi),
        }
    }
    let check = node.on_chi(&chi.unwrap().1).unwrap();
    verifier.on_check(&check.1).unwrap();
    (node, verifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supplier_gets_exactly_the_chosen_block_of_each_transfer() {
        let (mut node, mut verifier) = pair(3000);
        assert!(node.ready() && verifier.ready());
        let (choices, got) = node.take(3000).unwrap();
        let pairs = verifier.take(3000).unwrap();
        assert!(choices.iter().any(|&c| c) && choices.iter().any(|&c| !c));
        for ((choice, got), pair) in choices.iter().zip(&got).zip(&pairs) {
            assert_eq!(got, &pair[*choice as usize]);
            assert_ne!(pair[0], pair[1]);
        }
        // Neither side can draw more than the pool holds.
        assert!(node.take(1 << 30).is_err() && verifier.take(1 << 30).is_err());
    }

    #[test]
    fn inconsistent_extension_fails_the_check_and_stays_failed() {
        let (mut node, setup) = NodeOt::start(256).unwrap();
        let mut verifier = VerifierOt::new(256);
        let choose = verifier.on_setup(&setup.1).unwrap();
        let mut chi = None;
        for (kind, mut payload) in node.on_choose(&choose.1).unwrap() {
            match kind {
                wire::CO_PAYLOAD => verifier.on_payload(&payload).unwrap(),
                _ => {
                    // Make the rows disagree about the choice vector. One flipped bit
                    // goes unnoticed when the matching bit of the verifier's correlation
                    // is zero (the KOS15 leak: a guess, caught half the time), so flip
                    // enough that passing would take a correct guess of every one.
                    payload.iter_mut().skip(16).step_by(7).for_each(|byte| *byte ^= 0x55);
                    chi = verifier.on_extend(&payload).unwrap().or(chi);
                }
            }
        }
        let check = node.on_chi(&chi.unwrap().1).unwrap();
        assert!(verifier.on_check(&check.1).is_err());
        assert!(!verifier.ready() && verifier.take(1).is_err());
    }

    #[test]
    fn frames_out_of_order_are_refused() {
        let mut verifier = VerifierOt::new(8);
        assert!(verifier.on_payload(&[]).is_err());
        assert!(verifier.on_extend(&[]).is_err());
        assert!(verifier.on_check(&[]).is_err());
        let (mut node, _) = NodeOt::start(8).unwrap();
        assert!(node.on_chi(&[]).is_err());
        assert!(node.take(1).is_err());
    }
}
