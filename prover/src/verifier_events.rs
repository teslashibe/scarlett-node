//! The verifier's event feed (`GET /v1/events`): an in-memory ring of web
//! sessions' terminal commits, so the app learns that a hop chain finished
//! from the verifier on loopback rather than from the node's report.
//!
//! An event is appended only after its commit: the final hop once its receipt
//! and body are durable (`complete`), or a committed rejection (`rejected`).
//! Redirect hops, refusals that spend nothing and revocations are not events.
//! The ring needs no durability: a restart starts a new epoch, and the app's
//! node reports and reconciler still cover anything it missed.

use std::{collections::VecDeque, sync::Mutex};

use serde::Serialize;
use tokio::sync::watch;

/// Events the ring keeps; older ones are dropped.
pub const RING: usize = 10_000;
/// Events one reply carries at most; the consumer pages on with `next`.
pub const MAX_REPLY: usize = 1000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Event {
    pub seq: u64,
    pub job_id: String,
    pub attempt: String,
    /// `complete` or `rejected`.
    pub kind: &'static str,
    pub committed_at_ms: u64,
}

/// What a consumer at `after` gets now.
#[derive(Debug, PartialEq, Eq)]
pub enum Read {
    /// Events after `after`, oldest first, and the `after` to ask with next.
    Events(Vec<Event>, u64),
    /// `after` is not a position of this ring (another epoch, or events it
    /// dropped): the consumer starts again at `next`, the newest event.
    Reset { next: u64 },
}

struct Ring {
    events: VecDeque<Event>,
    /// The newest event's seq, 0 before the first.
    head: u64,
}

pub struct Feed {
    /// Random per process start: a seq means nothing in another epoch.
    pub epoch: String,
    capacity: usize,
    ring: Mutex<Ring>,
    newest: watch::Sender<u64>,
}

impl Feed {
    pub fn new() -> Self {
        Self::with_capacity(RING)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self { epoch: format!("{:032x}", rand::random::<u128>()), capacity: capacity.max(1), ring: Mutex::new(Ring { events: VecDeque::new(), head: 0 }), newest: watch::channel(0).0 }
    }

    /// Records a terminal commit that has already happened.
    pub fn append(&self, job_id: &str, attempt: &str, kind: &'static str, committed_at_ms: u64) {
        let seq = {
            let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
            ring.head += 1;
            let seq = ring.head;
            ring.events.push_back(Event { seq, job_id: job_id.to_owned(), attempt: attempt.to_owned(), kind, committed_at_ms });
            while ring.events.len() > self.capacity {
                ring.events.pop_front();
            }
            seq
        };
        self.newest.send_replace(seq);
    }

    /// Events after `after`, at most `max`, or a reset when `after` is not a
    /// position this ring can continue from.
    pub fn read(&self, after: u64, max: usize) -> Read {
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let oldest = ring.events.front().map_or(ring.head + 1, |e| e.seq);
        if after > ring.head || after + 1 < oldest {
            return Read::Reset { next: ring.head };
        }
        let events: Vec<Event> = ring.events.iter().skip((after + 1 - oldest) as usize).take(max).cloned().collect();
        let next = events.last().map_or(after, |e| e.seq);
        Read::Events(events, next)
    }

    /// The newest event's seq, 0 before the first.
    pub fn head(&self) -> u64 {
        self.ring.lock().unwrap_or_else(|e| e.into_inner()).head
    }

    /// Wakes when an event is appended. Subscribe before reading, so an
    /// append between the read and the wait is not missed.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.newest.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seqs(read: Read) -> (Vec<u64>, u64) {
        match read {
            Read::Events(events, next) => (events.iter().map(|e| e.seq).collect(), next),
            Read::Reset { next } => panic!("reset to {next}"),
        }
    }

    #[test]
    fn a_consumer_reads_on_from_its_position_and_resets_when_it_cannot() {
        let feed = Feed::with_capacity(4);
        // Nothing yet: the start is a position, the future is not.
        assert_eq!(feed.read(0, 10), Read::Events(Vec::new(), 0));
        assert_eq!(feed.read(1, 10), Read::Reset { next: 0 });
        for i in 1..=3 {
            feed.append("job", &format!("a{i}"), if i == 2 { "rejected" } else { "complete" }, 1000 + i);
        }
        assert_eq!(seqs(feed.read(0, 10)), (vec![1, 2, 3], 3));
        assert_eq!(seqs(feed.read(1, 10)), (vec![2, 3], 3));
        assert_eq!(seqs(feed.read(3, 10)), (vec![], 3));
        // Paged replies continue where the last one ended.
        assert_eq!(seqs(feed.read(0, 2)), (vec![1, 2], 2));
        assert_eq!(seqs(feed.read(2, 2)), (vec![3], 3));
        let Read::Events(events, _) = feed.read(1, 1) else { panic!() };
        assert_eq!(events, vec![Event { seq: 2, job_id: "job".into(), attempt: "a2".into(), kind: "rejected", committed_at_ms: 1002 }]);
        // The ring keeps four: a consumer behind the oldest has lost events.
        for i in 4..=7 {
            feed.append("job", &format!("a{i}"), "complete", 1000 + i);
        }
        assert_eq!(seqs(feed.read(3, 10)), (vec![4, 5, 6, 7], 7));
        assert_eq!(feed.read(2, 10), Read::Reset { next: 7 });
        assert_eq!(feed.read(0, 10), Read::Reset { next: 7 });
        // A position from another epoch's longer history.
        assert_eq!(feed.read(8, 10), Read::Reset { next: 7 });
        assert_eq!(feed.epoch.len(), 32);
        assert_ne!(feed.epoch, Feed::new().epoch);
    }

    #[tokio::test]
    async fn an_append_wakes_a_subscriber_that_subscribed_before_reading() {
        let feed = std::sync::Arc::new(Feed::new());
        let mut wake = feed.subscribe();
        assert_eq!(seqs(feed.read(0, 10)), (vec![], 0));
        let appender = feed.clone();
        tokio::spawn(async move { appender.append("job", "a", "complete", 1) });
        tokio::time::timeout(std::time::Duration::from_secs(5), wake.changed()).await.unwrap().unwrap();
        assert_eq!(seqs(feed.read(0, 10)), (vec![1], 1));
    }
}
