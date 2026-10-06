//! Bounded, supplier-local operational timings. These never enter proof evidence.
use std::{
    future::Future,
    io::Write,
    sync::{Arc, Mutex},
    time::Instant,
};

use serde::Serialize;

const MAX_SPANS: usize = 32;
const MAX_DURATION_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_JSON_BYTES: usize = 8 << 10;
pub const STDERR_PREFIX: &str = "SCARLETT_DIAGNOSTICS=";

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    ControlConfig,
    VerifierTcpConnect,
    VerifierTls,
    XTcpConnect,
    RelaySession,
    XTlsReady,
    OtReady,
    RelayAuthorization,
    RequestSent,
    ResponseFirstByte,
    ResponseComplete,
    OpeningCheck,
    ProofFinalize,
}

#[derive(Clone, Copy, Serialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Error,
    Cancelled,
}

#[derive(Clone, Serialize)]
pub struct Span {
    phase: Phase,
    start_ms: u64,
    duration_ms: u64,
    outcome: Outcome,
}

#[derive(Serialize)]
pub struct Snapshot {
    version: u8,
    duration_ms: u64,
    outcome: Outcome,
    spans: Vec<Span>,
}

struct State {
    started: Instant,
    spans: Vec<Span>,
}

#[derive(Clone)]
pub struct Trace(Arc<Mutex<State>>);

impl Trace {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            started: Instant::now(),
            spans: Vec::new(),
        })))
    }

    pub fn span(&self, phase: Phase) -> ActiveSpan {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let index = (state.spans.len() < MAX_SPANS).then(|| {
            let index = state.spans.len();
            let start_ms = elapsed(state.started);
            state.spans.push(Span {
                phase,
                start_ms,
                duration_ms: 0,
                outcome: Outcome::Cancelled,
            });
            index
        });
        ActiveSpan {
            trace: self.clone(),
            index,
        }
    }

    pub fn milestone(&self, phase: Phase) {
        self.milestone_at(phase, Instant::now());
    }

    pub fn milestone_at(&self, phase: Phase, at: Instant) {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.spans.len() < MAX_SPANS {
            let start_ms = at
                .saturating_duration_since(state.started)
                .as_millis()
                .min(u128::from(elapsed(state.started))) as u64;
            state.spans.push(Span {
                phase,
                start_ms,
                duration_ms: 0,
                outcome: Outcome::Success,
            });
        }
    }

    pub async fn measure<T, E>(
        &self,
        phase: Phase,
        future: impl Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        let span = self.span(phase);
        let result = future.await;
        span.finish(if result.is_ok() {
            Outcome::Success
        } else {
            Outcome::Error
        });
        result
    }

    pub fn measure_sync<T, E>(
        &self,
        phase: Phase,
        work: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let span = self.span(phase);
        let result = work();
        span.finish(if result.is_ok() {
            Outcome::Success
        } else {
            Outcome::Error
        });
        result
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        Snapshot {
            version: 1,
            duration_ms: elapsed(state.started),
            outcome: Outcome::Success,
            spans: state.spans.clone(),
        }
    }
}

fn elapsed(started: Instant) -> u64 {
    started
        .elapsed()
        .as_millis()
        .min(u128::from(MAX_DURATION_MS)) as u64
}

pub struct ActiveSpan {
    trace: Trace,
    index: Option<usize>,
}

impl ActiveSpan {
    pub fn finish(mut self, outcome: Outcome) {
        self.complete(outcome);
    }

    fn complete(&mut self, outcome: Outcome) {
        if let Some(index) = self.index.take() {
            let mut state = self.trace.0.lock().unwrap_or_else(|e| e.into_inner());
            let now = elapsed(state.started);
            let span = &mut state.spans[index];
            span.duration_ms = now.saturating_sub(span.start_ms);
            span.outcome = outcome;
        }
    }
}

impl Drop for ActiveSpan {
    fn drop(&mut self) {
        self.complete(Outcome::Cancelled);
    }
}

/// Retain a measured prefix on ordinary errors or dropped futures. A killed
/// process may produce none; the parent reports its own observed runtime.
pub struct Run {
    trace: Trace,
    completed: bool,
}

impl Run {
    pub fn new() -> Self {
        Self {
            trace: Trace::new(),
            completed: false,
        }
    }

    pub fn trace(&self) -> Trace {
        self.trace.clone()
    }

    pub fn success(mut self) -> Snapshot {
        self.completed = true;
        self.trace.snapshot()
    }

    fn failure_json(&self) -> Option<String> {
        let mut snapshot = self.trace.snapshot();
        snapshot.outcome = Outcome::Error;
        serde_json::to_string(&snapshot)
            .ok()
            .filter(|json| json.len() <= MAX_JSON_BYTES)
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        if !self.completed
            && let Some(json) = self.failure_json()
        {
            let _ = writeln!(std::io::stderr().lock(), "{STDERR_PREFIX}{json}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn delayed_overlapping_spans_use_one_monotonic_axis() {
        let trace = Trace::new();
        let tls = trace.span(Phase::XTlsReady);
        let ot = trace.span(Phase::OtReady);
        tokio::time::sleep(Duration::from_millis(15)).await;
        tls.finish(Outcome::Success);
        tokio::time::sleep(Duration::from_millis(15)).await;
        ot.finish(Outcome::Success);
        let snapshot = trace.snapshot();
        assert_eq!(snapshot.version, 1);
        assert!(snapshot.spans[0].duration_ms >= 15);
        assert!(snapshot.spans[1].duration_ms >= 30);
        let tls_end = snapshot.spans[0].start_ms + snapshot.spans[0].duration_ms;
        let ot_end = snapshot.spans[1].start_ms + snapshot.spans[1].duration_ms;
        let union =
            tls_end.max(ot_end) - snapshot.spans[0].start_ms.min(snapshot.spans[1].start_ms);
        assert!(snapshot.spans[0].duration_ms + snapshot.spans[1].duration_ms > union);
        assert!(
            snapshot
                .spans
                .iter()
                .all(|s| s.start_ms + s.duration_ms <= snapshot.duration_ms)
        );
    }

    #[tokio::test]
    async fn failed_and_cancelled_work_retains_the_measured_prefix() {
        let trace = Trace::new();
        trace
            .measure(Phase::XTcpConnect, async { Ok::<_, ()>(()) })
            .await
            .unwrap();
        assert!(
            trace
                .measure(Phase::VerifierTcpConnect, async { Err::<(), _>(()) })
                .await
                .is_err()
        );
        let waiting = trace.measure(Phase::VerifierTls, async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok::<_, ()>(())
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(15), waiting)
                .await
                .is_err()
        );
        let snapshot = trace.snapshot();
        assert_eq!(snapshot.spans.len(), 3);
        assert_eq!(snapshot.spans[0].outcome, Outcome::Success);
        assert_eq!(snapshot.spans[1].outcome, Outcome::Error);
        assert_eq!(snapshot.spans[2].outcome, Outcome::Cancelled);
        assert!(snapshot.spans[2].duration_ms >= 15);
    }

    #[test]
    fn output_is_bounded_and_only_contains_fixed_labels_and_numbers() {
        let trace = Trace::new();
        for _ in 0..1000 {
            trace.milestone(Phase::RelayAuthorization);
        }
        let snapshot = trace.snapshot();
        assert_eq!(snapshot.spans.len(), MAX_SPANS);
        let bytes = serde_json::to_vec(&snapshot).unwrap();
        assert!(bytes.len() < MAX_JSON_BYTES);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 4);
        assert_eq!(value["outcome"], "success");
        for span in value["spans"].as_array().unwrap() {
            let keys: Vec<_> = span
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(keys, ["duration_ms", "outcome", "phase", "start_ms"]);
            assert_eq!(span["phase"], "relay_authorization");
            assert_eq!(span["outcome"], "success");
        }
    }

    #[test]
    fn failed_prefix_has_an_error_total_even_before_any_phase_started() {
        let run = Run::new();
        let value: serde_json::Value = serde_json::from_str(&run.failure_json().unwrap()).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["outcome"], "error");
        assert!(value["spans"].as_array().unwrap().is_empty());
        // Avoid emitting the tested marker to the surrounding test harness.
        let _ = run.success();
    }
}
