//! A bounded local diagnostics projection. No raw node output reaches the webview.
use serde::{Deserialize, Serialize};

pub(crate) const OUTPUT_LIMIT: usize = 1024 * 1024 + 64 * 1024;
const MAX_MS: f64 = 86_400_000.0;

#[derive(Default, Serialize)]
pub(crate) struct Diagnostics {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Snapshot>,
}
#[derive(Deserialize, Serialize)]
pub(crate) struct Snapshot {
    version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    load_error: Option<String>,
    attempts: Vec<Record>,
    summaries: Vec<Summary>,
}
#[derive(Deserialize, Serialize)]
struct Record {
    id: String,
    operation: String,
    pages: u8,
    proof_mode: String,
    started_at: String,
    outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_ms: Option<f64>,
    spans: Vec<Span>,
    missing_phases: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unclassified_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "is_false")]
    truncated: bool,
}
#[derive(Deserialize, Serialize)]
struct Span {
    phase: String,
    source: String,
    exchange: u8,
    start_ms: f64,
    duration_ms: f64,
    outcome: String,
}
#[derive(Deserialize, Serialize)]
struct Summary {
    operation: String,
    pages: u8,
    proof_mode: String,
    samples: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    p50_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    p95_ms: Option<f64>,
    newest_at: String,
}
const OPERATIONS: &[&str] = &["search", "profile", "post", "thread", "codex", "other"];
const PROOFS: &[&str] = &["relay", "mpc", "none"];
const OUTCOMES: &[&str] = &[
    "success",
    "running",
    "interrupted",
    "cancelled",
    "error",
    "auth_required",
    "capacity_unavailable",
    "expired",
    "gateway_error",
    "invalid_gateway_response",
    "invalid_lease",
    "prover_error",
    "usage_out_of_bounds",
    "x_error",
    "x_incomplete",
    "x_rate_limited",
    "x_reset_wait",
    "report_error",
    "journal_error",
    "accept_error",
    "report_pending",
    "rejected",
    "cache_hit",
    "cache_miss",
    "service_unavailable",
    "x_request_failed",
    "execution_uncertain",
    "relay_misuse",
];
const NODE_PHASES: &[&str] = &[
    "account_acquire",
    "worker_acquire",
    "accept_http",
    "worker",
    "client_acquire",
    "client_rebuild",
    "binding_check",
    "page_wall",
    "pacing_wait",
    "quota_wait",
    "fixed_gap_wait",
    "jitter_wait",
    "quota_spread_wait",
    "quota_reset_wait",
    "request_encode",
    "proof_journal_begin",
    "helper_wall",
    "helper_stdout_decode",
    "response_decode",
    "proof_journal_complete",
    "journal_lock",
    "journal_scan",
    "journal_write",
    "journal_finish",
    "journal_ready",
    "journal_terminal",
    "report_prepare",
    "report_http",
];
const HELPER_PHASES: &[&str] = &[
    "helper_total",
    "control_config",
    "verifier_tcp_connect",
    "verifier_tls",
    "x_tcp_connect",
    "relay_session",
    "x_tls_ready",
    "ot_ready",
    "relay_authorization",
    "request_sent",
    "response_first_byte",
    "response_complete",
    "opening_check",
    "proof_finalize",
];
fn timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if !(20..=30).contains(&b.len()) || b.last() != Some(&b'Z') {
        return false;
    }
    for (i, v) in b.iter().enumerate() {
        let expected = match i {
            4 | 7 => Some(b'-'),
            10 => Some(b'T'),
            13 | 16 => Some(b':'),
            19 if b.len() > 20 => Some(b'.'),
            n if n == b.len() - 1 => Some(b'Z'),
            _ => None,
        };
        if expected.map_or_else(|| !v.is_ascii_digit(), |e| *v != e) {
            return false;
        }
    }
    let component = |a: usize, z: usize| s[a..z].parse::<u32>().unwrap_or(u32::MAX);
    (1..=12).contains(&component(5, 7))
        && (1..=31).contains(&component(8, 10))
        && component(11, 13) <= 23
        && component(14, 16) <= 59
        && component(17, 19) <= 59
        && b.len() != 21
}
fn ms(n: f64) -> bool {
    n.is_finite() && (0.0..=MAX_MS).contains(&n)
}
fn is_false(value: &bool) -> bool {
    !*value
}
fn optional_ms(n: Option<f64>) -> bool {
    n.is_none_or(ms)
}
fn group(operation: &str, pages: u8, proof: &str) -> bool {
    OPERATIONS.contains(&operation) && pages <= 3 && PROOFS.contains(&proof)
}
fn phase(phase: &str) -> bool {
    NODE_PHASES.contains(&phase) || HELPER_PHASES.contains(&phase)
}
impl Record {
    fn valid(&self) -> bool {
        self.id.len() == 64
            && self
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && group(&self.operation, self.pages, &self.proof_mode)
            && timestamp(&self.started_at)
            && OUTCOMES.contains(&self.outcome.as_str())
            && optional_ms(self.duration_ms)
            && (self.outcome != "running" || self.duration_ms.is_none())
            && optional_ms(self.unclassified_ms)
            && self.unclassified_ms.is_none_or(|unclassified| {
                self.duration_ms.is_some_and(|total| unclassified <= total)
            })
            && self.spans.len() <= 64
            && self.missing_phases.len() <= 64
            && self.missing_phases.iter().all(|p| phase(p))
            && self.spans.iter().all(|s| {
                s.exchange <= 3
                    && ms(s.start_ms)
                    && ms(s.duration_ms)
                    && ms(s.start_ms + s.duration_ms)
                    && OUTCOMES.contains(&s.outcome.as_str())
                    && match s.source.as_str() {
                        "node" => {
                            NODE_PHASES.contains(&s.phase.as_str())
                                && self
                                    .duration_ms
                                    .is_none_or(|total| s.start_ms + s.duration_ms <= total + 0.001)
                        }
                        "helper" => s.exchange > 0 && HELPER_PHASES.contains(&s.phase.as_str()),
                        _ => false,
                    }
            })
            && serde_json::to_vec(self).is_ok_and(|raw| raw.len() <= 8 * 1024)
    }
}
pub(crate) fn project(raw: &[u8]) -> Option<Snapshot> {
    if raw.len() > OUTPUT_LIMIT {
        return None;
    }
    let value: Snapshot = serde_json::from_slice(raw).ok()?;
    if value.version != 1
        || value.attempts.len() > 200
        || value.summaries.len() > 200
        || value.updated_at.as_deref().is_some_and(|s| !timestamp(s))
        || value.load_error.as_deref().is_some_and(|s| {
            ![
                "corrupt",
                "io_error",
                "unavailable",
                "write_error",
                "too_large",
            ]
            .contains(&s)
        })
        || !value.attempts.iter().all(Record::valid)
        || !value.summaries.iter().all(|s| {
            group(&s.operation, s.pages, &s.proof_mode)
                && (1..=200).contains(&s.samples)
                && optional_ms(s.p50_ms)
                && optional_ms(s.p95_ms)
                && s.p50_ms.zip(s.p95_ms).is_none_or(|(p50, p95)| p50 <= p95)
                && timestamp(&s.newest_at)
        })
    {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn sample() -> serde_json::Value {
        json!({"version":1,"updated_at":"2026-10-05T12:34:56.123456789Z","attempts":[{
            "id":"a".repeat(64),"operation":"search","pages":1,"proof_mode":"relay",
            "started_at":"2026-10-05T12:34:56Z","outcome":"success","duration_ms":3000,
            "spans":[{"phase":"helper_total","source":"helper","exchange":1,"start_ms":0,"duration_ms":2000,"outcome":"success"}],
            "missing_phases":[],"unclassified_ms":1000}],"summaries":[{
            "operation":"search","pages":1,"proof_mode":"relay","samples":1,
            "p50_ms":3000,"p95_ms":3000,"newest_at":"2026-10-05T12:34:56Z"}]})
    }
    #[test]
    fn emitted_pacing_history_remains_available_without_private_quota_fields() {
        let raw = include_bytes!("../../tests/fixtures/pacing-diagnostics-v1.json");
        let safe = project(raw).expect("Go-emitted pacing history must remain available");
        assert_eq!(safe.attempts.len(), 31);
        for (phase, count) in [
            ("fixed_gap_wait", 3),
            ("jitter_wait", 9),
            ("quota_spread_wait", 3),
            ("quota_reset_wait", 3),
        ] {
            assert_eq!(
                safe.attempts
                    .iter()
                    .flat_map(|r| &r.spans)
                    .filter(|s| s.phase == phase && s.source == "node")
                    .count(),
                count,
                "missing emitted {phase} spans"
            );
        }
        let output = serde_json::to_string(&safe).unwrap();
        assert!(std::str::from_utf8(raw)
            .unwrap()
            .contains("quota_snapshots"));
        assert!(!output.contains("quota_snapshots"));
        assert!(!output.contains("remaining"));
        assert!(safe.summaries.iter().any(|s| s.samples == 31));
    }
    #[test]
    fn emitted_history_still_rejects_unknown_or_misclassified_pacing_spans() {
        let raw = include_bytes!("../../tests/fixtures/pacing-diagnostics-v1.json");
        let original: serde_json::Value = serde_json::from_slice(raw).unwrap();
        for phase in ["future_pacing_wait", "SECRET_PROVIDER_DETAIL"] {
            let mut value = original.clone();
            let span = value["attempts"][22]["spans"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|s| s["phase"] == "jitter_wait")
                .unwrap();
            span["phase"] = json!(phase);
            assert!(project(&serde_json::to_vec(&value).unwrap()).is_none());
        }
        for (field, bad) in [("source", json!("helper")), ("exchange", json!(4))] {
            let mut value = original.clone();
            let span = value["attempts"][22]["spans"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|s| s["phase"] == "jitter_wait")
                .unwrap();
            span[field] = bad;
            assert!(project(&serde_json::to_vec(&value).unwrap()).is_none());
        }
    }
    #[test]
    fn projection_discards_every_unknown_field_at_every_level() {
        let mut v = sample();
        v["token"] = json!("SECRET");
        v["attempts"][0]["query"] = json!("SECRET");
        v["attempts"][0]["spans"][0]["path"] = json!("SECRET");
        v["summaries"][0]["response"] = json!("SECRET");
        let safe = project(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(!serde_json::to_string(&safe).unwrap().contains("SECRET"));
    }
    #[test]
    fn projection_rejects_arbitrary_strings_and_invalid_or_oversized_numbers() {
        for (key, bad) in [
            ("operation", json!("SECRET")),
            ("outcome", json!("SECRET")),
            ("id", json!("SECRET")),
            ("started_at", json!("SECRET")),
            ("pages", json!(4)),
            ("duration_ms", json!(-1)),
            ("duration_ms", json!(86_400_001)),
        ] {
            let mut v = sample();
            v["attempts"][0][key] = bad;
            assert!(project(&serde_json::to_vec(&v).unwrap()).is_none(), "{key}");
        }
        let mut v = sample();
        v["attempts"][0]["spans"][0]["source"] = json!("SECRET");
        assert!(project(&serde_json::to_vec(&v).unwrap()).is_none());
        v = sample();
        v["attempts"][0]["missing_phases"] = json!(["SECRET"]);
        assert!(project(&serde_json::to_vec(&v).unwrap()).is_none());
        v = sample();
        v["attempts"] = json!(vec![v["attempts"][0].clone(); 201]);
        assert!(project(&serde_json::to_vec(&v).unwrap()).is_none());
        assert!(project(&vec![b' '; OUTPUT_LIMIT + 1]).is_none());
    }
    #[test]
    fn unknown_durations_remain_unknown_and_empty_history_is_available() {
        let mut v = sample();
        v["attempts"][0]
            .as_object_mut()
            .unwrap()
            .remove("duration_ms");
        v["attempts"][0]
            .as_object_mut()
            .unwrap()
            .remove("unclassified_ms");
        let safe = project(&serde_json::to_vec(&v).unwrap()).unwrap();
        let out = serde_json::to_value(safe).unwrap();
        assert!(out["attempts"][0].get("duration_ms").is_none());
        assert!(project(br#"{"version":1,"attempts":[],"summaries":[]}"#).is_some());
        assert!(
            project(br#"{"version":1,"load_error":"corrupt","attempts":[],"summaries":[]}"#)
                .is_some()
        );
        assert!(
            project(br#"{"version":1,"load_error":"SECRET","attempts":[],"summaries":[]}"#)
                .is_none()
        );
    }
    #[test]
    fn projection_bounds_clock_sources_and_exposes_truncation() {
        let mut v = sample();
        v["attempts"][0]["truncated"] = json!(true);
        let safe = project(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(safe).unwrap()["attempts"][0]["truncated"],
            true
        );
        for bad in [json!(0), json!(4)] {
            v = sample();
            v["attempts"][0]["spans"][0]["exchange"] = bad;
            assert!(project(&serde_json::to_vec(&v).unwrap()).is_none());
        }
        v = sample();
        v["attempts"][0]["spans"][0]["source"] = json!("node");
        assert!(project(&serde_json::to_vec(&v).unwrap()).is_none());
        v = sample();
        v["attempts"][0]["spans"][0]["start_ms"] = json!(86_399_999);
        assert!(project(&serde_json::to_vec(&v).unwrap()).is_none());
    }
    #[test]
    fn final_failure_vocabulary_keeps_a_valid_snapshot_available() {
        for code in [
            "service_unavailable",
            "x_request_failed",
            "execution_uncertain",
            "relay_misuse",
        ] {
            let mut v = sample();
            v["attempts"][0]["outcome"] = json!(code);
            v["attempts"][0]["spans"][0]["outcome"] = json!(code);
            assert!(
                project(&serde_json::to_vec(&v).unwrap()).is_some(),
                "{code}"
            );
        }
    }
    #[test]
    fn clock_and_percentile_relationships_reject_impossible_timelines() {
        let encode = |v: &serde_json::Value| serde_json::to_vec(v).unwrap();
        let mut v = sample();
        v["attempts"][0]["spans"][0] = json!({"phase":"helper_wall","source":"node","exchange":1,"start_ms":2500,"duration_ms":501,"outcome":"success"});
        assert!(
            project(&encode(&v)).is_none(),
            "node span cannot outlast known attempt duration"
        );
        v["attempts"][0]["spans"][0]["duration_ms"] = json!(500.0005);
        assert!(
            project(&encode(&v)).is_some(),
            "sub-microsecond rounding tolerance is allowed"
        );
        v["attempts"][0]["spans"][0]["duration_ms"] = json!(500.0015);
        assert!(project(&encode(&v)).is_none());
        v = sample();
        v["attempts"][0]["spans"][0]["start_ms"] = json!(2500);
        assert!(
            project(&encode(&v)).is_some(),
            "helper clock must not be compared with the node clock"
        );
        v = sample();
        v["attempts"][0]["outcome"] = json!("running");
        assert!(
            project(&encode(&v)).is_none(),
            "running attempt duration is unknown"
        );
        v = sample();
        v["attempts"][0]
            .as_object_mut()
            .unwrap()
            .remove("duration_ms");
        assert!(
            project(&encode(&v)).is_none(),
            "unclassified time requires a known duration"
        );
        v = sample();
        v["attempts"][0]["unclassified_ms"] = json!(3001);
        assert!(
            project(&encode(&v)).is_none(),
            "unclassified time cannot exceed total duration"
        );
        v = sample();
        v["summaries"][0]["p50_ms"] = json!(3001);
        assert!(project(&encode(&v)).is_none(), "p50 cannot exceed p95");
    }
}
