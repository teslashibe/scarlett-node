#!/usr/bin/env python3
"""Summarize private Codex experiment JSONL without provider content."""
import argparse
import json
import math
import os
import pathlib
import stat
import sys

PHASES = ("control_connect", "commit", "websocket_handshake", "response_read", "tls_finish", "prove", "finalize", "total")


def percentile(values, q):
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * q) - 1)] if values else None


def number(row, key, maximum=1e18):
    n = row.get(key)
    if isinstance(n, bool) or not isinstance(n, (int, float)) or not math.isfinite(n) or n < 0 or n > maximum:
        raise ValueError("invalid numeric measurement")
    return n


def summarize(rows):
    groups = {}
    for row in rows:
        if row.get("schema") != 1 or row.get("mode") != "proxy" or row.get("workload") != "codex_trivial" or row.get("reasoning") != "low" or row.get("service_tier_omitted") is not True or not isinstance(row.get("verified"), bool):
            raise ValueError("invalid experiment labels")
        if row["verified"] and (row.get("status") != "verified" or row.get("model_matches") is not True or row.get("output_matches") is not True):
            raise ValueError("invalid verified result")
        # Older pinned baseline runners did not emit this field and used normal.
        strategy = row.get("close_strategy", "normal")
        if strategy not in ("normal", "tls_after_completed"):
            raise ValueError("invalid close strategy")
        model = row.get("model", "gpt-6.1-sol")
        cohort = row.get("account_cohort", "account-1")
        if model not in ("gpt-6.1-sol", "gpt-5.6-luna") or cohort not in ("account-1", "account-2"):
            raise ValueError("invalid model or account cohort")
        groups.setdefault((strategy, model, cohort), []).append(row)
    if len(groups) <= 1:
        key = next(iter(groups), ("normal", "gpt-6.1-sol", "account-1"))
        return summarize_strategy(rows, *key)
    return {"schema": 1, "comparison_dimensions": ["close_strategy", "model", "account_cohort"],
            "groups": [summarize_strategy(values, *key) for key, values in sorted(groups.items())]}


def summarize_strategy(rows, strategy, model, cohort):
    good = [r for r in rows if r["verified"]]
    metered = [r for r in good if r.get("verifier_telemetry_complete") is True]
    cached = [r for r in good if r.get("cached_input_tokens_reported") is True]
    for r in cached:
        if number(r, "cached_input_tokens", 1e9) > number(r, "input_tokens", 1e9):
            raise ValueError("cached usage exceeds total input usage")
    wall_seconds = (max(number(r, "finish_unix_ns", 1e20) for r in rows) - min(number(r, "start_unix_ns", 1e20) for r in rows)) / 1e9 if rows else 0
    return {"schema": 1, "mode": "proxy", "workload": "codex_trivial", "reasoning": "low", "service_tier_request": "omitted",
            "close_strategy": strategy,
            "model": model, "account_cohort": cohort,
            "quantile_method": "nearest_rank", "attempted_jobs": len(rows), "verified_jobs": len(good), "failed_jobs": len(rows) - len(good),
            "successful_samples_below_30": len(good) < 30,
            "verified_p50_ms": percentile([number(r, "duration_ms") for r in good], .5),
            "verified_p95_ms": percentile([number(r, "duration_ms") for r in good], .95),
            "verified_jobs_per_second": len(good) / wall_seconds if wall_seconds > 0 else None,
            "observed_serial_wall_seconds_including_gaps": wall_seconds,
            "codex_p50_ms": percentile([number(r, "codex_ms") for r in good if r.get("codex_ms") is not None], .5),
            "codex_p95_ms": percentile([number(r, "codex_ms") for r in good if r.get("codex_ms") is not None], .95),
            "metered_verified_jobs": len(metered),
            "verifier_upload_p50_bytes": percentile([number(r, "verifier_sent_bytes", 1 << 40) for r in metered], .5),
            "verifier_total_p50_bytes": percentile([number(r, "verifier_sent_bytes", 1 << 40) + number(r, "verifier_received_bytes", 1 << 40) for r in metered], .5),
            "transcript_counter_receipt_verified_jobs": sum(r.get("transcript_counters_verified_by_receipt") is True for r in good),
            "input_tokens_p50": percentile([number(r, "input_tokens", 1e9) for r in good], .5),
            "output_tokens_p50": percentile([number(r, "output_tokens", 1e9) for r in good], .5),
            "cached_usage_reported_jobs": len(cached),
            "cached_input_tokens_p50": percentile([number(r, "cached_input_tokens", 1e9) for r in cached], .5),
            "helper_peak_rss_p95_bytes": percentile([number(r, "helper_peak_rss_bytes") for r in good], .95),
            "helper_cpu_p50_seconds": percentile([number(r, "helper_user_cpu_seconds") + number(r, "helper_system_cpu_seconds") for r in good], .5),
            "phase_p95_ms": {phase: percentile([number(r["timings_ms"], phase) for r in good if phase in r.get("timings_ms", {})], .95) for phase in PHASES}}


def read_metrics(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 16 << 20:
            raise ValueError("metrics file must be private, regular and bounded")
        with os.fdopen(descriptor, "r", encoding="utf-8") as f:
            descriptor = None
            return [json.loads(line) for line in f if line.strip()]
    finally:
        if descriptor is not None:
            os.close(descriptor)


def self_test():
    good = {"schema": 1, "mode": "proxy", "workload": "codex_trivial", "reasoning": "low", "service_tier_omitted": True, "verified": True, "status": "verified", "model_matches": True, "output_matches": True, "start_unix_ns": 1, "finish_unix_ns": 100000001, "duration_ms": 100, "codex_ms": 80, "input_tokens": 20, "output_tokens": 3, "cached_input_tokens_reported": False, "verifier_telemetry_complete": True, "verifier_sent_bytes": 200, "verifier_received_bytes": 300, "helper_peak_rss_bytes": 1000, "helper_user_cpu_seconds": .1, "helper_system_cpu_seconds": .2, "timings_ms": {"prove": 10, "PRIVATE": 50}}
    failed = dict(good, verified=False, status="PRIVATE_ERROR", finish_unix_ns=200000001)
    report = summarize([good, failed])
    assert report["verified_jobs"] == 1 and report["failed_jobs"] == 1 and report["verified_p95_ms"] == 100
    assert report["verified_jobs_per_second"] == 5 and report["cached_usage_reported_jobs"] == 0 and report["cached_input_tokens_p50"] is None
    assert "PRIVATE" not in json.dumps(report)
    assert report["close_strategy"] == "normal"
    assert report["model"] == "gpt-6.1-sol" and report["account_cohort"] == "account-1"
    different_model = summarize([good, dict(good, model="gpt-5.6-luna", account_cohort="account-2")])
    assert len(different_model["groups"]) == 2
    mixed = summarize([good, dict(good, close_strategy="tls_after_completed", duration_ms=50)])
    assert len(mixed["groups"]) == 2
    assert mixed["groups"][0]["close_strategy"] == "normal" and mixed["groups"][0]["verified_p95_ms"] == 100
    assert mixed["groups"][1]["close_strategy"] == "tls_after_completed" and mixed["groups"][1]["verified_p95_ms"] == 50
    try:
        summarize([dict(good, cached_input_tokens_reported=True, cached_input_tokens=21)])
    except ValueError:
        pass
    else:
        raise AssertionError("invalid cached usage accepted")
    try:
        summarize([dict(good, close_strategy="PRIVATE_STRATEGY")])
    except ValueError:
        pass
    else:
        raise AssertionError("unknown private strategy accepted")
    print('{"offline_codex_report_tests_passed":true}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metrics", nargs="*", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.metrics:
        parser.error("provide private metrics.jsonl files")
    json.dump(summarize([row for path in args.metrics for row in read_metrics(path)]), sys.stdout, indent=2, allow_nan=False)
    print()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit("invalid private experiment measurements")
