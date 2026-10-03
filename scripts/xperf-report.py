#!/usr/bin/env python3
"""Summarize sanitized xperf JSONL without emitting raw records or paths."""
import argparse
import json
import math
import os
import pathlib
import stat
import sys


def percentile(values, q):
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * q) - 1)] if values else None


def number(row, name, maximum=1e18):
    value = row.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 or value > maximum:
        raise ValueError("invalid numeric measurement")
    return value


def summarize(rows):
    groups = {}
    for row in rows:
        if row.get("schema") != 1 or row.get("mode") not in ("mpc", "proxy") or row.get("headers") not in ("normal", "minimal") or row.get("workload") not in ("search", "empty", "profile", "post", "pagination") or not isinstance(row.get("verified"), bool):
            raise ValueError("invalid experiment labels")
        key = (row["mode"], row["headers"], row["workload"],
               number(row, "max_recv", 256 << 10), number(row, "max_sent_records", 32),
               number(row, "max_recv_records_online", 32), number(row, "prepare_hold_ms", 30000))
        groups.setdefault(key, []).append(row)
    result = []
    for key, values in sorted(groups.items()):
        good = [v for v in values if v["verified"] and v.get("status") == "verified"]
        latency = [number(v, "duration_ms") for v in good]
        item_counts = [number(v, "items") for v in good]
        wall_seconds = 0
        if good:
            wall_seconds = (max(number(v, "finish_unix_ns", 1e20) for v in values) - min(number(v, "start_unix_ns", 1e20) for v in values)) / 1e9
        metered = [v for v in good if v.get("verifier_telemetry_complete") is True]
        row = dict(zip(("mode", "headers", "workload", "max_recv", "max_sent_records", "max_recv_records_online", "prepare_hold_ms"), key))
        row.update({"attempted_jobs": len(values), "verified_jobs": len(good), "failed_jobs": len(values) - len(good),
                    "successful_samples_below_30": len(good) < 30,
                    "verified_p50_ms": percentile(latency, .5), "verified_p95_ms": percentile(latency, .95),
                    "verified_jobs_per_second": len(good) / wall_seconds if wall_seconds > 0 else None,
                    "verified_reads_per_second": sum(number(v, "exchanges", 3) for v in good) / wall_seconds if wall_seconds > 0 else None,
                    "observed_wall_seconds_including_gaps": wall_seconds,
                    "result_count_min": min(item_counts) if item_counts else None, "result_count_max": max(item_counts) if item_counts else None,
                    "metered_verified_jobs": len(metered),
                    "verifier_upload_p50_bytes": percentile([number(v, "verifier_sent_bytes", 3 << 40) for v in metered], .5),
                    "verifier_total_p50_bytes": percentile([number(v, "verifier_sent_bytes", 3 << 40) + number(v, "verifier_received_bytes", 3 << 40) for v in metered], .5),
                    "helper_peak_rss_p95_bytes": percentile([number(v, "helper_peak_rss_bytes") for v in good], .95),
                    "helper_cpu_p50_seconds": percentile([number(v, "helper_user_cpu_seconds") + number(v, "helper_system_cpu_seconds") for v in good], .5),
                    "helper_execution_p95_ms": percentile([number(v, "helper_execution_ms") for v in good if v.get("helper_execution_ms") is not None], .95),
                    "response_ready_p95_ms": percentile([number(v, "response_ready_ms") for v in good if v.get("response_ready_ms") is not None], .95),
                    "phase_p95_ms": {phase: percentile([number(v["timings_ms"], phase) for v in good if phase in v.get("timings_ms", {})], .95)
                                     for phase in ("control_connect", "commit", "request_write", "response_read", "tls_finish", "prove", "finalize", "total")}})
        result.append(row)
    return {"schema": 1, "quantile_method": "nearest_rank", "throughput_scope": "recorded_serial_windows_including_gaps", "groups": result}


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
    base = {"schema": 1, "mode": "mpc", "headers": "normal", "workload": "search", "verified": True, "status": "verified", "max_recv": 0, "max_sent_records": 0, "max_recv_records_online": 0, "prepare_hold_ms": 0, "duration_ms": 100, "start_unix_ns": 1, "finish_unix_ns": 100000001, "exchanges": 1, "items": 20, "verifier_telemetry_complete": True, "verifier_sent_bytes": 200, "verifier_received_bytes": 300, "helper_peak_rss_bytes": 1000, "helper_user_cpu_seconds": .1, "helper_system_cpu_seconds": .2, "timings_ms": {"prove": 10, "PRIVATE": 20}}
    failed = dict(base, verified=False, status="PRIVATE_ERROR", duration_ms=1, finish_unix_ns=200000001)
    output = summarize([base, failed])
    group = output["groups"][0]
    assert group["verified_jobs"] == 1 and group["failed_jobs"] == 1
    assert group["verified_p95_ms"] == 100 and group["verified_jobs_per_second"] == 5
    assert "PRIVATE" not in json.dumps(output)
    assert percentile(list(range(1, 31)), .95) == 29
    try:
        summarize([dict(base, mode="PRIVATE_COOKIE")])
    except ValueError:
        pass
    else:
        raise AssertionError("unknown private label was accepted")
    print('{"offline_report_tests_passed":true}')


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
    rows = [row for path in args.metrics for row in read_metrics(path)]
    json.dump(summarize(rows), sys.stdout, indent=2, allow_nan=False)
    print()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit("invalid private experiment measurements")
