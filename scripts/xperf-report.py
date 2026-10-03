#!/usr/bin/env python3
"""Summarize sanitized xperf JSONL without emitting raw records or paths."""
import argparse
import json
import math
import os
import pathlib
import stat
import sys

PROFILES = {"direct": 0, "simulated-rtt0": 0, "simulated-rtt20": 10, "simulated-rtt80": 40, "simulated-rtt160": 80}


def percentile(values, q):
    values = sorted(values)
    return values[max(0, math.ceil(len(values) * q) - 1)] if values else None


def number(row, name, maximum=1e18):
    value = row.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 or value > maximum:
        raise ValueError("invalid numeric measurement")
    return value


def option(row, name, default, maximum):
    return number(row, name, maximum) if name in row else default


def peak_jobs(rows):
    events = []
    for row in rows:
        start, finish = number(row, "start_unix_ns", 1e20), number(row, "finish_unix_ns", 1e20)
        if finish < start:
            raise ValueError("invalid measurement interval")
        if finish > start:
            events.extend(((start, 1), (finish, -1)))
    active = peak = 0
    for _, delta in sorted(events):
        active += delta
        peak = max(peak, active)
    return peak


def outcome_interval(successes, attempts):
    if not attempts:
        return None
    z = 1.959963984540054
    rate = successes / attempts
    scale = 1 + z * z / attempts
    centre = (rate + z * z / (2 * attempts)) / scale
    half = z * math.sqrt(rate * (1 - rate) / attempts + z * z / (4 * attempts * attempts)) / scale
    return [max(0, centre - half), min(1, centre + half)]


def summarize(rows):
    groups = {}
    for row in rows:
        if row.get("schema") != 1 or row.get("mode") not in ("mpc", "proxy") or row.get("headers") not in ("normal", "minimal") or row.get("workload") not in ("search", "empty", "profile", "post", "pagination") or not isinstance(row.get("verified"), bool):
            raise ValueError("invalid experiment labels")
        profile = row.get("network_profile", "direct")
        if profile not in PROFILES or option(row, "simulated_one_way_delay_ms", PROFILES[profile], 80) != PROFILES[profile]:
            raise ValueError("invalid simulated topology")
        concurrency = option(row, "concurrency", 1, 4)
        if concurrency not in (1, 2, 4) or option(row, "real_accounts", 1, 1) != 1:
            raise ValueError("unsupported account or concurrency claim")
        account_capacity = option(row, "account_capacity", 1, 4)
        receipt_capacity = option(row, "receipt_capacity", 1, 4)
        if min(account_capacity, receipt_capacity) < 1:
            raise ValueError("invalid capacity")
        sustained = option(row, "sustained_seconds", 0, 3600)
        if sustained and sustained < 60:
            raise ValueError("invalid sustained window")
        bandwidth = option(row, "bandwidth_bytes_second", 0, 1000000000)
        if profile == "direct" and bandwidth:
            raise ValueError("invalid direct bandwidth")
        key = (row["mode"], row["headers"], row["workload"],
               number(row, "max_recv", 256 << 10), number(row, "max_sent_records", 32),
               number(row, "max_recv_records_online", 32), number(row, "prepare_hold_ms", 30000),
               concurrency, account_capacity, receipt_capacity, sustained, profile, bandwidth)
        groups.setdefault(key, []).append(row)
    result = []
    for key, values in sorted(groups.items()):
        good = [v for v in values if v["verified"] and v.get("status") == "verified"]
        latency = [number(v, "duration_ms") for v in good]
        item_counts = [number(v, "items") for v in good]
        windows = {}
        for value in values:
            source = value.get("__source_index", 0)
            windows.setdefault(source, []).append(value)
        wall_seconds = 0
        sustained_passed = []
        observed_peak = 0
        for window in windows.values():
            first = min(option(v, "run_start_unix_ns", v["start_unix_ns"], 1e20) or v["start_unix_ns"] for v in window)
            last = max(option(v, "run_finish_unix_ns", v["finish_unix_ns"], 1e20) or v["finish_unix_ns"] for v in window)
            if last < first:
                raise ValueError("invalid run interval")
            elapsed = (last - first) / 1e9
            wall_seconds += elapsed
            window_peak = peak_jobs(window)
            if window_peak > min(key[7:10]):
                raise ValueError("observed concurrency exceeded capacity")
            observed_peak = max(observed_peak, window_peak)
            sustained_passed.append(key[10] >= 60 and elapsed >= key[10] and len(window) >= 30 and all(v["verified"] and v.get("status") == "verified" for v in window) and not any(v.get("__run_stopped", False) for v in window))
        metered = [v for v in good if v.get("verifier_telemetry_complete") is True]
        row = dict(zip(("mode", "headers", "workload", "max_recv", "max_sent_records", "max_recv_records_online", "prepare_hold_ms", "concurrency", "account_capacity", "receipt_capacity", "sustained_seconds", "network_profile", "bandwidth_bytes_second"), key))
        row.update({"attempted_jobs": len(values), "verified_jobs": len(good), "failed_jobs": len(values) - len(good),
                    "successful_samples_below_30": len(good) < 30,
                    "verified_fraction_wilson_95_interval": outcome_interval(len(good), len(values)),
                    "fraction_interval_assumption": "independent_bernoulli_attempts",
                    "real_accounts": 1, "independent_multiple_accounts_validated": False,
                    "simulated_topology": key[11] != "direct", "simulated_one_way_delay_ms": PROFILES[key[11]],
                    "effective_capacity_ceiling": min(key[7:10]), "observed_peak_jobs": observed_peak,
                    "recorded_windows": len(windows), "sustained_windows_passed": sum(sustained_passed),
                    "receipt_unrecovered_jobs": sum(v.get("receipt_observed") is not True or v.get("receipt_bound") is not True or v.get("receipt_complete") is not True for v in values),
                    "queue_wait_p95_ms": percentile([option(v, "queue_wait_ms", 0, 1e12) for v in values], .95),
                    "quota_remaining_min": min((number(v, "rate_limit_remaining", 1e12) for v in values if "rate_limit_remaining" in v), default=None),
                    "quota_reset_latest_epoch_seconds": max((number(v, "rate_limit_reset_epoch_seconds", 1e12) for v in values if "rate_limit_reset_epoch_seconds" in v), default=None),
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
    return {"schema": 1, "quantile_method": "nearest_rank", "throughput_scope": "recorded_experiment_windows_including_queue_gaps_and_failures", "groups": result}


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
    failed = dict(base, verified=False, status="PRIVATE_ERROR", duration_ms=1, start_unix_ns=100000001, finish_unix_ns=200000001)
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
    # Concurrent throughput uses elapsed run time, not summed job duration.
    concurrent = [dict(base, concurrency=2, account_capacity=2, receipt_capacity=2, start_unix_ns=1, finish_unix_ns=100000001, run_start_unix_ns=1, run_finish_unix_ns=200000001, queue_wait_ms=4),
                  dict(base, concurrency=2, account_capacity=2, receipt_capacity=2, start_unix_ns=50000001, finish_unix_ns=150000001, run_start_unix_ns=1, run_finish_unix_ns=200000001, queue_wait_ms=8)]
    group = summarize(concurrent)["groups"][0]
    assert group["verified_jobs_per_second"] == 10 and group["observed_peak_jobs"] == 2
    assert group["queue_wait_p95_ms"] == 8 and group["sustained_windows_passed"] == 0
    shaped = dict(base, network_profile="simulated-rtt80", simulated_one_way_delay_ms=40)
    assert len(summarize([base, shaped])["groups"]) == 2
    separate = [dict(base, __source_index=0), dict(base, __source_index=1, start_unix_ns=1000000001, finish_unix_ns=1100000001)]
    assert summarize(separate)["groups"][0]["verified_jobs_per_second"] == 10
    sustained = [dict(base, start_unix_ns=1 + i * 2000000000, finish_unix_ns=100000001 + i * 2000000000, sustained_seconds=60, run_start_unix_ns=1, run_finish_unix_ns=60000000001) for i in range(30)]
    assert summarize(sustained)["groups"][0]["sustained_windows_passed"] == 1
    assert summarize([dict(v, __run_stopped=True) for v in sustained])["groups"][0]["sustained_windows_passed"] == 0
    for unsafe in (dict(base, network_profile="PRIVATE_HOST"), dict(base, real_accounts=2), dict(base, concurrency=3), dict(base, sustained_seconds=5)):
        try:
            summarize([unsafe])
        except ValueError:
            pass
        else:
            raise AssertionError("unsupported capacity or topology was accepted")
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
    rows = []
    for index, path in enumerate(args.metrics):
        records = read_metrics(path)
        summary_path = path.with_name("run-summary.json")
        summary = None
        if summary_path.exists():
            summaries = read_metrics(summary_path)
            if len(summaries) != 1:
                raise ValueError("invalid run summary")
            summary = summaries[0]
            if summary.get("schema") != 1 or not isinstance(summary.get("stopped"), bool) or number(summary, "attempted_jobs", 1000) != len(records):
                raise ValueError("invalid run summary")
        for row in records:
            row["__source_index"] = index
            if summary is not None:
                first, last = number(summary, "start_unix_ns", 1e20), number(summary, "finish_unix_ns", 1e20)
                if first > number(row, "start_unix_ns", 1e20) or last < number(row, "finish_unix_ns", 1e20):
                    raise ValueError("summary does not contain sample")
                row["run_start_unix_ns"], row["run_finish_unix_ns"] = first, last
                row["__run_stopped"] = summary["stopped"]
            rows.append(row)
    json.dump(summarize(rows), sys.stdout, indent=2, allow_nan=False)
    print()


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError):
        raise SystemExit("invalid private experiment measurements")
