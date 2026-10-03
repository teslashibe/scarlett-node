#!/usr/bin/env bash
# Run from an isolated checkout. Provider secrets are private file inputs only.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--offline" ]]; then
  unset SCARLETT_XPERF
  go test -tags xperf -run '^TestXPerf' -count=1 ./internal/worker
  python3 scripts/xperf-shaper.py --self-test
  python3 scripts/xperf-shaper-test.py
  exec python3 scripts/xperf-report.py --self-test
fi

if [[ "${SCARLETT_XPERF:-}" != "1" ]]; then
  printf '%s\n' 'Real provider calls require SCARLETT_XPERF=1' >&2
  exit 2
fi
: "${SCARLETT_XPERF_OUTPUT:?Set a new private output directory}"

# This directory must be new. No existing metrics, diagnostics or identities
# can be overwritten or confused with the new run.
mkdir -m 700 -- "$SCARLETT_XPERF_OUTPUT"
export SCARLETT_XPERF_OUTPUT
python3 - "$SCARLETT_XPERF_OUTPUT" <<'PY'
import hashlib, json, os, pathlib, re, subprocess, sys
output = pathlib.Path(sys.argv[1])
revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
if not re.fullmatch(r"[0-9a-f]{40}", revision):
    raise SystemExit("invalid source revision")
diff = subprocess.check_output(["git", "diff", "--binary", "HEAD"])
helper = pathlib.Path(os.environ["SCARLETT_PROVER"])
digest = hashlib.sha256()
with helper.open("rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        digest.update(chunk)
profiles = {"direct": 0, "simulated-rtt0": 0, "simulated-rtt20": 10, "simulated-rtt80": 40, "simulated-rtt160": 80}
profile = os.environ.get("SCARLETT_XPERF_NETWORK_PROFILE", "direct")
if profile not in profiles:
    raise SystemExit("invalid network profile")
def option(name, default, minimum, maximum):
    value = os.environ.get(name, str(default))
    if not re.fullmatch(r"[0-9]+", value) or not minimum <= int(value) <= maximum:
        raise SystemExit("invalid bounded experiment option")
    return int(value)
concurrency = option("SCARLETT_XPERF_CONCURRENCY", 1, 1, 4)
if concurrency not in (1, 2, 4):
    raise SystemExit("invalid experiment concurrency")
batch_reads = option("SCARLETT_XPERF_BATCH_READS", 0, 0, 2)
if batch_reads not in (0, 2):
    raise SystemExit("invalid experiment batch size")
sustained = option("SCARLETT_XPERF_SUSTAINED_SECONDS", 0, 0, 3600)
if sustained and sustained < 60:
    raise SystemExit("sustained window must be at least 60 seconds")
bandwidth = option("SCARLETT_XPERF_BANDWIDTH_BYTES_SECOND", 0, 0, 1000000000)
if profile == "direct" and bandwidth:
    raise SystemExit("bandwidth requires a simulated profile")
mpc_network = os.environ.get("SCARLETT_XPERF_MPC_NETWORK", "reduce_bandwidth")
if mpc_network not in ("reduce_bandwidth", "reduce_roundtrips"):
    raise SystemExit("invalid MPC network setting")
manifest = {"mpc_network": mpc_network, "schema": 1, "source_revision": revision,
            "tracked_source_diff_sha256": hashlib.sha256(diff).hexdigest(),
            "source_modified": bool(diff), "helper_sha256": digest.hexdigest(),
            "bootstrap": "unproven_once_outside_samples", "funding": "none",
            "production_policy": "unchanged", "concurrency": concurrency,
            "batch_reads": batch_reads,
            "account_capacity": option("SCARLETT_XPERF_ACCOUNT_CAPACITY", 1, 1, 4),
            "receipt_capacity": option("SCARLETT_XPERF_RECEIPT_CAPACITY", 1, 1, 4),
            "min_gap_ms": option("SCARLETT_XPERF_MIN_GAP_MS", 1000, 0, 60000),
            "sample_ceiling": option("SCARLETT_XPERF_SAMPLES", 1, 1, 1000),
            "sustained_seconds": sustained, "real_accounts": 1,
            "network_profile": profile, "simulated_one_way_delay_ms": profiles[profile],
            "bandwidth_bytes_second_per_direction": bandwidth,
            "topology": "direct_tls" if profile == "direct" else "simulated_loopback_tcp_tls",
            "verifier_tls_server_name_override": bool(os.environ.get("SCARLETT_XPERF_VERIFIER_SERVER_NAME"))}
manifest["experiment_files_sha256"] = {
    name: hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
    for name in ("internal/worker/xperf_test.go", "scripts/xperf.sh", "scripts/xperf-report.py", "scripts/xperf-shaper.py", "scripts/xperf-shaper-test.py", "docs/x-performance-experiments.md")
}
with (output / "manifest.json").open("x") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PY

if ! go test -c -tags xperf -o "$SCARLETT_XPERF_OUTPUT/xperf.test" ./internal/worker >"$SCARLETT_XPERF_OUTPUT/build.log" 2>&1; then
  printf '%s\n' '{"build_complete":false,"experiment_started":false}'
  exit 1
fi
chmod 700 "$SCARLETT_XPERF_OUTPUT/xperf.test"
shaper_pid=""
cleanup_shaper() {
  if [[ -n "$shaper_pid" ]]; then
    kill -TERM "$shaper_pid" 2>/dev/null || true
    wait "$shaper_pid" 2>/dev/null || true
    shaper_pid=""
  fi
}
trap cleanup_shaper EXIT
if [[ "${SCARLETT_XPERF_NETWORK_PROFILE:-direct}" != "direct" ]]; then
  python3 scripts/xperf-shaper.py \
    --upstream "$SCARLETT_VERIFIER" \
    --profile "$SCARLETT_XPERF_NETWORK_PROFILE" \
    --bandwidth "${SCARLETT_XPERF_BANDWIDTH_BYTES_SECOND:-0}" \
    --max-connections "${SCARLETT_XPERF_CONCURRENCY:-1}" \
    --ready "$SCARLETT_XPERF_OUTPUT/shaper-ready.json" \
    --stats "$SCARLETT_XPERF_OUTPUT/shaper-stats.json" \
    >"$SCARLETT_XPERF_OUTPUT/shaper.log" 2>&1 &
  shaper_pid=$!
  # Bounded readiness wait; the relay has opened only a loopback listener.
  for i in $(seq 1 100); do
    [[ -f "$SCARLETT_XPERF_OUTPUT/shaper-ready.json" ]] && break
    kill -0 "$shaper_pid" 2>/dev/null || { printf '%s\n' 'shaper_start_failed' >&2; exit 1; }
    sleep 0.05
  done
  SCARLETT_VERIFIER=$(python3 - "$SCARLETT_XPERF_OUTPUT/shaper-ready.json" <<'PY_READY'
import json, sys
with open(sys.argv[1]) as stream:
    print(json.load(stream)["listen"])
PY_READY
)
  export SCARLETT_VERIFIER
fi
run_code=0
"$SCARLETT_XPERF_OUTPUT/xperf.test" -test.run '^TestXPerformance$' -test.count=1 -test.timeout=11h >"$SCARLETT_XPERF_OUTPUT/run.log" 2>&1 || run_code=$?
cleanup_shaper
printf '{"build_complete":true,"experiment_exit_code":%d}\n' "$run_code"
exit "$run_code"
