#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--offline" ]]; then
  unset SCARLETT_CODEXPERF
  exec go test -tags xperf -run '^TestCodexPerf' -count=1 ./internal/worker
fi

if [[ "${SCARLETT_CODEXPERF:-}" != "1" ]]; then
  printf '%s\n' 'Real provider calls require SCARLETT_CODEXPERF=1' >&2
  exit 2
fi
: "${SCARLETT_CODEXPERF_OUTPUT:?Set a new private output directory}"
mkdir -m 700 -- "$SCARLETT_CODEXPERF_OUTPUT"
export SCARLETT_CODEXPERF_OUTPUT
python3 - "$SCARLETT_CODEXPERF_OUTPUT" <<'PY'
import hashlib, json, os, pathlib, re, subprocess, sys
output = pathlib.Path(sys.argv[1])
revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
if not re.fullmatch(r"[0-9a-f]{40}", revision):
    raise SystemExit("invalid source revision")
diff = subprocess.check_output(["git", "diff", "--binary", "HEAD"])
digest = hashlib.sha256()
with pathlib.Path(os.environ["SCARLETT_PROVER"]).open("rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        digest.update(chunk)
manifest = {"schema": 1, "source_revision": revision,
            "tracked_source_diff_sha256": hashlib.sha256(diff).hexdigest(),
            "source_modified": bool(diff), "helper_sha256": digest.hexdigest(),
            "funding": "none", "concurrency": 1, "proof_mode": "proxy",
            "reasoning": "low", "service_tier_request": "omitted",
            "native_helper_owns_login_loading": True,
            "byte_counter_source": "supplier_operational_telemetry"}
manifest["experiment_files_sha256"] = {
    name: hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
    for name in ("internal/worker/codexperf_test.go", "internal/worker/xperf_test.go", "scripts/codexperf.sh", "scripts/codexperf-report.py", "docs/codex-performance-experiments.md")
}
with (output / "manifest.json").open("x") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
PY

if ! go test -c -tags xperf -o "$SCARLETT_CODEXPERF_OUTPUT/codexperf.test" ./internal/worker >"$SCARLETT_CODEXPERF_OUTPUT/build.log" 2>&1; then
  printf '%s\n' '{"build_complete":false,"experiment_started":false}'
  exit 1
fi
chmod 700 "$SCARLETT_CODEXPERF_OUTPUT/codexperf.test"
run_code=0
"$SCARLETT_CODEXPERF_OUTPUT/codexperf.test" -test.run '^TestCodexPerformance$' -test.count=1 -test.timeout=3h >"$SCARLETT_CODEXPERF_OUTPUT/run.log" 2>&1 || run_code=$?
printf '{"build_complete":true,"experiment_exit_code":%d}\n' "$run_code"
exit "$run_code"
