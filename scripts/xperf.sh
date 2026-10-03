#!/usr/bin/env bash
# Run from an isolated checkout. Provider secrets are private file inputs only.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--offline" ]]; then
  unset SCARLETT_XPERF
  exec go test -tags xperf -run '^TestXPerf' -count=1 ./internal/worker
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
manifest = {"schema": 1, "source_revision": revision,
            "tracked_source_diff_sha256": hashlib.sha256(diff).hexdigest(),
            "source_modified": bool(diff), "helper_sha256": digest.hexdigest(),
            "bootstrap": "unproven_once_outside_samples", "funding": "none",
            "production_policy": "unchanged", "concurrency": 1}
manifest["experiment_files_sha256"] = {
    name: hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
    for name in ("internal/worker/xperf_test.go", "scripts/xperf.sh", "scripts/xperf-report.py", "docs/x-performance-experiments.md")
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
run_code=0
"$SCARLETT_XPERF_OUTPUT/xperf.test" -test.run '^TestXPerformance$' -test.count=1 -test.timeout=11h >"$SCARLETT_XPERF_OUTPUT/run.log" 2>&1 || run_code=$?
printf '{"build_complete":true,"experiment_exit_code":%d}\n' "$run_code"
exit "$run_code"
