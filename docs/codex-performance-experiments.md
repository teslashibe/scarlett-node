# Codex proof performance experiments

This serial baseline runs one fixed synthetic request through the native helper's TLSNotary Proxy path. It asks `gpt-5.6-luna` to reply exactly `scarlettperf`, uses low reasoning and verbosity, and omits `service_tier` for normal requested speed. It enables no tools and creates no funding, payment, ARR or points evidence.

The first baseline used `gpt-6.1-sol` on the earlier local login. Following the user's account change, fresh experiments use the inexpensive Luna model exposed by the new login's CLI catalog. Every new metric and manifest records the model and synthetic cohort `account-2`; this label contains no real account identifier. Reports keep earlier unlabeled metrics in `gpt-6.1-sol` / `account-1`, and separate model/account cohorts. Compare shutdown settings on the same model and account. The [official model page](https://developers.openai.com/api/docs/models/gpt-5.6-luna) describes Luna as a model for cost-sensitive workloads; published API list prices do not establish charges for this Codex subscription path.

## Run a controlled sample

Use the existing local Codex login. The native helper loads it from `CODEX_HOME` or its usual default; the harness never opens, prints or copies `auth.json`. The verifier control key must be a local regular file with mode `0600`.

```sh
SCARLETT_CODEXPERF=1 \
SCARLETT_PROVER=/absolute/build/scarlett-prover \
SCARLETT_VERIFIER=127.0.0.1:17447 \
SCARLETT_VERIFIER_CA_FILE=/absolute/private/verifier-ca.pem \
SCARLETT_VERIFIER_API=http://127.0.0.1:17471 \
SCARLETT_VERIFIER_KEY_FILE=/absolute/private/verifier-control-key \
SCARLETT_CODEXPERF_OUTPUT=/absolute/private/runs/codex-proxy-001 \
SCARLETT_CODEXPERF_SAMPLES=1 \
scripts/codexperf.sh
```

Start with one compatibility sample. `SCARLETT_CODEXPERF_SAMPLES` permits 1–30 serial jobs. Set `SCARLETT_VERIFIER_SERVER_NAME` when the proof socket uses an IP or localhost tunnel with a certificate for another hostname. A custom CA is optional for a publicly trusted verifier certificate. The control API requires HTTPS or localhost HTTP reached through a protected tunnel; environment HTTP proxies and cross-origin redirects are disabled.

`SCARLETT_CODEXPERF_CLOSE_STRATEGY` selects `normal` by default or the experimental `tls_after_completed` shutdown. The candidate closes the underlying TLS write pipe after a fully parsed `response.completed`, bounds shutdown, and still awaits TLSNotary finalization, server EOF and independent receipt verification. It changes no provider request or verification requirement. Use a matching helper that reports its chosen `close_strategy`; a missing field is accepted only for older normal baseline helpers. The requested strategy is recorded in the manifest and every metrics row.

Each job receives a cryptographically random synthetic ID, a fresh single-use verifier token, an exact payload hash, a fence and a five-minute absolute expiry. The harness invokes `scarlett-prover prove` once, then independently retrieves its authenticated receipt. It counts a sample as verified only after acceptance, exact binding/model/output checks and validation of actual input/output token usage. Missing cached token details remain unknown; a reported cached subset must not exceed total input usage.

The runner stops at the first failure, including recognized provider quota, authentication and model errors. It never repeats unclear provider execution. Adversarial helper mode must be disabled. It does not contact X or modify production dispatch, earning, login state or databases.

## Measurements and privacy

Give each run a new output directory. The runner creates it with mode `0700`, refuses to overwrite existing files, and writes reports and diagnostics with mode `0600`. `manifest.json` records the source revision, tracked diff hash, experiment file hashes and helper binary SHA256. Commit and pin the code and record the verifier revision/topology before publishing reproducibility claims.

`metrics.jsonl` records only fixed experiment labels, correctness booleans and numeric measurements. It excludes provider account IDs, authentication, control tokens, prompt/output text and receipt identifiers. Exact output remains in the private verifier receipt and is represented by a match boolean. `run.log`, `build.log` and bounded helper stderr remain private; do not paste raw diagnostics into chats or reports.

End-to-end latency includes session registration, helper execution and receipt completion. `codex_ms` covers the helper's Codex WebSocket work, which includes handshake and response waiting; it is not a pure server inference time. Phase timings separate control connection, commitment, WebSocket handshake, response reading, TLS finish, proof and finalization. CPU and peak RSS are measured for the helper process; host/verifier resources require separate instrumentation.

Helper byte counters are supplier operational telemetry. Verifier counters count accepted TCP payload bytes and omit TCP/IP headers and retransmissions. Missing or saturated counters are incomplete telemetry. The current Codex receipt authenticates request binding, model/output and token usage; it does not authenticate byte counters. `transcript_counters_verified_by_receipt` stays false when receipt counters are unavailable. If a server supplies both transcript counters, they must match the helper before that field becomes true.

```sh
scripts/codexperf-report.py /absolute/private/runs/codex-proxy-001/metrics.jsonl
```

The summary reports actual successes/failures and nearest-rank p50/p95. It flags fewer than 30 successful samples. It groups normal and candidate shutdown measurements separately; older metrics without a strategy are normal baseline samples. A single-strategy report retains the flat summary format, while mixed inputs return a `groups` comparison. Achieved throughput covers the recorded serial window including gaps and failures; measure concurrent and sustained capacity separately. Normal requested speed does not establish a provider-reported service tier.

## Offline checks

```sh
scripts/codexperf.sh --offline
scripts/codexperf-report.py --self-test
```

These checks perform no provider calls. They cover the fixed payload, native TLS inputs, durable bindings, incomplete/rejected/wrong receipts, missing or invalid cached usage, finite error labels and report redaction. Live execution requires the `xperf` build tag and `SCARLETT_CODEXPERF=1`.
