# scarlett-node

Outbound-only, independently built supplier client. This is an early runnable **protocol proposal**, not a deployable marketplace node until the coordinator implements `api/node-v1.openapi.yaml`. No private app imports or hosted provider credentials are needed. Provider subscription terms and permission to relay paid inference are separate from this implementation and must be checked before serving real jobs.

Build: `go build -o scarlett-node .`; test: `go test ./...`.

Configure `SCARLETT_COORDINATOR=https://...` (HTTPS origin), `SCARLETT_PROFILE=...`.

Nodes advertise the reviewed Codex base catalog from `internal/config/codex-model-catalog.json`: `gpt-6.1-sol`, `gpt-6-astra`, `gpt-6-sol`, `gpt-6-luna`, `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-5.6-luna` and `gpt-5.5`. This is local compatibility metadata; subscription access remains unverified until the provider accepts a job. Proven paid execution accepts exact base IDs with low reasoning and the default service tier. The manifest maps other Codex efforts for reference; it does not enable paid effort variants or priority service. Legacy 5.6 gateway aliases remain limited to their existing allowlist. GPT-5.5 sign-in execution and advertising stop at 2026-10-14 00:00 UTC; historical receipts remain verifiable. Claude execution is unavailable in this binary.

`SCARLETT_EXECUTOR` is `gateway` (default), `codex` or `codex-tlsn`. Optional `SCARLETT_GATEWAY_KEY` stays on the node for the gateway only. `SCARLETT_BID` is the standing assignment bid (default 100; lower wins). `SCARLETT_STATE_DIR` defaults to `~/.local/state/scarlett-node`, `SCARLETT_INFERENCE_TIMEOUT_SECONDS` defaults to 45 (max 300), `SCARLETT_MAX_INPUT_BYTES` defaults to 32768 (max 65536), `SCARLETT_MAX_OUTPUT_TOKENS` defaults to 2048 (max 8192).

For a private coordinator CA, set `SCARLETT_COORDINATOR_CA_FILE` to an absolute path containing a PEM certificate bundle. This adds roots only to the coordinator transport; HTTPS, certificate verification and hostname checks remain enabled. It does not change provider trust or permit HTTP. Leave it unset for ordinary public certificates.

**Gateway mode** (`SCARLETT_GATEWAY=http://127.0.0.1:PORT`): a locally managed OpenAI-compatible gateway with `/v1/chat/completions`, non-streaming chat, `max_tokens`, exact resolved `model`, and `usage.prompt_tokens`/`usage.completion_tokens`. Paid mode also requires `usage_source: "upstream"`; missing or other sources fail with `usage_untrusted`. Results forward `usage_source` and `execution_mode`. Local fixtures always send `unpaid_local_demo`. The current app may record that as simulated Scarlett SCT and must not treat it as an on-chain mint. This is gateway-asserted provenance, not independently authenticated provider evidence. `duration_ms` is diagnostic gateway request time, never reward latency. `open-agent-api` advertises `/health/ready`, `/v1/models`, and chat completions. **Its current chat request struct does not define `max_tokens`, so the field sent by this node is ignored and is NOT an upstream cost ceiling.** The node checks reported completion tokens after inference and rejects over-budget results, but cannot bound billed tokens ahead of time with this gateway. No gateway URL comes from jobs.

**Embedded Codex mode** (`SCARLETT_EXECUTOR=codex`): the node runs Codex in-process through `open-agent-api`'s `pkg/codex` (pinned in `go.mod`) with its own `codex login` in `SCARLETT_CODEX_HOME` (default `~/.codex`; `auth.json` must be writable for token refresh). No gateway process, URL or key. `SCARLETT_CODEX_PROFILE` and `SCARLETT_CODEX_SCAFFOLD` are absolute paths to that module's `codex_profile.json` and `codex_scaffold.json`; the Docker image ships both under `/usr/local/share/scarlett-node/` and sets them. Results pass the same model, usage and deadline checks as gateway mode and report `usage_source: "upstream"`. Like the gateway it has no pre-execution token ceiling, and usage is Codex-reported, not proven.

**Codex TLSNotary mode** (`SCARLETT_EXECUTOR=codex-tlsn`, `SCARLETT_VERIFIER=host:port`, optional `SCARLETT_PROVER=scarlett-prover`): the node runs `scarlett-prover prove` against the assigned verifier. The lease carries the exact Codex `response.create` payload and a single-use verifier token. The node hides only the Codex login token, proves the transcript came from `chatgpt.com`, and posts `/proven`. It does not submit the answer. The coordinator reads model, output, and usage from the verifier. Build the helper with Rust 1.95: `cargo build --release --manifest-path prover/Cargo.toml`. The helper reads `~/.codex/auth.json` (or `CODEX_HOME`) and does not refresh it. While that access token cannot outlast a maximum-lifetime offer plus 30 seconds, or its expiry is unknown, heartbeats report `exhausted` (keeping their positive legacy capacity) so the coordinator stops dispatching offers the node would refuse locally. This proves the TLS session and the revealed request/response bytes, not that the supplier's machine is honest or that a subscription is unused. It is not on-chain settlement.

Verified Codex receipts preserve `usage.input_tokens_details.cached_tokens` from the fully revealed provider response as optional `cached_input_tokens`. An explicit zero stays zero; missing or null details stay unknown. Malformed values and cached counts greater than total input are rejected. Durable restart preserves the distinction, including older receipts without the field. The coordinator must use this verified subset when applying cached-input weights; node or gateway reports cannot fill missing proof evidence.

**X reads over TLSNotary** (`worker.XTransport` and typed services mode): an `http.RoundTripper` that runs x-go's read methods unchanged, with each X GraphQL GET proven by `scarlett-prover prove-x`. It uses MPC mode, so the node's own connection and IP reach `x.com` while the verifier jointly holds the TLS keys. Only the values of the `auth_token`, `ct0` and `kdt` cookies (at most 64, 160 and 64 bytes) and of `X-Csrf-Token` (at most 160) are hidden; cookie names, other cookies, the rest of the request and the whole response are revealed. Any other request to `x.com/i/api/` (POSTs, REST calls including DMs, plain HTTP) is refused; requests elsewhere (x-go's page and script fetches) go through `Base` unproven. The verifier accepts `{"type":"x.read","exchanges":[...],"max_attempts":N}` sessions. Each exchange pins one read the job pays for, exactly: `operation` (one of 14 allowlisted reads), `query_id`, `variables`, `features` and, only if given, `field_toggles`. `cursor_from: k` asks for the page after exchange k, which must be the same operation with the same variables: the request's variables must equal the exchange's own plus a `cursor` that is a `Bottom` timeline cursor in an entry of a timeline instruction in the response the verifier itself recorded for k. A proof counts only if its request exactly matches a pending exchange. The query must be form-encoded as Go writes it, with `variables`, `features` and `fieldToggles` each at most once, and its JSON must have no duplicate keys or non-integer numbers, so the verifier and X can't read it differently. The first matching HTTP 200 with a non-empty `data` object fulfils an exchange; any other matching response (a rate limit, or a 200 carrying only `errors`) is recorded and the exchange stays pending for a retry. Header lines must be strict `name: value` lines of printable ASCII, with no folding, bare CR or LF, framing headers (`Content-Length`, `Transfer-Encoding`, …) or method/URL override headers. Anything else is recorded as a rejection and isn't paid. The status (`status: "x_read"`) lists `pending` exchange indexes, `complete`, `remaining_attempts` (default twice the exchanges, at most 200; each proof spends one), the recorded `exchanges` (each with its `index` and `fulfilled`) and `rejections`. The token dies when every exchange is fulfilled or the attempts run out. The verifier also rejects writes, extra requests, other hosts, hidden response bytes or anything hidden beyond those secret values. This proves the response is exactly what X returned to exactly the request the job pinned. It doesn't prove X returned everything that exists: results are what X showed the node's account (its mutes, blocks and personalization) at that moment. Request headers other than `Host` aren't pinned, and TLSNotary can't inspect hidden bytes: a node could put CR/LF and a short extra header inside a hidden secret value (up to its length limit). That can't change the proven request line or query. It can change headers such as the account or client language, which, like the account itself, the job doesn't pin. Responses must be chunked or carry a Content-Length, because the prover ends the X stream itself once the response is complete; X does not reliably close the connection, and tlsn only finalizes after the server side ends. Measured on one Mac with a local verifier: 0.6–2.5 s per proof, and a fixed ~60 MB upload and ~4 MB download between node and verifier per request, whatever the response size (about 24 s of upload at 20 Mbit/s). Responses are capped at 256 KiB as received; the largest seen was a 102 KB gzipped `HomeLatestTimeline` page (901 KB decoded). The prover pins [teslashibe/tlsn](https://github.com/teslashibe/tlsn/tree/scarlett-alpha.15), which is v0.1.0-alpha.15 with the session's mux stream limit raised from 512 to 4096; stock alpha.15 intermittently fails MPC proofs with `context mux error`. The live check is `go test -tags xlive -run TestXLive ./internal/worker` (it uses the pinned x-go runtime snapshot and needs the environment variables listed in `internal/worker/xlive_test.go`). It uses a real X session and only calls read methods. It first records the exact requests x-go builds for every x-go v1.13.0 read method except the DM REST reads, without sending them, and pins them as the job: operation, query ID, variables and features. Page 2 of each paginated method (page 3 for search) is pinned by `cursor_from`. It then runs them and requires every exchange to be fulfilled with a body identical to what x-go parsed, covering all 14 operations. x-go's `GetList` sends `listId` to `ListBySlug`, which X rejects with HTTP 422; that response is still proven, but it never fulfils its exchange. A second job checks that a swapped search term, page 2 before page 1, and page 2 with another query's cursor are all proven by X but rejected by the verifier, and that the token dies once the job is complete.

**X reads over keyed relay** (`proof_mode: "relay"`, `proof_policy: "x-relay-v1"`): the same pinned reads, proven by `scarlett-prover relay-x` instead. The node still opens the TCP connection to `x.com`, so X sees the node's address, but the verifier is the TLS client: its TLS 1.3 handshake and records travel through the node, and the node never holds a session key. The node sends the verifier the request with the same four values hidden as zeros. The verifier checks that request against the job before using any key for it, seals it, and the node adds its hidden values by finishing the record's AES-GCM tag with the verifier over oblivious transfers, one per hidden bit. The node can complete only that record and can change only those bits; the verifier never sees them. The verifier decrypts X's response itself and records it through the same policy check as an MPC proof, so receipts and settlement are unchanged. One session proves one read and costs 68–89 KB of node upload against 60–62 MB for MPC-TLS, measured on the four catalog reads with a real account on Oct 3, 2026. The trade is that a relay node must trust its verifier with its X session. Under MPC-TLS the verifier can neither read the hidden values nor affect what is sent. Under relay only the verifier holds the client key, so it decides what is sealed: a dishonest or compromised verifier can make the node send one request of its own choosing per session with the node's real cookie and CSRF values, read the answer, and learn chosen hidden bits from whether X accepts a record it distorted; with the node's traffic to X it could read the values outright. The node cannot prevent this. It detects it afterwards: the verifier must open the request record once the response is complete, and the helper fails with `verifier misused this node's X session` if what it was made to send was not its own request, or if the verifier ended the session without opening the record at all. When that happens the node halts keyed relay for itself: it logs one `ALERT keyed relay halted` line, stops listing `relay` in its heartbeat, declines relay offers before funded acceptance, and keeps serving MPC-TLS. The halt is recorded in the state directory (`relay-halt`) so a restart does not re-arm relay; `scarlett-node status` reports `relay_halted` and `scarlett-node relay-resume` clears it once the operator has checked the verifier; the account that carried the session is not penalised, since the verifier misbehaved, not the account. Relay jobs therefore need both sides to choose them: the coordinator names the mode and its exact policy in the job, and the node serves it unless its operator has opted out with `SCARLETT_X_RELAY=0` (relay is on by default from this release because it cuts a node's upload per read by roughly three orders of magnitude, and the node already trusts the operator-run verifier with its session). A relay job may pin only the four reads in `api/x-request-catalog.json` (`SearchTimeline`, `UserByScreenName`, `TweetResultByRestId`, `TweetDetail`); the verifier refuses a relay job for any other read, including the account's own feed and details, so its authorization never covers them. A session authorizes one request record; any failure after that ends it. TLS 1.3 with AES-128-GCM is required and nothing falls back to another version or cipher. Because the verifier holds the session keys, the node forwards toward X only what parses as a TLS 1.3 client handshake naming `x.com` (hello, one change-cipher-spec, one Finished-sized record) and nothing after its own request record, so a verifier cannot send requests of its own from the node's address; what remains is that it chooses the handshake's contents. Rollout: an opted-in node lists `proof_modes: ["mpc","relay"]` in its `x_read` heartbeat entry, a node declines a relay offer it does not serve before funded acceptance when the offer carries the payload, and coordinators should omit `proof_mode` on MPC jobs because nodes and verifiers older than this field reject payloads that carry it. For the same reason a durable verifier cannot be rolled back to an older binary while it still holds a relay receipt (receipts are kept for a day past expiry).

Run `./scarlett-node pair` and enter a one-time coordinator code on stdin. Pairing creates a private `identity.json` (0600) under a 0700 state directory; run `./scarlett-node run` for outbound heartbeat polling and serial inference. Each heartbeat carries `wait_seconds: 20`: the coordinator records the report, then holds the request open while it has nothing to offer and answers the moment a job for this node is funded, or with `lease: null` at the deadline. The request runs under its own deadline of the hold plus ten seconds, other calls keep the ten-second client timeout, stopping the node aborts a held heartbeat at once, a drain, a service leaving ready or any other change to what the heartbeat advertised ends the hold within about a second and is reported by an immediate new heartbeat, and the loop adds no idle delay of its own; a failed heartbeat earns a five-second pause. On a terminal, the prompt hides the code and Enter submits it. A protected pipe or file can also supply one line; no EOF is needed after that line. Keep codes out of command arguments, environment variables and shell history. Pairing writes and syncs a private temporary file, then installs the complete identity without replacing an existing file. The coordinator is responsible for generating and expiring codes. An ambiguous pairing response is not retried automatically; check the coordinator before obtaining a replacement code. The Docker sim can skip pairing with `SCARLETT_NODE_ID` and `SCARLETT_CREDENTIAL` matching a seeded coordinator row. Configure externally managed secrets without logging them. No inbound port or wallet key is used. An optional heartbeat challenge is echoed to `/api/node/v1/challenge/echo` before any inference. Echoes use the same bearer credential, carry no duration, and are not retried after failure. Authenticated HTTPS and loopback HTTP may echo. The unpaid Docker fixture sets an explicit flag so it can echo `http://host.docker.internal`. The app issues the nonce, enforces expiry and single use, and measures RTT itself. A bonus requires a fresh sample from a node-scoped credential. RTT does not prove co-location.

For an **unpaid Docker fixture only**, `../scarlett-app/compose.yaml` builds this node twice with `SCARLETT_LOCAL_FIXTURE=1` and `local-fixture` profile. It polls the local app over Docker Desktop host loopback with a per-node seeded credential and standing bid. Each model calls its own isolated gateway container, which read-only mounts just the existing matching account; account credentials are never mounted into the nodes. This fixture is not provider authorization and cannot cap upstream inference usage because the Codex gateway ignores `max_tokens`.

**Independent community services** (`SCARLETT_EXECUTOR=services`): set `SCARLETT_SERVICES=codex`, `x_read` or `codex,x_read`. The node uses proven execution only in this mode. Set `SCARLETT_VERIFIER=host:port` and the local prover binary as above. Codex uses `SCARLETT_CODEX_HOME`; X uses an absolute `SCARLETT_X_SESSION` path to a private 0600 x-go session JSON file. The X session must not contain a proxy override, which would bypass its proof transport. Provider credentials remain on the supplier machine and are sent to the prover through stdin, never as command arguments or coordinator fields. `SCARLETT_CODEX_CONCURRENCY` and `SCARLETT_X_CONCURRENCY` are independent limits from 1 to 32, default 1 each. The legacy shared-concurrency setting does not replace these limits. `SCARLETT_X_REFRESH_SECONDS` (default 1800, 60 to 86400) is how often each warm X client's transaction-ID material is refreshed in the background.

Services-mode heartbeats report both services independently. A usable credential file initially means `configured`, rather than authenticated readiness. Local proof submission can change it to node-reported `ready`; the coordinator must still verify the proof independently. X quota/authentication errors suppress X without disabling Codex, and vice versa. Capacity includes separate in-flight counts. Quota/transport cooldowns last 30 seconds; an authentication failure waits for a changed local credential file. No numeric provider quota is guessed. Unknown or unavailable services receive a nonrewardable failure, without a provider call.

Typed Codex leases bind the base model, prompt and canonical single-turn request. Tools, instruction overrides, reasoning/service-tier changes and retained responses are rejected. Typed X leases bind a semantic public read and the verifier's exact `x.read` policy: search (Latest, 1–20 items, 1–3 exact pages), profile by handle, post by ID, or one thread response. The worker uses pinned x-go methods and refuses a different operation, query ID, variables, features, field toggles, destination or cursor chain before invoking the prover. Each requested exchange allows one attempt; provider failures are not automatically retried. A valid empty first search page can fulfil one exchange, but a missing next-page cursor fails a request for later pages. The thread scope is one response, not a guarantee of an entire conversation.

X session authentication and transaction-header bootstrap use unproven local requests, separate from paid exchanges, and happen once per account rather than once per job: the node keeps one warm x-go client per X account (`worker.XClients`, keyed by the session file), built at start for every configured account (one at a time, one log line each, a failure leaves it to the job path) or on first use. Building a client is x-go's two session-validation reads (`Viewer`, `UserByRestId`) and its two bootstrap fetches (the `x.com` page and the `ondemand.s` script the `X-Client-Transaction-Id` header is derived from), paced by its one-second request gap; a job on a warm account does only its proven reads. The client's transport is a switchboard that holds no job state: a job's pinned exchanges, verifier token and exchange counter travel in the request context, so two concurrent jobs on one account each see only their own binding, and an X API request whose context carries no job is refused. During a construction, and only then, exactly those four unproven requests pass (each validation read once); afterwards nothing unproven passes. The client is replaced when the session file's content changes (checked before each job), when a proven read is refused by X as unauthenticated (dropped at once, rebuilt in the background with a real validation; a transport failure during a build is `x_request_failed`, not an authentication failure), and every `SCARLETT_X_REFRESH_SECONDS` (default 1800, 60–86400) by a background refresh that rebuilds only the transaction-ID material: the new client is built while the old one keeps serving, x-go's validation reads are answered from the answers X gave the account's last validated build instead of going to X (every successful proven read has already shown the session valid), and the swap is an atomic pointer change, so jobs in flight keep the client they hold; a refresh that cannot fetch the transaction material keeps the current client. A lease pinning a query ID the warm client was not built with is refused by the switchboard before any proof is spent, and the job rebuilds once with that override (bootstrap fetches only) and tries again; the only waits a job can meet are that one and a dropped client being rebuilt, bounded by the lease deadline. After bootstrap, every requested API read goes through the proof transport. Bootstrap data, retry calls and supplier-parsed output do not authorize points. The node posts only `/proven`; the coordinator owns verifier response copies, complete fulfilment, payment reconciliation and eligibility. The node cannot prove X returned all existing data or remove account personalization. These bounded launch reads use four operations, while the lower-level transport/verifier still support their wider read allowlist.

The current production access foundation has not yet added services-mode heartbeats, typed dispatch or authoritative X result delivery. Keep this mode disabled there until its Scarlett companion lands. Local tests use synthetic transports and no real Codex/X subscription, so they do not measure remote proof performance or constitute provider authorization.

**Durable attempts (Linux and macOS)**: `run` holds an exclusive OS lock on a private `attempts/` directory inside `SCARLETT_STATE_DIR`. It commits the lease fingerprint before any provider call, then atomically persists the exact result/proven/failure report before submission. A second process, redelivered attempt or changed lease cannot execute the same journaled work. If the process dies during a provider call, startup reconciles with the coordinator; it never reruns that call. A still-live uncertain attempt is reported as `execution_uncertain`, which must not automatically requeue paid work.

**Verifier control TLS**: both Codex and X proof helpers encrypt the token and TLSNotary control traffic and verify the verifier certificate and hostname. The configured verifier remains `host:port`; it cannot come from a lease. The helper uses the pinned Mozilla trust roots. For a private test CA, set an absolute `SCARLETT_VERIFIER_CA_FILE` on the node. That CA applies only to this connection and never changes provider proof verification. There is no fallback to plaintext on a TLS failure.

On the verifier host, set absolute `SCARLETT_VERIFIER_TLS_CERT` and `SCARLETT_VERIFIER_TLS_KEY` PEM paths. Keep the key private (0600, owned by the process user); all TLS files must be regular, non-symlinked and at most 1 MiB. The HTTP registration/status API must bind loopback in every mode. Use a secure host-local tunnel when the coordinator runs elsewhere. Proof sockets have a ten-second handshake/token deadline. `SCARLETT_VERIFIER_CONCURRENCY` sets simultaneous connections (default 64, range 1 to 256). Accepted proof results still require separate funding and settlement reconciliation.

For an unpaid loopback test only, the verifier can set `SCARLETT_VERIFIER_PLAINTEXT_FIXTURE=1` and bind a literal loopback address with no TLS files. Direct helper test JSON can set `plaintext_fixture: true` only for a literal loopback address or the pinned `verifier:7047` fixture. The node accepts that environment setting only with its existing explicit unpaid Docker fixture configuration. Community services always use TLS. Docker verifier hosts therefore need a certificate for `verifier` and a test CA; this change does not expose a plaintext listener on a public interface.

**Durable verifier receipts**: set an absolute private `SCARLETT_VERIFIER_STATE_DIR` on the coordinator's verifier host. The verifier API must bind loopback in this mode. Registration requires a fence and `expires_at_ms` (within ten minutes), and retrying the exact job/attempt/fence/payload/expiry returns the original unspent token. Token spends are synced before proof work; results are synced before status can report them. A second verifier cannot open the same store. Disk failures make the service unavailable rather than acknowledge an uncommitted result.

An X job containing identical requested reads is rejected before a session is created. A fulfilled X request can count only once per session. Matching includes the proven operation, query ID, variables, features and field toggles. Repeated pagination cursors cannot fulfil another page, even if its response changes. Distinct requests may return identical response bodies. The same check applies when restoring private receipts; a stored duplicate cannot become completed work.

Restart preserves accepted receipts. A proof interrupted in flight becomes `execution_uncertain`, loses its token and cannot be retried as new provider work. Status includes the job/attempt, fence, exact registered request hash, absolute expiry and a `durable` flag; it never includes the token. The coordinator must check those bindings, complete X fulfilment, quoted bounds and separate funding/settlement evidence. A stored proof is not a paid receipt or a points award. Durable X sessions allow 1–3 pinned exchanges and one attempt per exchange; legacy ephemeral tests retain the wider read policy.

The private store has validated limits: `SCARLETT_VERIFIER_MAX_RECORDS` (default 1024, range 1 to 1,000,000), `SCARLETT_VERIFIER_MAX_RECORD_BYTES` (default 67108864, range 1048576 to 67108864), and `SCARLETT_VERIFIER_MAX_TOTAL_BYTES` (default 268435456, at least the per-record limit and at most 1099511627776). Values are decimal integers. Choose the per-record bound to hold the largest allowed request and verified response together; lowering it below an existing receipt prevents startup. Pending proofs reserve their full per-record budget before registration returns a token. Completed proofs release that reservation to their actual encoded size. Expired unspent tokens are revoked during maintenance and release their reservation while the receipt remains available for reconciliation. In-flight proofs keep their reservation through completion. The defaults therefore allow at most four pending durable sessions, fewer when retained receipts use space; the connection limit is a separate ceiling. Raising the record count alone does not raise this storage capacity.

Successful `prove` and `prove-x` summaries report provider transcript `sent_bytes` and `received_bytes`, plus `verifier_sent_bytes` and `verifier_received_bytes` measured below the verifier connection's outer TLS layer. `verifier_transport_layer` is `tcp_payload`: the counters include TLS handshake and record bytes accepted by TCP, excluding IP/TCP headers and retransmissions. Counts saturate at 1 TiB per direction and then set `verifier_bytes_saturated: true`. Use these supplier diagnostics for local bandwidth measurements; billing and points use verified provider evidence.

After funded acceptance, the node retains these verifier counters in optional private journal `proof_traffic` metadata bound to the attempt's lease fingerprint. It reserves a numbered sample before each helper starts, up to one Codex call or the signed X plan's one to three calls. A failed reservation prevents execution. Missing, malformed, failed or saturated summaries remain incomplete; numeric zero is recorded only when explicitly reported. A crash can leave a started sample without counters. Completion and worker-finished markers survive acknowledgement and restart under the existing journal retention rules, while recovery never starts another helper. These observations stay local and do not change the `node-v1` report or its hash. They measure verifier TCP payload bytes, excluding provider/bootstrap connections, coordinator requests and total network-interface overhead.

Authenticated `GET /v1/capacity` on the existing loopback verifier API reports `healthy`, `durable`, configured connection limits, receipt count and storage limits/actual/reserved bytes. `active_connections`, `in_flight_proofs` and `pending_sessions` report control connections, ongoing proofs and unexpired issued tokens. Pause new coordinator dispatch, then wait for all three to reach zero before a verifier restart; an issued token can still start a proof after dispatch is paused. `storage.can_register` indicates room for another worst-case receipt. A full store remains healthy for existing status/recovery reads; storage failures return HTTP 503 with `healthy: false`. The route contains no receipt content, tokens or credentials and requires the verifier key.

Resolved payloads and receipts are removed 24 hours after session expiry by a minute maintenance pass and on restart. Unacknowledged coordinator results must be reconciled within that window. Interrupted proof receipts become `execution_uncertain`, lose their tokens, and retain replay metadata beyond that window. They need an explicit reviewed reconciliation process before removal; capacity pressure never purges them. Corrupt, public, symlinked or oversized files fail startup; a full store refuses more work. Provider credential values never enter the store, but buyer requests and verified response copies do, so preserve its private permissions. Without a state directory the legacy verifier stays ephemeral and reports `durable: false`. Proof connections use verified TLS as described below.

Recovery uses the authenticated `GET /api/node/v1/jobs/{job_id}/attempt` contract. Identity must match the exact job/attempt/fence and the response must explicitly promise `replay_safe: true`. Only then may a ready report be retried with its original body. Accepted receipts must match the recorded submission hash; pending proofs stay pending without another provider call. Unsupported endpoints, lost responses and mismatched receipts keep the record unresolved. A missing response is not a payment, proof or points receipt. The production coordinator companion must implement this contract before recovery works there.

The journal stores no provider credentials, verifier tokens, prompts or complete leases. Gateway result reports can contain private output; files are 0600 in a 0700 directory. Accepted content is removed immediately; unresolved report content expires 24 hours after its lease deadline while uncertainty metadata remains. Terminal metadata is removed after both deadline and acknowledgement are 24 hours old. The node journal uses `SCARLETT_JOURNAL_MAX_RECORDS` (default 1024, range 1 to 1,000,000), `SCARLETT_JOURNAL_MAX_RECORD_BYTES` (default 192000, range 192000 to 1048576), and `SCARLETT_JOURNAL_MAX_TOTAL_BYTES` (default 268435456, at least the per-record limit and at most 17179869184). Pending attempts reserve their full encoded-record budget before funded acceptance; terminal attempts use their actual bytes. A full journal advertises exhausted service health before requesting new offers. Local status includes `journal_capacity` with actual/reserved bytes and available record slots. Existing pending attempts still reconcile without repeating provider work. A full, corrupt or unwritable journal refuses new work. Abandoned atomic-write files are removed under the exclusive lock on startup. State-dir environment changes must preserve the journal for restart recovery; deleting it forfeits that protection.

## Multiple local Codex and X accounts

Services mode supports up to eight accounts for each enabled provider. Set
`SCARLETT_EXECUTOR=services` and select `SCARLETT_SERVICES=codex,x_read` as usual.
`SCARLETT_CODEX_CONCURRENCY` and `SCARLETT_X_CONCURRENCY` remain the total
per-service limits, each at most 32; each account has its own limit underneath
that ceiling. A private account file controls which accounts receive new jobs.
Account configuration establishes compatibility, not provider authorization or
model entitlement.

For Codex, sign into each account with the Codex CLI using a separate
`CODEX_HOME`, then register that absolute home directory. For X, register an
absolute path to a private session file containing the existing session schema.
Credentials must not appear in command arguments. These examples contain only
local names and placeholder paths:

```sh
scarlett-node accounts add codex work /absolute/private/codex-home 1
scarlett-node accounts add x_read research /absolute/private/x-session.json 1
scarlett-node accounts list
scarlett-node status
scarlett-node accounts remove x_read research
```

Alternatively, `scarlett-node accounts connect SERVICE ID CONCURRENCY` imports
credential JSON from protected stdin into a private node-owned account directory.
Terminal input is hidden. The command refuses to overwrite existing credentials;
Codex owns its authentication schema and the proof helper validates it when used.
The helper does not refresh Codex tokens. The node renews them itself through
`open-agent-api`'s authentication-only `pkg/codex` wrapper, with no inference and
no credential returned, but only for registered Codex homes directly under
`SCARLETT_CODEX_MANAGED_ROOT`, a private user-owned root. The variable is empty by
default and requires the services executor. External, legacy and global profiles
(including `~/.codex`) stay manual. The wrapper serializes writers only within one
process, so nothing else may refresh a managed profile while the node runs. The
desktop app sets the root to its own login profiles and never runs the node and
its local model API at the same time.

Renewal reserves an idle profile only when its token expires within 30 minutes,
offers no new slots for that profile while renewing, and preserves selected work,
quota cooldowns and provider-auth failures. Idleness is per directory: a profile
is not renewed while any account ID on it, including a draining one, has selected
work. Each operation is bounded to 15 seconds (an exchange already sent finishes
under the wrapper's own bound), and a failure is retried after five minutes,
which leaves several retries before funded admission drops the profile. Removal
and profile-path changes cancel and join the operation; nothing else interrupts
it. Attempts left pending by an earlier process block their pinned account, and
block the whole pool if that account is no longer registered or the binding is
missing or ambiguous, until reconciliation (every 30 seconds while running)
resolves them. Local expiry, including the funded-admission guard refusing a
selected profile, is recorded with an optional private `local_auth_invalid` health
marker; older readers ignore it and conservatively quarantine. Provider auth
failures, and historical ones without that marker, require a genuine credential
change before automatic recovery. The final funded-admission expiry guard remains
in place.

Account IDs use 1–32 lowercase letters,
digits, underscores or hyphens; `legacy` is reserved. Two names cannot refer to
the same credential path or inode.

For an explicitly selected local X browser profile, list metadata with
`scarlett-node accounts browser-profiles`, then run
`scarlett-node accounts import-x PROFILE_ID ACCOUNT_ID CONCURRENCY`. Close the
selected browser first. The helper imports only its two X session cookies into
private account storage, refuses overwrite or ambiguous sessions, and returns
no credentials. Protected or unsupported stores can use cookie paste. See the
[desktop browser support matrix](../desktop/README.md#import-an-x-browser-account).

When X expires or revokes a connected session, the account reports
`auth_required`. Replace its session under the same ID with
`scarlett-node accounts reimport-x PROFILE_ID ACCOUNT_ID` or
`scarlett-node accounts reconnect x_read ACCOUNT_ID` (cookie JSON on protected
stdin). Only an existing account whose session the node saved through `connect`
or `import-x` can be re-imported; its ID, path and concurrency stay the same.
The new session is validated in a private staging file first, so a rejected
re-import leaves the previous one in place. A running node sees the changed file
on its next scheduling check and reports the account `configured` again;
attempts already in flight keep the session they started with.

The CLI writes `SCARLETT_STATE_DIR/accounts.json`, or the absolute private path
in `SCARLETT_ACCOUNTS_FILE`. Its bounded schema is:

```json
{"version":1,"accounts":[
  {"id":"work","service":"codex","path":"/absolute/private/codex-home","concurrency":1},
  {"id":"research","service":"x_read","path":"/absolute/private/x-session.json","concurrency":1}
]}
```

Keep the file and its directory private (0600 and 0700). The node reloads it
before scheduling. A file with an empty `accounts` array disables admission for both services.
When no default account file has ever existed, the existing
`SCARLETT_CODEX_HOME` and `SCARLETT_X_SESSION` single-account configuration still
works. An explicitly configured missing file, an invalid replacement, or a file
removed after use blocks new work instead of falling back to legacy credentials.

Selection rotates fairly among eligible accounts for fresh jobs. The local
account ID and provider are journaled before funded acceptance. That job retains
its selected configuration; all X pages use one loaded session. A failed or
uncertain attempt never moves to another account or repeats provider work.
Removing an account stops new admission and lets selected work drain; removal
retains its credential files. Wait until its local `in_flight` count reaches zero
before disposing of credentials. A changed credential location also waits for
that account's selected work to drain.

Authentication failures and quota cooldowns apply to the selected account.
Private `account-health.json` preserves them across restart. The private
`accounts-mode` marker keeps managed admission from falling back to legacy
credentials after an account file disappears across restart. X's typed reset
wait is honored, with a minimum 15-minute cooldown; Codex rate-limit errors use
15 minutes when no reset time is available. Reset times outside the bounded
30-day window require operator attention. Changing a credential file does not
erase an outstanding quota cooldown. Corrupt or unwritable health state stops
new admission. Preserve the state directory when upgrading or restarting.

`status` includes safe local account names, service, health, configured capacity,
in-flight count, a finite error code and cooldown time. `accounts list` lists
only local names, provider and concurrency. Credential paths, account names and
cooldown details are absent from coordinator heartbeats; those report aggregate
service health and capacity within the existing ceilings. The top-level typed
heartbeat capacity equals the service-capacity sum, including zero when all
accounts are blocked. These observations
provide no independently verified entitlement, billing or points evidence.

**Local lifecycle**: `scarlett-node status` prints a private local JSON observation: runtime state, last acknowledged heartbeat, independent service reports, in-flight work and unresolved journal records. It contains no credentials, prompts, results or verifier tokens. A snapshot older than 45 seconds is offline (a held heartbeat can keep one for 30); it does not prove current provider access or remote acceptance. These commands need only `SCARLETT_STATE_DIR`, which must match the running node.

`scarlett-node drain` persists a drain request across process restarts. The next poll advertises exhausted capacity, and work delivered after the node observes the request is rejected without calling its provider. Already accepted jobs continue. `scarlett-node resume` removes the request; the next poll can accept work again if its service is available. The coordinator must honor exhausted nodes when dispatching. Drain is a local scheduling control, not remote unpairing or revocation.

SIGTERM and Ctrl-C stop polling and give accepted workers up to two minutes to finish and journal their receipts, within their existing lease deadlines. At that limit their contexts are cancelled. Started or unacknowledged work stays journaled for reconciliation and is never automatically rerun. A second process still cannot acquire the same journal. Use drain before stopping or upgrading if you want the coordinator to observe exhausted capacity first.

**Native installation**: `scripts/package.sh VERSION` builds the node and the pinned Rust proof helper on a supported native platform, with file and archive checksums. The bundle's installer keeps versioned files, switches the active version atomically and preserves the node's identity/journal. It checks the platform and refuses corruption, different contents for an existing version or an unrelated executable. The helper resolves beside the node when available; a missing helper reports unreachable service capacity and cannot start provider work. See [installation instructions](../packaging/INSTALL.md) for configuration, the optional Linux user-service template and upgrade/rollback steps. CI produces review artifacts; this change publishes no release. The Docker image also includes the helper and its matching runtime.

Current gaps against [issue #1](https://github.com/teslashibe/scarlett-node/issues/1): committed job identities are not cryptographically verified against the Solana program. Dynamic capacity and independent tokenization remain incomplete. The node emits no rewardable report for missing usage, model mismatch, invalid finish reason or expired lease. Usage constraints are checked after inference, rather than imposing an upstream spending ceiling. TLSNotary still needs an authorized provider login and coordinator-run verifier. The coordinator has not enabled paid dispatch or the reconciliation contract; typed services await the production coordinator companion. The unpaid Docker fixture remains separate from the points-only community product.

Builds use the pinned private x-go runtime snapshot in `third_party/x-go`, with source hashes recorded in `UPSTREAM.json`. Hosted CI and Docker builds need no GitHub credential for it. The command and MCP adapters are outside this snapshot. The gateway remains the public pinned module in go.mod.

## Prototype funding evidence

`internal/funding` checks the v2 test-USDC protocol independently of coordinator assertions. It verifies the domain-separated Ed25519 quote, exact owner/request/service/work/deadline bindings, canonical configuration/job/escrow addresses and a finalized account snapshot from a reviewed local RPC endpoint. Configuration pins cover program, publisher, cluster genesis, mint and treasury. A missing account, changed job, closed escrow, wrong policy or insufficient balance fails. Unsolicited excess escrow does not block otherwise valid funding.

The reader has a combined three-second deadline, bounded responses and no redirects or automatic retries. HTTPS is required except for a literal loopback prototype validator. Mainnet genesis is rejected. It queries public account addresses only, never signs or submits a transaction, and always marks evidence as prototype test-USDC. This cannot establish real revenue or points eligibility.

The account and quote fixtures are generated using the companion protocol’s Anchor 0.31.1 and Solana libraries, without a chain call or payment. Regenerate with `node internal/funding/testdata/generate.cjs /path/to/isolated/scarlett-protocol` after that checkout’s local harness and v2 IDL are prepared. They contain synthetic public keys and a synthetic signature, with no provider credentials.

RPC snapshot behavior follows [Solana’s getMultipleAccounts contract](https://solana.com/docs/rpc/http/getmultipleaccounts); canonical addresses follow [Solana’s PDA derivation](https://solana.com/docs/core/pda). The curve decoder is pinned in `go.mod`.

The production payment contract, lease request commitment and execution gate still need their coordinator/runtime companions. This package does not enable dispatch, remove the current marketplace blockers or authorize provider work against test funds.

Committed `accepted` and `failed` attempt outcomes require a canonical lowercase 64-character report SHA-256. Missing or malformed receipts leave the local journal unresolved. Unpairing stops new reports; the coordinator may retain status-only recovery for an exact report it committed before unpairing or wallet unbinding, so already accepted buyer work can finish. This recovery does not grant execution or access to prompts, outputs, usage or provider credentials.

### Community funded acceptance

Community Codex/X offers require `acceptance_required` and the exact request/terms commitments, with no verifier token. The native process persists its journal before requesting HTTPS acceptance from its locally configured coordinator. It requires production-receipt authority, the exact unchanged lease and a canonical verifier token before starting the helper/provider. A lost or changed acknowledgement leaves work unstarted and unresolved; recovery never repeats the provider. Services mode and production Codex proof mode reject legacy offers without this handshake. Explicit local fixture mode retains the old fixture contract.

Buyer quote denominations are owned by the coordinator: legacy `usd` uses cents, `usdc` uses millionths of USDC, and prepaid `usd_micros` uses millionths of a US dollar. They are distinct units with no implicit conversion. The node receives the stored terms digest through `signed_job_id`, echoes it as `terms_sha256`, and requires the accepted lease to match that offer exactly. It receives no quote amount or buyer balance and cannot independently validate monetary precision, reserve credit or authenticate checkout evidence. Those checks belong to the coordinator's authoritative funding adapter. The Rust verifier checks provider proofs independently of buyer monetary units.

The `usd_micros` denomination leaves the public `node-v1` lease shape unchanged. The separate `internal/funding` Borsh reader retains its devnet test-USDC contract and provides no prepaid funding authority.

The coordinator's production payment ingester and pricing policy remain separate dependencies. Acceptance refers to normalized payment evidence from that trusted owner; the node does not independently authenticate a checkout or turn the test-USDC prototype reader into real funding. `signed_job_id` carries the immutable community terms digest, including the buyer quote, and is not an on-chain signature. Suppliers earn points only.
## Public X request catalog

[`api/x-request-catalog.json`](../api/x-request-catalog.json) publishes the exact
query IDs, shared feature flags and fixed variables emitted by the pinned
`x-go` v1.13.0 runtime for search, profile, post and thread reads. Its example
query, handle and post IDs are placeholders for bounded buyer input. The
coordinator constructs the plan; buyers cannot supply provider URLs, query IDs,
feature flags, extra variables or an initial cursor. Search pages follow the
previous verified response cursor and remain limited to three exchanges.

`TestPublicXRequestCatalogMatchesRuntime` captures each operation through a
synthetic transport with no upstream dial path and compares it to this public
artifact. Changes to the pinned client or request policy must update the
catalog and coordinator pin together. The artifact is a compatibility snapshot,
not evidence that its query IDs still work on live X or that an account is
authorized for paid execution. It contains no session credentials and enables
no paid demand itself.

## Reported execution limits

Services-mode heartbeats include each enabled service's local `max_input_bytes`.
For Codex this counts prompt UTF-8 bytes; for X it counts the serialized
`x_request`, as the worker does. Codex also reports its configured
`max_output_tokens` and the accepted base-model catalog. X reports neither.
Disabled services advertise no limits. These reports describe local validation,
not verified provider access, successful work or payment evidence.

The coordinator must reject incompatible new assignments and check limits again
before funded acceptance. Legacy heartbeats can still report health, but cannot
establish compatibility for new paid work. Roll out the coordinator parser before
nodes publish the added fields. Existing local worker checks remain in force.
