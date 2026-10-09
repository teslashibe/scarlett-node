# scarlett-node

Outbound-only, independently built supplier client. The production coordinator at `https://network.scarlett.ai` implements `api/node-v1.openapi.yaml`; the operator guide is at <https://network.scarlett.ai/docs/>. No private app imports or hosted provider credentials are needed. Provider subscription terms and permission to relay paid inference are separate from this implementation and must be checked before serving real jobs.

Build: `go build -o scarlett-node .`; test: `go test ./...`.

Configure `SCARLETT_COORDINATOR=https://...` (HTTPS origin), `SCARLETT_PROFILE=...`.

Nodes advertise the reviewed Codex base catalog from `internal/config/codex-model-catalog.json`: `gpt-6.1-sol`, `gpt-6-astra`, `gpt-6-sol`, `gpt-6-luna`, `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-5.6-luna` and `gpt-5.5`. This is local compatibility metadata; subscription access remains unverified until the provider accepts a job. Proven paid execution accepts exact base IDs with low reasoning and the default service tier. The manifest maps other Codex efforts for reference; it does not enable paid effort variants or priority service. Legacy 5.6 gateway aliases remain limited to their existing allowlist. GPT-5.5 sign-in execution and advertising stop at 2026-10-14 00:00 UTC; historical receipts remain verifiable. Claude execution is unavailable in this binary.

`SCARLETT_EXECUTOR` is `gateway` (default), `codex` or `codex-tlsn`. Optional `SCARLETT_GATEWAY_KEY` stays on the node for the gateway only. `SCARLETT_BID` is the standing assignment bid (default 100; lower wins). `SCARLETT_STATE_DIR` defaults to `~/.local/state/scarlett-node`, `SCARLETT_INFERENCE_TIMEOUT_SECONDS` defaults to 45 (max 300) and bounds a Codex/gateway job, one X request and one X client build (an x_read job itself runs to its lease deadline less a 15 s report margin), `SCARLETT_MAX_INPUT_BYTES` defaults to 32768 (max 65536), `SCARLETT_MAX_OUTPUT_TOKENS` defaults to 2048 (max 8192).

For a private coordinator CA, set `SCARLETT_COORDINATOR_CA_FILE` to an absolute path containing a PEM certificate bundle. This adds roots only to the coordinator transport; HTTPS, certificate verification and hostname checks remain enabled. It does not change provider trust or permit HTTP. Leave it unset for ordinary public certificates.

**Gateway mode** (`SCARLETT_GATEWAY=http://127.0.0.1:PORT`): a locally managed OpenAI-compatible gateway with `/v1/chat/completions`, non-streaming chat, `max_tokens`, exact resolved `model`, and `usage.prompt_tokens`/`usage.completion_tokens`. Paid mode also requires `usage_source: "upstream"`; missing or other sources fail with `usage_untrusted`. Results forward `usage_source` and `execution_mode`. Local fixtures always send `unpaid_local_demo`. The current app may record that as simulated Scarlett SCT and must not treat it as an on-chain mint. This is gateway-asserted provenance, not independently authenticated provider evidence. `duration_ms` is diagnostic gateway request time, never reward latency. `open-agent-api` advertises `/health/ready`, `/v1/models`, and chat completions. **Its current chat request struct does not define `max_tokens`, so the field sent by this node is ignored and is NOT an upstream cost ceiling.** The node checks reported completion tokens after inference and rejects over-budget results, but cannot bound billed tokens ahead of time with this gateway. No gateway URL comes from jobs.

**Embedded Codex mode** (`SCARLETT_EXECUTOR=codex`): the node runs Codex in-process through `open-agent-api`'s `pkg/codex` (pinned in `go.mod`) with its own `codex login` in `SCARLETT_CODEX_HOME` (default `~/.codex`; `auth.json` must be writable for token refresh). No gateway process, URL or key. `SCARLETT_CODEX_PROFILE` and `SCARLETT_CODEX_SCAFFOLD` are absolute paths to that module's `codex_profile.json` and `codex_scaffold.json`; the Docker image ships both under `/usr/local/share/scarlett-node/` and sets them. Results pass the same model, usage and deadline checks as gateway mode and report `usage_source: "upstream"`. Like the gateway it has no pre-execution token ceiling, and usage is Codex-reported, not proven.

**Codex TLSNotary mode** (`SCARLETT_EXECUTOR=codex-tlsn`, `SCARLETT_VERIFIER=host:port`, optional `SCARLETT_PROVER=scarlett-prover`): the node runs `scarlett-prover prove` against the assigned verifier. The lease carries the exact Codex `response.create` payload and a single-use verifier token. The node hides only the Codex login token, proves the transcript came from `chatgpt.com`, and posts `/proven`. It does not submit the answer. The coordinator reads model, output, and usage from the verifier. Build the helper with Rust 1.95: `cargo build --release --manifest-path prover/Cargo.toml`. The helper reads `~/.codex/auth.json` (or `CODEX_HOME`) and does not refresh it. While that access token cannot outlast a maximum-lifetime offer plus 30 seconds, or its expiry is unknown, heartbeats report `exhausted` (keeping their positive legacy capacity) so the coordinator stops dispatching offers the node would refuse locally. This proves the TLS session and the revealed request/response bytes, not that the supplier's machine is honest or that a subscription is unused. It is not on-chain settlement.

Verified Codex receipts preserve `usage.input_tokens_details.cached_tokens` from the fully revealed provider response as optional `cached_input_tokens`. An explicit zero stays zero; missing or null details stay unknown. Malformed values and cached counts greater than total input are rejected. Durable restart preserves the distinction, including older receipts without the field. The coordinator must use this verified subset when applying cached-input weights; node or gateway reports cannot fill missing proof evidence.

**X reads over TLSNotary** (`worker.XTransport` and typed services mode): an `http.RoundTripper` that runs x-go's read methods unchanged, with each X GraphQL GET proven by `scarlett-prover prove-x`. It uses MPC mode, so the node's own connection and IP reach `x.com` while the verifier jointly holds the TLS keys. Only the values of the `auth_token`, `ct0` and `kdt` cookies (at most 64, 160 and 64 bytes) and of `X-Csrf-Token` (at most 160) are hidden; cookie names, other cookies, the rest of the request and the whole response are revealed. Any other request to `x.com/i/api/` (POSTs, REST calls including DMs, plain HTTP) is refused; requests elsewhere (x-go's page and script fetches) go through `Base` unproven. The verifier accepts `{"type":"x.read","exchanges":[...],"max_attempts":N}` sessions. Each exchange pins one read the job pays for, exactly: `operation` (one of 14 allowlisted reads), `query_id`, `variables`, `features` and, only if given, `field_toggles`. `cursor_from: k` asks for the page after exchange k, which must be the same operation with the same variables: the request's variables must equal the exchange's own plus a `cursor` that is a `Bottom` timeline cursor in an entry of a timeline instruction in the response the verifier itself recorded for k. A proof counts only if its request exactly matches a pending exchange. The query must be form-encoded as Go writes it, with `variables`, `features` and `fieldToggles` each at most once, and its JSON must have no duplicate keys or non-integer numbers, so the verifier and X can't read it differently. The first matching HTTP 200 with a non-empty `data` object fulfils an exchange; any other matching response (a rate limit, or a 200 carrying only `errors`) is recorded and the exchange stays pending for a retry. Header lines must be strict `name: value` lines of printable ASCII, with no folding, bare CR or LF, framing headers (`Content-Length`, `Transfer-Encoding`, …) or method/URL override headers. Anything else is recorded as a rejection and isn't paid. The status (`status: "x_read"`) lists `pending` exchange indexes, `complete`, `remaining_attempts` (default twice the exchanges, at most 200; each proof spends one), the recorded `exchanges` (each with its `index` and `fulfilled`) and `rejections`. The token dies when every exchange is fulfilled or the attempts run out. The verifier also rejects writes, extra requests, other hosts, hidden response bytes or anything hidden beyond those secret values. This proves the response is exactly what X returned to exactly the request the job pinned. It doesn't prove X returned everything that exists: results are what X showed the node's account (its mutes, blocks and personalization) at that moment. Request headers other than `Host` aren't pinned, and TLSNotary can't inspect hidden bytes: a node could put CR/LF and a short extra header inside a hidden secret value (up to its length limit). That can't change the proven request line or query. It can change headers such as the account or client language, which, like the account itself, the job doesn't pin. Responses must be chunked or carry a Content-Length, because the prover ends the X stream itself once the response is complete; X does not reliably close the connection, and tlsn only finalizes after the server side ends. Measured on one Mac with a local verifier: 0.6–2.5 s per proof, and a fixed ~60 MB upload and ~4 MB download between node and verifier per request, whatever the response size (about 24 s of upload at 20 Mbit/s). Responses are capped at 256 KiB as received; the largest seen was a 102 KB gzipped `HomeLatestTimeline` page (901 KB decoded). The prover pins [teslashibe/tlsn](https://github.com/teslashibe/tlsn/tree/scarlett-alpha.15), which is v0.1.0-alpha.15 with the session's mux stream limit raised from 512 to 4096; stock alpha.15 intermittently fails MPC proofs with `context mux error`. The live check is `go test -tags xlive -run TestXLive ./internal/worker` (it uses the pinned x-go runtime snapshot and needs the environment variables listed in `internal/worker/xlive_test.go`). It uses a real X session and only calls read methods. It first records the exact requests x-go builds for every x-go v1.13.0 read method except the DM REST reads, without sending them, and pins them as the job: operation, query ID, variables and features. Page 2 of each paginated method (page 3 for search) is pinned by `cursor_from`. It then runs them and requires every exchange to be fulfilled with a body identical to what x-go parsed, covering all 14 operations. x-go's `GetList` sends `listId` to `ListBySlug`, which X rejects with HTTP 422; that response is still proven, but it never fulfils its exchange. A second job checks that a swapped search term, page 2 before page 1, and page 2 with another query's cursor are all proven by X but rejected by the verifier, and that the token dies once the job is complete.

**X reads over keyed relay** (`proof_mode: "relay"`, `proof_policy: "x-relay-v1"`): the same pinned reads, proven by `scarlett-prover relay-x` instead. The node still opens the TCP connection to `x.com`, so X sees the node's address, but the verifier is the TLS client: its TLS 1.3 handshake and records travel through the node, and the node never holds a session key. The node sends the verifier the request with the same four values hidden as zeros. The verifier checks that request against the job before using any key for it, seals it, and the node adds its hidden values by finishing the record's AES-GCM tag with the verifier over oblivious transfers, one per hidden bit. The node can complete only that record and can change only those bits; the verifier never sees them. The verifier decrypts X's response itself and records it through the same policy check as an MPC proof, so receipts and settlement are unchanged. One session proves one read and costs 68–89 KB of node upload against 60–62 MB for MPC-TLS, measured on the four catalog reads with a real account on Oct 3, 2026. The trade is that a relay node must trust its verifier with its X session. Under MPC-TLS the verifier can neither read the hidden values nor affect what is sent. Under relay only the verifier holds the client key, so it decides what is sealed: a dishonest or compromised verifier can make the node send one request of its own choosing per session with the node's real cookie and CSRF values, read the answer, and learn chosen hidden bits from whether X accepts a record it distorted; with the node's traffic to X it could read the values outright. The node cannot prevent this. It detects it afterwards: the verifier must open the request record once the response is complete, and the helper fails with `verifier misused this node's X session` if what it was made to send was not its own request, or if the verifier ended the session without opening the record at all. When that happens the node halts keyed relay for itself: it logs one `ALERT keyed relay halted` line, stops listing `relay` in its heartbeat, declines relay offers before funded acceptance, and keeps serving MPC-TLS. The halt is recorded in the state directory (`relay-halt`) so a restart does not re-arm relay; `scarlett-node status` reports `relay_halted` and `scarlett-node relay-resume` clears it once the operator has checked the verifier; the account that carried the session is not penalised, since the verifier misbehaved, not the account. Relay jobs therefore need both sides to choose them: the coordinator names the mode and its exact policy in the job, and the node serves it unless its operator has opted out with `SCARLETT_X_RELAY=0` (relay is on by default from this release because it cuts a node's upload per read by roughly three orders of magnitude, and the node already trusts the operator-run verifier with its session). A relay job may pin only the four reads in `api/x-request-catalog.json` (`SearchTimeline`, `UserByScreenName`, `TweetResultByRestId`, `TweetDetail`); the verifier refuses a relay job for any other read, including the account's own feed and details, so its authorization never covers them. A session authorizes one request record; any failure after that ends it. TLS 1.3 with AES-128-GCM is required and nothing falls back to another version or cipher. Because the verifier holds the session keys, the node forwards toward X only what parses as a TLS 1.3 client handshake naming `x.com` (hello, one change-cipher-spec, one Finished-sized record) and nothing after its own request record, so a verifier cannot send requests of its own from the node's address; what remains is that it chooses the handshake's contents. Rollout: an opted-in node lists `proof_modes: ["mpc","relay"]` in its `x_read` heartbeat entry, a node declines a relay offer it does not serve before funded acceptance when the offer carries the payload, and coordinators should omit `proof_mode` on MPC jobs because nodes and verifiers older than this field reject payloads that carry it. For the same reason a durable verifier cannot be rolled back to an older binary while it still holds a relay receipt (receipts are kept for a day past expiry).

Run `./scarlett-node pair` and enter a one-time coordinator code on stdin. Pairing creates a private `identity.json` (0600) under a 0700 state directory; run `./scarlett-node run` for outbound heartbeat polling and serial inference. Each heartbeat carries `wait_seconds: 20`: the coordinator records the report, then holds the request open while it has nothing to offer and answers the moment a job for this node is funded, or with `lease: null` at the deadline. The request runs under its own deadline of the hold plus ten seconds, other calls keep the ten-second client timeout, stopping the node aborts a held heartbeat at once, a drain, a service leaving ready or any other change to what the heartbeat advertised ends the hold within about a second and is reported by an immediate new heartbeat, and the loop adds no idle delay of its own. A failed heartbeat earns a pause whose step starts at one second and doubles to a 15-second cap, inside the coordinator's 30-second staleness rule, with equal jitter (half the step, never under a second, plus a random share of the other half, so the first pause is already one to one and a half seconds) so nodes that failed together, such as when a coordinator crashes or a proxy drops every held heartbeat at once, come back spread over seconds; any answered heartbeat resets it. A `Retry-After` on a 429 or 503, or on a 200 with `lease: null` (a coordinator shutting down answers held heartbeats that way, with one to five seconds), makes the node wait at least that long, clamped to 1–60 seconds, plus up to half of it again. A heartbeat the coordinator rejects (400, or 413 `heartbeat_too_large` above 32 KiB) is logged and backed off the same way; the node never resends it in an older, reduced shape. A coordinator from before the 32 KiB heartbeat limit (including one rolled back past it) takes at most 4,096 bytes, which holds only about 18 `active_leases` across services: against one, keep `SCARLETT_CODEX_CONCURRENCY` plus `SCARLETT_X_CONCURRENCY` at or below that, or a busy node's heartbeats are rejected and it goes stale until its work drains. On a terminal, the prompt hides the code and Enter submits it. A protected pipe or file can also supply one line; no EOF is needed after that line. Keep codes out of command arguments, environment variables and shell history. Pairing writes and syncs a private temporary file, then installs the complete identity without replacing an existing file. The coordinator is responsible for generating and expiring codes. An ambiguous pairing response is not retried automatically; check the coordinator before obtaining a replacement code. The Docker sim can skip pairing with `SCARLETT_NODE_ID` and `SCARLETT_CREDENTIAL` matching a seeded coordinator row. Configure externally managed secrets without logging them. No inbound port or wallet key is used. An optional heartbeat challenge is echoed to `/api/node/v1/challenge/echo` before any inference. Echoes use the same bearer credential, carry no duration, and are not retried after failure. Authenticated HTTPS and loopback HTTP may echo. The unpaid Docker fixture sets an explicit flag so it can echo `http://host.docker.internal`. The app issues the nonce, enforces expiry and single use, and measures RTT itself. A bonus requires a fresh sample from a node-scoped credential. RTT does not prove co-location.

For an **unpaid Docker fixture only**, `../scarlett-app/compose.yaml` builds this node twice with `SCARLETT_LOCAL_FIXTURE=1` and `local-fixture` profile. It polls the local app over Docker Desktop host loopback with a per-node seeded credential and standing bid. Each model calls its own isolated gateway container, which read-only mounts just the existing matching account; account credentials are never mounted into the nodes. This fixture is not provider authorization and cannot cap upstream inference usage because the Codex gateway ignores `max_tokens`.

**Independent community services** (`SCARLETT_EXECUTOR=services`): set `SCARLETT_SERVICES` to one or more of `codex`, `x_read` and `web` (see [Web pages](#web-pages)). The node uses proven execution only in this mode. Set `SCARLETT_VERIFIER=host:port` and the local prover binary as above. Codex uses `SCARLETT_CODEX_HOME`; X uses an absolute `SCARLETT_X_SESSION` path to a private 0600 x-go session JSON file. The X session must not contain a proxy override, which would bypass its proof transport. Provider credentials remain on the supplier machine and are sent to the prover through stdin, never as command arguments or coordinator fields. `SCARLETT_CODEX_CONCURRENCY` and `SCARLETT_X_CONCURRENCY` are independent limits from 1 to 32, default 1 each. The legacy shared-concurrency setting does not replace these limits. `SCARLETT_X_REFRESH_SECONDS` (default 1800, 60 to 86400) is how often each warm X client's transaction-ID material is refreshed in the background.

Services-mode heartbeats report both services independently. A usable credential file initially means `configured`, rather than authenticated readiness. Local proof submission can change it to node-reported `ready`; the coordinator must still verify the proof independently. For `x_read` the node does not wait for a job: an account is `configured` while its warm client is being built and becomes `ready` when that build has validated the session against X, `auth_required` when X refused it, `exhausted` when X rate-limited the build and `unreachable` when X could not be reached or answered the validation with not-found (a rotated query ID, not a refusal), with the same rests a failed job earns. A validated build only promotes `configured` to `ready`; it never clears an authentication failure or ends a rest. An account that goes back to `configured` while its validated client is still installed (a rest ended, or the session file was rewritten with the same content) is reported `ready` again by the next 15-second check, without a request to X. An outcome for a session file that was replaced while X answered is discarded. `configured` accounts stay leasable. X quota/authentication errors suppress X without disabling Codex, and vice versa. Capacity includes separate in-flight counts. Quota/transport cooldowns last 30 seconds; an authentication failure waits for a changed local credential file. No numeric provider quota is guessed. Unknown or unavailable services receive a nonrewardable failure, without a provider call.

Typed Codex leases bind the base model, prompt and canonical single-turn request. Tools, instruction overrides, reasoning/service-tier changes and retained responses are rejected. Typed X leases bind a semantic public read and the verifier's exact `x.read` policy: search (Latest, 1–20 items, 1–10 exact pages; nodes before 0.1.16 take at most 3), profile by handle, post by ID, or one thread response. The worker uses pinned x-go methods and refuses a different operation, query ID, variables, features, field toggles, destination or cursor chain before invoking the prover. Each requested exchange allows one attempt; provider failures are not automatically retried. A valid empty first search page can fulfil one exchange, but a missing next-page cursor fails a request for later pages. The thread scope is one response, not a guarantee of an entire conversation.

X session authentication and transaction-header bootstrap use unproven local requests, separate from paid exchanges, and happen once per account rather than once per job: the node keeps one warm x-go client per X account (`worker.XClients`, keyed by the session file), built at start for every usable account (one at a time, one log line each) and kept warm from then on: every 15 seconds the node reads the session files and starts a background build for an account that has no client for its session file as it is now (an account added later, a replaced session file, an account back from a rest that lost its client, an earlier failed build), one build per check. A failed background build is retried after 1 minute, doubling up to the refresh interval; a session X refused is not tried again until its file changes, by the check or by the refresh, and a client built from the file's earlier content is dropped with it. When X's last answer on an account reported no requests left in the window, a job waits for the reset before its first read when the lease allows it and otherwise fails as `x_rate_limited` without spending a proof; a multi-page read held back for that reason ends the same way and keeps its client. The same check closes the clients of accounts the node no longer holds, once their jobs have drained, so a removed account is not refreshed against X. A job builds a client itself only when none exists yet. Building a client is x-go's two session-validation reads (`Viewer`, `UserByRestId`) and its two bootstrap fetches (the `x.com` page and the `ondemand.s` script the `X-Client-Transaction-Id` header is derived from), paced by its one-second request gap; a job on a warm account does only its proven reads. The client's transport is a switchboard that holds no job state: a job's pinned exchanges, verifier token and exchange counter travel in the request context, so two concurrent jobs on one account each see only their own binding, and an X API request whose context carries no job is refused. During a construction, and only then, exactly those four unproven requests pass (each validation read once); afterwards nothing unproven passes. The client is replaced when the session file's content changes (noticed by the 15-second check and before each job), when a proven read is refused by X as unauthenticated (dropped at once, rebuilt in the background with a real validation; a transport failure during a build is `x_request_failed`, not an authentication failure), and every `SCARLETT_X_REFRESH_SECONDS` (default 1800, 60–86400) by a background refresh: the new client is built while the old one keeps serving, its `Viewer` read goes to X (the one light check per interval that notices a session revoked while the node was idle) while `UserByRestId` is answered from the account's last validated build, and the swap is an atomic pointer change, so jobs in flight keep the client they hold. A refresh X answers by refusing the session drops the client and reports `auth_required`; a refresh that meets a rate limit, cannot reach X or cannot fetch the transaction material keeps the current client. A client built without transaction-ID material (the bootstrap pages failed) is still installed, because profile, post and thread reads work without it, but it is logged as such rather than as ready and its bootstrap is retried after 1 minute, doubling up to the refresh interval; those retries replay both validation reads and cost only the two bootstrap fetches. A lease pinning a query ID the warm client was not built with is refused by the switchboard before any proof is spent, and the job rebuilds once with that override (bootstrap fetches only) and tries again. The waits a job can meet are that one, a build already running for an account that has no client yet, and x-go's request pacing, all bounded by the lease deadline; a job that waited on a background refresh which then failed starts its own build instead of failing. x-go spreads the quota X last reported over the rest of its window, and that state lives on the shared client: when the wait it implies cannot fit inside the lease, the job fails at once as `x_rate_limited`, rests the account until the reset and spends no proof, and when a job ends while its read was still being held back, the client is replaced in the background (bootstrap fetches only) so the slot it reserved does not delay later jobs. After bootstrap, every requested API read goes through the proof transport. Bootstrap data, retry calls and supplier-parsed output do not authorize points. The node posts only `/proven`; the coordinator owns verifier response copies, complete fulfilment, payment reconciliation and eligibility. The node cannot prove X returned all existing data or remove account personalization. These bounded launch reads use four operations, while the lower-level transport/verifier still support their wider read allowlist.

The production coordinator accepts services-mode heartbeats and typed dispatch, and the desktop app always runs this mode. Local tests use synthetic transports and no real Codex/X subscription, so they do not measure remote proof performance or constitute provider authorization.

**Durable attempts (Linux and macOS)**: `run` holds an exclusive OS lock on a private `attempts/` directory inside `SCARLETT_STATE_DIR`. It commits the lease fingerprint before any provider call, then atomically persists the exact result/proven/failure report before submission. A second process, redelivered attempt or changed lease cannot execute the same journaled work. If the process dies during a provider call, startup reconciles with the coordinator; it never reruns that call. A still-live uncertain attempt is reported as `execution_uncertain`, which must not automatically requeue paid work.

**Verifier control TLS**: both Codex and X proof helpers encrypt the token and TLSNotary control traffic and verify the verifier certificate and hostname. The configured verifier remains `host:port`; it cannot come from a lease. The helper uses the pinned Mozilla trust roots. For a private test CA, set an absolute `SCARLETT_VERIFIER_CA_FILE` on the node. That CA applies only to this connection and never changes provider proof verification. There is no fallback to plaintext on a TLS failure.

On the verifier host, set absolute `SCARLETT_VERIFIER_TLS_CERT` and `SCARLETT_VERIFIER_TLS_KEY` PEM paths. Keep the key private (0600, owned by the process user); all TLS files must be regular, non-symlinked and at most 1 MiB. The HTTP registration/status API must bind loopback in every mode. Use a secure host-local tunnel when the coordinator runs elsewhere. Proof sockets have a ten-second handshake/token deadline. `SCARLETT_VERIFIER_CONCURRENCY` sets simultaneous connections (default 64, range 1 to 256). Accepted proof results still require separate funding and settlement reconciliation.

For an unpaid loopback test only, the verifier can set `SCARLETT_VERIFIER_PLAINTEXT_FIXTURE=1` and bind a literal loopback address with no TLS files. Direct helper test JSON can set `plaintext_fixture: true` only for a literal loopback address or the pinned `verifier:7047` fixture. The node accepts that environment setting only with its existing explicit unpaid Docker fixture configuration. Community services always use TLS. Docker verifier hosts therefore need a certificate for `verifier` and a test CA; this change does not expose a plaintext listener on a public interface.

**Durable verifier receipts**: set an absolute private `SCARLETT_VERIFIER_STATE_DIR` on the coordinator's verifier host. The verifier API must bind loopback in this mode. Registration requires a fence and `expires_at_ms` (within ten minutes), and retrying the exact job/attempt/fence/payload/expiry returns the original unspent token. Token spends are synced before proof work; results are synced before status can report them. A second verifier cannot open the same store. Disk failures make the service unavailable rather than acknowledge an uncommitted result.

An X job containing identical requested reads is rejected before a session is created. A fulfilled X request can count only once per session. Matching includes the proven operation, query ID, variables, features and field toggles. Repeated pagination cursors cannot fulfil another page, even if its response changes. Distinct requests may return identical response bodies. The same check applies when restoring private receipts; a stored duplicate cannot become completed work.

Restart preserves accepted receipts. A proof interrupted in flight becomes `execution_uncertain`, loses its token and cannot be retried as new provider work. Status includes the job/attempt, fence, exact registered request hash, absolute expiry and a `durable` flag; it never includes the token. The coordinator must check those bindings, complete X fulfilment, quoted bounds and separate funding/settlement evidence. A stored proof is not a paid receipt or a points award. Durable X sessions allow 1–10 pinned exchanges and one attempt per exchange; legacy ephemeral tests retain the wider read policy.

The private store has validated limits: `SCARLETT_VERIFIER_MAX_RECORDS` (default 1024, range 1 to 1,000,000), `SCARLETT_VERIFIER_MAX_RECORD_BYTES` (default 67108864, range 1048576 to 67108864), and `SCARLETT_VERIFIER_MAX_TOTAL_BYTES` (default 268435456, at least the per-record limit and at most 1099511627776). Values are decimal integers. Choose the per-record bound to hold the largest allowed request and verified response together; lowering it below an existing receipt prevents startup. Pending proofs reserve their full per-record budget before registration returns a token. A pending web fetch reserves its own bound instead, never clamped by the per-record budget: its receipt JSON (at most 658,324 bytes with five redirects; the page is never in the JSON) plus a full 64 MiB page, 67,767,188 bytes in all. Completed proofs release that reservation to their actual encoded size. Expired unspent tokens are revoked during maintenance and release their reservation while the receipt remains available for reconciliation. In-flight proofs keep their reservation through completion. The defaults therefore allow at most four pending durable sessions, fewer when retained receipts use space; the connection limit is a separate ceiling. Raising the record count alone does not raise this storage capacity.

**Web pages in the verifier** (contract `api/verifier-v1.md`, fixtures `api/fixtures/verifier/`): a web job's final page is streamed to a private body file `<sha256(job\nattempt)>.body` beside its receipt (written as `.body.partial`, fsynced, renamed and the directory fsynced before the receipt that names it is committed), never into the receipt. The final hop of a complete chain says `body_stored: true`; `body_bytes` and `body_sha256` describe the entity (de-chunked, still content-encoded) on every hop. The coordinator reads the page with authenticated `GET /v1/sessions/{job_id}/{attempt}/body` (`application/octet-stream`, `X-Body-SHA256`, `X-Body-Bytes`, one `Range: bytes=a-b` or `a-` answered 206; 404 `no body` or `unknown session`, 410 `body released`, 416 `invalid range`) and releases it with `DELETE` on the same path (204, idempotent), which records `body_released_at_ms` in the receipt before unlinking the file. Retention purges a web receipt and its body 10 minutes after expiry either way. Startup deletes partial and orphan body files, and refuses to start when a receipt says a body is stored but the file is missing, not private or not `body_bytes` long, or when any receipt still holds a page inline as `body_base64` (from before body files: pause web and let those age out). `SCARLETT_VERIFIER_MAX_WEB_BYTES` (default 201326592, range 67767188 to 1099511627776) bounds the web pool: web receipts' charges plus their stored bodies. It must leave one full receipt beside it (`MAX_WEB_BYTES + MAX_RECORD_BYTES <= MAX_TOTAL_BYTES`), so web can never take the room X and Codex need; a web registration needs room in the pool and in the total (`503 verifier web capacity reached`), X and Codex in the total only. Production uses a 32 GiB total and a 24 GiB pool (380 pending web pages, an 8 GiB X/Codex floor). `SCARLETT_VERIFIER_WEB_CONCURRENCY` (default 48, range 1 to 240, at most `SCARLETT_VERIFIER_CONCURRENCY - 16`) bounds web hops in progress; a web session beyond it is answered with one relay `FAILED` frame `{"reason":"verifier_busy"}` and closed without spending its token, and X and Codex always keep 16 connection slots. A web job's `max_response_bytes` must be 67108864 (the page ceiling, on the final hop's entity bytes); a hop may take at most 68,222,976 decrypted bytes in all (heads, interim heads, trailers and chunk framing included). Each hop runs at most `min(280 s, session limit, receipt expiry)`; the verifier also ends it as `session_timeout` 60 s after the sealed request with no response byte, 20 s after the last target byte, or when, from 30 s after the first byte, the target sent fewer than 1,966,080 bytes (64 KiB/s) over the trailing 30 s. These limits run inside the session, so a sealed request is always opened for the node first. A failed hop's receipt carries `rejection` `{reason, received_bytes, entity_bytes, declared_bytes}` beside `rejections` (`response_too_large` is now `page_too_large`), and once it is committed the node gets one `FAILED` frame with the reason.

Successful `prove` and `prove-x` summaries report provider transcript `sent_bytes` and `received_bytes`, plus `verifier_sent_bytes` and `verifier_received_bytes` measured below the verifier connection's outer TLS layer. `verifier_transport_layer` is `tcp_payload`: the counters include TLS handshake and record bytes accepted by TCP, excluding IP/TCP headers and retransmissions. Counts saturate at 1 TiB per direction and then set `verifier_bytes_saturated: true`. Use these supplier diagnostics for local bandwidth measurements; billing and points use verified provider evidence.

After funded acceptance, the node retains these verifier counters in optional private journal `proof_traffic` metadata bound to the attempt's lease fingerprint. It reserves a numbered sample before each helper starts, up to one Codex call or the signed X plan's one to ten calls. A failed reservation prevents execution. Missing, malformed, failed or saturated summaries remain incomplete; numeric zero is recorded only when explicitly reported. A crash can leave a started sample without counters. Completion and worker-finished markers survive acknowledgement and restart under the existing journal retention rules, while recovery never starts another helper. These observations stay local and do not change the `node-v1` report or its hash. They measure verifier TCP payload bytes, excluding provider/bootstrap connections, coordinator requests and total network-interface overhead.

Authenticated `GET /v1/capacity` on the existing loopback verifier API reports `healthy`, `durable`, configured connection limits, receipt count and storage limits/actual/reserved bytes, including stored body files (`storage.body_files`, `storage.body_bytes`), and under `web` the web pool (`can_register`, `reserved_bytes`, `body_files`, `body_bytes`, `max_bytes`) and web sessions (`concurrency`, `active_sessions`, `busy_refusals`). `active_connections`, `in_flight_proofs` and `pending_sessions` report control connections, ongoing proofs and unexpired issued tokens. Pause new coordinator dispatch, then wait for all three to reach zero before a verifier restart; an issued token can still start a proof after dispatch is paused. `storage.can_register` indicates room for another worst-case receipt. A full store remains healthy for existing status/recovery reads; storage failures return HTTP 503 with `healthy: false`. The route contains no receipt content, tokens or credentials and requires the verifier key.

Resolved payloads and receipts are removed 24 hours after session expiry by a minute maintenance pass and on restart. Unacknowledged coordinator results must be reconciled within that window. Web fetch receipts are removed 10 minutes after session expiry instead: the coordinator reads a web receipt only before its job's deadline and keeps the signed result itself, and a day of web pages would fill the store Codex and X share. Interrupted proof receipts become `execution_uncertain`, lose their tokens, and retain replay metadata beyond that window. They need an explicit reviewed reconciliation process before removal; capacity pressure never purges them. Corrupt, public, symlinked or oversized files fail startup; a full store refuses more work. Provider credential values never enter the store, but buyer requests and verified response copies do, so preserve its private permissions. Without a state directory the legacy verifier stays ephemeral and reports `durable: false`. Proof connections use verified TLS as described below.

Recovery uses the authenticated `GET /api/node/v1/jobs/{job_id}/attempt` contract. Identity must match the exact job/attempt/fence and the response must explicitly promise `replay_safe: true`. Only then may a ready report be retried with its original body. Accepted receipts must match the recorded submission hash; pending proofs stay pending without another provider call. Unsupported endpoints, lost responses and mismatched receipts keep the record unresolved. A missing response is not a payment, proof or points receipt. The production coordinator implements this contract.

The journal stores no provider credentials, verifier tokens, prompts or complete leases. Gateway result reports can contain private output; files are 0600 in a 0700 directory. Accepted content is removed immediately; unresolved report content expires 24 hours after its lease deadline while uncertainty metadata remains. Terminal metadata is removed after both deadline and acknowledgement are 24 hours old. Admission counts only live records: started or ready attempts that can still need a provider call, proof, report or coordinator reconciliation. `SCARLETT_JOURNAL_MAX_RECORDS` (default 1024, range 1 to 1,000,000) caps live records, `SCARLETT_JOURNAL_MAX_RECORD_BYTES` (default 192000, range 192000 to 1048576) bounds one record, and each live record reserves that full size against `SCARLETT_JOURNAL_MAX_TOTAL_BYTES` (default 268435456, at least the per-record limit and at most 17179869184) before funded acceptance. Finished (terminal) receipts keep only replay metadata and reserve no admission space; `SCARLETT_JOURNAL_MAX_TERMINAL_RECORDS` (default 100000, range 1 to 1,000,000) and `SCARLETT_JOURNAL_MAX_TERMINAL_BYTES` (default 134217728, at least the per-record limit and at most 17179869184) bound them separately, so the journal's files stay within the two byte limits combined. Above seven eighths of either terminal limit, each purge removes the oldest receipts early, but never one whose deadline or acknowledgement is less than an hour old: every executor refuses an expired lease before any provider call, so an older receipt no longer guards a runnable lease. Only if receipts that recent fill terminal storage does admission wait for them. At the defaults a node keeps a full day of receipts up to about 87,000 attempts a day and keeps taking work well beyond that. A journal that blocks admission advertises exhausted service health before requesting new offers, and local status sets `journal_full`, which the desktop app shows as "Receipt journal full". Local status includes `journal_capacity` with live records, their actual and reserved bytes, terminal records and bytes, and available record slots. Existing pending attempts still reconcile without repeating provider work. A full, corrupt or unwritable journal refuses new work. The node reads and validates every record when it opens the journal and keeps their accounting in memory under the exclusive lock; each admission and purge lists the directory, validates any record file it has not seen and refuses unexpected files. Abandoned atomic-write files are removed under the exclusive lock on startup. State-dir environment changes must preserve the journal for restart recovery; deleting it forfeits that protection. An older node counts receipts against its record limit and refuses to open a journal holding more records than that limit; to roll back past this accounting, raise its `SCARLETT_JOURNAL_MAX_RECORDS` or wait for receipts to expire.

## Release updates

Every request to `/api/node/v1` carries `Scarlett-Node-Version` with this build's release (`NodeRelease` in `internal/coordinator/release.go`; `release-manifest.py check-version` refuses a release where it differs from the desktop version). The coordinator offers new jobs to its latest published release and the one before it. Its replies carry `Scarlett-Node-Latest-Version` and `Scarlett-Node-Minimum-Version`, plus `Scarlett-Node-Update-Required: true` for a node older than the minimum; such a node keeps heartbeating and finishing work it holds but is offered nothing new. A node that sends no version (0.1.9 and older) is treated as 0.1.9. The contract is `api/fixtures/version-headers.json`. `scarlett-node status` reports `release`, `latest_release`, `update_available` and `update_required`; the node logs one `release:` line when an update first appears or becomes required, and the desktop app shows a toast linking to the download page. "Later" hides an available update until a newer one appears; a required update cannot be dismissed. The app replaces that link with its own updater, described next.

### Updater

Both the desktop app and `scarlett-node update` read `https://network.scarlett.ai/downloads/manifest.json` (headless: the configured `SCARLETT_COORDINATOR` origin; HTTPS only, no redirects, at most 64 KiB). Besides the three installers the manifest carries `notes` (title, date, up to three highlights and links derived from the version) and, for a signed release, `updates`: a minisign signature for each installer and each headless bundle (`scarlett-node-<version>-{linux-amd64,darwin-arm64,darwin-amd64}.tar.gz`, with its own path, length and SHA-256). Every download URL is derived as `/downloads/v<version>/<fixed file name>`; the manifest cannot point anywhere else. Code is in `internal/update`.

An update installs only after all of these pass: length and SHA-256 from the manifest; a prehashed (BLAKE2b-512) Ed25519 minisign signature from a key pinned in the build (`internal/update/keys.go`, generated from `desktop/signing/identities.json` `updater.minisign`), whose signed trusted comment names exactly that file and version; on macOS, the DMG, the app and its three sidecars signed with the pinned certificate (`codesign --verify --strict -R`, one embedded certificate, no team), the same designated requirement as the running app and `CFBundleShortVersionString` equal to the version; on Windows, WinVerifyTrust reporting exactly `CERT_E_UNTRUSTEDROOT`, the pinned leaf SHA-256, a self-issued signer and the product version. A version below the highest one already installed is refused; rollback is the only downgrade. A build with no pinned updater key reports updates and links the download page.

The node never interrupts accepted work for an update. With the node serving, the updater pauses new work (`drain`), waits until the node's own status reports `draining` with `in_flight` zero (a status written before the node saw the pause may not count a job accepted in that instant; at most 30 minutes, then it resumes and retries an hour later), stops the node and hands over. On the desktop, new work stays paused until the new version proves healthy, so a rollback never has accepted work to wait for. Optional updates in automatic mode install at a fixed per-node offset within four hours of first being seen (`SHA-256(node_id ‖ version)`), so the network never drains at once; required updates install as soon as they are ready, and immediately when the node is not serving.

Automatic installs are opt-in. In the default notify mode the desktop app shows a toast with the release title, up to three highlights, **Update now** (the same verified, drain-safe install), **What's new** (`https://network.scarlett.ai/changelog/#v<version>`) and **Later**, which hides that version for 24 hours. A required update's notice follows the coordinator's `update_required` from the first status poll, before the updater's first check and while the manifest is unreachable (then with the download page), and cannot be dismissed. After an update the app shows "Updated to Scarlett Node x.y.z" once, with that version's highlights compiled in from `release-notes/<version>.json` and a link to its changelog entry.

Desktop: the app keeps private `update-state.json` in its data directory through `scarlett-node desktop update-state-get|update-state-set` (a compare-and-swap: get prints the state with its revision, set names the revision it read and is refused with `{"conflict":true}` when the guard, `update-stage` or another task changed the state since, so the app applies its change again to the newer state; strict schema; phases `staged → draining → handoff → installed → verifying → healthy`, or `unhealthy → rolled_back`, or `failed` when nothing was replaced or, with reason `restore_failed`, when the previous version could not be put back). `desktop update-check` reads the manifest; `desktop update-stage auto|auto-throttled|manual` downloads with resume (4 MiB/s while serving in automatic mode), verifies and stages, printing JSON lines; `desktop update-guard` runs from a copy of the old node binary at a fixed path outside the bundle (`updates/guard/`, so a macOS App Management grant made for it once still applies to later updates): it waits for the app to exit, swaps the bundle (`renamex_np` `RENAME_SWAP`) or runs the verified NSIS installer with `/P /UPDATE`, relaunches the app and waits up to five minutes for it to report healthy (an update the app already moved past, by clearing the healthy record on its next launch or staging a newer release over it, counts as kept; a state that briefly cannot be read is read again) (its window rendered and, when it was serving, its node running the new release a minute later). Otherwise it lets the new app finish its own draining shutdown, waits for that version's node to release the attempt journal (it finishes accepted work by itself), restores the previous bundle or the cached previous installer and records the version as failed so automatic mode skips it. A version the guard could not install at all is skipped the same way until the operator chooses **Try again**, so a lasting refusal never quits and relaunches the app on every automatic attempt. Downloads are never quarantined or marked with Mark-of-the-Web, so updated apps open without another Gatekeeper or SmartScreen approval. Nothing asks for administrator rights; a folder the app cannot write, a translocated Mac app or a blocked App Management permission leaves the running version in place with an explanation and **Try again**.

Headless: `scarlett-node update check [--json]`, `scarlett-node update apply [--yes] [--bin DIR]`, `scarlett-node update rollback [--bin DIR]`, `scarlett-node update --auto` (the `scarlett-node-update.timer` entry point; installs only with `SCARLETT_AUTO_UPDATE=install`) and `scarlett-node update version`. They work only for an `install.sh` layout and keep their state in `<root>/update-state.json`. `apply` and `rollback` first wait for accepted jobs as above. `apply` runs the new bundle's `install.sh`, checks the new binary's release, restarts `scarlett-node.service` when that user service is active and requires a fresh running status from the new release within three minutes; otherwise it reinstalls the previous version with its own `install.sh`. See `packaging/INSTALL.md`.

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

**Local lifecycle**: `scarlett-node status` prints a private local JSON observation: runtime state, last acknowledged heartbeat, independent service reports, in-flight work and unresolved journal records. It contains no credentials, prompts, results or verifier tokens. A snapshot older than 45 seconds is offline (a held heartbeat can keep one for 30, and the node saves it again when it starts a pause between heartbeats and every ten seconds during one); it does not prove current provider access or remote acceptance. These commands need only `SCARLETT_STATE_DIR`, which must match the running node.

`scarlett-node drain` persists a drain request across process restarts. The next poll advertises exhausted capacity, and work delivered after the node observes the request is rejected without calling its provider. Already accepted jobs continue. `scarlett-node resume` removes the request; the next poll can accept work again if its service is available. The coordinator must honor exhausted nodes when dispatching. Drain is a local scheduling control, not remote unpairing or revocation.

SIGTERM and Ctrl-C stop polling and give accepted workers up to two minutes to finish and journal their receipts, within their existing lease deadlines. At that limit their contexts are cancelled. Started or unacknowledged work stays journaled for reconciliation and is never automatically rerun. A second process still cannot acquire the same journal. Use drain before stopping or upgrading if you want the coordinator to observe exhausted capacity first.

**Native installation**: `scripts/package.sh VERSION` builds the node and the pinned Rust proof helper on a supported native platform, with file and archive checksums. The bundle's installer keeps versioned files, switches the active version atomically and preserves the node's identity/journal. It checks the platform and refuses corruption, different contents for an existing version or an unrelated executable. The helper resolves beside the node when available; a missing helper reports unreachable service capacity and cannot start provider work. See [installation instructions](../packaging/INSTALL.md) for configuration, the optional Linux user-service template and upgrade/rollback steps. CI produces review artifacts; this change publishes no release. The Docker image also includes the helper and its matching runtime.

Current gaps against [issue #1](https://github.com/teslashibe/scarlett-node/issues/1): committed job identities are not cryptographically verified against the Solana program. Dynamic capacity and independent tokenization remain incomplete. The node emits no rewardable report for missing usage, model mismatch, invalid finish reason or expired lease. Usage constraints are checked after inference, rather than imposing an upstream spending ceiling. TLSNotary still needs an authorized provider login and coordinator-run verifier. The unpaid Docker fixture remains separate from the points-only community product.

Builds use the pinned private x-go runtime snapshot in `third_party/x-go`, with source hashes recorded in `UPSTREAM.json`. Hosted CI and Docker builds need no GitHub credential for it. The command and MCP adapters are outside this snapshot. The gateway remains the public pinned module in go.mod.

## Prototype funding evidence

`internal/funding` checks the v2 test-USDC protocol independently of coordinator assertions. It verifies the domain-separated Ed25519 quote, exact owner/request/service/work/deadline bindings, canonical configuration/job/escrow addresses and a finalized account snapshot from a reviewed local RPC endpoint. Configuration pins cover program, publisher, cluster genesis, mint and treasury. A missing account, changed job, closed escrow, wrong policy or insufficient balance fails. Unsolicited excess escrow does not block otherwise valid funding.

The reader has a combined three-second deadline, bounded responses and no redirects or automatic retries. HTTPS is required except for a literal loopback prototype validator. Mainnet genesis is rejected. It queries public account addresses only, never signs or submits a transaction, and always marks evidence as prototype test-USDC. This cannot establish real revenue or points eligibility.

The account and quote fixtures are generated using the companion protocol’s Anchor 0.31.1 and Solana libraries, without a chain call or payment. Regenerate with `node internal/funding/testdata/generate.cjs /path/to/isolated/scarlett-protocol` after that checkout’s local harness and v2 IDL are prepared. They contain synthetic public keys and a synthetic signature, with no provider credentials.

RPC snapshot behavior follows [Solana’s getMultipleAccounts contract](https://solana.com/docs/rpc/http/getmultipleaccounts); canonical addresses follow [Solana’s PDA derivation](https://solana.com/docs/core/pda). The curve decoder is pinned in `go.mod`.

The production payment contract, lease request commitment and execution gate still need their coordinator/runtime companions. This package does not enable dispatch, remove the current marketplace blockers or authorize provider work against test funds.

Committed `accepted` and `failed` attempt outcomes require a canonical lowercase 64-character report SHA-256. Missing or malformed receipts leave the local journal unresolved. Unpairing stops new reports; the coordinator may retain status-only recovery for an exact report it committed before unpairing or wallet unbinding, so already accepted buyer work can finish. This recovery does not grant execution or access to prompts, outputs, usage or provider credentials.

### Community funded acceptance

Community Codex/X offers require `acceptance_required` and the exact request/terms commitments, with no verifier token. The native process persists its journal before requesting HTTPS acceptance from its locally configured coordinator. It requires production-receipt authority, the exact unchanged lease and a canonical verifier token before starting the helper/provider. A lost or changed acknowledgement leaves work unstarted and unresolved; recovery never repeats the provider. Acceptance of the exact attempt and fence is idempotent at the coordinator, so a 503 `dispatch_busy` (bounded registration capacity, sent with `Retry-After: 1`) or `network_unavailable` is retried inside the same acceptance: at most three more requests, each after the `Retry-After` (clamped to 1–60 seconds, one second when absent) plus up to half of it again, and none that would start later than 30 seconds before the lease deadline. A 401, 404, 409 or 429, any other 503 and a transport failure are never retried; no provider work starts before an accepted reply. Services mode and production Codex proof mode reject legacy offers without this handshake. Explicit local fixture mode retains the old fixture contract.

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
`x_request`, and for web the serialized `web_request`, as the workers do. Codex
also reports its configured `max_output_tokens` and the accepted base-model
catalog. X and web report neither. An enabled web entry also reports `egress`
(`direct` or `proxy`) and `browser`, the browser tier's readiness (see
[Browser tier](#browser-tier)). Disabled services report `not_added` and no limits. These
reports describe local validation, not verified provider access, successful
work or payment evidence. A heartbeat lists at most three services and a total
capacity of at most 96 (32 each).

## Web pages

`SCARLETT_SERVICES` may include `web` (alone or with `codex` and `x_read`). Web
needs no account and no credential path. `SCARLETT_WEB_CONCURRENCY` (1–32,
default 4) bounds simultaneous pages; the web entry reports it as capacity.

**Lease.** A web lease carries `web_request` (`{"operation":"scrape","url":…}`)
and `web_payload`, the exact verifier `web.fetch` payload (`api/node-v1.openapi.yaml`,
fixtures `lease-web-offer.json` and `lease-web.json`). Before acceptance the node
refuses an offer whose payload is not `proof_mode` `relay` with `proof_policy`
`web-relay-v1` (or `web-browser-v1` for a browser job while the browser tier is
ready), or while keyed relay is halted. After acceptance it checks that
`input_sha256` is the SHA-256 of Go's encoding of `web_request` (at most
`SCARLETT_MAX_INPUT_BYTES`), that the payload has unique keys, integer numbers,
exactly its seven fields (eight with `node_headers` for `web-browser-v1`), a
URL equal to `web_request.url`, 0–5 redirects,
`max_response_bytes` exactly 67108864 (the 64 MiB page ceiling, on the final
hop's entity bytes) and at most the three allowlisted headers in order,
and that the lease carries no Codex or X fields; otherwise it reports
`invalid_lease`. Well-formed terms whose URL is not canonical (including an IP
literal, a reserved name or an X host) are reported `web_egress_denied` without
any lookup. The job runs until the lease deadline less a 10 s report margin. A
web job's deadline is its creation second plus 298 s. An X search of four to
ten pages gets the same 298 s; one of one to three pages, every other X read
and Codex keep 118 s. The node accepts a web or x_read offer whose deadline is
at most 300 s (plus 5 s of clock skew) ahead of its own clock, and a Codex
offer at most 120 s.

A browser-mode lease (`web_request.mode` `browser`) also carries
`web_request.browser` and a `web-browser-v1` payload; see
[Browser tier](#browser-tier). A relay offer may carry the lease-level hint
`web_prewarm_browser: true` (fixture `lease-web-prewarm-offer.json`), which
is outside `web_request`, never hashed and not part of the accepted terms.
**Canonical URLs.** The strict rules are shared with the app and the verifier
through `api/web-vectors.json`: absolute `https`, lowercase ASCII host with at
least two labels and a letter in the last, port 443 only, no userinfo, no IP
literal (bracketed, an all-digit last label or one starting with `0x`), no
reserved name (`localhost`, `local`, `internal`, `home.arpa`, `lan`,
`localdomain`, `onion`, `invalid`, `test` or a subdomain), no `x.com` or
`twitter.com` host, fragment dropped, path and query percent-encoded and dot
segments removed, at most 2048 bytes. A URL is canonical when these rules leave
it unchanged.

**Hops.** Each hop is one `scarlett-prover relay-web` run under the job's single
verifier token, at most `max_redirects + 1` of them. For each hop the node:

1. re-checks the hop URL is canonical;
2. resolves the host with the system resolver (5 s);
3. checks every returned address with the egress guard, refusing the hop if any
   is denied;
4. picks the first IPv4 address, else the first IPv6 address;
5. runs the helper with stdin `{verifier, verifier_ca_file?, plaintext_fixture?,
   token, hop, url, ip, port: 443, proxy?, payload, timeout_ms, node_headers?}`,
   where `timeout_ms` is the smaller of 280 s and the time left and
   `node_headers` (`{user_agent, cookie?}`) is present only for a browser job's
   re-fetch. stdout is capped at 64 KiB and stderr at 16 KiB;
6. reads the one-line summary: `status` `proof_sent`, the same `hop`, a
   `status_code`, and either `final: true` or a canonical `next_url` for a
   301, 302, 303, 307 or 308 that the verifier authorized.

A verifier at its web session limit answers the hop `verifier_busy`
(`SCARLETT_WEB_ERROR=verifier_busy`) before anything is spent; the node runs
the hop again after 1, 2 and 4 s and then every 5 s, while at least a second of
the hop's budget would remain (diagnostics phase `verifier_busy_wait`). A page
whose final entity is over 64 MiB fails the hop at the verifier
(`SCARLETT_WEB_ERROR=page_too_large`); a Content-Length over it fails at the
head, before any body byte is relayed.

The helper never receives page plaintext; the summary carries counters and the
next URL only. Each hop is one proof-traffic sample (up to six per attempt) and
one diagnostics exchange (operation `scrape`, proof mode `relay`). No URL, host,
address, proxy or page content is logged or kept in diagnostics.

**Outcomes.** Failures of the first hop are reported with these codes; once the
first hop was verified, any later failure other than verifier misuse is
reported `proven`, because the verifier already holds the verified hops.

| Code | First hop |
| --- | --- |
| `web_egress_denied` | The URL failed node validation, or the host resolved to a denied address |
| `web_dns_failed` | No address within 5 s |
| `web_connect_failed` | The helper could not open TCP to the checked address (`SCARLETT_WEB_ERROR=connect_failed`); no verifier session was spent |
| `web_proxy_failed` | The egress proxy was unreachable, refused authentication or did not answer 200 (`SCARLETT_WEB_ERROR=proxy_failed`) |
| `web_fetch_failed` | The relay session failed after the token was presented, the verifier stayed busy for the whole hop budget, or the helper's summary was invalid |
| `page_too_large` | The page is over the 64 MiB ceiling: `stage` `wire` when the verifier refused the first hop's entity (`observed_bytes` 67108865, a lower bound; the coordinator reads the verifier's own counts), or `stage` `dom` for a browser job whose DOM was over 64 MiB when neither its manifest was stored nor a re-fetch hop verified (`observed_bytes` the DOM's UTF-8 size) |
| `relay_misuse` | The helper caught the verifier misusing the session; keyed relay halts node-wide, for X and web alike, until `scarlett-node relay-resume` |
| `expired` | The lease deadline passed first |
| `prover_error` | The helper could not run |
| `web_browser_unavailable` | Browser job: the browser tier was not ready or its helper could not start |
| `web_browser_failed` | Browser job: the browser failed (navigation, TLS, crash, timeout or memory kill) and neither a stored copy nor a verified re-fetch hop exists |

**Readiness.** The web entry is `configured` when enabled with the helper
present and `ready` after a proven job. It is `unreachable` with
`last_error_code` `prover_error` while the helper is missing, `relay_misuse`
while relay is halted and `web_proxy_failed` for 60 s after the egress proxy
failed. Failures on the target's side (`web_dns_failed`, `web_egress_denied`,
`web_connect_failed`, `web_fetch_failed`) never change it. Account files, their
errors and account mode never apply to web, so a desktop node with Serve web
pages on (the default) can start with no accounts. The two browser codes
never change it either.

**Egress guard.** IPv4-mapped IPv6 is judged as its IPv4 address. Denied IPv4:
0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
192.0.0.0/24, 192.0.2.0/24, 192.31.196.0/24, 192.52.193.0/24, 192.88.99.0/24,
192.168.0.0/16, 192.175.48.0/24, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24,
224.0.0.0/4 and 240.0.0.0/4. IPv6 must be in 2000::/3 and outside 2001::/23,
2001:db8::/32, 2002::/16 and 3fff::/20. NAT64 prefixes are discovered from the
AAAA answers for `ipv4only.arpa` (RFC 7050) at start and every 10 minutes; an
address inside one is judged by the IPv4 address it embeds. Without discovery
64:ff9b::/96 is denied like any address outside 2000::/3. Every address on a
local interface (refreshed each minute) is denied, and scoped addresses never
pass. Only port 443 is dialled. The node's own public address behind NAT
(hairpin) is not detected.

**Proxy egress.** `SCARLETT_WEB_EGRESS_PROXY=http://[user:pass@]host:port`
(services executor only; port required, no path, query or fragment) makes the
helper send `CONNECT <checked-ip>:443` to the proxy, with
`Proxy-Authorization: Basic …` when credentials are given, and require a `200`.
DNS is still resolved and checked on the node. The proxy must be a
non-intercepting tunnel. The value is never logged, printed in errors or
status, or sent to the coordinator; the heartbeat reports only `egress: proxy`.
The browser tier's filtering proxy chains through the same proxy, sending
`CONNECT <checked-ip>:<port>` for both its forms. The browser download itself
uses ordinary system networking, never the egress proxy.

## Browser tier

Web jobs in browser mode render the page in a hidden browser on the node before
the proven re-fetch. Contract: `api/node-v1.openapi.yaml` (`WebRequest.mode`,
`WebBrowser`, `BrowserHealth`, `/browser-result`, `BrowserResult`) and
`api/web-vectors.json` version 2.

**Settings.** `SCARLETT_WEB_BROWSER` is `on` or `off` (also `1`/`0`,
`true`/`false`); it defaults to `on` with web on macOS and Linux and to `off`
on Windows in this release. Without web the tier is off whatever it says.
`SCARLETT_WEB_BROWSER_CONCURRENCY` (1–4) sets the pages rendered at once and
may not exceed `SCARLETT_WEB_CONCURRENCY`; unset, the runtime uses 1 below
16 GiB of physical memory and 2 otherwise, never more than web capacity.
`SCARLETT_WEB_BROWSER_IDLE_SECONDS` (30–3600, default 120) is the idle stop.
All three need the services executor (so do the solver settings below). A desktop node with Serve web
pages on (the default) inherits the defaults; the desktop app passes an
explicit `SCARLETT_WEB_BROWSER` of `on` or `off` from its own environment to
the node, and only together with web.

**What ships and what is fetched.** The node bundle and the desktop app carry
`web-runtime-<platform>.tar.gz` and `web-runtime.json` beside
`x-login-runtime/`: a pinned CPython 3.13.16 (python-build-standalone
`20261003`) with Scrapling `0.4.15+scarlett.2`, Patchright and Playwright
1.63.0 from a hash-locked, wheels-only lock, and the node's helper
`scarlett_web_helper`. The Scrapling wheel is the asset of release
`v0.4.15-scarlett.2` on [teslashibe/Scrapling](https://github.com/teslashibe/Scrapling)
(branch `scarlett/antibot`, commit `87bbb2a`), named in
`third_party/web-browser/requirements.lock` by URL and sha256; `pip
--require-hashes --only-binary=:all:` installs those exact bytes and nothing is
built from source. The helper's driver reuses the x-login runtime's Node
22.23.3. The resource directory is found as for X login:
`SCARLETT_X_LOGIN_RESOURCE_DIR` when set (the desktop sets it), else the
installed layout beside the executable. The archive is extracted into
`<state>/web-runtime/<digest>/` after its manifest, sizes and digests are
checked. The browser is Chrome for Testing 155.0.8059.39, downloaded by the node
from its fixed `storage.googleapis.com` URL over HTTPS with the system roots,
checked against a pinned zip digest and a per-file inventory (exact paths,
sizes, digests, modes and links), and extracted into
`<state>/web-browser-bin/<digest>/`. Older browser versions are removed once
the current one passes its launch probe. `scarlett-node web-runtime check
[--resources DIR] [--with-browser]` runs the same verification without a node
and prints `{"webRuntime":"passed"}`.

**Lease.** `web_request` gains `mode: "browser"` and `browser`
(`{wait, wait_ms, wait_selector?, timeout_ms, block_resources,
solve_challenge}`), all bound into `input_sha256`. Mode, the `web-browser-v1`
policy, `browser` and `node_headers` go together. Bounds: `wait` is `load` or
`networkidle` (load, then at most 3 s more for the network to go quiet),
`wait_ms` 0–15000, `wait_selector` 1–256 printable ASCII bytes, `timeout_ms`
5000–45000. A `web-browser-v1` payload has exactly the two headers `accept`
and `accept-language` with their default values in that order, no
`user-agent`, `node_headers` exactly `["user-agent","cookie"]`, five
redirects and 67108864 response bytes; anything else is `invalid_lease`. The
pre-warm hint on a browser lease is `invalid_lease`, and an offer carrying it
is refused before acceptance.

**Admission.** A browser offer is taken only while the tier is `ready`, holds
one browser slot inside its web slot, and starts the helper in the background
while the node accepts. A relay offer with `web_prewarm_browser` starts the
helper too when the tier is ready, so an escalation that follows finds it warm.

**Run.** The report deadline is the lease deadline less 10 s. The browser
phase ends 15 s before it and gets the smaller of `timeout_ms` and the time
left; under 5 s the job is `expired`. Then:

1. The page's host is resolved and checked with the egress guard before any
   browser work: `web_dns_failed` or `web_egress_denied`.
2. The browser renders the page in a fresh context: `web_browser_unavailable`
   if it could not run at all, `web_browser_failed` if it failed. After the
   page loads, the anti-bot pass (below) runs within the browser budget.
3. The final document must be an absolute `http` or `https` URL of at most
   2048 bytes and not an X host; otherwise the browser copy is dropped.
4. As soon as the browser returns, two things run at once. The **upload**
   sends the rendered DOM in parts and then its manifest (below). The
   **re-fetch** is the relay hop loop above with the same token, each hop
   carrying `node_headers`: the pinned User-Agent and a Cookie built from the
   browser's cookies (below). The re-fetch is skipped when the browser could not
   clear a bot challenge.
5. The node reports once both are done, or at the report deadline: `/proven`
   when the manifest was stored or the verifier holds at least one re-fetch hop,
   otherwise `/fail` with `page_too_large` (`stage` `dom`) for a DOM over the
   ceiling, else the first code from steps 1–2, then the re-fetch's first-hop
   code. Verifier misuse in the re-fetch is reported `relay_misuse`
   and halts relay as always.

**Anti-bot pass.** The helper's session is built with Scrapling's
`solve_antibot` on, so the browser launches hardened: the fork drops the
display-only headless switches the helper's argv carries
(`--hide-scrollbars`, `--force-color-profile=srgb`, the touch-pointer
`--blink-settings`, window placement and the like) and adds `--screen-info`,
scale and window size for one common display (a 14" MacBook Pro screen on
macOS, a 1080p screen elsewhere), a wide-gamut colour profile on macOS, and
`--user-agent` with the pinned value. Pages see that display in every frame,
never the operator's own monitors, their layout or the menu bar and Dock
settings, and the helper's self-check fails if the fork would describe the
host's displays instead. Nothing else changes: the deny
proxy, the sandbox, the seeded profile, the pipe and every other switch are
as built, and the helper's self-check fails if the launch argv differs from
that in any other way. Each page is hardened in every frame and worker before
it navigates. After navigation the page is read without touching its own
JavaScript world and checked for DataDome, HUMAN (PerimeterX), Akamai,
Imperva, AWS WAF, Kasada and Cloudflare; a detected vendor's handler runs
until the pass's budget less a tenth (1–3 s), and a solved page is checked
again, up to three layers; until a new document loads, that check keeps the
status and headers the page was detected with, so a block page that never
changed is never reported solved. Handlers navigate only within the page's origin
and the vendor's own challenge frames and type only into vendor widgets. The
outcome maps to `challenge`: nothing detected is `none`, every layer solved is
`solved`, anything else `unsolved`. A hard ban, and anything a captcha solver
touched or needs, is not retried in a fresh context; other unsolved pages are,
once, with at least 15 s left. The retry pass gets only the time left of the
browser budget, so its handlers and any paid solve end inside it.

**Captcha solvers.** Optional and paid by the operator.
`SCARLETT_WEB_SOLVERS` lists providers (`capmonster`, `capsolver`,
`2captcha`; `twocaptcha` is accepted) and needs the browser tier. Each listed
provider needs `SCARLETT_WEB_SOLVER_<PROVIDER>_KEY_FILE`: a clean absolute
path to a regular file only its owner can read (mode 0600 on macOS and Linux;
on Windows a file whose ACL grants only you and SYSTEM, below such a
directory, such as the node's state directory), at most 4 KiB, holding one key
of 8–256 printable characters. A key file for an unlisted provider, or a
solver setting without the list, is a configuration error, and errors name the
variable, never the key. `SCARLETT_WEB_SOLVER_MAX_SOLVES_PER_FETCH` (1–4,
default 2) caps paid solves per page, `SCARLETT_WEB_SOLVER_MAX_USD_PER_DAY`
(up to six decimals, default 1.00) caps the providers' estimated spend per UTC
day, and `SCARLETT_WEB_SOLVER_EXPERIMENTAL=on` lets them take DataDome's
jigsaw slider and Turnstile challenge pages. The node reads the keys once at
start and passes them to each helper in `WEB_SOLVER_CONFIG`, which the helper
removes from its environment before the driver or the browser start. The
helper reaches the providers directly over TLS verified against certifi's
roots, never through the page's proxy or `SCARLETT_WEB_EGRESS_PROXY`, and
never hands a provider a proxy. For a token (Turnstile, hCaptcha, AWS WAF) a
provider sees the challenge's site key and the page's address cut to
`scheme://host/path`, never its query string, fragment or credentials (the
AWS WAF task also carries the challenge's own `gokuProps` and script URLs);
for a recognition task (DataDome's jigsaw slider, AWS WAF's image grid) it
sees only the puzzle images and the question. Nothing else. DataDome's
slide-to-target slider is not dragged (a live drag ended in DataDome's
hard-block page, which then holds for the operator's IP): it ends the pass
as unsolved with no solver need, and the fresh-context retry runs.
Routing is by challenge
type with fallback: tokens (Turnstile, reCAPTCHA, GeeTest, AWS WAF) go to
CapMonster Cloud first, image and slider recognition to CapSolver, and
FunCaptcha to 2Captcha, each falling back to the next configured provider; a
provider that reports a bad key, an empty balance or throttling rests for a
while. Spend is counted when a task is sent to a provider, at its estimated
price (the provider's own figure replaces it when it reports one), so a task
abandoned at the deadline or lost to network errors still counts; only
failures providers do not bill (a refused task, an unsolvable challenge) are
refunded, and a provider that fails after accepting a task is not followed by
another for the same challenge. Both passes of a fetch share one budget
(`SCARLETT_WEB_SOLVER_MAX_SOLVES_PER_FETCH` covers the retry too) and one
ledger, and the helper reports that ledger's total for the fetch, also when
the fetch timed out. The node adds it to
the day's total in `<state>/web-browser/solver-spend.json` (private) and,
once the cap is reached, sends the helper `"solver": false` until the next UTC
day. The helper's `/v1/capabilities` names the providers it built, and a
helper that built anything but the configured set never becomes ready. The
browser upload carries `solver: "used"` when a paid solve cleared the page and
`"needed"` when the page stopped at a captcha a provider can take (a
Turnstile gate, Imperva's hCaptcha, an AWS WAF captcha, DataDome's jigsaw
slider) or after a paid solve that did not clear it; a ban, a press-and-hold,
a block and widgets no provider takes never set it. The
coordinator remembers such a domain and offers its browser jobs to nodes that
report `solvers` first. The desktop app does not configure solvers yet; a
keychain-backed setting is the planned next step.

**DOM.** The helper writes the rendered document's DOM (UTF-8, at most 64 MiB,
never cut) to a private file `dom-*.html` (0600, exclusive) in its own temporary
directory and answers only `html_path`, `html_bytes` and `html_sha256`; its JSON
answer is at most 1 MiB. The node moves the file into its private
`<state>/web-browser/dom/` directory, checks its size and SHA-256 there, and
deletes it after the upload (and its gzip copy) or on failure; that directory
is emptied once per node start. A DOM over 64 MiB is never written: the helper
answers `failed` with `error: "too_large"` and `html_bytes`.

**Upload.** The DOM is compressed once with gzip level 6 into a private file,
which is cut into parts of 2097152 bytes (the last 1–2097152), at most 33.
`upload_sha256` is the SHA-256 of the whole gzip stream. The node reads the
stored set (`GET …/browser-result/parts`), sends each part it lacks with
`PUT /api/node/v1/jobs/{job_id}/browser-result/parts/{n}` (headers
`X-Scarlett-Attempt`, `X-Scarlett-Fence`, `X-Scarlett-Request-SHA256`,
`X-Scarlett-Upload-SHA256`, `X-Scarlett-Part-SHA256`; one part in memory at a
time), then posts the manifest, plain JSON of at most 256 KiB, to
`/api/node/v1/jobs/{job_id}/browser-result`: today's metadata without the DOM,
plus `dom` (`ok`, `too_large` with `html_bytes` and no parts, or `memory` with
`tree_peak_bytes` when the node killed its browser before the page finished),
`html_bytes`, `html_sha256`, `gzip_bytes`, `upload_sha256` and the part
digests. A manifest answered `409 parts_incomplete` sends what is missing
once more and posts again; a coordinator that holds parts under another upload
sha replaces them. Response headers are lowercased and kept only as token
names of at most 64 bytes with printable values of at most 4096 bytes (128
pairs and 65536 bytes in total), never `set-cookie` or `cookie`;
`set_cookie_names` carries names only. `started_at_ms` and `duration_ms` come
from the node's clock around the browser phase. Every request uses the node's
coordinator transport and version headers but its own client without the 10 s
timeout, runs under the report deadline, and is tried at most three times (1,
2 and 4 s apart, or the coordinator's longer `Retry-After`), retried only after
a transport error, 429 or 5xx; a part try starts only while `max(10 s, part
size / 250 kB/s + 5 s)` remains, a manifest try while 3 s does. A too_large or
memory manifest still runs the proven re-fetch, so the coordinator can serve
it. An upload that is not stored is logged once it gives up, with the route,
the status and the coordinator's error code, the DOM state and the part
counts, and nothing else: `web browser: result upload not stored (dom ok, 2
parts sent, 0 skipped, 1 retries): PUT part: coordinator HTTP 409 fenced`.
The job is still served from the re-fetch, so this line is the only sign on
the node that the coordinator never received the browser's result.

**Clearance cookies.** The Cookie for a re-fetch hop holds only cookies whose
names are on the allowlist the verifier enforces: exactly `cf_clearance`,
`__cf_bm`, `_cfuvid`, `datadome`, `_abck`, `bm_sz`, `ak_bmsc`, `bm_sv`,
`bm_s`, `bm_so`, `bm_sc`, `bm_lso`, `bm_mi`, `sbsd`, `sbsd_o`, `sec_cpt`,
`pxcts`, `reese84`, `___utmvc`, `aws-waf-token`, `KP_UIDz`, `KP_UIDz-ssn`,
`tkrm_alpekz_s1.3`, `tkrm_alpekz_s1.3-ssn`, or a name starting with `_px`,
`incap_ses_`, `visid_incap_`, `nlbi_` or `incap_sh_` followed by at least one
more byte.
Each must match the hop's host (host-only, or a domain cookie for the host or
a parent) and path, be unexpired, and have a valid name and value; secure
cookies are sent only over `https`. Longer paths come first, then the browser's
order, capped at 50 pairs and 4096 bytes, in the grammar
`name=value; name=value`. A hop with no matching cookie sends no Cookie line.
The verifier records the cookie names and a SHA-256 of the value, never the
value. Cookie values reach the node only over loopback from the helper, live
for one job and are never logged, uploaded, stored or reported.

**User-Agent.** The browser and every re-fetch hop send exactly
`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36`
on macOS, with `Windows NT 10.0; Win64; x64` or `X11; Linux x86_64` in place of
the platform on Windows and Linux. The verifier accepts only these for the
pinned browser major.

**Isolation.** New headless mode only, and never the operator's browser. The
Chrome sandbox stays on; where Linux blocks unprivileged user namespaces the
tier reports `sandbox_unavailable` instead of running without it. Each launch
gets a fresh profile under `<state>/web-browser/tmp/` (wiped before every
start), which the helper creates and seeds before the browser opens it, and
each job a fresh browser context with no permissions, downloads off, muted
audio, a mock keychain and basic password store, and invalid certificates
refused. The helper
inherits only an allowlist of environment variables, with HOME, the temporary
and cache directories and the crash-dump location inside node state and no
display, D-Bus or proxy variables. On macOS the node unregisters its browser
from LaunchServices after each stop and before removing an old version; the
one file outside node state it can leave is
`~/Library/Preferences/com.google.chrome.for.testing.plist`, which is shared
with any Chrome for Testing the operator runs and is therefore never deleted.
On Windows the helper runs in a Job object with no window and below-normal
priority; on macOS and Linux at nice 10.

**Operating-system reach.** A page must not open an app, show a system prompt
or crash the browser on the operator's machine, with or without a click (the
Cloudflare solver's click is a real user gesture). The helper passes the
browser's whole argv itself, Patchright's defaults unchanged, so that the
browser starts on the profile it seeded; its `Default/Preferences` holds:

- The URL blocklist preference (the one the `URLBlocklist` policy sets) with
  `mailto:*`, `news:*` and `snews:*`, Chrome's always-allowed external
  schemes. Chrome 155 still hands `mailto:` to the OS mail client without a
  prompt, and without a gesture once per start. A blocked navigation fails in
  the browser before Chrome's external-protocol code runs. The preference is
  read from the profile like any other, so no administrator rights are
  needed; command-line policies exist only on Android, and no switch turns
  external protocols off.
- Protocol handlers for `mailto:` and `news:`, the second layer, pointing at
  `https://scarlett-blocked.invalid/?u=%s` and usable in the job contexts
  (which are off-the-record children of the profile). A registered handler
  takes precedence over the OS handler, so the link becomes an https
  navigation that the egress proxy refuses by name before any lookup. Chrome
  for Testing never registers itself with the OS as a default handler.
- The "don't allow sites to ask" setting for Bluetooth, USB, HID and serial
  devices. `requestDevice` and `requestPort` reject with `NotFoundError` (HID
  resolves with an empty list) before any scan; a scan made a macOS Bluetooth
  privacy request and crashed the browser.
- Screen capture off (the setting behind the `ScreenCaptureAllowed` policy):
  `getDisplayMedia` rejects with `NotAllowedError` before its picker, which
  made Screen Recording privacy requests.

Camera and microphone are fake devices (`--use-fake-device-for-media-stream`),
so `getUserMedia` is refused without a device or a prompt. The helper also
fails any document response that redirects to a scheme other than http(s): a
3xx is followed like a typed navigation, which skips Chrome's anti-flood check
for external protocols. If that check cannot be set up on a page, the helper
closes the page before it navigates and the fetch fails; a fetch whose
challenge handling did not finish fails too, never reported as a success.
Every other external scheme (`tel:`, `sms:`, `facetime:`, `itms-apps:`,
`intent:`, an app's own scheme) reaches Chrome's external-protocol dialog,
which the hidden browser never shows, so nothing is opened; blocking those
too would make their frames load an error page, which a normal Chrome does not
do. `file:` and `chrome:` navigations from a page are refused by Chrome
itself, and `javascript:`, `data:` and `blob:` stay in the browser.

What a page can still tell: Bluetooth reports `getAvailability()` false and
its refusal reads "User or their enterprise policy has disabled Web
Bluetooth." rather than the cancelled-chooser text; screen capture reads
"Permission denied" rather than "Permission denied by user"; a frame sent to
`mailto:`, `news:` or `snews:` loads an error page, as with a webmail handler
that is unreachable. The redirect check covers the page's main frame and its
same-process frames; a redirect in a cross-site frame, a pop-up or a service
worker reaches the blocklist, the handlers and the dialog instead.

**Network.** Every page context uses a loopback filtering proxy in the node.
It accepts `CONNECT host:443` and absolute-form `http://host[:80]` requests
only, applies the canonical host rules and reserved names before any lookup,
resolves with a 5 s limit, refuses the request if any address fails the
egress guard, and dials exactly the checked address. The browser's own
background traffic is sent to a second loopback listener that answers 403 to
everything and never dials or resolves. QUIC is disabled, WebRTC may not send
UDP outside the proxy, and multicast DNS candidates are off. Tunnels are capped
at `32 × capacity + 16` per helper, 60 s idle and 128 MiB each. Hosts are never
logged; only counters are kept.

**Lifecycle.** At start, with web and the tier on, the node prepares in the
background: memory check, cleanup of crash dumps and partial downloads, runtime
extraction and full verification, browser download and verification, then one
launch-and-close probe. The helper starts on demand, or early for a browser
offer or the pre-warm hint, stays warm while jobs flow and stops after the idle
time (30 s after a pre-warm that served nothing). It is recycled after 50 pages,
or, draining first, when the memory of its whole process tree passes
`recycle = 1.25 GiB + 0.75 GiB × capacity`: the pages in flight finish, then
the helper restarts. It is killed at once above `kill = max(recycle + 1.5 GiB,
physical memory / 4)` (`kill_bytes` in the heartbeat; on Windows the job
object's limit is `kill + 2 GiB`). On macOS the node also reads the host's
memory pressure level (`kern.memorystatus_vm_pressure_level`, sampled every
500 ms while a page renders): with a page in flight, critical kills the helper
at once whatever its size; warn only drains above the recycle size, so a large
page finishes (warn is common on healthy Macs). The diagnostics log names the
action: `kill_size`, `kill_critical` or `recycle_after_page`. A page in flight
when the helper is killed still runs the proven re-fetch and posts a `memory`
manifest with the largest tree size sampled while it loaded
(`tree_peak_bytes`); the coordinator may send the job once more to a node whose
`kill_bytes` is at least 1.5 times that. Elsewhere the tree-size limits stand
alone. A failed preparation is retried after 60 s, doubling to 1 h; a
restart retries at once. `memory_low` is not retried until the node restarts.
Three start failures within ten minutes make it `helper_failed` for ten
minutes. A full verification of the runtime and browser repeats every six hours
while no helper is warm.

**Readiness.** The enabled web entry always carries `browser`:
`{"state":"ready","capacity":N,"in_flight":M,"version":"155.0.8059.39","kill_bytes":K}`,
with capacity 1–4 and at most the web capacity, `kill_bytes` the tree size at
which this node kills its browser (above), and, when solvers are configured and
the day's spend is under its cap, `"solvers":["capmonster","capsolver"]`
(provider names in that order, never keys), or
`{"state":"unavailable","reason":R,"capacity":0,"in_flight":0}`. A browser job
also counts in the web entry's `in_flight`.

| Reason | Meaning |
| --- | --- |
| `disabled` | `SCARLETT_WEB_BROWSER=off` (the Windows default in this release) |
| `web_unavailable` | Web itself is not offerable: helper missing, relay halted or proxy rest |
| `memory_low` | Under 8 GiB of physical memory; not checked again until the node restarts |
| `disk_low` | Not enough free disk to extract, download or start (1.5 GiB before a download or extraction, 512 MiB at helper start) |
| `runtime_missing` | No runtime archive in the resource directory |
| `runtime_invalid` | The archive or the extracted runtime failed verification |
| `browser_downloading` | The browser download is in progress |
| `browser_download_failed` | The download failed; it is retried with backoff |
| `browser_invalid` | The extracted browser failed verification |
| `deps_missing` | Linux shared libraries are missing |
| `sandbox_unavailable` | Linux unprivileged user namespaces are blocked |
| `helper_failed` | The preparation's launch-and-close probe failed (retried with the 60 s to 1 h backoff), three helper start failures within ten minutes (a ten-minute rest), or any state the node cannot name |

**Diagnostics.** A browser job is recorded as operation `scrape` with proof
mode `browser`; the browser phase and the upload are node spans
`browser_fetch` and `browser_upload` (exchange 0), and the re-fetch hops are
exchanges 1–6 as for a relay job. No URL, host, header, cookie or page content
is kept.

The coordinator must reject incompatible new assignments and check limits again
before funded acceptance. Legacy heartbeats can still report health, but cannot
establish compatibility for new paid work. Roll out the coordinator parser before
nodes publish the added fields. Existing local worker checks remain in force.
