# Scarlett Node desktop

Tauri 2 with bundled vanilla TypeScript. The native bridge delegates execution and account scheduling to the independently built Go node and its Rust proof helper. It does not embed the private Scarlett application.

This slice provides pairing, status, start/drain/resume/stop, a menu-bar/tray supervisor and account controls. Account management requires the native pool release; older node binaries show it as unavailable. Automatic Codex token refresh for the proof-only runtime, browser import, signed public installers, automatic updates and native Windows private-storage/process support remain separate release gates. The Mac development app is unsigned and is not a community release.

## Build

Use Node 26 and Rust 1.95, plus the platform prerequisites from [Tauri](https://v2.tauri.app/start/prerequisites/).

```sh
cd desktop
npm ci --ignore-scripts
npm test
npm run build
npm run prepare:sidecars -- /absolute/reviewed/scarlett-node /absolute/reviewed/scarlett-prover
cd src-tauri
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Then run `npm run tauri build -- --bundles app` from `desktop` on Mac. The sidecar preparation script copies only explicitly supplied native binaries, records their target names and makes no provider calls. Review source/digest provenance before preparing release binaries. Generated assets, downloaded dependencies and binaries are ignored; both dependency lockfiles are tracked. The production bundle uses the copies next to the app executable, never a renderer-provided path or a node discovered on PATH.

## Native dependency contract

- Coordinator: `https://network.scarlett.ai`; verifier: `verifier.scarlett.ai:7047`, with normal public TLS verification. These public defaults were supplied by the release owner. There is no plaintext test transport or browser networking bridge.
- Node commands: `pair`, `status`, `run`, `drain`, `resume`.
- Pool commands: `accounts list`; `accounts connect SERVICE ID CONCURRENCY` with credential JSON on stdin; `accounts add codex ID ABSOLUTE_PROFILE CONCURRENCY`; `accounts remove SERVICE ID`.
- Pool list: an array of `{id,service,concurrency}`. Local status can contain `accounts[{id,service,state,capacity,in_flight,last_error_code,rest_until}]`. Only bounded selected metadata reaches JS.
- Services: `codex` and `x_read`. IDs use lowercase letters/digits/underscore/hyphen, 1–32 characters; `legacy` is reserved. The binary owns maximum eight accounts/provider, concurrency, cooldown and pinned-attempt recovery.
- Desktop Codex login detects an actual executable reporting exactly `codex-cli 0.159.2`, opens official login in a separate derived app-owned profile with file cache explicitly selected, then registers that profile through the CLI. It does not silently reuse `~/.codex`, read the user's existing login or claim that the CLI is bundled. Missing/incompatible CLI disables Connect Codex. Login and model entitlement remain distinct.
- X connects only the two approved cookie fields through protected stdin, preserving node validation and storage. Remove updates the private registry; the running node stops new admission on its next scheduling observation and retains credentials until safe explicit disposal after drain; it does not revoke the upstream session.
- Total service concurrency remains the native default of one per service in this slice. Per-account limits cannot increase that total. Broader local capacity/preferences belong in the account-management integration.

The native pool contract landed in [node PR 27](https://github.com/teslashibe/scarlett-node/pull/27), merged at `5ea00650`. This desktop branch includes that main revision. Rebuild both sidecars from the reviewed combined checkout before real account testing. An explicit missing app-owned registry lists no accounts and fails closed for new work; unrelated host profiles are not inherited.

## Local release validation

Debug builds accept explicit `SCARLETT_DESKTOP_LOCAL_COORDINATOR`, `SCARLETT_DESKTOP_LOCAL_VERIFIER` and `SCARLETT_DESKTOP_LOCAL_VERIFIER_CA` environment variables at startup. The coordinator must be a loopback HTTP/HTTPS origin with an explicit unprivileged port; credentials, paths, queries and fragments are rejected. The verifier must be a literal loopback socket address and requires an absolute regular CA file. Its certificate and server name are still verified by the existing native TLS client. There is no plaintext or insecure TLS option; the local verifier certificate must cover its supplied loopback address.

For example, the release owner can start the debug executable with coordinator `http://localhost:18083`, verifier `127.0.0.1:17047` and the isolated verifier's CA path. Remote overrides fail startup. Release builds ignore these variables and retain the public defaults. Pair only disposable test identities against the isolated local API; the app uses its own private state directory.

## Security and lifecycle

Only the bundled main webview can invoke the explicit custom commands. Production navigation and native invocation reject remote pages and lookalike origins; no JavaScript shell/filesystem permissions are granted. The OS browser opens fixed Network destinations only. UI values are inserted as text, and unknown CLI/provider errors become fixed messages.

Pairing codes and X cookies are cleared from masked form inputs after submission, never used as process arguments/environment, and not persisted by the webview. Raw command stdout/stderr is not returned to JS or logged. The node receives an allowlisted environment with app-owned paths; unrelated credentials and fixture flags are not inherited. File-based credentials remain private local files, not encrypted vault storage. Optional vault support requires a compatible reader/refresh adapter before it can advertise capacity.

Closing the main window hides it in the tray/menu bar. Explicit Quit requests drain and sends graceful termination to the supervised node, allowing the node's existing two-minute accepted-work window before a bounded forced stop. The journal remains the execution/recovery authority; the shell never retries provider work or reconstructs a receipt. Stop does not unpair/revoke a node. A second instance focuses the existing window and the node retains its journal lock.

Native Windows storage and graceful process controls must land and be independently validated before enabling Windows runtime operations. Current Windows controls return `windows_pending`; a portable webview alone is not proof of Windows support.

Tests use synthetic credentials and disposable temporary directories/fake executables. Launching the app does not itself start provider work: Start remains explicit. Real account/canary testing and production validation belong to the release owner.
