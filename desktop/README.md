# Scarlett Node desktop

Tauri 2 with bundled vanilla TypeScript. The native bridge delegates execution and account scheduling to the independently built Go node and its Rust proof helper. It does not embed the private Scarlett application.

The desktop provides pairing, status, start/drain/resume/stop, a menu-bar/tray supervisor and account controls. Account management requires the native pool release; older node binaries show it as unavailable. Automatic Codex token refresh for the proof-only runtime, browser import, signed public installers, automatic updates and native Windows private-storage/process support remain separate release gates. The Mac development app is unsigned and is not a community release.

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
- Desktop Codex login uses the native CLI at the fixed bundled resource path and requires exactly `codex-cli 0.159.2`. It opens official login in a separate app-owned profile with file cache explicitly selected, then registers that profile through the CLI. It does not reuse `~/.codex` or discover a CLI on PATH. Missing or incompatible bundled CLI disables Connect Codex. Login and model entitlement remain distinct.
- X connects only the two approved cookie fields through protected stdin, preserving node validation and storage. Remove updates the private registry; the running node stops new admission on its next scheduling observation and retains credentials until safe explicit disposal after drain; it does not revoke the upstream session.
- Total service concurrency remains the native default of one per service in this slice. Per-account limits cannot increase that total. Broader local capacity/preferences belong in the account-management integration.

The native pool contract landed in [node PR 27](https://github.com/teslashibe/scarlett-node/pull/27), merged at `5ea00650`. This desktop branch includes that main revision. Rebuild both sidecars from the reviewed combined checkout before real account testing. An explicit missing app-owned registry lists no accounts and fails closed for new work; unrelated host profiles are not inherited.

## Local release validation

Debug builds accept explicit `SCARLETT_DESKTOP_LOCAL_COORDINATOR`, `SCARLETT_DESKTOP_LOCAL_COORDINATOR_CA`, `SCARLETT_DESKTOP_LOCAL_VERIFIER` and `SCARLETT_DESKTOP_LOCAL_VERIFIER_CA` environment variables at startup. The coordinator must be a loopback HTTPS origin with its own absolute regular CA file with an explicit unprivileged port; credentials, paths, queries and fragments are rejected. The verifier must be a literal loopback socket address and requires an absolute regular CA file. Its certificate and server name are still verified by the existing native TLS client. There is no plaintext or insecure TLS option; the local verifier certificate must cover its supplied loopback address.

For example, the release owner can start the debug executable with coordinator `https://localhost:18443`, the coordinator CA path, verifier `127.0.0.1:17047` and the isolated verifier's CA path. Remote overrides fail startup. Release builds ignore these variables and retain the public defaults. Pair only disposable test identities against the isolated local API; the app uses its own private state directory.

## Security and lifecycle

Only the bundled main webview can invoke the explicit custom commands. Production navigation and native invocation reject remote pages and lookalike origins; no JavaScript shell/filesystem permissions are granted. The OS browser opens fixed Network destinations only. UI values are inserted as text, and unknown CLI/provider errors become fixed messages.

Pairing codes and X cookies are cleared from masked form inputs after submission, never used as process arguments/environment, and not persisted by the webview. Raw command stdout/stderr is not returned to JS or logged. The node receives an allowlisted environment with app-owned paths; unrelated credentials and fixture flags are not inherited. File-based credentials remain private local files, not encrypted vault storage. Optional vault support requires a compatible reader/refresh adapter before it can advertise capacity.

Closing the main window hides it in the tray/menu bar. Explicit Quit requests drain and sends graceful termination to the supervised node, allowing the node's existing two-minute accepted-work window before a bounded forced stop. The journal remains the execution/recovery authority; the shell never retries provider work or reconstructs a receipt. Stop does not unpair/revoke a node. A second instance focuses the existing window and the node retains its journal lock.

Native Windows storage and graceful process controls must land and be independently validated before enabling Windows runtime operations. Current Windows controls return `windows_pending`; a portable webview alone is not proof of Windows support.

Tests use synthetic credentials and disposable temporary directories/fake executables. Launching the app does not itself start provider work: Start remains explicit. Real account/canary testing and production validation belong to the release owner.

## Complete runtime package

The complete bundle contains the desktop shell, native Go node, Rust proof helper, `open-agent-api` v0.1.28, Codex CLI 0.159.2 and Claude CLI 2.1.286. Users do not need a development toolchain to run these packaged binaries. The model API binary is packaged but its desktop supervisor and configuration UI are still required before the desktop exposes a usable local chat endpoint. The node's verified network services remain Codex and X; packaging Claude does not add a verified Claude network service.

Build on the target OS and architecture. Prepare the three reviewed native binaries and the official unpacked native provider packages, then run:

```sh
node desktop/scripts/prepare-complete-bundle.mjs \
  /absolute/scarlett-node /absolute/scarlett-prover /absolute/open-agent-api \
  /absolute/codex/package /absolute/claude/package
cd desktop
npm run tauri build -- --debug --config src-tauri/tauri.complete.generated.json
```

Use `.exe` binary paths on Windows. The preparation script verifies native provider versions, the model API's reviewed release, Go package/target metadata and regular files. It preserves the provider binaries and bundled notices, and records resource and sidecar SHA-256 hashes in `runtime/COMPONENTS.json`. The archive verifier uses fixed SHA-512 pins for all three native provider targets. Generated resources and the config overlay are ignored.

On Mac, validate the installed payload with:

```sh
python3 desktop/scripts/check-complete-bundle.py \
  "/absolute/Scarlett Node.app/Contents/MacOS" \
  "/absolute/Scarlett Node.app/Contents/Resources"
```

This checks packaged bytes, native CLI versions and the bundled model API's loopback readiness, bearer enforcement and current Codex/Claude model aliases. It uses disposable profiles and makes no provider jobs or login calls. Passing it does not establish real account access, desktop API supervision, a signed installer or Windows installation acceptance. The native desktop workflow builds test DMG/NSIS artifacts; they are never automatically published to the supplier download manifest.

Claude's native package and license are kept intact. Each user must authenticate with their own supported credentials. Commercial use through a separate application must follow the [provider's terms](https://code.claude.com/docs/en/legal-and-compliance); do not route subscription credentials on behalf of other users.
