# Scarlett Node desktop

Tauri 2 with bundled vanilla TypeScript. The native bridge delegates execution and account scheduling to the independently built Go node and its Rust proof helper. It does not embed the private Scarlett application.

The desktop UI supports X account setup, pairing, status, start/drain/resume/stop and a menu-bar/tray supervisor. Codex connection, Claude connection and local model API controls are hidden for this release. Saved model accounts, credentials, native commands and bundled runtimes remain available for compatibility; model accounts and their historical measurements are excluded from the desktop display. Account management requires the native pool release; older node binaries show it as unavailable. Real-account acceptance of automatic Codex token renewal, automatic updates and full installed Windows GUI acceptance remain separate release gates. Release installers are signed with Scarlett's own stable self-signed certificates by the release workflow (see [Release signing](#release-signing)); they are not notarized by Apple and Windows shows an unknown publisher. The Mac development app is unsigned and is not a community release.

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

## UI preview

Run `npm run dev` from `desktop`, then open `http://127.0.0.1:1420/tests/preview.html`. This development page renders the desktop UI with synthetic accounts and intercepts every native command. It does not read installed node state or contact providers, and it is excluded from the production bundle.

Use `?scenario=ready`, `unpaired`, `relay-halted`, `auth-required`, `pending-login` or `running-local-api` to check the main states, `web-only`, `web-off`, `browser-downloading`, `browser-off` or `history-full` for the web tiles, and `available`, `required`, `downloading`, `draining`, `updated` or `rolled-back` for the update notices. Controls update only the fixture. Check the default 960 × 760 window and the minimum 640 × 560 window, including keyboard expansion, account re-import and login verification.

## Native dependency contract

- Coordinator: `https://network.scarlett.ai`; verifier: `verifier.scarlett.ai:7047`, with normal public TLS verification. These public defaults were supplied by the release owner. There is no plaintext test transport or browser networking bridge.
- Node commands: `pair`, `status`, `run`, `drain`, `resume`, `relay-resume`.
- Pool commands: `accounts list`; `accounts connect SERVICE ID CONCURRENCY` with credential JSON on stdin; `accounts reconnect x_read ID` with cookie JSON on stdin; `accounts import-x PROFILE_ID ID CONCURRENCY`; `accounts reimport-x PROFILE_ID ID`; `accounts add codex ID ABSOLUTE_PROFILE CONCURRENCY`; `accounts remove SERVICE ID`.
- Pool list: an array of `{id,service,concurrency}`. Local status can contain `relay_halted`, `services[{kind,state,capacity,in_flight,last_error_code,proof_modes}]` and `accounts[{id,service,state,capacity,in_flight,last_error_code,rest_until}]`. Proof modes are reduced to `mpc` and `relay`. Only bounded selected metadata reaches JS.
- Services: `codex` and `x_read`, plus `web` when web is on (see [Web pages](#web-pages)). IDs use lowercase letters/digits/underscore/hyphen, 1–32 characters; `legacy` is reserved. The binary owns maximum eight accounts/provider, concurrency, cooldown and pinned-attempt recovery.
- The hidden Codex connection flow signs in with a ChatGPT account in the browser. Scarlett assigns a local name such as `codex-1`, reserves a new private profile and registers it after successful login, with one concurrent job per account. Repeat to connect another account, up to eight Codex accounts; at eight, Connect Codex is disabled until you remove one. Existing profiles, including cancelled login directories, are never reused. On Windows the profile is created by the fixed `desktop private-dir-new` helper with its current-user/SYSTEM protected ACL applied at creation; an existing name, including an older unprotected directory, is skipped and never adopted or repaired. No OpenAI account ID or local nickname is required. The native CLI is fixed to the bundled `codex-cli 0.159.2`, with file credential storage explicitly selected; it does not reuse `~/.codex` or discover a CLI on PATH. Missing or incompatible bundled CLI disables Connect Codex. Login and model entitlement remain distinct.
- X connects only the two approved cookie fields through protected stdin, preserving node validation and storage. Remove updates the private registry; the running node stops new admission on its next scheduling observation and retains credentials until safe explicit disposal after drain; it does not revoke the upstream session.
- This device saves a maximum simultaneous X job setting, default 2 and bounded 1–8. The launcher passes it explicitly to the node and caps each authenticated X identity at one job, including aliases. Actual advertised capacity is limited by distinct, ready accounts. Changes apply on the next Stop/Start; saving preferences never restarts accepted work. Codex keeps its native default of one total job. Existing schema-1 preference files load with X concurrency 2 and retain their other values without being rewritten on reads. Saving X concurrency writes a separate private `throughput-preferences-v1.json` extension; `preferences.json` retains the representation desktop 0.1.3 understands for rollback. An invalid extension fails closed.

The native pool contract landed in [node PR 27](https://github.com/teslashibe/scarlett-node/pull/27), merged at `5ea00650`. This desktop branch includes that main revision. Rebuild both sidecars from the reviewed combined checkout before real account testing. An explicit missing app-owned registry lists no accounts and fails closed for new work; unrelated host profiles are not inherited.

Codex admission requires a known access-token expiry beyond the job deadline plus 30 seconds. Expired, malformed or unknown expiry blocks new work before funded acceptance; it does not prevent existing accepted attempts from reconciling. This guard does not establish provider entitlement. While network work runs, the node renews the app's own login profiles itself: the desktop sets `SCARLETT_CODEX_MANAGED_ROOT` to the `codex-logins` directory, and a profile is renewed only between its jobs, once its token expires within 30 minutes. Network work and the local API remain mutually exclusive, so only one process writes a profile at a time. A state path the node would reject as a managed root leaves renewal off rather than stopping the node. A profile the provider has rejected still requires a new login.

## Local release validation

Debug builds accept explicit `SCARLETT_DESKTOP_LOCAL_COORDINATOR`, `SCARLETT_DESKTOP_LOCAL_COORDINATOR_CA`, `SCARLETT_DESKTOP_LOCAL_VERIFIER` and `SCARLETT_DESKTOP_LOCAL_VERIFIER_CA` environment variables at startup. The coordinator must be a loopback HTTPS origin with its own absolute regular CA file with an explicit unprivileged port; credentials, paths, queries and fragments are rejected. The verifier must be a literal loopback socket address and requires an absolute regular CA file. Its certificate and server name are still verified by the existing native TLS client. There is no plaintext or insecure TLS option; the local verifier certificate must cover its supplied loopback address.

For example, the release owner can start the debug executable with coordinator `https://localhost:18443`, the coordinator CA path, verifier `127.0.0.1:17047` and the isolated verifier's CA path. Remote overrides fail startup. Release builds ignore these variables and retain the public defaults. Pair only disposable test identities against the isolated local API; the app uses its own private state directory.

## Security and lifecycle

Only the bundled main webview can invoke the explicit custom commands. Production navigation and native invocation reject remote pages and lookalike origins; no JavaScript shell/filesystem permissions are granted. The OS browser opens fixed Network destinations only. UI values are inserted as text, and unknown CLI/provider errors become fixed messages.

Pairing codes and X cookies are cleared from masked form inputs after submission, never used as process arguments/environment, and not persisted by the webview. Raw command stdout/stderr is not returned to JS or logged. The node receives an allowlisted environment with app-owned paths; unrelated credentials and fixture flags are not inherited. File-based credentials remain private local files, not encrypted vault storage. Optional vault support requires a compatible reader/refresh adapter before it can advertise capacity.

Closing the main window drains and quits by default. Operators can enable background operation to hide it in the tray/menu bar instead. Explicit Quit requests drain and close the supervised node's owner pipe, allowing the node's existing two-minute accepted-work window before a bounded forced stop. The journal remains the execution/recovery authority; the shell never retries provider work or reconstructs a receipt. Stop does not unpair/revoke a node. A second instance focuses the existing window and the node retains its journal lock.

Windows runtime operations require private NTFS storage and the bundled native helpers. Native tests validate ACLs, locking, process trees and owner-pipe shutdown; installed Windows GUI acceptance remains required before publishing its installer.

Windows release signing uses an existing current-user code-signing identity and
the trusted Microsoft SDK SignTool. No certificate or key is imported by the
release helper, and it never adds a trust root. On a disposable native Windows
release runner, set `SCARLETT_SIGNING_SCHEME` (`self-signed-stable` or
`authenticode`; there is no default), `SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT` to
the reviewed public certificate thumbprint and `SCARLETT_WINDOWS_SIGNTOOL` to the
absolute SDK executable. In `self-signed-stable` mode the thumbprint must equal
`windows.sha1` in `desktop/signing/identities.json`. The helper then exports the
pinned certificate SHA-256 (`SCARLETT_WINDOWS_CERT_SHA256`) and the reviewed
RFC3161 endpoint (`SCARLETT_WINDOWS_TIMESTAMP_URL`, exactly
`http://timestamp.digicert.com`) to the Tauri callback and the checker. The
timestamp token is itself signed and verified, so the endpoint is an exact-match
allowlist rather than an HTTPS rule. Keep key access on that runner.

After preparing the complete native runtime, build the release executable with
`npm run tauri -- build --no-bundle --config src-tauri/tauri.complete.generated.json`.
Then run `python scripts/sign-windows-bundle.py <absolute-desktop-checkout> <new-absolute-evidence.json>`.
The helper validates the original inventory, signs Scarlett executables and
the pinned NSIS packaging components,
retains unsigned sidecar hashes and preserves provider bytes. It packages NSIS
with Tauri's binary patching disabled, verifies pinned publisher and trusted
timestamp signatures and tests that exact installer with isolated local state.
Tauri invokes the callback again for files it already signed; the callback
leaves our pinned signature byte for byte and refuses any other signature. Evidence is
written only after installed payload, lifecycle, preferences and browser tests
pass. Real account login, signed upgrade/downgrade and publication remain
separate gates; contract tests and unsigned rejection do not prove real signing.

A failed run prints the fixed summary and one `Reason:` line built only from our
own literal strings: the operation (for example `Signing scarlett-node`), its exit
code and, when one raised it, the literal `throw` reason from
`sign-windows-file.ps1`, `check-windows-signatures.ps1` or
`import-windows-identity.ps1`, optionally followed by SignTool's eight-digit
HRESULT. Python checker failures add the script line and exception class, and
installed acceptance adds its script line numbers. Native messages, paths,
certificate details and secrets are never printed.

Tauri 2.12.1 passes sidecars to the callback relative to `src-tauri`
(`binaries/<name>-<triple>.exe`); the callback resolves a plain relative path
against its working directory and then applies every prepared-root and allowlist
check. The Tauri callback permits exactly its five copied x86 NSIS plugin DLL paths.
Generated x86 uninstallers must match NSIS 3.11's `nst<hex>.tmp` filename inside
a fresh `target/release/nsis-signing-temp` directory. Only the packaging child
receives that directory as TMP/TEMP and explicit callback context; it is removed
on completion or failure. System temporary files, links, unexpected DLLs and
other architectures are rejected. Provider resource callbacks verify exact paths,
sizes and hashes against the finalized component inventory and preserve the
original bytes and signing status; they add no Scarlett publisher signature.

The signing options follow [Microsoft's SignTool reference](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
and [Tauri's custom Windows signing support](https://v2.tauri.app/distribute/sign/windows/#custom-sign-command).

Tests use synthetic credentials and disposable temporary directories/fake executables. Launching the app starts provider work only when the operator's last choice was Start (`resume_serving`, saved by Start and cleared by Stop; quitting and updates leave it unchanged), so a reboot with "Open Scarlett when I log in" brings the node back. A saved Pause (the drain marker) is respected: the node starts paused. Real account/canary testing and production validation belong to the release owner.

## Updates

Device settings → Updates chooses **Notify me when an update is available** (the default) or **Install updates automatically** (`updates` in the private `lifecycle-preferences-v1.json`, beside `preferences.json`, so 0.1.12 and earlier still read their own file on rollback). The app checks a minute after it opens, every six hours (±15 %), within about a minute of the coordinator announcing a release to a running node, and on **Check for updates** (Settings or the tray menu, which also shows "Update available (x.y.z)…").

- Notify mode: a toast "Scarlett Node x.y.z is available" with the release title, up to three highlights, **Update now**, **What's new ↗** (the version's entry on <https://network.scarlett.ai/changelog/>) and **Later** (24 hours). Nothing downloads until Update now, which runs the same verified, drain-safe install as automatic mode.
- Automatic mode: no available toast. The update downloads in the background (4 MiB/s while serving), installs at this node's slot in a four-hour rollout window, or as soon as it is ready when required or when the node is not serving. With the window visible and focused, a one-minute "Installing … when current jobs finish" notice offers **Install later** (an hour, three times; ten minutes once for a required update).
- Required updates (below the coordinator's minimum) show a persistent alert in both modes.
- During an install: "Downloading x.y.z · n %", "Finishing N accepted jobs before updating" (new jobs paused, accepted jobs never interrupted) and "Installing and restarting…", with **Cancel** until the hand-off.
- After an update, a dismissible "Updated to Scarlett Node x.y.z" banner shows the release's highlights (compiled in from `release-notes/<version>.json`, no network needed) and **See what's new ↗**, once per version; the first manual install of a version with the updater also offers **Turn on automatic updates**. A version that fails to start is rolled back and the restored app explains why, with **Download manually ↗**.

The renderer has fixed commands only (`update_status`, `update_check`, `update_install`, `update_cancel`, `update_later`, `update_ack`, `update_dismiss`, `set_update_mode`); every link is built natively from a validated version. Verification, staging, hand-off, health and rollback are in `src-tauri/src/updater.rs` and the node's `internal/update` (see `docs/REFERENCE.md`, "Updater"). Debug builds accept `SCARLETT_DESKTOP_UPDATE_FIRST_CHECK_SECONDS` and pass `SCARLETT_SIGNING_REHEARSAL`/`SCARLETT_UPDATER_REHEARSAL_TRUST` to a node built with `-tags rehearsal`, for loopback rehearsals with throwaway keys; release builds ignore all three.

## Complete runtime package

The complete bundle contains the desktop shell, native Go node, Rust proof helper, `open-agent-api` v0.1.32, Codex CLI 0.159.2 and Claude CLI 2.1.286. Users do not need a development toolchain to run these packaged binaries. The desktop starts and stops the local model API through its native supervisor. The node's verified network services remain Codex and X; packaging Claude does not add a verified Claude network service.

Build on the target OS and architecture. Prepare the three reviewed native binaries and the official unpacked native provider packages, then run:

```sh
node desktop/scripts/prepare-complete-bundle.mjs \
  /absolute/scarlett-node /absolute/scarlett-prover /absolute/open-agent-api \
  /absolute/codex/package /absolute/claude/package
cd desktop
npm run tauri build -- --debug --config src-tauri/tauri.complete.generated.json
```

Use `.exe` binary paths on Windows. The preparation script verifies native provider versions, the model API's reviewed release, Go package/target metadata and regular files. It preserves the provider binaries and bundled notices, and records resource and sidecar SHA-256 hashes in `runtime/COMPONENTS.json`. The archive verifier uses fixed SHA-512 pins for all three native provider targets. Generated resources and the config overlay are ignored.

The repository's Cargo configuration statically links the C runtime for Scarlett's Windows x64 Rust binaries. Keep that configuration when building the proof helper. Native package checks inspect direct and delayed PE imports before starting any service and reject Scarlett executables that require a separately installed developer CRT. The pinned provider binaries and their own dependencies remain unchanged.

On Mac, validate the installed payload with:

```sh
python3 desktop/scripts/check-complete-bundle.py \
  "/absolute/Scarlett Node.app/Contents/MacOS" \
  "/absolute/Scarlett Node.app/Contents/Resources"
```

This checks packaged bytes, native CLI versions and the bundled model API's loopback readiness, bearer enforcement and current Codex/Claude model aliases. It uses disposable profiles and makes no provider jobs or login calls. Passing it does not establish real account access, desktop API supervision, a signed installer or Windows installation acceptance. The native desktop workflow builds test DMG/NSIS artifacts; they are never automatically published to the supplier download manifest.

Claude's native package and license are kept intact. Each user must authenticate with their own supported credentials. Commercial use through a separate application must follow the [provider's terms](https://code.claude.com/docs/en/legal-and-compliance); do not route subscription credentials on behalf of other users.

## Bundled local model API

Local API models expose their reviewed effort levels and normal/Fast modes. Codex Fast requests priority; Claude Fast supports Opus 5.5, Opus 5 and Opus 4.8, subject to provider access and credits, and may fall back to standard execution. Listings do not establish account entitlement or measured speed. Ultra is deferred from this launch. Verified Codex network jobs keep base model IDs, low effort and the default tier; Claude runs through the local API only.

The complete bundle retains native supervision for its bundled model API. The connection and API controls are hidden in the current X-only desktop UI; the following describes the retained native contract. It binds only `127.0.0.1` on an operator-selected port (default 8088), requires a generated 256-bit bearer, and reports Ready only after health succeeds, unauthenticated model access returns 401 and authenticated access returns 200. Show local API key explicitly reveals the private bearer; it clears on window blur or page exit. The file is private to the current user (mode 0600 on Unix; current-user/SYSTEM ACL on Windows), and symlink or shared-file reads fail closed. The bearer is never included in status, logs or process arguments.

Codex clients use only completed app-owned login profiles for registered account IDs, plus bundled profile/scaffold files. Unrelated environment credentials and host profiles are cleared. Connect Claude subscription runs the fixed bundled CLI’s `auth login --claudeai`. Login, status, logout and inference share the app’s private `local-api/claude` directory through `CLAUDE_CONFIG_DIR`; the CLI manages its own per-directory credential storage. No global provider profile, credential or Keychain entry is copied or inspected by Scarlett. A successful known `claude.ai` status enables Claude when starting in subscription mode. Status exposes only connection/pending/error flags, never provider identity JSON. The X-only desktop UI does not poll Claude status or launch its CLI during status refresh. Cancellation and disconnect persist a private admission block, so an unfinished login or failed logout cannot reactivate after restart. Disconnect stops the local API before the official logout command.

API key billing is a separate explicit choice. A personal Anthropic API key stays only in the running service’s environment, is not saved to disk, and must be re-entered after stopping. API-key mode uses a separate private `claude-api-key` directory so it cannot fall back to stored subscription credentials. Billing mode controls are disabled while the API runs. Neither discovery nor readiness establishes provider entitlement.

Authentication metadata and model discovery do not guarantee current subscription entitlement or a successful provider request. The CLI remains responsible for credential expiry, refresh and provider authentication; malformed, unknown, unauthenticated or mismatched-directory statuses disable subscription activation. Claude CLI 2.1.286 reports configured credentials, not token expiry or live entitlement; expired credentials can still appear connected until the CLI refreshes or rejects them during an actual request. Scarlett does not read credential files to infer expiry.

The app permits network execution or the local API at a time, serialized through one native control lock, so independent processes cannot silently exceed account capacity. Adding an account takes effect in the local API after restart; removing a Codex account first stops the API. Quit stops the API before draining the node. Windows private storage uses the Go node’s NTFS, current-user/SYSTEM ACL and reparse-point checks. Local API supervision uses the same native process-tree boundary as node helpers. Full installed Windows GUI acceptance remains a release gate.

## Ownership of local processes

The desktop starts `scarlett-node desktop run` and holds its input pipe open. Stop closes that owned pipe after requesting drain; the node stops admission and lets accepted work finish within the existing two-minute shutdown bound. An unexpected desktop exit also closes the pipe. No runtime PID from a file or status response is signalled. The ordinary terminal `scarlett-node run` keeps its existing signal-based behavior.

The local API runs through `scarlett-node desktop api PORT`. That host selects only the API binary beside its own executable, fixes the listener to loopback and stops its owned API tree when desktop input closes. Unix uses an owned process group; Windows uses suspended startup and a kill-on-close Job Object. Windowless creation does not grant process breakaway. Local API stop can cancel requests in progress; it does not submit them again.

The Windows bridge creates or checks private directories before starting the webview and obtains its bearer through fixed `desktop private-dir` and `desktop bearer` helpers. Existing broad ACLs, symlinks/reparse points and unsupported filesystems fail closed. The API bearer stays in the private local file and protected helper output; it is never a process argument or a status field.

## Import an X browser account

Choose a local account ID, select a browser profile, tick the X-session consent box, then press **Import X account**. Close the selected browser first so its cookie database has no active journal. Browsers with custom profile locations can use the existing masked cookie-paste form.

Profile discovery reads directory/file metadata only. It returns opaque profile IDs and labels, without cookie-store paths or account credentials. Import reads only `auth_token` and `ct0` for a complete, secure, unexpired root-domain X/Twitter session at `/`. It keeps container/partition sessions separate and refuses conflicting identities. Credentials go directly from the native reader to the private account file; the renderer receives only success or a fixed error code. Existing accounts are never overwritten.

| Browser | Mac | Windows | Limits |
| --- | --- | --- | --- |
| Chrome | Standard Google Chrome profiles; plaintext or v10 CBC cookies, with normal Keychain approval | Standard Google Chrome profiles; plaintext or v10 GCM cookies, with current-user DPAPI | App-bound v20 cookies are protected; use cookie paste. No password fallback, elevation or protection bypass |
| Firefox | Standard Firefox profiles | Standard Firefox profiles | Root-domain session cookies in a closed SQLite store; containers are kept separate |
| Safari | Standard container or legacy `Cookies.binarycookies` | Unavailable | macOS may deny access; use cookie paste. Scarlett does not grant itself Full Disk Access |

The helper uses a bundled, cgo-free SQLite reader, opens stores read-only and immutable, and refuses populated WAL/journal files. It neither copies nor changes a browser database. Cookie-store changes during import fail with a retry message. Unsupported or inaccessible stores do not add an account. Linux CLI builds support standard Firefox profiles only; the desktop release targets remain Mac and Windows.

Tests use disposable synthetic databases, encrypted cookie fixtures and malformed Safari records. Windows native tests generate their own current-user DPAPI fixture. These checks do not establish compatibility with every installed browser version or prove real X access. Imported accounts remain **Configured · access not verified** until the node reports on them. While the running node checks an X account's login it shows **Warming up · checking login**.

### Re-import an expired X session

When X expires or revokes a session, the account shows **X session expired or revoked. Re-import the account** with an **Import X account again** button. The button opens the same import form for that account: its ID and job limit are fixed, and either a browser profile import (with the same consent tick) or cookie paste replaces only its saved session through `accounts reimport-x` or `accounts reconnect`. Import and Connect X still never overwrite an account. The node validates the new session before replacing the old one, and the running node picks it up on its next scheduling check without a restart. Until the node writes a newer status, the row says it is waiting for the node to check the new login.

## Keyed relay halt

When the node cannot verify a relay request it stops serving keyed relay and keeps serving MPC-TLS. This includes a request mismatch or a connection ending before the verifier opens the request record; the pause alone does not establish misuse. The app shows a red **Keyed relay is paused on this node** banner. **Resume relay** asks for confirmation, then runs only the bundled node's `relay-resume`, which removes the saved `relay-halt` marker. The running node observes that removal during its next admission or service-health check and advertises relay again. It never drains, stops or restarts the supervised node, so warm X clients and accepted work continue. Until its status stops reporting `relay_halted`, the banner says the resume is saved. Filesystem errors or a halt that could not be saved keep relay paused. The node section shows what the running node advertises for X: **MPC + relay** or **MPC only**.

In desktop releases through 0.1.7, removing the marker does not clear the running node's memory latch. After the operator checks the verifier, use **Stop**, **Resume relay**, **Start node**, then **Resume** to clear that existing halt and restore normal admission. Stop lets accepted work finish; saved accounts and credentials remain on the device.

## Web pages

The app serves web pages by default. **Serve web pages** in Device settings turns it off or on again. The switch is saved at once through the fixed `set_web_serving` command and applies to the next node start: a running node is never drained or restarted by it, and until the operator stops and starts it the settings panel says the change is waiting. The setting lives in the private `web-preferences-v1.json` (`{"schema":1,"serve_web":false}`) beside `preferences.json`; absent means on. Desktop 0.1.13 and earlier decode `preferences.json` and its other extensions strictly and never open this file, so they still start after a rollback; they serve web only when started with `SCARLETT_DESKTOP_WEB=1`, a variable 0.1.14 no longer reads. An invalid file fails closed like the other extensions.

With web on, the launcher sets `SCARLETT_SERVICES=codex,x_read,web` and `SCARLETT_WEB_CONCURRENCY=4`, and **Start node** is enabled for a paired node with no X account, because web needs no provider account. `SCARLETT_WEB_BROWSER` from the same environment is passed to the node only with web and only as `on` or `off`; unset, the node's platform default applies (the browser tier on for macOS, off for Windows in this release). The app never passes `SCARLETT_WEB_EGRESS_PROXY`, so a node that must send web traffic through a residential proxy runs headless. Nor does it pass the captcha-solver settings (`SCARLETT_WEB_SOLVERS` and the provider key files): solvers run on a headless node for now, and a setting that keeps the keys in the macOS keychain and hands them to the node at start is the planned next step. A keyed relay halt stops web too, since web has no MPC mode; **Resume relay** restores it. The snapshot the app keeps from local status carries the web entry's `egress` and reduces its browser tier to `state`, `reason`, `capacity`, `in_flight` and `version`. Below the X tiles at the top of the app, a row of web tiles shows **Web pages** (On, Off or Paused with the reason, from what the running node reports, or the saved setting while it is stopped; a full receipt journal reads as Paused), **Available web slots** (free web capacity, zero while the node is stopped or paused, like the X slots), **Web pages served** (web attempts that finished and reported successfully, with how many the hidden browser rendered) and **Hidden browser** (Ready, Downloading, Unavailable with the reason, or Off). While the node is stopped the browser tile reads Off. Its note says relay pages only when the next node would run without the browser (`SCARLETT_WEB_BROWSER=off`, or Windows by default; the snapshot carries this as `web_browser`), and otherwise that the running node checks it, since memory, disk and the download decide whether the browser gets ready. The served count reads the bundled node's `diagnostics` history. The node keeps 24 hours of attempts of every kind, but at most 200 and at most 1 MiB by its own size estimate (700 bytes an attempt, 144 a span, 512 an X quota snapshot), and a busy web node, at about 37 spans a page, reaches the size bound first with about 175 pages. The app applies the same estimate, counting one quota snapshot per X page because it never receives them; when the history holds 200 attempts or comes within 48 KiB (one attempt's maximum) of 1 MiB, the node may have dropped attempts, and the tile says the time its count starts from instead of the last 24 hours. Nothing new is written to disk for these tiles. The [network dashboard](https://network.scarlett.ai/dashboard/) shows the web service and its browser readiness as the coordinator sees them.

## Device preferences

Device settings saves the window-close choice, maximum simultaneous X jobs and Serve web pages in the private app directory, preserving the hidden saved local API port. New installations default to port 8088 and drain/quit when the window closes. Operators can explicitly choose to keep running in the menu bar or tray. Open Scarlett in the native menu (Cmd/Ctrl-1), the tray, macOS Finder/Dock reopen and Windows duplicate launch restore the existing window without starting a second runtime. Saved ports apply on the next local API start; updating a preference does not interrupt accepted jobs or start a service. Corrupt/private-storage failures are reported rather than silently resetting preferences.

Open Scarlett when I log in is a separate OS setting, disabled until the operator opts in. The native Tauri autostart manager queries the actual OS registration and uses a macOS LaunchAgent or Windows user startup registration. It registers only the installed app, without credentials or provider arguments. Opening at login still requires the operator to start the node or local API. The renderer receives no direct autostart-plugin permissions; fixed local-window commands own this setting. A failed setting change is reported and the UI rereads OS state. Moving an app after enabling login launch requires disabling/re-enabling it at its new installed location.

Go preference persistence tests use disposable private directories, including repeated reads/writes, invalid version/port/secret input, corruption and concurrent writer rejection. Native installed UI and OS login-registration acceptance remain required on Mac and Windows before claiming those platform flows passed.

## Installed Windows validation

The native complete-bundle workflow installs its testing NSIS package into a clean disposable runner directory, checks the installed component hashes and versions, then clears the development PATH before launching the installed desktop. Windows UI Automation checks visible X controls and the absence of model controls, then exercises device preferences, idle close/reopen, forced exit/relaunch and native Quit. The installed complete-bundle check separately verifies loopback model API readiness and private bearer enforcement; the prepared-bundle Rust test verifies native API supervision. All profiles are new, no provider accounts are connected and no inference or X requests run. Evidence records only outcomes, never credentials. The script refuses to run outside a disposable Windows CI runner or against existing app-owned state.

Passing this check establishes the tested installer and UI lifecycle. It does not establish signature trust, remote provider login or verified paid network execution; those remain release requirements.

The Windows acceptance also builds an installation-only next-patch version of
the same runtime source. In its disposable profile it retains two synthetic X
accounts, a synthetic node identity, an uncertain journal record, preferences
and the private local API bearer across installation of the next version and
reinstallation of the original version. Each replaced app must reopen without
starting work, retain the durable bytes including X preferences, show only X
controls and exit on Quit. Each installed payload separately passes the protected
model API check. Evidence is recorded only after these assertions pass. This tests the
installation lifecycle for that version pair; signed installers, historical
schema compatibility and the Mac upgrade/downgrade UI remain separate checks.

Installed Windows browser acceptance uses new synthetic Chrome/Firefox stores below RUNNER_TEMP and redirects only browser roots for the test app. It exercises profile-specific consent and reset, incomplete Firefox session rejection, the protected Chrome fallback and unchanged prepared stores. Protected synthetic inventory covers installed account removal, cancellation, readback, retained credentials and restart persistence. A duplicate local nickname exercises masked paste without authenticating synthetic cookies. It makes no provider requests. Successful cookie extraction is covered by source fixtures; real account authentication remains a separate release gate. Account ID fields have distinct X/Codex labels for assistive technology. Test configuration is not a browser import mode for operators.

## Windows release signature acceptance

Verify the final signed setup and its installed complete payload on a clean native
Windows machine before selecting a stable download. Supply the scheme and the
reviewed certificate's public thumbprint and SHA-256; private keys and certificate
passwords are not inputs to this read-only checker. Never install a test
certificate or add trust roots to make a release pass.

```powershell
& desktop/scripts/check-windows-signatures.ps1 `
  -Installer 'C:\release\Scarlett-Node-0.1.1-windows-amd64.exe' `
  -InstalledDirectory 'C:\acceptance\Scarlett Node' `
  -ExpectedPublisherThumbprint $ReviewedCertificateThumbprint `
  -Scheme self-signed-stable -CertificateSha256 $ReviewedCertificateSha256 `
  -EvidenceFile 'C:\evidence\windows-signatures.json'
```

The setup, desktop, node, proof helper and local model API must each have an
embedded Authenticode signature matching that certificate and a timestamp whose
certificate chains to a root Windows trusts. In `self-signed-stable` mode every
file must report `UnknownError`, and a direct WinVerifyTrust call (no UI, no
revocation, cache-only retrieval) must return exactly `0x800B0109`
(CERT_E_UNTRUSTEDROOT): the digest verified and only the root is untrusted. The
signer must be self-issued, and its SHA-1 thumbprint and SHA-256 over the raw
certificate must equal the pins. `Valid` is rejected in this mode, because it
would mean someone made the certificate a trusted root. In `authenticode` mode
the signature must be `Valid` and the publisher may not be self-issued. Unsigned,
altered, catalog-only, untimestamped or unexpected-publisher files fail in both
modes. Read hashes before and after
signature validation to reject changes during the check. Local file paths cannot
use alternate streams or traverse reparse points. A new outcome/digest file is
written only after all signature checks; existing evidence is never overwritten.
Native tool failures disclose no raw certificate details or local paths.

Run the complete installed payload/hash/protected-API checker and installed UI
acceptance separately. These signature checks do not establish that an arbitrary
installed directory came from the supplied setup, validate every provider byte,
or prove login, upgrades, paid jobs or SmartScreen reputation. The native CI gate
tests signature-record rejection, rejects the actual unsigned Go executable and
runs an ephemeral self-signed fixture with no secrets: two RSA-3072
`New-SelfSignedCertificate` code-signing certificates in `CurrentUser\My` (never
a root store), the real signer, SDK SignTool and DigiCert sign a copy of the Go
executable, which must pass with its own pins, fail with HashMismatch after one
flipped byte and fail against the second certificate. Both certificates and keys
are deleted afterwards. The installed release acceptance runs in the release
workflow.
The checker uses [Windows Authenticode validation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature).

## Mac release signing

After reviewing the exact release source and native components, build the complete
release app with `npm run tauri build -- --bundles app --no-sign --config
src-tauri/tauri.complete.generated.json`. Omit `--debug`. Keep the original unsigned
build as provenance and sign a separate copy. The provider archives must already
have passed their pinned archive checks during complete-bundle preparation.

`SCARLETT_SIGNING_SCHEME` is required and has no default.

`self-signed-stable` (current releases) signs with Scarlett's own certificate,
pinned in `desktop/signing/identities.json`. Set `SCARLETT_MAC_KEYCHAIN` to the
absolute path of a temporary keychain that holds that identity, created by
`desktop/scripts/import-macos-identity.sh` (it imports with `-T /usr/bin/codesign`,
deletes the PKCS#12 file and sets the key partition list). Never use the login
keychain. codesign finds an untrusted self-signed identity only through the user
keychain search list, so the signer puts the temporary keychain first while it
signs and restores the original list afterwards, also when signing fails. Every
signature selects the identity by its pinned SHA-1 and uses `--timestamp=none`, a
fixed `--identifier` (`ai.scarlett.node`, `ai.scarlett.node.<sidecar>` and
`ai.scarlett.node.dmg`) and the explicit designated requirement
`identifier "<identifier>" and certificate leaf = H"<sha1>"`. That requirement keeps
Full Disk Access and other TCC grants valid across updates signed by the same
certificate. There is no notarization, stapling or Gatekeeper assessment: users
approve the unverified developer in Privacy & Security after each download.

`developer-id` (kept for when an Apple Developer ID arrives) needs an existing
`APPLE_SIGNING_IDENTITY` that starts with `Developer ID Application: `, its
ten-character `SCARLETT_APPLE_TEAM_ID`, and an existing
`SCARLETT_NOTARY_KEYCHAIN_PROFILE`. Store notarization credentials through Apple's
Keychain tooling, outside the repository and chat. The signing script does not
create certificates, import credentials or alter Keychain trust settings.

```sh
SCARLETT_SIGNING_SCHEME=self-signed-stable SCARLETT_MAC_KEYCHAIN=/absolute/release.keychain-db \
python3 desktop/scripts/sign-macos-bundle.py \
  "/absolute/release-copy/Scarlett Node.app" \
  "/absolute/new-output/Scarlett-Node-0.1.1-darwin-arm64.dmg"
```

The script refuses a changed component inventory, altered input bytes, links,
another product identity or an already finalized signing manifest. It verifies
every bundled native provider object's existing Developer ID signature and
hardened runtime, preserving those exact bytes and notices in both schemes. It
signs Scarlett's three sidecars and desktop executable, verifies them, records both
input and signed sidecar digests, then seals the outer app. In
`self-signed-stable` mode each verification requires the pinned requirement
(`codesign --verify --strict -R`), the exact designated requirement from
`codesign -d -r-`, exactly one embedded certificate whose SHA-256 equals the pin,
`TeamIdentifier=not set` and hardened runtime. In `developer-id` mode it requires
the configured team. A generic
hash refresh cannot turn an altered vendor binary into an accepted release.

The packaged integrity and protected local API check must pass under the new
signatures. In `developer-id` mode both the app and resulting drag-to-Applications
DMG then require an Accepted notarization response and a valid stapled ticket, the
app must pass Gatekeeper assessment and the DMG signature must match the
configured team. In `self-signed-stable` mode the signed DMG must pass the pinned
verification. Only then is a neighboring `.evidence.json` written with the
artifact digest: notarization IDs for `developer-id`, or the certificate pins,
designated requirement, `"notarization": "not-performed"` and
`"gatekeeper": "user-approval-required"` for `self-signed-stable`. A failed or
partly signed app must be rebuilt from its reviewed inputs, rather than signed
again in place. Tool failures expose no raw signing or Keychain output.

This is a Mac release preparation step, not automatic publication. It does not
replace downloaded-installer UI, remote account, upgrade/downgrade or paid-loop
acceptance. Stable download publication still uses the infrastructure release
process after those checks. Platform setup follows
[Tauri's signing guide](https://v2.tauri.app/distribute/sign/macos/).

## Release signing

`desktop/signing/` holds the only signing material in this repository: the two
public certificates (`macos-codesign.cert.pem`, `windows-authenticode.cert.pem`)
and `identities.json`, which records each subject, expiry and lowercase SHA-1 and
SHA-256 over the DER certificate, the Mac identifiers and designated requirement,
and the Windows timestamp endpoint. `desktop/scripts/signing_identities.py`
recomputes every pin from the certificates on each load, so a pin changes only
together with its certificate in a reviewed pull request. The download publisher
and the download page carry reviewed copies of the four hashes. Private keys never
enter the repository; they exist only as `release-signing` environment secrets.

`.github/workflows/desktop-release.yml` is the release path. It runs only by
manual dispatch on `main`, with a `version` input that must equal
`tauri.conf.json`, a read-only token and no caches. Its `sign` job uses the
`release-signing` environment on macos-15, macos-15-intel and windows-2025: it
builds the runtime with the same `build-complete-runtime.sh` as PR CI, builds the
unsigned app, imports the key (the secrets are visible to that step alone), signs,
removes the key in an `always()` cleanup and, on Mac, runs
`smoke-macos-dmg.sh`: it checks the DMG digest against the signer's evidence,
verifies the DMG and the packaged app and sidecars against their pinned designated
requirements, then launches the app from the DMG. The Mac legs and a
`headless_linux` job also build and test the headless bundles. `updater_sign`
(ubuntu-latest, `release-signing`) signs the three installers and three bundles
with the updater's minisign key (`SCARLETT_UPDATER_MINISIGN_KEY` and
`SCARLETT_UPDATER_MINISIGN_PASSWORD`, visible to that one step) through the
pinned `tauri signer sign --app-version`, then verifies every signature against
the pinned keys; without the secret the release simply has no updater signatures.
The `assemble` job has no
secrets. It runs `release-manifest.py`, which checks every evidence file and component manifest against
`identities.json` and the installer SHA-256, verifies the updater signatures,
then writes `release/` (`manifest.json` with `notes` and, when signed, `updates`;
`provenance.json`; `changelog.json`; `Scarlett-Node-<version>-{darwin-arm64.dmg,
darwin-amd64.dmg,windows-amd64.exe}` and the signed headless bundles, the set the
publisher accepts) beside `SHA256SUMS`, `evidence/` (including
`release-notes.md` for the GitHub release) and, when unsigned, `headless/`.
The release runbook is [`docs/RELEASE.md`](../docs/RELEASE.md).

On Windows the key is imported by `desktop/scripts/import-windows-identity.ps1`
with `Import-PfxCertificate` and no `-Exportable`. It then requires exactly the
pinned certificate with a non-exportable, current-user RSA-3072 key in the CNG
Microsoft Software Key Storage Provider (where Windows Server 2025 puts an
OpenSSL 3 PKCS#12 key), refuses a trusted-root copy and deletes the PKCS#12 file.

PR CI rehearses both platforms with no secrets.
`desktop/scripts/rehearse-macos-signing.sh` makes a throwaway certificate with the
release extensions, imports it with the release import script and runs the
`self-signed-stable` signer over a copy of the complete debug app, then the launch
smoke runs on the rehearsal DMG. The `windows_release_rehearsal` job repeats the
release Windows job's build steps, then `desktop/scripts/rehearse-windows-signing.ps1`
makes a throwaway RSA-3072 certificate with the release extensions, exports it as
PKCS#12 with OpenSSL 3 defaults (AES-256-CBC, PBKDF2, SHA-256 MAC) like the release
key, imports it with `import-windows-identity.ps1` and runs
`sign-windows-bundle.py`: signing, NSIS packaging, installed acceptance and the
pinned signature checks on the complete release build. The ephemeral fixture
described above also still runs.
A rehearsal may substitute its own identities file through
`SCARLETT_SIGNING_IDENTITIES`, which is honoured only with
`SCARLETT_SIGNING_REHEARSAL=1`. Everything signed that way records
`"rehearsal": true`, which the release assembler rejects.

When an Apple Developer ID and a commercial Windows certificate arrive, run the
`developer-id` and `authenticode` schemes, which are kept and tested. The Mac
designated requirement then changes, so users grant Full Disk Access once more.

## Local release when Actions is unavailable

When GitHub Actions cannot run (for example, the account is out of minutes), the
release owner can build and sign the Mac installers on their own Mac with
`desktop/scripts/local-release.sh`. It repeats the release workflow's macOS
`sign` job using the release commit's own scripts. It never publishes, tags or
pushes.

```sh
git fetch origin
desktop/scripts/local-release.sh 0.1.12 darwin-arm64 /absolute/new/work/darwin-arm64 \
  > /absolute/darwin-arm64.log 2>&1
```

The script:

1. Fetches the release commit (`SCARLETT_RELEASE_COMMIT`, which must be on
   `origin/main`; default `origin/main`) at depth 1 into a new repository under
   the work directory, so local edits never reach the build.
2. Runs `release-manifest.py check-version`, then checks the toolchains: Node 26,
   the Go version in `go.mod` exactly (through `GOTOOLCHAIN`), Rust 1.95 from
   rustup, and Python 3.11 or newer, all native to the target architecture.
3. Runs `build-complete-runtime.sh`, `npm ci --ignore-scripts` and
   `tauri build --bundles app --no-sign` with the generated complete config.
   `CARGO_TARGET_DIR` applies to the Tauri build only; the prover builds in the
   clean checkout because `build-complete-runtime.sh` reads it from there.
4. Copies `~/.scarlett-signing/macos.p12` (`SCARLETT_MAC_P12`) into a private
   directory and reads its export passphrase from the login keychain item
   `scarlett-signing`/`macos-export` (`SCARLETT_MAC_P12_SERVICE`,
   `SCARLETT_MAC_P12_ACCOUNT`; `macos-key` protects the PEM key instead). The
   passphrase goes to
   `import-macos-identity.sh` only through `SCARLETT_MAC_P12_PASSWORD`, as in the
   workflow, and is never printed, written or put on this script's command lines.
   The importer creates a temporary keychain, deletes the PKCS#12 copy and checks
   the SHA-1 pinned in `identities.json`. An exit trap deletes the keychain and
   checks that it has left the user search list. Because the signer changes that
   list while it works, parallel local releases take turns through a lock
   directory in `$TMPDIR`.
5. Signs a copy of the app with `sign-macos-bundle.py` (`self-signed-stable`),
   requires the original search list afterwards and copies `COMPONENTS.json`
   next to the DMG.
6. Runs `smoke-macos-dmg.sh --verify-only`, which checks the DMG digest against
   the evidence and the DMG, app and sidecars against their pinned designated
   requirements, then applies the assembler's per-platform checks
   (`release-manifest.py` `verify_platform`) to the output.

The work directory then holds `signed-<platform>/` (the DMG, its
`.evidence.json` and `COMPONENTS.json`, exactly what the workflow uploads as
`signed-<platform>`) and `LOCAL-BUILD.json`, which records the commit, toolchains
and host.

The launch half of the smoke still needs a disposable Mac. It creates app state
for `ai.scarlett.node` in the user's Library and uses the app's single-instance
socket (`/tmp/ai_scarlett_node_si.sock`), so on a Mac where Scarlett Node is
installed or running it would hand off to, or share state with, the real app.
On a disposable Mac or macOS user, run the full `smoke-macos-dmg.sh` on the
signed DMG as the workflow does. It refuses to launch unless `GITHUB_ACTIONS=true`,
which acknowledges that the machine is disposable.

`darwin-amd64` needs an Intel Mac. Run the same command there with x86_64
Node 26, Go and Rust 1.95, building both Mac platforms from the same
`SCARLETT_RELEASE_COMMIT`. Rosetta on Apple Silicon does not work. Run under
`arch -x86_64` with x86_64 Node, Go, a separate `RUSTUP_HOME` whose default host
is `x86_64-apple-darwin`, and a universal `python3`, the toolchain and
architecture checks pass. The build then stops at the 10-second provider version
check in `prepare-complete-bundle.mjs` (`ETIMEDOUT`). Rosetta translates each
newly extracted executable on its first launch, once per file: about 32 seconds
for Codex and 16 seconds for Claude in the 0.1.12 rehearsal. A fresh extraction
never starts translated. Passing would mean relaxing a reviewed release check,
and the Intel app still would not have run on Intel hardware.

Windows cannot be built here. `sign-windows-bundle.py` needs Windows SignTool and
the current-user certificate store, and it installs the NSIS installer it signs
for acceptance, so it runs only on a native Windows host.

Assembly and publication are not part of the local path yet.
`release-manifest.py assemble` requires all three platforms and a GitHub Actions
run URL for `provenance.json`. The download publisher accepts one to three
artifacts, but every publication replaces the live `manifest.json`. The publisher
and the download page both derive each installer's name and path from the one
manifest `version`. A Mac-only 0.1.13 would therefore remove the 0.1.12 Windows
download. Publishing a platform subset needs a per-artifact version: the
download page must accept it first, then the publisher must carry a retained
artifact (for example `v0.1.12`'s Windows installer and its signing record) into
the new manifest without copying it, and then the assembler must accept a
platform subset and a local-build provenance record in place of the workflow run.

## X browser login helper

Complete native preparation includes the pinned helper runtime and verifies its
full resource inventory before bundling. Install Google Chrome at the documented
fixed platform path; login never downloads a browser or discovers executables
through PATH. Missing prerequisites return an unavailable result. The local helper
uses loopback authentication and private persistent browser profiles. Read
[the runtime preparation and release gates](../docs/x-browser-runtime.md) before
building or testing this component.

### Occupied lease references

The native heartbeat optionally includes `active_leases[{job_id,attempt,fence}]` per service, bounded by its in-flight count and containing only canonical coordinator UUIDs. Account admission and release own these references; accepted work keeps them until reporting returns. They let a supporting coordinator deduplicate its committed live lease from the same reported local work. Unknown work remains additive. A rejected heartbeat is logged and backed off; the node does not resend it without `active_leases` or `proof_modes`. The desktop status projection omits lease identifiers.
