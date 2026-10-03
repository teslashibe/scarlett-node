# Scarlett Node desktop

Tauri 2 with bundled vanilla TypeScript. The native bridge delegates execution and account scheduling to the independently built Go node and its Rust proof helper. It does not embed the private Scarlett application.

The desktop provides pairing, status, start/drain/resume/stop, a menu-bar/tray supervisor and account controls. Account management requires the native pool release; older node binaries show it as unavailable. Automatic Codex token refresh for the proof-only runtime, signed public installers, automatic updates and full installed Windows GUI acceptance remain separate release gates. The Mac development app is unsigned and is not a community release.

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

Closing the main window drains and quits by default. Operators can enable background operation to hide it in the tray/menu bar instead. Explicit Quit requests drain and close the supervised node's owner pipe, allowing the node's existing two-minute accepted-work window before a bounded forced stop. The journal remains the execution/recovery authority; the shell never retries provider work or reconstructs a receipt. Stop does not unpair/revoke a node. A second instance focuses the existing window and the node retains its journal lock.

Windows runtime operations require private NTFS storage and the bundled native helpers. Native tests validate ACLs, locking, process trees and owner-pipe shutdown; installed Windows GUI acceptance remains required before publishing its installer.

Windows release signing uses an existing current-user code-signing identity and
the trusted Microsoft SDK SignTool. No certificate or key is imported by the
release helper. Set `SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT` to the reviewed public
certificate thumbprint, `SCARLETT_WINDOWS_SIGNTOOL` to the absolute SDK executable
and `SCARLETT_WINDOWS_TIMESTAMP_URL` to the approved HTTPS RFC3161 endpoint on a
disposable native Windows release runner. Keep hardware-provider credentials and
key access on that runner.

After preparing the complete native runtime, build the release executable with
`npm run tauri -- build --no-bundle --config src-tauri/tauri.complete.generated.json`.
Then run `python scripts/sign-windows-bundle.py <absolute-desktop-checkout> <new-absolute-evidence.json>`.
The helper validates the original inventory, signs only Scarlett executables,
retains unsigned sidecar hashes and preserves provider bytes. It packages NSIS
with Tauri's binary patching disabled, verifies trusted publisher/timestamp
signatures and tests that exact installer with isolated local state. Evidence is
written only after installed payload, lifecycle, preferences and browser tests
pass. Real account login, signed upgrade/downgrade and publication remain
separate gates; contract tests and unsigned rejection do not prove real signing.

The signing options follow [Microsoft's SignTool reference](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
and [Tauri's custom Windows signing support](https://v2.tauri.app/distribute/sign/windows/#custom-sign-command).

Tests use synthetic credentials and disposable temporary directories/fake executables. Launching the app does not itself start provider work: Start remains explicit. Real account/canary testing and production validation belong to the release owner.

## Complete runtime package

The complete bundle contains the desktop shell, native Go node, Rust proof helper, `open-agent-api` v0.1.29, Codex CLI 0.159.2 and Claude CLI 2.1.286. Users do not need a development toolchain to run these packaged binaries. The desktop starts and stops the local model API through its native supervisor. The node's verified network services remain Codex and X; packaging Claude does not add a verified Claude network service.

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

## Local model API controls

The complete bundle can start and stop its bundled model API from the desktop. It binds only `127.0.0.1` on an operator-selected port (default 8088), requires a generated 256-bit bearer, and reports Ready only after health succeeds, unauthenticated model access returns 401 and authenticated access returns 200. Show local API key explicitly reveals the private bearer; it clears on window blur or page exit. The file is private to the current user (mode 0600 on Unix; current-user/SYSTEM ACL on Windows), and symlink or shared-file reads fail closed. The bearer is never included in status, logs or process arguments.

Codex clients use only completed app-owned login profiles for registered account IDs, plus bundled profile/scaffold files. Unrelated environment credentials and host profiles are cleared. An optional personal Anthropic API key enables the bundled Claude provider; it stays only in that service's environment, is not saved to disk, and must be re-entered after stopping. Claude subscription OAuth is not imported into this API. Neither discovery nor readiness establishes provider entitlement.

The app permits network execution or the local API at a time, serialized through one native control lock, so independent processes cannot silently exceed account capacity. Adding an account takes effect in the local API after restart; removing a Codex account first stops the API. Quit stops the API before draining the node. Windows private storage uses the Go node’s NTFS, current-user/SYSTEM ACL and reparse-point checks. Local API supervision uses the same native process-tree boundary as node helpers. Full installed Windows GUI acceptance remains a release gate.

## Ownership of local processes

The desktop starts `scarlett-node desktop run` and holds its input pipe open. Stop closes that owned pipe after requesting drain; the node stops admission and lets accepted work finish within the existing two-minute shutdown bound. An unexpected desktop exit also closes the pipe. No runtime PID from a file or status response is signalled. The ordinary terminal `scarlett-node run` keeps its existing signal-based behavior.

The local API runs through `scarlett-node desktop api PORT`. That host selects only the API binary beside its own executable, fixes the listener to loopback and stops its owned API tree when desktop input closes. Unix uses an owned process group; Windows uses suspended startup and a kill-on-close Job Object. Windowless creation does not grant process breakaway. Local API stop can cancel requests in progress; it does not submit them again.

The Windows bridge creates or checks private directories before starting the webview and obtains its bearer through fixed `desktop private-dir` and `desktop bearer` helpers. Existing broad ACLs, symlinks/reparse points and unsupported filesystems fail closed. The API bearer stays in the private local file and protected helper output; it is never a process argument or a status field.

## Import an X browser account

Choose a local account ID and concurrency, select a browser profile, tick the X-session consent box, then press **Import X account**. Close the selected browser first so its cookie database has no active journal. Browsers with custom profile locations can use the existing masked cookie-paste form.

Profile discovery reads directory/file metadata only. It returns opaque profile IDs and labels, without cookie-store paths or account credentials. Import reads only `auth_token` and `ct0` for a complete, secure, unexpired root-domain X/Twitter session at `/`. It keeps container/partition sessions separate and refuses conflicting identities. Credentials go directly from the native reader to the private account file; the renderer receives only success or a fixed error code. Existing accounts are never overwritten.

| Browser | Mac | Windows | Limits |
| --- | --- | --- | --- |
| Chrome | Standard Google Chrome profiles; plaintext or v10 CBC cookies, with normal Keychain approval | Standard Google Chrome profiles; plaintext or v10 GCM cookies, with current-user DPAPI | App-bound v20 cookies are protected; use cookie paste. No password fallback, elevation or protection bypass |
| Firefox | Standard Firefox profiles | Standard Firefox profiles | Root-domain session cookies in a closed SQLite store; containers are kept separate |
| Safari | Standard container or legacy `Cookies.binarycookies` | Unavailable | macOS may deny access; use cookie paste. Scarlett does not grant itself Full Disk Access |

The helper uses a bundled, cgo-free SQLite reader, opens stores read-only and immutable, and refuses populated WAL/journal files. It neither copies nor changes a browser database. Cookie-store changes during import fail with a retry message. Unsupported or inaccessible stores do not add an account. Linux CLI builds support standard Firefox profiles only; the desktop release targets remain Mac and Windows.

Tests use disposable synthetic databases, encrypted cookie fixtures and malformed Safari records. Windows native tests generate their own current-user DPAPI fixture. These checks do not establish compatibility with every installed browser version or prove real X access. Imported accounts remain **Configured · access not verified** until their existing provider execution path verifies access.

## Device preferences

The This device section saves only a versioned local API port and a window-close choice in the private app directory. New installations default to port 8088 and drain/quit when the window closes. Operators can explicitly choose to keep running in the menu bar or tray. Open Scarlett in the native menu (Cmd/Ctrl-1), the tray, macOS Finder/Dock reopen and Windows duplicate launch restore the existing window without starting a second runtime. Saved ports apply on the next local API start; updating a preference does not interrupt accepted jobs or start a service. Corrupt/private-storage failures are reported rather than silently resetting preferences.

Open Scarlett when I log in is a separate OS setting, disabled until the operator opts in. The native Tauri autostart manager queries the actual OS registration and uses a macOS LaunchAgent or Windows user startup registration. It registers only the installed app, without credentials or provider arguments. Opening at login still requires the operator to start the node or local API. The renderer receives no direct autostart-plugin permissions; fixed local-window commands own this setting. A failed setting change is reported and the UI rereads OS state. Moving an app after enabling login launch requires disabling/re-enabling it at its new installed location.

Go preference persistence tests use disposable private directories, including repeated reads/writes, invalid version/port/secret input, corruption and concurrent writer rejection. Native installed UI and OS login-registration acceptance remain required on Mac and Windows before claiming those platform flows passed.

## Installed Windows validation

The native complete-bundle workflow installs its testing NSIS package into a clean disposable runner directory, checks the installed component hashes and versions, then clears the development PATH before launching the installed desktop. Windows UI Automation invokes the real Start and Stop controls. Authenticated and unauthenticated model requests check the private bearer; a forced desktop exit and Ctrl-Q check API cleanup and recovery. All profiles are new, no provider accounts are connected and no inference or X requests run. Evidence records only outcomes, never credentials. The script refuses to run outside a disposable Windows CI runner or against existing app-owned state.

Passing this check establishes the tested installer and UI lifecycle. It does not establish signature trust, remote provider login or verified paid network execution; those remain release requirements.

Installed Windows import acceptance uses new synthetic Chrome/Firefox stores below RUNNER_TEMP and redirects only browser roots for the test app. It exercises profile-specific consent and reset, Firefox import, the protected Chrome paste fallback, masked paste, unchanged stores and native private account persistence. It makes no provider requests. Account ID fields have distinct X/Codex labels for assistive technology. This acceptance is a release gate; test configuration is not a browser import mode for operators.

## Windows release signature acceptance

Verify the final signed setup and its installed complete payload on a clean native
Windows machine before selecting a stable download. Supply the reviewed publisher
certificate's public thumbprint; private keys and certificate passwords are not
inputs to this read-only checker. Do not install a test certificate or add trust
roots to make a release pass.

```powershell
& desktop/scripts/check-windows-signatures.ps1 `
  -Installer 'C:\release\Scarlett-Node-setup.exe' `
  -InstalledDirectory 'C:\acceptance\Scarlett Node' `
  -ExpectedPublisherThumbprint $ReviewedCertificateThumbprint `
  -EvidenceFile 'C:\evidence\windows-signatures.json'
```

The setup, desktop, node, proof helper and local model API must each have a
Windows-trusted embedded Authenticode signature matching that certificate and a
trusted timestamp. Unsigned, altered, untrusted, catalog-only, self-signed,
untimestamped or unexpected-publisher files fail. Read hashes before and after
signature validation to reject changes during the check. Local file paths cannot
use alternate streams or traverse reparse points. A new outcome/digest file is
written only after all signature checks; existing evidence is never overwritten.
Native tool failures disclose no raw certificate details or local paths.

Run the complete installed payload/hash/protected-API checker and installed UI
acceptance separately. These signature checks do not establish that an arbitrary
installed directory came from the supplied setup, validate every provider byte,
or prove login, upgrades, paid jobs or SmartScreen reputation. The native CI gate
tests signature-record rejection and rejects the actual unsigned Go executable
without creating signing certificates or modifying trust stores. Genuine signed
installer acceptance and the Windows signing integration remain release work.
The checker uses [Windows Authenticode validation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature).
