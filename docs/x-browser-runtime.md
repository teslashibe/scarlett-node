# Browser login runtime

Scarlett uses Go for X session validation and reads, and a local Chrome helper
for browser login. A verification code continues the retained browser page.
No TOTP seed is required. Source, license and patch provenance live in
`third_party/social-login`; `scripts/verify-social-login.mjs` validates the pins.

## Desktop prerequisites

The native build supplies Node 22.23.3 and the lockfile-pinned Playwright library.
It does not download a browser during login or search PATH. Install Google Chrome
at the supported fixed path, or configure an explicit absolute browser path:

| Platform | Default browser executable | Release gate |
| --- | --- | --- |
| macOS arm64 or Intel | `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome` | Installed signed bundle, helper readiness, browser continuation and shutdown |
| Windows x64 | `C:\Program Files\Google\Chrome\Application\chrome.exe` | Installed signed bundle, private-file ACLs, readiness, continuation and process-tree shutdown |
| Linux amd64 or arm64 | `/opt/google/chrome/chrome` | Native runtime smoke; container Chrome image currently requires amd64 |

A missing runtime, incompatible manifest or absent Chrome produces an unavailable
result. The helper listens on `127.0.0.1` with a random per-install bearer stored
privately under the node state directory. Browser profiles are under
`x-browser/profiles`. Helper logs and request bodies are not forwarded to the UI.
Shutdown closes the helper's private stdin, allowing it to release browser holds;
a bounded timeout terminates the process tree.

## Prepare a native release

On the target host, run `node scripts/prepare-x-login-runtime.mjs
<darwin-arm64|darwin-x64|win32-x64|linux-x64|linux-arm64>
<absolute-output-directory>`. This is explicit build-time preparation: it downloads
Node from its pinned official release, verifies the reviewed archive hash, then
installs Playwright using npm lock integrity without package scripts or browser
installation. It writes a complete file inventory in `manifest.json`.
`node scripts/verify-x-login-runtime.mjs <runtime-directory>` rejects missing,
extra, modified or symlinked files. The complete desktop preparation invokes this
step before recording its full bundle inventory. Do not commit generated runtime
binaries or node_modules. Preserve Node and dependency license notices.

Native Node vendor bytes retain their official signature, matching the existing
release signing policy. The app inventories and seals those bytes unchanged.
Installed bundle integrity and native runtime tests must pass before publishing
macOS or Windows releases. Linux fixture tests do not establish those
installed-platform results.

## Docker companion

Use `packaging/x-login.compose.yml` with the node's existing operator configuration.
Create a private random bearer file outside the checkout, set
`SCARLETT_X_LOGIN_BEARER_FILE` to its absolute path, and grant both services the
same Docker secret. Trusted container startup reads that root-mounted secret,
creates a fresh node-owned private bearer under a root-owned `/run` ancestor, and drops privileges before starting
the Go node or browser service. The node joins a dedicated companion bridge; the browser
service publishes no host port. Chrome needs outbound internet access, so that
bridge permits egress. Headed Chrome runs under Xvfb with Mesa software rendering.
Profiles persist in a named volume. Health, init and bounded shutdown are enabled.
This file is a deployment composition, not a production deployment instruction.
The container build installs Google Chrome explicitly; operators should record
that browser version in release evidence.

## Opt-in live acceptance

Run only after offline browser fixtures, package verification and Go tests pass.
Use one operator-authorized burner account and a private profile. Allow one
password submission. If X asks for a code, enter it once and continue the same
challenge; verify no second password submission or login navigation occurs.
Verify the expected authenticated identity, perform one small Go read, stop the
node and restart it to confirm saved-session reuse without a password submission.

Stop immediately on 399, 366, 429, provider cooldown, ambiguous challenge or
unexpected account identity. Retain the cooldown state. Do not sweep passwords,
proxies, headers or alternative login protocols. Do not include credentials,
cookies, bearer values or real browser profiles in logs, fixtures, issues or PRs.
Offline acceptance uses synthetic accounts and intercepts every provider route;
it proves continuation and lifecycle behavior, not live Castle acceptance.
