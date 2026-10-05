# Interactive X login review

This branch implements [x-go #31](https://github.com/teslashibe/x-go/issues/31),
[Node #51](https://github.com/teslashibe/scarlett-node/issues/51) and
[Node #52](https://github.com/teslashibe/scarlett-node/issues/52).
The reviewed x-go snapshot is pinned to
`fb031a0f6f69b68a7038efdf52d1c4ef22d54f85`; its commit is available in
[x-go PR #32](https://github.com/teslashibe/x-go/pull/32).

## Acceptance evidence

| Contract | Implementation and offline evidence |
| --- | --- |
| User-entered verification code | Go start/continue/cancel API, hidden CLI prompts and trusted desktop commands; no seed field. Desktop fixture confirms pending copy, cleared password, code submission and cancellation |
| Same browser throughout verification | Real Chromium fixtures intercept every provider route. Invalid then valid code continues the held page with one browser launch, one password submission and no second login navigation |
| Wire interoperability | `TestBrowserLoginRuntimeContract` runs the actual Go adapter against the pinned Node service over local HTTP and checks UA/session output and aggregate work observations |
| Ownership and bounded work | Wrong owner, profile, proxy and challenge tests fail before provider work. Continuation keeps the original deadline and aggregate allowances; a parked browser holds profile ownership and capacity |
| Lifecycle | Cancel, expiry, browser crash, terminal success and shutdown release holds. Managed helper fixtures exercise bearer enforcement, readiness, EOF and process shutdown |
| Verified persistence | Go Viewer checks authenticated handle and prior identity before saving canonical `twid`. Failed verification, mismatched identity, late cancellation and conflicting replacement preserve prior credentials |
| Saved-session recovery | A saved session is checked before lazy helper startup. Only definitive unauthorized permits an explicitly requested login; rate limits, challenges and outages retain separate outcomes |
| Credential boundaries | Password/code use protected local stdin/native calls. Pending state stays in memory; provider output is projected to fixed safe messages. The credential RPC disables environment proxies and rejects redirects |
| Provenance and packaging | Per-file snapshot hashes, pinned upstream source, replayable patch and runtime inventory checks. Missing, changed, extra and symlinked resource fixtures fail closed. Native CLI and complete desktop preparation include the helper |
| Docker | Actual Linux Chrome container fixtures verify readiness, unauthorized requests, private-secret startup under UID 10001 and clean shutdown. The companion publishes no host port; profiles use a named volume |
| Existing contracts | Cookie import and account admission remain available. Coordinator/node-v1 and proof semantics are unchanged; existing Go and prover suites pass |

## Forensic findings resolved

Separate agents reviewed the Go API and Node implementation against the issues.
The review found and corrected these defects:

- Provider code 88 without wait headers could allow immediate read retries. It now
  establishes a shared 60-second cooldown, covered by race tests.
- Recovery documentation allowed a fresh password operation immediately after a
  failed harvest. It now requires explicit authorization and preserves work and
  cooldown accounting.
- Docker secret permissions were incompatible with the Go private-file reader.
  Trusted root startup copies the secret into a fixed root-owned `/run` ancestor,
  sets private node ownership, then drops privileges.
- Desktop cleared the documented browser-path override. It now validates and
  forwards an absolute regular browser executable.
- Inherited HTTP proxy configuration could route local credential RPC through an
  unrelated proxy. The dedicated transport disables proxies; a trap fixture
  observes zero proxy requests.
- macOS preserves an executable's launch symlink. Native runtime discovery now
  resolves the complete installed symlink chain before locating sibling resources;
  a native subprocess regression fixture checks that path.
- Reinstallation could execute an altered installed runtime before checking its
  fixed checksum. Validation now checks executable bytes first and uses the
  verified incoming runtime to inspect the installed inventory.
- The new login account field duplicated the cookie-import field's accessible
  name, causing Windows installed acceptance to fill the wrong form. The login
  field now has a distinct accessible name; cookie import retains its existing
  label and focus contract.

Both independent reviews report no unresolved confirmed P1/P2 implementation
findings. This does not replace the platform and provider acceptance below.

Windows CI also exposed fixture setup errors. Git attributes now preserve the
vendored source bytes instead of converting them to CRLF during checkout. Login
fixtures reuse the repository's protected private-directory helper and atomic
private-file writer, since Unix mode bits do not establish NTFS ACLs. Production
private-storage checks are unchanged. Native Windows CI verifies these fixes.

## Validation limits

Go race tests, vet/build, desktop's 20 tests and TypeScript/Vite build pass.
The prover suite passes with 87 tests and two existing ignored tests. Desktop Rust
unit checks use the test-only external-binary override; they do not establish a
complete installed release. Runtime source/patch and resource tampering checks
pass. Linux real-browser acceptance also passes in a pinned Playwright container
with networking disabled and all provider routes intercepted.

The real macOS arm64 CLI bundle builds with Go, the release prover and pinned
Node/Playwright resources. Its installer passes install, reinstall, upgrade,
rollback, missing-resource and tampering fixtures, including rejection of an
altered installed Node executable before execution. Launching through the actual
installed CLI symlink finds the helper without a resource override, reports
readiness, requires its private bearer and shuts down on EOF. A synthetic browser
exits before provider work in that startup smoke. The 107 existing desktop
packaging/signing Python tests also pass.

GitHub Actions did not start the companion x-go job because an Actions budget
is preventing further use. Node's remote checks started normally, and its Go,
prover, Linux native bundle and real-browser contract jobs passed before this
documentation update. Native desktop jobs are tracked separately. Rerun x-go
after its budget limit is restored.

Signed installed macOS and Windows browser continuation, private-file ACLs and
process containment remain explicit release gates. No installer has been
published, no production service deployed and no PR merged by this work.

No test in this implementation used a live X account. The earlier diagnostic
failed with provider code 366 before sending credentials and did not reproduce
399. Follow the single-attempt opt-in procedure in [x-browser-runtime.md](x-browser-runtime.md)
to validate live login, authenticated identity, a small Go read and restart reuse.
Stop on rejection, rate limits or ambiguity; fixture success does not establish
live Castle acceptance.
