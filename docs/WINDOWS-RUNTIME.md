# Native Windows runtime work

The native Go node uses Windows private storage and locks for its identity,
account registry, lifecycle controls and attempt journal. The Rust supplier
proof client is separated from the Unix verifier server and receipt store.
This runtime change does not establish a tested Windows desktop installer.

Windows opens use non-inheritable handles with `FILE_FLAG_OPEN_REPARSE_POINT`,
check the actual opened file and its owner, and require a protected DACL granting
access only to the current user and LocalSystem. Parent directories are opened
from the volume root downward and held without write/delete sharing while the
final path resolves. Device namespaces, UNC paths and alternate streams are
rejected. Locks use nonblocking exclusive `LockFileEx` ownership until handle
close. Numeric Unix modes are never accepted as evidence of Windows privacy.
These contracts follow Microsoft's [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
and [LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex)
interfaces. The native Windows CI exercises file privacy and process locks,
including lock release after an owning process crashes.

The proof client retains the existing pinned roots, hostname validation,
request binding and telemetry. Windows cannot run the verifier or fake server.
An explicitly configured public CA file must be absolute, regular, bounded and
not a reparse point; no private verifier key is read on Windows.

## State and process contracts

Private directories are created with protected, inheritable current-user and
LocalSystem permissions. Existing broad permissions are rejected. Local state
requires NTFS and rejects reparse ancestors. A flushed private temporary file
is published through a same-volume write-through rename; identity publication
claims its destination exclusively and never replaces an existing identity.
Windows has no Unix directory-fsync equivalent here. A power loss may restore
a removed terminal-history file or drain marker; neither permits replay of
started provider work.

Per-user state defaults to LocalAppData/Scarlett/node. Native helper discovery
uses the sibling scarlett-prover.exe. Paths with spaces and Unicode remain
valid. Helper processes start suspended, enter a non-inheritable Windows Job
Object before execution, and cannot break away. Closing that job after a
cancellation or node crash terminates descendants. Journals retain uncertain
attempts for coordinator reconciliation; local restart never repeats started
provider work merely because a process died.

## Validation and remaining work

Local Mac Go race tests, build and vet passed, and the complete Windows x64
node cross-build and Windows-target vet passed. The full native Windows CI
runs the built node through synthetic TLS/coordinator crash recovery and
persistent drain/resume, private filesystem and account-pool tests, helper
process-tree cancellation/crash tests, and the locked Rust proof-client suite.
Cross-compilation does not prove installed Windows behavior. Native CI results
must be read back for the exact PR head before merging or packaging.

Windows 11 non-admin desktop behavior, provider login, live Codex/X proof
acceptance, signed installers and updates remain separate release gates. Test
inputs contain no real provider credentials and make no live provider calls.

## Native acceptance inputs

Provide a Windows 11 x64 test host with a non-admin supplier account, local NTFS
storage and an approved way to create reparse-point fixtures. Native builds need
the pinned Go/Rust toolchains plus Visual Studio C++ Build Tools and a Windows
SDK. Hosted Windows CI can test builds and synthetic filesystem behavior; it
does not establish installed desktop behavior or real provider authorization.

Controlled acceptance also needs locally authorized Codex login and X session
setup, the existing trusted verifier/coordinator endpoints and isolated paid-job
fixtures with earning disabled. Never copy Mac credentials to establish Windows
support. Record independent Codex and X proof acceptance, latency/bandwidth,
TLS rejection, interrupted attempts and recovery before calling the port ready.

The installer companion separately needs the product's reviewed Authenticode
signing identity, secure signing service/key access and timestamp policy. No
signing identity or certificate is generated or selected by this runtime slice.
