# Native Windows runtime work

This first ND2 slice adds private file and process-lock primitives, connects X
session reads to them, and separates the Rust supplier proof client from the
Unix-only verifier server and receipt store. It does not advertise or package a
working Windows node.

Windows opens use non-inheritable handles with `FILE_FLAG_OPEN_REPARSE_POINT`,
check the actual opened file and its owner, and require a protected DACL granting
access only to the current user and LocalSystem. Parent directories are opened
from the volume root downward and held without write/delete sharing while the
final path resolves. Device namespaces, UNC paths and alternate streams are
rejected. Locks use nonblocking exclusive `LockFileEx` ownership until handle
close. Numeric Unix modes are never accepted as evidence of Windows privacy.
These contracts follow Microsoft's [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
and [LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex)
interfaces; native execution remains to be verified.

The proof client retains the existing pinned roots, hostname validation,
request binding and telemetry. Windows cannot run the verifier or fake server.
An explicitly configured public CA file must be absolute, regular, bounded and
not a reparse point; no private verifier key is read on Windows.

## Validation and remaining work

Mac Go build, vet and full race tests pass; the pinned Rust suite passes 47 tests
with one synthetic benchmark ignored. The new Go Windows test binary
cross-compiles, including Windows ACL tests. The local Rust Windows MSVC check
reaches the dependency build and stops because `ml64.exe` and the Windows SDK
are unavailable. This establishes a native build prerequisite, not a working
Windows proof client. The new native Windows CI job checks only this first
filesystem/client slice and uses no provider credentials.

Complete the node port after the provider-account pool companion is reconciled:

- Wire the helpers into account locks, account credential checks, local lifecycle
  reads and the attempt journal without changing scheduler or receipt semantics
- Add protected directory/temp creation, atomic identity publication and durable
  replacement on NTFS; test interrupted writes and recovery instead of treating
  Unix directory sync as a portable contract
- Resolve per-user Windows data paths and `.exe` siblings, preserving spaces and
  Unicode paths
- Bound helper/login process trees with native Windows process controls and test
  graceful stop, forced termination and no replay of started attempts
- Run full native Go build/vet/race and locked Rust tests before packaging

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
