#!/usr/bin/env python3
"""Sign prepared release inputs, package NSIS, then test that exact installer.

Requires a disposable native Windows CI runner and an existing publisher
identity. SCARLETT_SIGNING_SCHEME has no default: self-signed-stable uses the
certificate pinned in desktop/signing (Windows reports an untrusted root, and
trust roots are never added); authenticode uses a Windows-trusted publisher.
Provider binaries stay unchanged; no provider login or work occurs.
"""
import argparse
import ast
import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import signing_identities  # noqa: E402

SCRIPTS = Path(__file__).resolve().parent
SCHEMES = ('self-signed-stable', 'authenticode')
UNTRUSTED_ROOT = '0x800B0109'
SIDECARS = {'scarlett-node', 'scarlett-prover', 'open-agent-api'}
TARGET = 'x86_64-pc-windows-msvc'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path):
    def reparse(entry):
        return entry.is_symlink() or bool(getattr(entry.lstat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    if reparse(path) or not path.is_file() or any(reparse(p) for p in path.parents):
        raise ValueError('Release inputs must be regular local files')
    return path


def sidecar(root, name):
    return root / 'binaries' / (name + '-' + TARGET + '.exe')


def verify_inputs(root):
    runtime = root / 'runtime'
    path = regular(runtime / 'COMPONENTS.json')
    metadata = json.loads(path.read_text())
    if metadata.get('schemaVersion') != 1 or metadata.get('target') != TARGET or metadata.get('releaseSigning'):
        raise ValueError('Expected an unsigned native Windows component manifest')
    if [metadata.get(k) for k in ('codexVersion', 'claudeVersion', 'modelApiVersion')] != ['0.159.2', '2.1.286', '0.1.32']:
        raise ValueError('Expected the reviewed provider and model API versions')
    entries = metadata['files']
    expected = {p.relative_to(runtime).as_posix() for p in runtime.rglob('*') if p.is_file() and p != path}
    if len(entries) != len(expected) or {e['path'] for e in entries} != expected:
        raise ValueError('Runtime inventory changed before signing')
    for entry in entries:
        file = regular(runtime / entry['path'])
        if not file.resolve().is_relative_to(runtime.resolve()) or file.stat().st_size != entry['bytes'] or digest(file) != entry['sha256']:
            raise ValueError('Runtime bytes changed before signing')
    owned = metadata['sidecars']
    if len(owned) != 3 or {e['name'] for e in owned} != SIDECARS:
        raise ValueError('Expected exactly three reviewed sidecars')
    for entry in owned:
        file = regular(sidecar(root, entry['name']))
        if file.stat().st_size != entry['bytes'] or digest(file) != entry['sha256']:
            raise ValueError('Sidecar bytes changed before signing')
    regular(root / 'target/release/scarlett-node-desktop.exe')
    return metadata


def release_identity(environ, identities):
    """Return the scheme, publisher thumbprint, certificate SHA-256 and timestamp URL."""
    scheme = environ.get('SCARLETT_SIGNING_SCHEME', '')
    if scheme not in SCHEMES:
        raise ValueError('Set SCARLETT_SIGNING_SCHEME to self-signed-stable or authenticode')
    publisher = environ.get('SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT', '')
    if not re.fullmatch('[a-fA-F0-9]{40}', publisher):
        raise ValueError('Existing reviewed Windows publisher identity required')
    supplied = environ.get('SCARLETT_WINDOWS_CERT_SHA256', '')
    if supplied and not re.fullmatch('[a-f0-9]{64}', supplied):
        raise ValueError('Certificate SHA-256 pins are lowercase hex')
    pinned = identities['windows']
    if scheme == 'self-signed-stable':
        if publisher.lower() != pinned['sha1'] or (supplied and supplied != pinned['sha256']):
            raise ValueError('Windows publisher differs from the pinned self-signed certificate')
        certificate = pinned['sha256']
    else:
        if not supplied:
            raise ValueError('An authenticode release names its certificate SHA-256')
        if publisher.lower() == pinned['sha1'] or supplied == pinned['sha256']:
            raise ValueError('The self-signed certificate is not an authenticode publisher')
        certificate = supplied
    return scheme, publisher.upper(), certificate, pinned['timestampUrl']


def release_signing(scheme, publisher, certificate, rehearsal=False):
    record = {'scheme': scheme, 'publisherThumbprint': publisher.upper(), 'certificateSha256': certificate,
              'vendorBytesPreserved': True}
    if rehearsal:
        record['rehearsal'] = True
    return record


def finalize_metadata(root, original, signing):
    result = copy.deepcopy(original)
    for entry in result['files']:
        file = regular(root / 'runtime' / entry['path'])
        if file.stat().st_size != entry['bytes'] or digest(file) != entry['sha256']:
            raise ValueError('Provider or runtime bytes changed during signing')
    for entry in result['sidecars']:
        file = regular(sidecar(root, entry['name']))
        entry['unsignedSha256'], entry['unsignedBytes'] = entry['sha256'], entry['bytes']
        entry['sha256'], entry['bytes'] = digest(file), file.stat().st_size
    result['releaseSigning'] = dict(signing)
    return result


def signing_config(script):
    return {'bundle': {'targets': ['nsis'], 'windows': {'signCommand': {
        'cmd': 'powershell.exe', 'args': ['-NoProfile', '-NonInteractive', '-File', str(script), '-File', '%1']}}}}


@contextmanager
def nsis_signing_environment(root, env):
    # NSIS 3.11 uses GetTempPath/GetTempFileName("nst") for its uninstaller.
    # Own a fresh directory inside the prepared build, only for this child.
    directory = root / 'target/release/nsis-signing-temp'
    parent = regular(root / 'target/release/scarlett-node-desktop.exe').parent
    if len(str(directory)) > 246:
        raise ValueError('NSIS temporary directory exceeds its GetTempFileName path bound')
    if directory.exists() or directory.is_symlink():
        raise ValueError('Isolated NSIS signing directory already exists')
    directory.mkdir()
    ownership = directory.stat()
    try:
        child = dict(env, TMP=str(directory), TEMP=str(directory),
                     SCARLETT_WINDOWS_NSIS_TEMP=str(directory))
        yield child
    finally:
        current = directory.lstat()
        if directory.is_symlink() or getattr(current, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT or \
                (current.st_dev, current.st_ino) != (ownership.st_dev, ownership.st_ino) or directory.parent != parent:
            raise ValueError('Isolated NSIS signing directory changed ownership')
        shutil.rmtree(directory)


# Failure output is diagnosable without disclosing secrets or local paths: only
# our own literal strings, operation names, exit codes, line numbers, HRESULTs
# and exception class names are ever printed.
POWERSHELL_REASON_SOURCES = ('sign-windows-file.ps1', 'check-windows-signatures.ps1', 'import-windows-identity.ps1',
                             'check-windows-install.ps1')
PYTHON_REASON_SOURCES = ('sign-windows-bundle.py', 'signing_identities.py')
PYTHON_CHILD_SOURCES = ('check-complete-bundle.py', 'prepare-browser-fixtures.py', 'windows_pe_imports.py')
LITERAL_THROW = re.compile(r"\bthrow '((?:[^']|'')+)'")
NATIVE_CODE = re.compile(r'(.+) \((0x[0-9A-F]{8})\)')
PYTHON_FRAME = re.compile(r'File "[^"\r\n]*[\\/](check-complete-bundle|prepare-browser-fixtures|windows_pe_imports)\.py", line ([0-9]{1,6})')
PYTHON_EXCEPTION = re.compile(r'([A-Za-z_][A-Za-z0-9_.]{0,127}(?:Error|Exception))(?:: (.*))?')
ACCEPTANCE_LINES = re.compile(r'"acceptanceFailureLines"\s*:\s*\[([0-9,\s]{0,200})\]')


class ChildFailure(ValueError):
    """A failed child operation, described only by fixed or validated fields."""


def powershell_reasons():
    """The single-quoted literal throw messages of our signing scripts."""
    reasons = set()
    for name in POWERSHELL_REASON_SOURCES:
        text = (SCRIPTS / name).read_text(encoding='utf-8')
        reasons.update(match.replace("''", "'") for match in LITERAL_THROW.findall(text))
    return reasons


def literal_reason(stderr):
    """The last stderr line that is exactly one of our literal PowerShell reasons.

    A SignTool HRESULT of eight upper-case hex digits may follow the reason.
    Anything else (native messages, paths, values) is never returned.
    """
    try:
        reasons = powershell_reasons()
    except (OSError, UnicodeDecodeError):
        return None
    for line in reversed(stderr.decode('utf-8', 'replace').splitlines()):
        line = line.strip().lstrip('\ufeff')
        coded = NATIVE_CODE.fullmatch(line)
        if line in reasons or (coded and coded.group(1) in reasons):
            return line
    return None


def child_detail(stdout, stderr):
    reason = literal_reason(stderr)
    if reason:
        return reason
    text = stderr.decode('utf-8', 'replace')
    frames = PYTHON_FRAME.findall(text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    exception = PYTHON_EXCEPTION.fullmatch(lines[-1]) if lines else None
    if frames and exception:
        detail = '%s.py line %s, %s' % (frames[-1][0], frames[-1][1], exception.group(1))
        try:
            literals = python_literals(PYTHON_CHILD_SOURCES)
        except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
            literals = set()
        return detail + (': ' + exception.group(2) if exception.group(2) in literals else '')
    acceptance = ACCEPTANCE_LINES.findall(stdout.decode('utf-8', 'replace'))
    if acceptance:
        numbers = [n for n in re.split(r'[,\s]+', acceptance[-1]) if n]
        return 'check-windows-install.ps1 lines ' + (','.join(numbers) or 'unknown')
    return None


def run(operation, arguments, cwd, env, seconds=180):
    try:
        result = subprocess.run(arguments, cwd=cwd, env=env, capture_output=True, timeout=seconds)
    except subprocess.TimeoutExpired:
        raise ChildFailure('%s timed out after %d seconds' % (operation, seconds)) from None
    except OSError:
        raise ChildFailure('%s could not start' % operation) from None
    if result.returncode:
        detail = child_detail(result.stdout, result.stderr)
        raise ChildFailure('%s failed with exit code %d%s' % (operation, result.returncode, ': ' + detail if detail else ''))
    return result.stdout


def python_literals(names=PYTHON_REASON_SOURCES):
    """Every string constant written in these Python sources."""
    literals = set()
    for name in names:
        tree = ast.parse((SCRIPTS / name).read_text(encoding='utf-8'))
        literals.update(node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str))
    return literals


def failure_reason(error):
    """One printable line: our literal strings, numbers and class names only."""
    if isinstance(error, ChildFailure):
        return str(error)
    try:
        literals = python_literals()
    except (OSError, SyntaxError, UnicodeDecodeError, ValueError):
        literals = set()
    value = error.args[0] if len(error.args) == 1 else None
    if type(error) in (ValueError, TypeError) and isinstance(value, str) and value in literals:
        return value
    if isinstance(error, KeyError) and isinstance(value, str) and value in literals:
        return 'Missing field %r' % value
    if isinstance(error, OSError) and isinstance(error.errno, int):
        return '%s errno %d' % (type(error).__name__, error.errno)
    return type(error).__name__


def progress(message):
    # Fixed milestones; the CI log timestamps show how far a run got.
    print(message, flush=True)


def check_prepared_payload(desktop, root, env):
    # The established checker expects installed names, not target-suffixed
    # build inputs. Copy only the three sidecars into disposable staging.
    with tempfile.TemporaryDirectory(prefix='scarlett-signing-payload-') as folder:
        staged = Path(folder)
        for name in SIDECARS:
            shutil.copyfile(sidecar(root, name), staged / (name + '.exe'))
        run('Prepared payload check', [sys.executable, str(desktop / 'scripts/check-complete-bundle.py'), str(staged), str(root)],
            desktop, env, 120)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('desktop', type=Path)
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args()
    if sys.platform != 'win32' or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('RUNNER_OS') != 'Windows':
        raise ValueError('Use a disposable native Windows release CI runner')
    desktop, evidence = args.desktop, args.evidence
    if not desktop.is_absolute() or not evidence.is_absolute() or evidence.exists() or evidence.is_symlink() or not evidence.parent.is_dir():
        raise ValueError('Supply the prepared desktop checkout and a new evidence destination')
    root = desktop / 'src-tauri'
    identities = signing_identities.load()
    scheme, publisher, certificate, timestamp = release_identity(os.environ, identities)
    progress('Pinned publisher identity and signing scheme accepted')
    # Children (the Tauri callback and the checker) receive the validated pins.
    env = dict(os.environ, SCARLETT_WINDOWS_SIGNING_ROOT=str(root), SCARLETT_SIGNING_SCHEME=scheme,
               SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT=publisher, SCARLETT_WINDOWS_CERT_SHA256=certificate,
               SCARLETT_WINDOWS_TIMESTAMP_URL=timestamp)
    if run('Source checkout status', ['git', 'status', '--porcelain', '--untracked-files=no'], desktop, env).strip():
        raise ValueError('Sign only a clean reviewed source checkout')
    source = run('Source commit lookup', ['git', 'rev-parse', 'HEAD'], desktop, env).decode().strip()
    progress('Source checkout is clean')
    metadata = verify_inputs(root)
    progress('Unsigned inputs match the component inventory')
    check_prepared_payload(desktop, root, env)
    progress('Unsigned payload check passed')
    cli = regular(desktop / 'node_modules/@tauri-apps/cli/tauri.js')
    if run('Tauri CLI version', ['node.exe', str(cli), '--version'], desktop, env).decode().strip() != 'tauri-cli 2.12.1':
        raise ValueError('Use the pinned Tauri CLI')
    setup_dir = root / 'target/release/bundle/nsis'
    if setup_dir.exists() and any(setup_dir.iterdir()):
        raise ValueError('Preserve previous installers and prepare a fresh NSIS destination')
    progress('Pinned Tauri CLI and a fresh NSIS destination confirmed')
    signer = desktop / 'scripts/sign-windows-file.ps1'
    for name in sorted(SIDECARS) + ['scarlett-node-desktop']:
        file = sidecar(root, name) if name in SIDECARS else root / 'target/release/scarlett-node-desktop.exe'
        run('Signing ' + name, ['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(signer), '-File', str(file)], desktop, env)
        progress('Signed and verified ' + name)
    final = finalize_metadata(root, metadata, release_signing(scheme, publisher, certificate, identities['rehearsal']))
    manifest = root / 'runtime/COMPONENTS.json'
    temporary = manifest.with_name('COMPONENTS.signing.tmp')
    with temporary.open('x') as file:
        json.dump(final, file, indent=2); file.write('\n')
    temporary.replace(manifest)
    check_prepared_payload(desktop, root, env)
    progress('Signed payload check passed')
    with tempfile.TemporaryDirectory(prefix='scarlett-windows-signing-') as folder:
        configuration = Path(folder) / 'signing.json'
        configuration.write_text(json.dumps(signing_config(signer)))
        # Preserve signed bytes: Tauri's bundle-type patch otherwise invalidates
        # the main executable signature. Its callback preserves valid signatures.
        with nsis_signing_environment(root, env) as packaging_env:
            run('NSIS packaging and callback signing',
                ['node.exe', str(cli), 'bundle', '--ci', '--bundles', 'nsis', '--no-binary-patching',
                 '--config', str(root / 'tauri.complete.generated.json'), '--config', str(configuration)], desktop, packaging_env, 600)
    installers = list(setup_dir.glob('*.exe'))
    if len(installers) != 1:
        raise ValueError('Expected exactly one signed native release installer')
    progress('Packaged the NSIS installer with callback signing')
    installer = installers[0]
    installer_hash = digest(installer)
    runner = Path(env['RUNNER_TEMP'])
    fixture = runner / 'scarlett-browser-fixtures'
    acceptance = runner / 'scarlett-installed-evidence'
    signature_file = runner / 'scarlett-signed-release-signatures.json'
    if fixture.exists() or acceptance.exists() or signature_file.exists():
        raise ValueError('Require fresh disposable installer acceptance paths')
    run('Browser fixture preparation', [sys.executable, str(desktop / 'scripts/prepare-browser-fixtures.py'), str(fixture)], desktop, env)
    run('Installed acceptance', ['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(desktop / 'scripts/check-windows-install.ps1'),
         '-Installer', str(installer), '-EvidenceDirectory', str(acceptance), '-Preferences', '-BrowserFixture', str(fixture / 'fixture.json')], desktop, env, 900)
    progress('Installed lifecycle, preferences and browser-import acceptance passed')
    installed = runner / 'Scarlett Installed UI Acceptance'
    run('Signature acceptance', ['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(desktop / 'scripts/check-windows-signatures.ps1'),
         '-Installer', str(installer), '-InstalledDirectory', str(installed), '-ExpectedPublisherThumbprint', publisher,
         '-Scheme', scheme, '-CertificateSha256', certificate, '-EvidenceFile', str(signature_file)], desktop, env)
    signatures = json.loads(signature_file.read_text())
    if signatures['signature'] != scheme or signatures['publisherThumbprint'] != publisher or \
            signatures['certificateSha256'] != certificate or \
            (scheme == 'self-signed-stable' and signatures['trustResult'] != UNTRUSTED_ROOT):
        raise ValueError('Native signature evidence differs from the selected pins')
    if digest(installer) != installer_hash or signatures['installer']['sha256'] != installer_hash:
        raise ValueError('Installer changed during installed acceptance')
    if digest(installed / 'runtime/COMPONENTS.json') != digest(manifest):
        raise ValueError('Installed component manifest differs from the signed build')
    for name in SIDECARS | {'scarlett-node-desktop'}:
        built = sidecar(root, name) if name in SIDECARS else root / 'target/release/scarlett-node-desktop.exe'
        if signatures['installedExecutables'][name]['sha256'] != digest(built):
            raise ValueError('Installed signed executable differs from the signed build')
    for filename in ('windows-installed-ui.json', 'windows-preferences-ui.json', 'windows-browser-import-ui.json'):
        regular(acceptance / filename)
    record = {'schemaVersion': 1, 'sourceCommit': source, 'signature': scheme,
              'publisherThumbprint': publisher, 'certificateSha1': publisher.lower(), 'certificateSha256': certificate,
              'installerSha256': installer_hash,
              'componentManifestSha256': digest(manifest), 'installedFromThisInstaller': True,
              'nativeInstalledLifecyclePreferencesAndBrowserAcceptance': True,
              'vendorBytesPreserved': True, 'providerJobs': 0,
              'realAccountLoginAndUpgradeAcceptance': 'separate gates required'}
    if scheme == 'self-signed-stable':
        record['trustResult'] = UNTRUSTED_ROOT
    if identities['rehearsal']:
        record['rehearsal'] = True
    with evidence.open('x') as file:
        json.dump(record, file, indent=2); file.write('\n')
    print('Signed Windows installer passed native signature and installed payload/UI acceptance')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:  # noqa: BLE001 - every failure gets the fixed summary and a safe reason
        print('Windows release signing failed; artifact is not approved for publication', file=sys.stderr)
        print('Reason: ' + failure_reason(error), file=sys.stderr)
        raise SystemExit(1) from None
