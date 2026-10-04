#!/usr/bin/env python3
"""Sign prepared release inputs, package NSIS, then test that exact installer.

Requires a disposable native Windows CI runner and an existing publisher
identity. Provider binaries stay unchanged; no provider login or work occurs.
"""
import argparse
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
    if [metadata.get(k) for k in ('codexVersion', 'claudeVersion', 'modelApiVersion')] != ['0.159.2', '2.1.286', '0.1.31']:
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


def finalize_metadata(root, original, publisher):
    result = copy.deepcopy(original)
    for entry in result['files']:
        file = regular(root / 'runtime' / entry['path'])
        if file.stat().st_size != entry['bytes'] or digest(file) != entry['sha256']:
            raise ValueError('Provider or runtime bytes changed during signing')
    for entry in result['sidecars']:
        file = regular(sidecar(root, entry['name']))
        entry['unsignedSha256'], entry['unsignedBytes'] = entry['sha256'], entry['bytes']
        entry['sha256'], entry['bytes'] = digest(file), file.stat().st_size
    result['releaseSigning'] = {'publisherThumbprint': publisher.upper(), 'vendorBytesPreserved': True}
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


def run(arguments, cwd, env, seconds=180):
    try:
        result = subprocess.run(arguments, cwd=cwd, env=env, capture_output=True, timeout=seconds)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Native release operation unavailable') from None
    if result.returncode:
        raise ValueError('Native release operation failed')
    return result.stdout


def check_prepared_payload(desktop, root, env):
    # The established checker expects installed names, not target-suffixed
    # build inputs. Copy only the three sidecars into disposable staging.
    with tempfile.TemporaryDirectory(prefix='scarlett-signing-payload-') as folder:
        staged = Path(folder)
        for name in SIDECARS:
            shutil.copyfile(sidecar(root, name), staged / (name + '.exe'))
        run([sys.executable, str(desktop / 'scripts/check-complete-bundle.py'), str(staged), str(root)], desktop, env, 120)


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
    publisher = os.environ.get('SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT', '')
    if not re.fullmatch('[a-fA-F0-9]{40}', publisher):
        raise ValueError('Existing reviewed Windows publisher identity required')
    env = dict(os.environ, SCARLETT_WINDOWS_SIGNING_ROOT=str(root))
    if run(['git', 'status', '--porcelain', '--untracked-files=no'], desktop, env).strip():
        raise ValueError('Sign only a clean reviewed source checkout')
    source = run(['git', 'rev-parse', 'HEAD'], desktop, env).decode().strip()
    metadata = verify_inputs(root)
    check_prepared_payload(desktop, root, env)
    cli = regular(desktop / 'node_modules/@tauri-apps/cli/tauri.js')
    if run(['node.exe', str(cli), '--version'], desktop, env).decode().strip() != 'tauri-cli 2.12.1':
        raise ValueError('Use the pinned Tauri CLI')
    setup_dir = root / 'target/release/bundle/nsis'
    if setup_dir.exists() and any(setup_dir.iterdir()):
        raise ValueError('Preserve previous installers and prepare a fresh NSIS destination')
    signer = desktop / 'scripts/sign-windows-file.ps1'
    for file in [sidecar(root, name) for name in sorted(SIDECARS)] + [root / 'target/release/scarlett-node-desktop.exe']:
        run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(signer), '-File', str(file)], desktop, env)
    final = finalize_metadata(root, metadata, publisher)
    manifest = root / 'runtime/COMPONENTS.json'
    temporary = manifest.with_name('COMPONENTS.signing.tmp')
    with temporary.open('x') as file:
        json.dump(final, file, indent=2); file.write('\n')
    temporary.replace(manifest)
    check_prepared_payload(desktop, root, env)
    with tempfile.TemporaryDirectory(prefix='scarlett-windows-signing-') as folder:
        configuration = Path(folder) / 'signing.json'
        configuration.write_text(json.dumps(signing_config(signer)))
        # Preserve signed bytes: Tauri's bundle-type patch otherwise invalidates
        # the main executable signature. Its callback preserves valid signatures.
        with nsis_signing_environment(root, env) as packaging_env:
            run(['node.exe', str(cli), 'bundle', '--ci', '--bundles', 'nsis', '--no-binary-patching',
                 '--config', str(root / 'tauri.complete.generated.json'), '--config', str(configuration)], desktop, packaging_env, 600)
    installers = list(setup_dir.glob('*.exe'))
    if len(installers) != 1:
        raise ValueError('Expected exactly one signed native release installer')
    installer = installers[0]
    installer_hash = digest(installer)
    runner = Path(env['RUNNER_TEMP'])
    fixture = runner / 'scarlett-browser-fixtures'
    acceptance = runner / 'scarlett-installed-evidence'
    signature_file = runner / 'scarlett-signed-release-signatures.json'
    if fixture.exists() or acceptance.exists() or signature_file.exists():
        raise ValueError('Require fresh disposable installer acceptance paths')
    run([sys.executable, str(desktop / 'scripts/prepare-browser-fixtures.py'), str(fixture)], desktop, env)
    run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(desktop / 'scripts/check-windows-install.ps1'),
         '-Installer', str(installer), '-EvidenceDirectory', str(acceptance), '-Preferences', '-BrowserFixture', str(fixture / 'fixture.json')], desktop, env, 900)
    installed = runner / 'Scarlett Installed UI Acceptance'
    run(['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(desktop / 'scripts/check-windows-signatures.ps1'),
         '-Installer', str(installer), '-InstalledDirectory', str(installed), '-ExpectedPublisherThumbprint', publisher,
         '-EvidenceFile', str(signature_file)], desktop, env)
    signatures = json.loads(signature_file.read_text())
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
    record = {'schemaVersion': 1, 'sourceCommit': source, 'signature': 'authenticode',
              'publisherThumbprint': publisher.upper(), 'installerSha256': installer_hash,
              'componentManifestSha256': digest(manifest), 'installedFromThisInstaller': True,
              'nativeInstalledLifecyclePreferencesAndBrowserAcceptance': True,
              'vendorBytesPreserved': True, 'providerJobs': 0,
              'realAccountLoginAndUpgradeAcceptance': 'separate gates required'}
    with evidence.open('x') as file:
        json.dump(record, file, indent=2); file.write('\n')
    print('Signed Windows installer passed native signature and installed payload/UI acceptance')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError):
        print('Windows release signing failed; artifact is not approved for publication', file=sys.stderr)
        raise SystemExit(1) from None
