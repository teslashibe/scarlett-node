#!/usr/bin/env python3
"""Sign a reviewed complete app without changing its pinned provider binaries.

Run after a native release build with --bundles app --no-sign. Credentials are
an existing Keychain identity and notarytool profile, never read from chat/files.
No download, account login or provider execution occurs here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile

DEVELOPER_ID = 'anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
SIDECARS = {'scarlett-node', 'scarlett-prover', 'open-agent-api'}
MACHO = {b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}


def run(args, timeout=60):
    # Native tool output can contain local paths and signing configuration.
    # Return it only to internal parsers; failures disclose the operation name.
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Native release operation unavailable: ' + Path(args[0]).name) from None
    if result.returncode:
        raise ValueError('Native release operation failed: ' + Path(args[0]).name)
    return result.stdout, result.stderr


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular_tree(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Complete app must be a regular directory')
    for path in root.rglob('*'):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError('Complete app cannot contain links or special files')


def verify_input(app):
    regular_tree(app)
    contents = app / 'Contents'
    info = plistlib.loads((contents / 'Info.plist').read_bytes())
    if info.get('CFBundleIdentifier') != 'ai.scarlett.node' or info.get('CFBundleExecutable') != 'scarlett-node-desktop':
        raise ValueError('Expected the stable Scarlett desktop identity')
    runtime = contents / 'Resources' / 'runtime'
    metadata_path = runtime / 'COMPONENTS.json'
    metadata = json.loads(metadata_path.read_text())
    if metadata.get('schemaVersion') != 1 or metadata.get('target') not in ('aarch64-apple-darwin', 'x86_64-apple-darwin'):
        raise ValueError('Expected a complete native Mac component manifest')
    if metadata.get('releaseSigning'):
        raise ValueError('This app already has release signing evidence; rebuild before signing again')
    entries = metadata['files']
    expected = {path.relative_to(runtime).as_posix() for path in runtime.rglob('*') if path.is_file() and path != metadata_path}
    if len(entries) != len(expected) or {item['path'] for item in entries} != expected:
        raise ValueError('Runtime inventory changed before signing')
    for item in entries:
        path = runtime / item['path']
        if not path.resolve().is_relative_to(runtime.resolve()) or path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise ValueError('Runtime bytes changed before signing')
    sidecars = metadata['sidecars']
    if len(sidecars) != 3 or {item['name'] for item in sidecars} != SIDECARS:
        raise ValueError('Expected exactly the three reviewed sidecars')
    for item in sidecars:
        path = contents / 'MacOS' / item['name']
        if not path.is_file() or path.stat().st_size != item['bytes'] or digest(path) != item['sha256']:
            raise ValueError('Sidecar bytes changed before signing')
    main = contents / 'MacOS' / 'scarlett-node-desktop'
    if not main.is_file():
        raise ValueError('Desktop executable missing')
    # Every native vendor object keeps its official signature and exact bytes.
    vendors = []
    for item in entries:
        path = runtime / item['path']
        with path.open('rb') as stream:
            if stream.read(4) in MACHO:
                vendors.append(path)
    if not vendors:
        raise ValueError('Native provider runtime missing')
    return contents, metadata_path, metadata, vendors


def verify_signature(path, team=None):
    requirement = DEVELOPER_ID
    if team:
        requirement += ' and certificate leaf[subject.OU] = "' + team + '"'
    run(['/usr/bin/codesign', '--verify', '--strict', '-R=' + requirement, str(path)])
    _, detail = run(['/usr/bin/codesign', '--display', '--verbose=4', str(path)])
    if not any(line.startswith('CodeDirectory') and '(runtime)' in line for line in detail.splitlines()):
        raise ValueError('Signed executable requires hardened runtime')


def notarize(path, profile):
    output, _ = run(['/usr/bin/xcrun', 'notarytool', 'submit', str(path), '--keychain-profile', profile, '--wait', '--output-format', 'json'], timeout=1800)
    try:
        response = json.loads(output)
    except json.JSONDecodeError:
        raise ValueError('Notarization did not return structured acceptance') from None
    if response.get('status') != 'Accepted':
        raise ValueError('Notarization did not accept the artifact')
    return response['id']


def sign_app(app, identity, team):
    contents, metadata_path, metadata, vendors = verify_input(app)
    for path in vendors:
        verify_signature(path)
    for path in [contents / 'MacOS' / name for name in sorted(SIDECARS)] + [contents / 'MacOS' / 'scarlett-node-desktop']:
        run(['/usr/bin/codesign', '--force', '--sign', identity, '--options', 'runtime', '--timestamp', str(path)])
        verify_signature(path, team)
    # Only our successfully verified sidecars may receive new signed hashes.
    # Vendor entries remain immutable; preserve the input digests for provenance.
    for item in metadata['sidecars']:
        path = contents / 'MacOS' / item['name']
        item['unsignedSha256'], item['unsignedBytes'] = item['sha256'], item['bytes']
        item['sha256'], item['bytes'] = digest(path), path.stat().st_size
    metadata['releaseSigning'] = {'teamIdentifier': team, 'vendorBytesPreserved': True}
    temporary = metadata_path.with_name('COMPONENTS.signing.tmp')
    temporary.write_text(json.dumps(metadata, indent=2) + '\n')
    temporary.replace(metadata_path)
    # Seal only after the signed-byte inventory is final. Never use --deep to sign
    # vendor code: its published identity and notices must remain unchanged.
    run(['/usr/bin/codesign', '--force', '--sign', identity, '--options', 'runtime', '--timestamp', str(app)])
    run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)])
    verify_signature(app, team)
    for item in metadata['files']:
        if digest(contents / 'Resources' / 'runtime' / item['path']) != item['sha256']:
            raise ValueError('Vendor bytes changed during signing')
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('app', type=Path)
    parser.add_argument('dmg', type=Path)
    args = parser.parse_args()
    if sys.platform != 'darwin':
        raise ValueError('Mac signing requires a native Mac')
    app, dmg = args.app, args.dmg
    evidence_path = dmg.with_suffix('.evidence.json')
    if not app.is_absolute() or not dmg.is_absolute() or app.suffix != '.app' or dmg.suffix != '.dmg' or dmg.exists() or dmg.is_symlink() or evidence_path.exists() or evidence_path.is_symlink() or not dmg.parent.is_dir():
        raise ValueError('Supply an existing absolute app and a new absolute DMG destination')
    if dmg.resolve().is_relative_to(app.resolve()):
        raise ValueError('Installer output must stay outside the sealed app')
    identity = os.environ.get('APPLE_SIGNING_IDENTITY', '')
    team = os.environ.get('SCARLETT_APPLE_TEAM_ID', '')
    profile = os.environ.get('SCARLETT_NOTARY_KEYCHAIN_PROFILE', '')
    if not identity.startswith('Developer ID Application: ') or not re.fullmatch('[A-Z0-9]{10}', team) or not profile:
        raise ValueError('Existing Developer ID identity, team and notary Keychain profile are required')
    sign_app(app, identity, team)
    # Prove the revised manifest and packaged local API before notarization.
    run([sys.executable, str(Path(__file__).with_name('check-complete-bundle.py')), str(app / 'Contents' / 'MacOS'), str(app / 'Contents' / 'Resources')], timeout=90)
    with tempfile.TemporaryDirectory(prefix='scarlett-mac-signing-') as folder:
        archive = Path(folder) / 'Scarlett Node.zip'
        run(['/usr/bin/ditto', '-c', '-k', '--keepParent', str(app), str(archive)], timeout=180)
        app_submission = notarize(archive, profile)
        run(['/usr/bin/xcrun', 'stapler', 'staple', str(app)], timeout=120)
        run(['/usr/bin/xcrun', 'stapler', 'validate', str(app)])
        run(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)])
        stage = Path(folder) / 'disk'
        stage.mkdir()
        # ditto retains the sealed/notarized bundle. The only link is the normal
        # drag-to-Applications shortcut in the disk image, outside the app.
        run(['/usr/bin/ditto', str(app), str(stage / 'Scarlett Node.app')], timeout=180)
        (stage / 'Applications').symlink_to('/Applications')
        run(['/usr/bin/hdiutil', 'create', '-srcfolder', str(stage), '-volname', 'Scarlett Node', '-format', 'UDZO', str(dmg)], timeout=180)
        run(['/usr/bin/codesign', '--sign', identity, '--timestamp', str(dmg)])
        dmg_submission = notarize(dmg, profile)
    run(['/usr/bin/xcrun', 'stapler', 'staple', str(dmg)], timeout=120)
    run(['/usr/bin/xcrun', 'stapler', 'validate', str(dmg)])
    run(['/usr/bin/codesign', '--verify', '--strict', '-R=' + DEVELOPER_ID + ' and certificate leaf[subject.OU] = "' + team + '"', str(dmg)])
    evidence = {'schemaVersion': 1, 'signature': 'developer-id-notarized', 'teamIdentifier': team,
                'appNotarization': app_submission, 'dmgNotarization': dmg_submission,
                'bytes': dmg.stat().st_size, 'sha256': digest(dmg), 'vendorBytesPreserved': True}
    dmg.with_suffix('.evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print('Signed app and DMG passed integrity, notarization, stapling and Gatekeeper checks')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError):
        # Do not disclose parser/path/keychain exception payloads.
        print('Mac release signing failed; artifact is not approved for publication', file=sys.stderr)
        raise SystemExit(1) from None
