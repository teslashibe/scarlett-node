#!/usr/bin/env python3
"""Sign a reviewed complete app without changing its pinned provider binaries.

Run after a native release build with --bundles app --no-sign. The required
SCARLETT_SIGNING_SCHEME has no default:

  self-signed-stable  Scarlett's own certificate, pinned in desktop/signing, from
                      an unlocked temporary keychain named by SCARLETT_MAC_KEYCHAIN.
                      There is no notarization; users approve the app themselves.
  developer-id        An existing Developer ID identity and notarytool profile.

Credentials are never read from chat/files. No download, account login or
provider execution occurs here.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import signing_identities  # noqa: E402

DEVELOPER_ID = 'anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists'
SIDECARS = {'scarlett-node', 'scarlett-prover', 'open-agent-api'}
MACHO = {b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}


class NativeOperationError(ValueError):
    """Only operation and status are safe for unattended signing diagnostics."""


RELEASE_PHASES = {'inventory', 'vendor-signature', 'own-signature', 'bundle-seal', 'model-api', 'dmg', 'signing-identity', 'notarization'}


@contextmanager
def release_phase(phase):
    """Keep the innermost fixed phase without exposing exception payloads."""
    if phase not in RELEASE_PHASES:
        raise ValueError('Unknown release phase')
    try:
        yield
    except (ValueError, KeyError, OSError, TypeError) as error:
        if getattr(error, 'release_phase', None) not in RELEASE_PHASES:
            error.release_phase = phase
        raise


def failure_summary(error):
    phase = getattr(error, 'release_phase', None)
    if phase not in RELEASE_PHASES:
        phase = 'validation'
    detail = str(error) if isinstance(error, NativeOperationError) else 'Release validation failed: ' + type(error).__name__
    return '[phase=' + phase + '] ' + detail


def run(args, timeout=60):
    # Native tool output can contain local paths and signing configuration.
    # Return it only to internal parsers; failures disclose the operation name.
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise NativeOperationError('Native release operation unavailable: ' + Path(args[0]).name) from None
    if result.returncode:
        raise NativeOperationError('Native release operation failed: ' + Path(args[0]).name + ' (exit ' + str(result.returncode) + ')')
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


def verify_ours(path, identifier, identity, runtime=True):
    """Prove Scarlett's own signature: pinned requirement, one exact certificate, no team."""
    requirement = 'identifier "%s" and certificate leaf = H"%s"' % (identifier, identity['sha1'])
    run(['/usr/bin/codesign', '--verify', '--strict', '-R=' + requirement, str(path)])
    output, _ = run(['/usr/bin/codesign', '--display', '-r-', str(path)])
    if [line for line in output.splitlines() if line.strip()] != ['designated => ' + requirement]:
        raise ValueError('Signed code does not carry the pinned designated requirement')
    with tempfile.TemporaryDirectory(prefix='scarlett-mac-certificates-') as folder:
        prefix = Path(folder) / 'certificate'
        run(['/usr/bin/codesign', '--display', '--extract-certificates=' + str(prefix), str(path)])
        if sorted(item.name for item in Path(folder).iterdir()) != ['certificate0']:
            raise ValueError('Signed code must embed only the pinned self-signed certificate')
        certificate = (Path(folder) / 'certificate0').read_bytes()
    if signing_identities.fingerprints(certificate) != (identity['sha1'], identity['sha256']):
        raise ValueError('Embedded certificate differs from the pinned certificate')
    _, detail = run(['/usr/bin/codesign', '--display', '--verbose=4', str(path)])
    lines = detail.splitlines()
    if 'Identifier=' + identifier not in lines or 'TeamIdentifier=not set' not in lines:
        raise ValueError('Self-signed code must have its fixed identifier and no team')
    if runtime and not any(line.startswith('CodeDirectory') and '(runtime)' in line for line in lines):
        raise ValueError('Signed executable requires hardened runtime')


class DeveloperID:
    scheme = 'developer-id'

    def __init__(self, identity, team):
        self.identity, self.team = identity, team

    def sign(self, path, name):
        run(['/usr/bin/codesign', '--force', '--sign', self.identity, '--options', 'runtime', '--timestamp', str(path)])

    def verify(self, path, name):
        verify_signature(path, self.team)

    def release_signing(self):
        return {'teamIdentifier': self.team, 'vendorBytesPreserved': True}


class SelfSigned:
    """Scarlett's stable self-signed identity, selected by its pinned SHA-1."""
    scheme = 'self-signed-stable'

    def __init__(self, identity, keychain, rehearsal):
        self.identity, self.keychain, self.rehearsal = identity, keychain, rehearsal

    def requirement(self, name):
        return signing_identities.designated_requirement(self.identity['identifiers'][name], self.identity['sha1'])

    def sign(self, path, name, runtime=True):
        # Apple's timestamp service may refuse non-Apple identities, and a secure
        # timestamp matters only for notarization. The certificate outlives releases.
        arguments = ['/usr/bin/codesign', '--force', '--sign', self.identity['sha1'], '--keychain', self.keychain,
                     '--identifier', self.identity['identifiers'][name]]
        if runtime:
            arguments += ['--options', 'runtime']
        run(arguments + ['--timestamp=none', '-r=' + self.requirement(name), str(path)])

    def verify(self, path, name, runtime=True):
        verify_ours(path, self.identity['identifiers'][name], self.identity, runtime)

    def release_signing(self):
        record = {'scheme': self.scheme, 'certificateSha1': self.identity['sha1'],
                  'certificateSha256': self.identity['sha256'], 'designatedRequirement': self.requirement('app'),
                  'vendorBytesPreserved': True}
        if self.rehearsal:
            record['rehearsal'] = True
        return record


@release_phase('signing-identity')
def signing_keychain(value, sha1):
    keychain = Path(value)
    if not value or not keychain.is_absolute() or keychain.is_symlink() or not keychain.is_file() or \
            keychain.name.startswith('login.keychain'):
        raise ValueError('Self-signed mode requires an absolute temporary keychain in SCARLETT_MAC_KEYCHAIN')
    # Without -v: an untrusted self-signed identity is expected and still listed.
    output, _ = run(['/usr/bin/security', 'find-identity', '-p', 'codesigning', str(keychain)])
    if not re.search(r'^\s*\d+\)\s+' + sha1.upper() + r'\s', output, re.MULTILINE):
        raise ValueError('The temporary keychain does not hold the pinned signing identity')
    return str(keychain)


def keychain_list(output):
    entries = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if len(line) < 2 or not line.startswith('"') or not line.endswith('"'):
            raise ValueError('Unexpected keychain search list')
        entries.append(line[1:-1])
    return entries


@contextmanager
def keychain_search_list(keychain):
    """codesign finds an untrusted identity only through the user search list.

    Put the temporary keychain first for the duration, then restore the exact
    original list, also when signing fails.
    """
    output, _ = run(['/usr/bin/security', 'list-keychains', '-d', 'user'])
    original = keychain_list(output)
    try:
        run(['/usr/bin/security', 'list-keychains', '-d', 'user', '-s', keychain] + [k for k in original if k != keychain])
        yield
    finally:
        run(['/usr/bin/security', 'list-keychains', '-d', 'user', '-s'] + original)


@release_phase('notarization')
def notarize(path, profile):
    output, _ = run(['/usr/bin/xcrun', 'notarytool', 'submit', str(path), '--keychain-profile', profile, '--wait', '--output-format', 'json'], timeout=1800)
    try:
        response = json.loads(output)
    except json.JSONDecodeError:
        raise ValueError('Notarization did not return structured acceptance') from None
    if response.get('status') != 'Accepted':
        raise ValueError('Notarization did not accept the artifact')
    return response['id']


@release_phase('inventory')
def sign_app(app, identity=None, team=None, signer=None):
    signer = signer or DeveloperID(identity, team)
    contents, metadata_path, metadata, vendors = verify_input(app)
    # Vendor objects keep their publishers' Developer ID signatures in every scheme.
    with release_phase('vendor-signature'):
        for path in vendors:
            verify_signature(path)
    for name in sorted(SIDECARS) + ['scarlett-node-desktop']:
        path = contents / 'MacOS' / name
        key = name if name in SIDECARS else 'app'
        with release_phase('own-signature'):
            signer.sign(path, key)
            signer.verify(path, key)
    # Only our successfully verified sidecars may receive new signed hashes.
    # Vendor entries remain immutable; preserve the input digests for provenance.
    for item in metadata['sidecars']:
        path = contents / 'MacOS' / item['name']
        item['unsignedSha256'], item['unsignedBytes'] = item['sha256'], item['bytes']
        item['sha256'], item['bytes'] = digest(path), path.stat().st_size
    metadata['releaseSigning'] = signer.release_signing()
    temporary = metadata_path.with_name('COMPONENTS.signing.tmp')
    temporary.write_text(json.dumps(metadata, indent=2) + '\n')
    temporary.replace(metadata_path)
    # Seal only after the signed-byte inventory is final. Never use --deep to sign
    # vendor code: its published identity and notices must remain unchanged.
    with release_phase('bundle-seal'):
        signer.sign(app, 'app')
        run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)])
        signer.verify(app, 'app')
    for item in metadata['files']:
        if digest(contents / 'Resources' / 'runtime' / item['path']) != item['sha256']:
            raise ValueError('Vendor bytes changed during signing')
    return metadata


@release_phase('model-api')
def check_bundle(app):
    # Prove the revised manifest and packaged local API under the new signatures.
    run([sys.executable, str(Path(__file__).with_name('check-complete-bundle.py')), str(app / 'Contents' / 'MacOS'), str(app / 'Contents' / 'Resources')], timeout=90)


@release_phase('dmg')
def stage_disk_image(app, dmg, folder):
    stage = Path(folder) / 'disk'
    stage.mkdir()
    # ditto retains the sealed bundle. The only link is the normal
    # drag-to-Applications shortcut in the disk image, outside the app.
    run(['/usr/bin/ditto', str(app), str(stage / 'Scarlett Node.app')], timeout=180)
    (stage / 'Applications').symlink_to('/Applications')
    run(['/usr/bin/hdiutil', 'create', '-srcfolder', str(stage), '-volname', 'Scarlett Node', '-format', 'UDZO', str(dmg)], timeout=180)


def developer_id_release(app, dmg):
    identity = os.environ.get('APPLE_SIGNING_IDENTITY', '')
    team = os.environ.get('SCARLETT_APPLE_TEAM_ID', '')
    profile = os.environ.get('SCARLETT_NOTARY_KEYCHAIN_PROFILE', '')
    if not identity.startswith('Developer ID Application: ') or not re.fullmatch('[A-Z0-9]{10}', team) or not profile:
        raise ValueError('Existing Developer ID identity, team and notary Keychain profile are required')
    sign_app(app, identity, team)
    check_bundle(app)
    with tempfile.TemporaryDirectory(prefix='scarlett-mac-signing-') as folder:
        archive = Path(folder) / 'Scarlett Node.zip'
        run(['/usr/bin/ditto', '-c', '-k', '--keepParent', str(app), str(archive)], timeout=180)
        app_submission = notarize(archive, profile)
        run(['/usr/bin/xcrun', 'stapler', 'staple', str(app)], timeout=120)
        run(['/usr/bin/xcrun', 'stapler', 'validate', str(app)])
        run(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)])
        stage_disk_image(app, dmg, folder)
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


def self_signed_release(app, dmg):
    identities = signing_identities.load()
    identity = identities['macos']
    keychain = signing_keychain(os.environ.get('SCARLETT_MAC_KEYCHAIN', ''), identity['sha1'])
    signer = SelfSigned(identity, keychain, identities['rehearsal'])
    with keychain_search_list(keychain):
        metadata = sign_app(app, signer=signer)
        check_bundle(app)
        with tempfile.TemporaryDirectory(prefix='scarlett-mac-signing-') as folder:
            stage_disk_image(app, dmg, folder)
            with release_phase('dmg'):
                signer.sign(dmg, 'dmg', runtime=False)
    # No notarization, stapling or Gatekeeper assessment exists for this scheme:
    # users approve the unverified developer in Privacy & Security.
    with release_phase('dmg'):
        signer.verify(dmg, 'dmg', runtime=False)
    evidence = {'schemaVersion': 1, 'signature': signer.scheme, 'certificateSha1': identity['sha1'],
                'certificateSha256': identity['sha256'], 'designatedRequirement': signer.requirement('app'),
                'notarization': 'not-performed', 'gatekeeper': 'user-approval-required',
                'target': metadata['target'],
                'componentManifestSha256': digest(app / 'Contents' / 'Resources' / 'runtime' / 'COMPONENTS.json'),
                'bytes': dmg.stat().st_size, 'sha256': digest(dmg), 'vendorBytesPreserved': True}
    if signer.rehearsal:
        evidence['rehearsal'] = True
    dmg.with_suffix('.evidence.json').write_text(json.dumps(evidence, indent=2) + '\n')
    print('Signed app and DMG passed pinned self-signed integrity checks; not notarized')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
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
    scheme = os.environ.get('SCARLETT_SIGNING_SCHEME', '')
    if scheme == 'self-signed-stable':
        self_signed_release(app, dmg)
    elif scheme == 'developer-id':
        developer_id_release(app, dmg)
    else:
        raise ValueError('Set SCARLETT_SIGNING_SCHEME to self-signed-stable or developer-id')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError) as error:
        # Tool output, arguments and parser/path/keychain payloads stay private.
        print('Mac release signing failed; artifact is not approved for publication. ' + failure_summary(error), file=sys.stderr)
        raise SystemExit(1) from None
