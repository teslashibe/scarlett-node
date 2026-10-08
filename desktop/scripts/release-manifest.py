#!/usr/bin/env python3
"""Assemble the publishable desktop release from the three signed platform outputs.

The release workflow's assemble job runs this with no secrets and no signing
tools. Each platform directory holds exactly what its signing job uploaded: one
installer (.dmg or .exe), its .evidence.json and the signed COMPONENTS.json.
Every record is checked against desktop/signing/identities.json (never a
rehearsal file, never rehearsal evidence) and against the installer's own
SHA-256 before anything is written.

Release notes come from release-notes/<version>.json (one file per release,
see release-notes/README.md). They become the manifest's "notes", the
cumulative changelog.json the network site renders, and the GitHub release body.

Headless bundles (scripts/package.sh) and the updater's minisign signatures
(`tauri signer sign --app-version`, from the release-signing job) are optional
inputs. With signatures, every one is verified against the pinned updater keys
in desktop/signing/identities.json and the manifest gains "updates"; the
headless bundles are then published beside the installers. Without them the
release has no "updates" and installed apps fall back to the download page.

The new output directory receives:
  release/    manifest.json, provenance.json, changelog.json, the three renamed
              installers and, when signed, the three headless bundles; exactly
              the set the download publisher accepts
  SHA256SUMS  "<sha256>  <file>" lines, sorted (the publisher writes its own
              copy inside the published version, so this stays outside release/)
  evidence/   the signing evidence, component manifests and release-notes.md
  headless/   unsigned headless bundles (GitHub release assets only)

  release-manifest.py check-version 0.1.1
  release-manifest.py assemble --version 0.1.1 --channel stable \\
      --node-commit <GITHUB_SHA> --model-api-commit <open-agent-api v0.1.32 commit> \\
      --workflow-run https://github.com/<owner>/<repo>/actions/runs/<id>/attempts/<n> \\
      --darwin-arm64 DIR --darwin-amd64 DIR --windows-amd64 DIR \\
      [--headless-linux-amd64 DIR --headless-darwin-arm64 DIR --headless-darwin-amd64 DIR] \\
      [--signatures DIR] --output NEW_DIR
  release-manifest.py changelog --version 0.1.1 --output changelog.json
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import signing_identities  # noqa: E402
import updater_signatures  # noqa: E402

REPOSITORY = Path(__file__).resolve().parents[2]
VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?')
COMMIT = re.compile('[0-9a-f]{40}')
SHA256 = re.compile('[0-9a-f]{64}')
WORKFLOW_RUN = re.compile(r'https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/actions/runs/[0-9]+/attempts/[0-9]+')
CHANNELS = ('stable', 'preview')
SCHEME = 'self-signed-stable'
PUBLISHER = 'Scarlett (self-signed)'
# Reviewed native runtime pins; test_version_pins.py keeps every copy in agreement.
CODEX_VERSION = '0.159.2'
CLAUDE_VERSION = '2.1.286'
MODEL_API_VERSION = '0.1.32'
# open-agent-api refs/tags/v0.1.32^{}: the revision prepare-complete-bundle.mjs accepts.
MODEL_API_COMMIT = '3a2559dbe65c85a051de40e2bbafc2639fb99e73'
COMPONENTS = ['claude-cli', 'codex-cli', 'desktop', 'model-api', 'node', 'prover']
SIDECARS = {'scarlett-node', 'scarlett-prover', 'open-agent-api'}
UNTRUSTED_ROOT = '0x800B0109'
HEADLESS_PLATFORMS = ('linux-amd64', 'darwin-arm64', 'darwin-amd64')
RELEASE_NOTES = REPOSITORY / 'release-notes'
CHANGELOG_URL = 'https://network.scarlett.ai/changelog/#v%s'
GITHUB_RELEASE = 'https://github.com/teslashibe/scarlett-node/releases/tag/v%s'
DETAILS_PREFIX = 'https://network.scarlett.ai/docs/'
DATE = re.compile(r'20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])')
NOTES_KEYS = {'schemaVersion', 'version', 'date', 'title', 'highlights'}
MAX_CHANGELOG_BYTES = 65536
PLATFORMS = {
    'darwin-arm64': {'identity': 'macos', 'extension': '.dmg', 'target': 'aarch64-apple-darwin'},
    'darwin-amd64': {'identity': 'macos', 'extension': '.dmg', 'target': 'x86_64-apple-darwin'},
    'windows-amd64': {'identity': 'windows', 'extension': '.exe', 'target': 'x86_64-pc-windows-msvc'},
}
MAC_EVIDENCE = {'schemaVersion', 'signature', 'certificateSha1', 'certificateSha256', 'designatedRequirement',
                'notarization', 'gatekeeper', 'target', 'componentManifestSha256', 'bytes', 'sha256',
                'vendorBytesPreserved'}
WINDOWS_EVIDENCE = {'schemaVersion', 'sourceCommit', 'signature', 'publisherThumbprint', 'certificateSha1',
                    'certificateSha256', 'installerSha256', 'componentManifestSha256', 'installedFromThisInstaller',
                    'nativeInstalledLifecyclePreferencesAndBrowserAcceptance', 'vendorBytesPreserved', 'providerJobs',
                    'realAccountLoginAndUpgradeAcceptance', 'trustResult'}
VERIFIED_WITH = {
    'macos': 'sign-macos-bundle.py: codesign --verify --strict -R pinned designated requirement, exactly one embedded '
             'certificate equal to the pinned SHA-256, no TeamIdentifier, hardened runtime, vendor Developer ID '
             'signatures unchanged, packaged component and local API check',
    'windows': 'sign-windows-bundle.py: WinVerifyTrust 0x800B0109 only, pinned thumbprint and certificate SHA-256, '
               'self-issued signer, trusted RFC3161 timestamp, installed payload, lifecycle, preferences and '
               'browser import acceptance of this installer',
}


def regular(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Release inputs must be regular files')
    return path


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def read_json(path, limit=1048576):
    regular(path)
    if path.stat().st_size > limit:
        raise ValueError('Release record is too large')
    return json.loads(path.read_text(encoding='utf-8'))


def app_versions():
    """The desktop version recorded in tauri.conf.json, package.json, Cargo.toml, both lockfiles and the
    node's NodeRelease, which it reports to the coordinator."""
    tauri = json.loads((REPOSITORY / 'desktop/src-tauri/tauri.conf.json').read_text())['version']
    package = json.loads((REPOSITORY / 'desktop/package.json').read_text())['version']
    lock = json.loads((REPOSITORY / 'desktop/package-lock.json').read_text())
    cargo = re.search(r'^\[package\]\n(?:[^\[\n][^\n]*\n)*?version = "([^"]+)"$',
                      (REPOSITORY / 'desktop/src-tauri/Cargo.toml').read_text(), re.MULTILINE)
    locked = re.search(r'^name = "scarlett-node-desktop"\nversion = "([^"]+)"$',
                       (REPOSITORY / 'desktop/src-tauri/Cargo.lock').read_text(), re.MULTILINE)
    node = re.search(r'^const NodeRelease = "([^"]+)"$',
                     (REPOSITORY / 'internal/coordinator/release.go').read_text(), re.MULTILINE)
    return {tauri, package, lock.get('version'), lock.get('packages', {}).get('', {}).get('version'),
            cargo.group(1) if cargo else None, locked.group(1) if locked else None, node.group(1) if node else None}


def check_version(version):
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError('Release versions are semantic versions')
    if app_versions() != {version}:
        raise ValueError('The release version must equal the reviewed desktop version on this commit')
    load_notes(version)
    return version


def version_key(version):
    """Semantic version precedence for release ordering."""
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError('Release versions are semantic versions')
    core, _, pre = version.partition('-')
    numbers = tuple(int(part) for part in core.split('.'))
    if not pre:
        return numbers + (1,)
    ids = tuple((0, int(i), '') if i.isdigit() else (1, 0, i) for i in pre.split('.'))
    return numbers + (0,) + ids


def plain_text(value, limit):
    """Operator-facing note text: short, trimmed, no markup or control characters."""
    return (isinstance(value, str) and 0 < len(value) <= limit and value.strip() == value and
            not any(c in '<>' or ord(c) < 32 or 0x7f <= ord(c) < 0xa0 or c in '\u2028\u2029\ufffd' for c in value))


def check_notes(notes, version):
    if not isinstance(notes, dict) or not NOTES_KEYS <= set(notes) <= NOTES_KEYS | {'details'}:
        raise ValueError('Release notes have schemaVersion, version, date, title, highlights and optional details')
    if notes['schemaVersion'] != 1 or notes['version'] != version:
        raise ValueError('Release notes belong to another version')
    if not isinstance(notes['date'], str) or not DATE.fullmatch(notes['date']):
        raise ValueError('Release notes need a YYYY-MM-DD date')
    if not plain_text(notes['title'], 80):
        raise ValueError('Release notes need a plain title of at most 80 characters')
    highlights = notes['highlights']
    if not isinstance(highlights, list) or not 1 <= len(highlights) <= 3 or not all(plain_text(h, 160) for h in highlights):
        raise ValueError('Release notes need one to three plain highlights of at most 160 characters')
    details = notes.get('details')
    if details is not None and (not isinstance(details, str) or not details.startswith(DETAILS_PREFIX) or len(details) > 200 or
                                any(c in details for c in '<>"\' \\') or not plain_text(details, 200)):
        raise ValueError('Release note details link to the developer docs on network.scarlett.ai')
    return notes


def load_notes(version, directory=None):
    """release-notes/<version>.json, validated."""
    path = Path(directory or RELEASE_NOTES) / ('%s.json' % version)
    version_key(version)
    return check_notes(read_json(path, 4096), version)


def manifest_notes(notes):
    """The manifest's notes: what the app shows before a version is installed."""
    version = notes['version']
    return {'title': notes['title'], 'date': notes['date'], 'highlights': list(notes['highlights']),
            'changelog': CHANGELOG_URL % version, 'release': GITHUB_RELEASE % version}


def changelog(version, directory=None):
    """Every release's notes up to version, newest first: the public changelog."""
    directory = Path(directory or RELEASE_NOTES)
    entries = []
    for path in directory.glob('*.json'):
        name = path.name[:-len('.json')]
        if not VERSION.fullmatch(name) or version_key(name) > version_key(version):
            continue
        notes = load_notes(name, directory)
        entry = {'version': name, 'date': notes['date'], 'title': notes['title'],
                 'highlights': list(notes['highlights']), 'release': GITHUB_RELEASE % name}
        if 'details' in notes:
            entry['details'] = notes['details']
        entries.append(entry)
    entries.sort(key=lambda e: version_key(e['version']), reverse=True)
    if not entries or entries[0]['version'] != version:
        raise ValueError('The changelog needs release notes for this version')
    document = {'schemaVersion': 1, 'releases': entries[:100]}
    if len(json.dumps(document, indent=2).encode()) > MAX_CHANGELOG_BYTES:
        raise ValueError('The changelog exceeds 64 KiB')
    return document


def release_body(notes):
    """The GitHub release body, from the same notes."""
    version = notes['version']
    lines = ['**%s**' % notes['title'], '']
    lines += ['- %s' % h for h in notes['highlights']]
    lines += ['', 'Changelog: %s' % (CHANGELOG_URL % version)]
    if 'details' in notes:
        lines.append('Developer details: %s' % notes['details'])
    return '\n'.join(lines) + '\n'


def headless_name(version, platform):
    return 'scarlett-node-%s-%s.tar.gz' % (version, platform)


def headless_input(directory, version, platform):
    """package.sh output: exactly the bundle and its .sha256 line."""
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise ValueError('Each headless bundle output must be an absolute directory')
    name = headless_name(version, platform)
    if sorted(p.name for p in directory.iterdir()) != [name, name + '.sha256']:
        raise ValueError('A headless output holds exactly %s and its .sha256' % name)
    bundle = regular(directory / name)
    sha256 = digest(bundle)
    if (directory / (name + '.sha256')).read_text(encoding='ascii') != '%s  %s\n' % (sha256, name) or bundle.stat().st_size == 0:
        raise ValueError('Headless bundle checksum does not match')
    return {'platform': platform, 'path': bundle, 'filename': name, 'sha256': sha256, 'bytes': bundle.stat().st_size}


def verify_signatures(directory, version, files, identities):
    """Check one updater signature per file against the pinned keys."""
    keys = signing_identities.updater_keys(identities)
    if not keys:
        raise ValueError('Signed updates need pinned updater keys in desktop/signing/identities.json')
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise ValueError('Updater signatures must be an absolute directory')
    expected = {name + '.sig' for name in files}
    if {p.name for p in directory.iterdir()} != expected:
        raise ValueError('Updater signatures must cover exactly the installers and headless bundles')
    signatures, signers = {}, set()
    for name, path in files.items():
        text = read_json_text(directory / (name + '.sig'), 4096)
        signers.add(updater_signatures.verify(text, updater_signatures.blake2b_file(path), name, version, keys))
        signatures[name] = text.strip()
    if len(signers) != 1:
        raise ValueError('One updater key signs a whole release')
    return signers.pop(), signatures


def read_json_text(path, limit):
    regular(path)
    if path.stat().st_size > limit:
        raise ValueError('Release record is too large')
    return path.read_text(encoding='ascii')


def installer_name(version, platform):
    return 'Scarlett-Node-%s-%s%s' % (version, platform, PLATFORMS[platform]['extension'])


def platform_inputs(directory, platform):
    """Exactly one installer, one evidence record and one signed component manifest."""
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        raise ValueError('Each signed platform output must be an absolute directory')
    entries = list(directory.iterdir())
    installers = [p for p in entries if p.name.endswith(PLATFORMS[platform]['extension'])]
    evidence = [p for p in entries if p.name.endswith('.evidence.json')]
    components = [p for p in entries if p.name == 'COMPONENTS.json']
    if len(installers) != 1 or len(evidence) != 1 or len(components) != 1 or len(entries) != 3:
        raise ValueError('A signed platform output holds exactly its installer, evidence and COMPONENTS.json')
    return regular(installers[0]), regular(evidence[0]), regular(components[0])


def check_components(components, platform, identity):
    if not isinstance(components, dict) or components.get('schemaVersion') != 1 or \
            components.get('target') != PLATFORMS[platform]['target']:
        raise ValueError('Component manifest belongs to another platform')
    if [components.get(k) for k in ('codexVersion', 'claudeVersion', 'modelApiVersion')] != \
            [CODEX_VERSION, CLAUDE_VERSION, MODEL_API_VERSION]:
        raise ValueError('Component manifest does not carry the reviewed provider and model API versions')
    sidecars = components.get('sidecars')
    if not isinstance(sidecars, list) or len(sidecars) != 3 or \
            not all(isinstance(s, dict) for s in sidecars) or {s.get('name') for s in sidecars} != SIDECARS:
        raise ValueError('Component manifest must record the three signed sidecars')
    for item in sidecars:
        # Signing replaced each sidecar's bytes and kept the unsigned digest for provenance.
        hashes = [item.get('sha256'), item.get('unsignedSha256')]
        if not all(isinstance(h, str) and SHA256.fullmatch(h) for h in hashes) or hashes[0] == hashes[1]:
            raise ValueError('Component manifest must record the three signed sidecars')
    if PLATFORMS[platform]['identity'] == 'macos':
        expected = {'scheme': SCHEME, 'certificateSha1': identity['sha1'], 'certificateSha256': identity['sha256'],
                    'designatedRequirement': identity['designatedRequirement'], 'vendorBytesPreserved': True}
    else:
        expected = {'scheme': SCHEME, 'publisherThumbprint': identity['sha1'].upper(),
                    'certificateSha256': identity['sha256'], 'vendorBytesPreserved': True}
    # Exact equality also rejects a "rehearsal" marker.
    if components.get('releaseSigning') != expected:
        raise ValueError('Component manifest was not finalized with the pinned release certificate')


def check_evidence(evidence, platform, identity, installer_sha256, installer_bytes, components_sha256, node_commit):
    if not isinstance(evidence, dict) or 'rehearsal' in evidence:
        raise ValueError('Rehearsal evidence is never release evidence')
    if PLATFORMS[platform]['identity'] == 'macos':
        expected = {'schemaVersion': 1, 'signature': SCHEME, 'certificateSha1': identity['sha1'],
                    'certificateSha256': identity['sha256'], 'designatedRequirement': identity['designatedRequirement'],
                    'notarization': 'not-performed', 'gatekeeper': 'user-approval-required',
                    'target': PLATFORMS[platform]['target'], 'componentManifestSha256': components_sha256,
                    'bytes': installer_bytes, 'sha256': installer_sha256, 'vendorBytesPreserved': True}
        keys = MAC_EVIDENCE
    else:
        expected = {'schemaVersion': 1, 'sourceCommit': node_commit, 'signature': SCHEME,
                    'publisherThumbprint': identity['sha1'].upper(), 'certificateSha1': identity['sha1'],
                    'certificateSha256': identity['sha256'], 'installerSha256': installer_sha256,
                    'componentManifestSha256': components_sha256, 'installedFromThisInstaller': True,
                    'nativeInstalledLifecyclePreferencesAndBrowserAcceptance': True, 'vendorBytesPreserved': True,
                    'providerJobs': 0, 'realAccountLoginAndUpgradeAcceptance': 'separate gates required',
                    'trustResult': UNTRUSTED_ROOT}
        keys = WINDOWS_EVIDENCE
    if set(evidence) != keys or evidence != expected:
        raise ValueError('Signing evidence differs from the pinned certificate, installer or component manifest')


def verify_platform(directory, platform, identities, node_commit):
    identity = identities[PLATFORMS[platform]['identity']]
    installer, evidence_path, components_path = platform_inputs(directory, platform)
    installer_sha256, installer_bytes = digest(installer), installer.stat().st_size
    if installer_bytes == 0:
        raise ValueError('Installers cannot be empty')
    components_sha256 = digest(components_path)
    check_components(read_json(components_path, 16777216), platform, identity)
    check_evidence(read_json(evidence_path), platform, identity, installer_sha256, installer_bytes,
                   components_sha256, node_commit)
    return {'platform': platform, 'installer': installer, 'evidence': evidence_path, 'components': components_path,
            'sha256': installer_sha256, 'bytes': installer_bytes, 'componentManifestSha256': components_sha256,
            'evidenceSha256': digest(evidence_path), 'identity': identity}


def copy_exact(source, destination, sha256):
    with source.open('rb') as reader, destination.open('xb') as writer:
        shutil.copyfileobj(reader, writer, 1048576)
    if digest(destination) != sha256:
        raise ValueError('Input changed while it was copied')


def write_json(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def build_records(verified, version, channel, source, workflow_run, notes=None, updates=None):
    artifacts, signing = [], {}
    for item in verified:
        platform, identity = item['platform'], item['identity']
        name = installer_name(version, platform)
        artifacts.append({'platform': platform, 'filename': name, 'path': '/downloads/v%s/%s' % (version, name),
                          'bytes': item['bytes'], 'sha256': item['sha256'], 'nativeValidated': True,
                          'components': list(COMPONENTS),
                          'signature': {'status': SCHEME, 'publisher': PUBLISHER, 'certificateSha1': identity['sha1'],
                                        'certificateSha256': identity['sha256']}})
        record = {'status': SCHEME, 'certificateSha1': identity['sha1'], 'certificateSha256': identity['sha256'],
                  'installerSha256': item['sha256']}
        if PLATFORMS[platform]['identity'] == 'macos':
            record['designatedRequirement'] = identity['designatedRequirement']
        record['verifiedWith'] = {'evidence': 'evidence/%s.evidence.json' % platform, 'evidenceSha256': item['evidenceSha256'],
                                  'componentManifestSha256': item['componentManifestSha256'],
                                  'checks': VERIFIED_WITH[PLATFORMS[platform]['identity']]}
        signing[platform] = record
    manifest = {'schemaVersion': 1, 'version': version, 'channel': channel, 'source': dict(source), 'artifacts': artifacts}
    if notes is not None:
        manifest['notes'] = manifest_notes(notes)
    if updates is not None:
        manifest['updates'] = updates
    provenance = {'version': version, 'source': dict(source), 'workflowRun': workflow_run,
                  'components': {'codex': CODEX_VERSION, 'claude': CLAUDE_VERSION, 'modelApi': MODEL_API_VERSION},
                  'signing': signing}
    return manifest, provenance


def updates_record(version, key_id, signatures, verified, headless):
    """The manifest's "updates": signatures over the installers already listed
    in artifacts, plus each signed headless bundle with its own path and hash."""
    desktop = {}
    for item in verified:
        name = installer_name(version, item['platform'])
        desktop[item['platform']] = {'filename': name, 'signature': signatures[name]}
    bundles = {}
    for item in headless:
        bundles[item['platform']] = {'filename': item['filename'], 'path': '/downloads/v%s/%s' % (version, item['filename']),
                                     'bytes': item['bytes'], 'sha256': item['sha256'], 'signature': signatures[item['filename']]}
    record = {'schemaVersion': 1, 'keyId': key_id, 'desktop': desktop}
    if bundles:
        record['headless'] = bundles
    return record


def assemble(version, channel, node_commit, model_api_commit, workflow_run, inputs, output, environ=None,
             headless=None, signatures=None):
    """Verify every input, then write the release layout into a new directory."""
    check_version(version)
    if channel not in CHANNELS:
        raise ValueError('Release channel is stable or preview')
    if not isinstance(node_commit, str) or not COMMIT.fullmatch(node_commit):
        raise ValueError('The node source is an exact lowercase commit')
    if model_api_commit != MODEL_API_COMMIT:
        raise ValueError('The model API source must be the reviewed open-agent-api v0.1.32 commit')
    if not isinstance(workflow_run, str) or not WORKFLOW_RUN.fullmatch(workflow_run):
        raise ValueError('Name the exact workflow run attempt that signed this release')
    if set(inputs) != set(PLATFORMS):
        raise ValueError('A release has exactly the three reviewed platforms')
    if headless is not None and set(headless) != set(HEADLESS_PLATFORMS):
        raise ValueError('Headless bundles come for all three platforms or none')
    identities = signing_identities.load(os.environ if environ is None else environ)
    if identities['rehearsal']:
        raise ValueError('Rehearsal identities never assemble a release')
    output = Path(output)
    if not output.is_absolute() or output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError('Supply a new absolute output directory')
    notes = load_notes(version)
    history = changelog(version)
    verified = [verify_platform(inputs[platform], platform, identities, node_commit) for platform in PLATFORMS]
    if len({item['sha256'] for item in verified}) != len(verified):
        raise ValueError('Each platform has its own installer')
    bundles = [headless_input(headless[platform], version, platform) for platform in HEADLESS_PLATFORMS] if headless else []
    updates = None
    if signatures is not None:
        files = {installer_name(version, item['platform']): item['installer'] for item in verified}
        files.update({item['filename']: item['path'] for item in bundles})
        key_id, signed = verify_signatures(signatures, version, files, identities)
        updates = updates_record(version, key_id, signed, verified, bundles)
    source = {'node': node_commit, 'modelApi': model_api_commit}
    manifest, provenance = build_records(verified, version, channel, source, workflow_run, notes, updates)
    output.mkdir()
    try:
        release, evidence = output / 'release', output / 'evidence'
        release.mkdir()
        evidence.mkdir()
        files = {}
        for item in verified:
            name = installer_name(version, item['platform'])
            copy_exact(item['installer'], release / name, item['sha256'])
            copy_exact(item['evidence'], evidence / ('%s.evidence.json' % item['platform']), item['evidenceSha256'])
            copy_exact(item['components'], evidence / ('%s.COMPONENTS.json' % item['platform']),
                       item['componentManifestSha256'])
            files[name] = item['sha256']
        if bundles:
            # Only signed bundles are published; unsigned ones stay GitHub assets.
            destination = release if updates else output / 'headless'
            destination.mkdir(exist_ok=True)
            for item in bundles:
                copy_exact(item['path'], destination / item['filename'], item['sha256'])
                if updates:
                    files[item['filename']] = item['sha256']
        write_json(release / 'manifest.json', manifest)
        write_json(release / 'provenance.json', provenance)
        write_json(release / 'changelog.json', history)
        with (evidence / 'release-notes.md').open('x', encoding='utf-8') as stream:
            stream.write(release_body(notes))
        with (output / 'SHA256SUMS').open('x', encoding='ascii', newline='\n') as stream:
            stream.write(''.join('%s  %s\n' % (sha, name) for name, sha in sorted(files.items())))
        if (release / 'manifest.json').stat().st_size > 16384:
            raise ValueError('Release manifest exceeds the publisher limit')
        if {p.name for p in release.iterdir()} != set(files) | {'manifest.json', 'provenance.json', 'changelog.json'}:
            raise ValueError('Release directory must hold only the publishable set')
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise
    return manifest, provenance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    version = commands.add_parser('check-version', help='require the reviewed desktop version')
    version.add_argument('version')
    build = commands.add_parser('assemble', help='verify signed outputs and write the release layout')
    build.add_argument('--version', required=True)
    build.add_argument('--channel', required=True, choices=CHANNELS)
    build.add_argument('--node-commit', required=True)
    build.add_argument('--model-api-commit', required=True)
    build.add_argument('--workflow-run', required=True)
    for platform in PLATFORMS:
        build.add_argument('--' + platform, required=True, type=Path)
    for platform in HEADLESS_PLATFORMS:
        build.add_argument('--headless-' + platform, type=Path)
    build.add_argument('--signatures', type=Path)
    build.add_argument('--output', required=True, type=Path)
    history = commands.add_parser('changelog', help='write the cumulative changelog.json for a version')
    history.add_argument('--version', required=True)
    history.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == 'check-version':
        print('Release version %s matches the reviewed desktop version and has release notes' % check_version(args.version))
        return
    if args.command == 'changelog':
        if args.output.exists():
            raise ValueError('Supply a new output file')
        write_json(args.output, changelog(args.version))
        return
    inputs = {platform: getattr(args, platform.replace('-', '_')) for platform in PLATFORMS}
    given = {platform: getattr(args, 'headless_' + platform.replace('-', '_')) for platform in HEADLESS_PLATFORMS}
    if any(given.values()) and not all(given.values()):
        raise ValueError('Supply headless bundles for all three platforms or none')
    manifest, _ = assemble(args.version, args.channel, args.node_commit, args.model_api_commit, args.workflow_run,
                           inputs, args.output, headless=given if all(given.values()) else None, signatures=args.signatures)
    for artifact in manifest['artifacts']:
        print('%s  %s' % (artifact['sha256'], artifact['filename']))
    if 'updates' in manifest:
        print('Updater signatures verified with pinned key %s' % manifest['updates']['keyId'])
    else:
        print('No updater signatures: installed apps will offer the download page for this release')
    print('Assembled Scarlett Node %s (%s) from pinned self-signed evidence' % (manifest['version'], manifest['channel']))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError, AttributeError) as error:
        # Inputs are public release files; name the failed rule, never a traceback.
        message = str(error) if isinstance(error, ValueError) else type(error).__name__
        print('Release assembly failed: ' + message, file=sys.stderr)
        raise SystemExit(1) from None
