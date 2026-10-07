#!/usr/bin/env python3
"""Assemble the publishable desktop release from the three signed platform outputs.

The release workflow's assemble job runs this with no secrets and no signing
tools. Each platform directory holds exactly what its signing job uploaded: one
installer (.dmg or .exe), its .evidence.json and the signed COMPONENTS.json.
Every record is checked against desktop/signing/identities.json (never a
rehearsal file, never rehearsal evidence) and against the installer's own
SHA-256 before anything is written.

The new output directory receives:
  release/    manifest.json, provenance.json and the three renamed installers;
              exactly the set the download publisher accepts
  SHA256SUMS  "<sha256>  <installer>" lines, sorted (the publisher writes its own
              copy inside the published version, so this stays outside release/)
  evidence/   the signing evidence and component manifests, for review

  release-manifest.py check-version 0.1.1
  release-manifest.py assemble --version 0.1.1 --channel stable \\
      --node-commit <GITHUB_SHA> --model-api-commit <open-agent-api v0.1.32 commit> \\
      --workflow-run https://github.com/<owner>/<repo>/actions/runs/<id>/attempts/<n> \\
      --darwin-arm64 DIR --darwin-amd64 DIR --windows-amd64 DIR --output NEW_DIR
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
    return version


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


def build_records(verified, version, channel, source, workflow_run):
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
    provenance = {'version': version, 'source': dict(source), 'workflowRun': workflow_run,
                  'components': {'codex': CODEX_VERSION, 'claude': CLAUDE_VERSION, 'modelApi': MODEL_API_VERSION},
                  'signing': signing}
    return manifest, provenance


def assemble(version, channel, node_commit, model_api_commit, workflow_run, inputs, output, environ=None):
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
    identities = signing_identities.load(os.environ if environ is None else environ)
    if identities['rehearsal']:
        raise ValueError('Rehearsal identities never assemble a release')
    output = Path(output)
    if not output.is_absolute() or output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError('Supply a new absolute output directory')
    verified = [verify_platform(inputs[platform], platform, identities, node_commit) for platform in PLATFORMS]
    if len({item['sha256'] for item in verified}) != len(verified):
        raise ValueError('Each platform has its own installer')
    source = {'node': node_commit, 'modelApi': model_api_commit}
    manifest, provenance = build_records(verified, version, channel, source, workflow_run)
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
        write_json(release / 'manifest.json', manifest)
        write_json(release / 'provenance.json', provenance)
        with (output / 'SHA256SUMS').open('x', encoding='ascii', newline='\n') as stream:
            stream.write(''.join('%s  %s\n' % (sha, name) for name, sha in sorted(files.items())))
        if (release / 'manifest.json').stat().st_size > 16384:
            raise ValueError('Release manifest exceeds the publisher limit')
        if {p.name for p in release.iterdir()} != set(files) | {'manifest.json', 'provenance.json'}:
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
    build.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == 'check-version':
        print('Release version %s matches the reviewed desktop version' % check_version(args.version))
        return
    inputs = {platform: getattr(args, platform.replace('-', '_')) for platform in PLATFORMS}
    manifest, _ = assemble(args.version, args.channel, args.node_commit, args.model_api_commit, args.workflow_run,
                           inputs, args.output)
    for artifact in manifest['artifacts']:
        print('%s  %s' % (artifact['sha256'], artifact['filename']))
    print('Assembled Scarlett Node %s (%s) from pinned self-signed evidence' % (manifest['version'], manifest['channel']))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, TypeError, AttributeError) as error:
        # Inputs are public release files; name the failed rule, never a traceback.
        message = str(error) if isinstance(error, ValueError) else type(error).__name__
        print('Release assembly failed: ' + message, file=sys.stderr)
        raise SystemExit(1) from None
