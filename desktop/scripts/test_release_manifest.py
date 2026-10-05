"""Contracts for assembling the publishable release from signed platform outputs."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('release_manifest', Path(__file__).with_name('release-manifest.py'))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
identities = release.signing_identities
PINS = identities.load({})
VERSION = json.loads((release.REPOSITORY / 'desktop/src-tauri/tauri.conf.json').read_text())['version']
NODE = 'a1' * 20
RUN = 'https://github.com/teslashibe/scarlett-node/actions/runs/123456/attempts/1'
# The download publisher's rules (k8s-control publish-node-downloads.py), restated here.
PUBLISHER_COMPONENTS = {'desktop', 'node', 'prover', 'model-api', 'codex-cli', 'claude-cli'}
PUBLISHER_SIGNATURE_FIELDS = {'status', 'publisher', 'certificateSha1', 'certificateSha256'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ReleaseFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name).resolve()
        self.inputs = {platform: self.signed_output(platform) for platform in release.PLATFORMS}
        self.output = self.folder / 'scarlett-node-release'

    def signed_output(self, platform):
        directory = self.folder / ('signed-' + platform)
        directory.mkdir()
        family = release.PLATFORMS[platform]['identity']
        identity = PINS[family]
        installer = directory / ('Scarlett Node_%s_%s%s' % (VERSION, platform, release.PLATFORMS[platform]['extension']))
        installer.write_bytes(b'synthetic signed installer ' + platform.encode())
        sidecars = [{'name': name, 'bytes': 10, 'sha256': sha(b'signed ' + name.encode()),
                     'unsignedSha256': sha(name.encode()), 'unsignedBytes': 9} for name in sorted(release.SIDECARS)]
        if family == 'macos':
            signing = {'scheme': 'self-signed-stable', 'certificateSha1': identity['sha1'],
                       'certificateSha256': identity['sha256'], 'designatedRequirement': identity['designatedRequirement'],
                       'vendorBytesPreserved': True}
        else:
            signing = {'scheme': 'self-signed-stable', 'publisherThumbprint': identity['sha1'].upper(),
                       'certificateSha256': identity['sha256'], 'vendorBytesPreserved': True}
        components = {'schemaVersion': 1, 'target': release.PLATFORMS[platform]['target'], 'codexVersion': '0.159.2',
                      'claudeVersion': '2.1.286', 'modelApiVersion': '0.1.32', 'sidecars': sidecars,
                      'files': [{'path': 'codex/bin/codex', 'bytes': 1, 'sha256': sha(b'x')}], 'releaseSigning': signing}
        self.write(directory / 'COMPONENTS.json', components)
        components_sha256 = release.digest(directory / 'COMPONENTS.json')
        data = installer.read_bytes()
        if family == 'macos':
            evidence = {'schemaVersion': 1, 'signature': 'self-signed-stable', 'certificateSha1': identity['sha1'],
                        'certificateSha256': identity['sha256'], 'designatedRequirement': identity['designatedRequirement'],
                        'notarization': 'not-performed', 'gatekeeper': 'user-approval-required',
                        'target': release.PLATFORMS[platform]['target'], 'componentManifestSha256': components_sha256,
                        'bytes': len(data), 'sha256': sha(data), 'vendorBytesPreserved': True}
            name = 'Scarlett-Node-%s-%s.evidence.json' % (VERSION, platform)
        else:
            evidence = {'schemaVersion': 1, 'sourceCommit': NODE, 'signature': 'self-signed-stable',
                        'publisherThumbprint': identity['sha1'].upper(), 'certificateSha1': identity['sha1'],
                        'certificateSha256': identity['sha256'], 'installerSha256': sha(data),
                        'componentManifestSha256': components_sha256, 'installedFromThisInstaller': True,
                        'nativeInstalledLifecyclePreferencesAndBrowserAcceptance': True, 'vendorBytesPreserved': True,
                        'providerJobs': 0, 'realAccountLoginAndUpgradeAcceptance': 'separate gates required',
                        'trustResult': '0x800B0109'}
            name = 'windows.evidence.json'
        self.write(directory / name, evidence)
        return directory

    @staticmethod
    def write(path, value):
        path.write_text(json.dumps(value, indent=2) + '\n')

    def evidence_path(self, platform):
        return next(self.inputs[platform].glob('*.evidence.json'))

    def edit(self, path, change):
        value = json.loads(path.read_text())
        change(value)
        self.write(path, value)

    def edit_evidence(self, platform, change):
        self.edit(self.evidence_path(platform), change)

    def edit_components(self, platform, change):
        """Change COMPONENTS.json and keep the evidence digest consistent with it."""
        path = self.inputs[platform] / 'COMPONENTS.json'
        self.edit(path, change)
        digest = release.digest(path)
        self.edit_evidence(platform, lambda e: e.update(componentManifestSha256=digest))

    def assemble(self, **overrides):
        values = {'version': VERSION, 'channel': 'stable', 'node_commit': NODE, 'model_api_commit': release.MODEL_API_COMMIT,
                  'workflow_run': RUN, 'inputs': self.inputs, 'output': self.output, 'environ': {}}
        values.update(overrides)
        return release.assemble(**values)

    def rejected(self, pattern=None, **overrides):
        with self.assertRaisesRegex(ValueError, pattern or '.'):
            self.assemble(**overrides)
        self.assertFalse(self.output.exists())


class ReleaseManifestTests(ReleaseFixture):
    def test_assembles_exactly_the_publishable_layout(self):
        manifest, provenance = self.assemble()
        names = {p: 'Scarlett-Node-%s-%s' % (VERSION, p) for p in release.PLATFORMS}
        installers = {names['darwin-arm64'] + '.dmg', names['darwin-amd64'] + '.dmg', names['windows-amd64'] + '.exe'}
        self.assertEqual({p.name for p in (self.output / 'release').iterdir()}, installers | {'manifest.json', 'provenance.json'})
        self.assertEqual({p.name for p in self.output.iterdir()}, {'release', 'SHA256SUMS', 'evidence'})
        self.assertEqual({p.name for p in (self.output / 'evidence').iterdir()},
                         {'%s.%s' % (p, kind) for p in release.PLATFORMS for kind in ('evidence.json', 'COMPONENTS.json')})
        self.assertEqual(json.loads((self.output / 'release/manifest.json').read_text()), manifest)
        self.assertEqual(json.loads((self.output / 'release/provenance.json').read_text()), provenance)
        files = {name: release.digest(self.output / 'release' / name) for name in installers}
        self.assertEqual((self.output / 'SHA256SUMS').read_text(),
                         ''.join('%s  %s\n' % (files[name], name) for name in sorted(files)))
        for platform in release.PLATFORMS:
            original = next(p for p in self.inputs[platform].iterdir() if p.suffix in ('.dmg', '.exe'))
            self.assertEqual(release.digest(original), files[release.installer_name(VERSION, platform)])

    def test_manifest_and_provenance_satisfy_the_publisher_rules(self):
        manifest, provenance = self.assemble()
        self.assertEqual((manifest['schemaVersion'], manifest['version'], manifest['channel']), (1, VERSION, 'stable'))
        self.assertEqual(manifest['source'], {'node': NODE, 'modelApi': release.MODEL_API_COMMIT})
        self.assertEqual([a['platform'] for a in manifest['artifacts']], ['darwin-arm64', 'darwin-amd64', 'windows-amd64'])
        for artifact in manifest['artifacts']:
            platform = artifact['platform']
            pin = PINS['macos' if platform.startswith('darwin') else 'windows']
            name = release.installer_name(VERSION, platform)
            self.assertEqual((artifact['filename'], artifact['path']), (name, '/downloads/v%s/%s' % (VERSION, name)))
            self.assertIs(artifact['nativeValidated'], True)
            self.assertEqual(set(artifact['components']), PUBLISHER_COMPONENTS)
            self.assertEqual(artifact['signature'], {'status': 'self-signed-stable', 'publisher': 'Scarlett (self-signed)',
                                                     'certificateSha1': pin['sha1'], 'certificateSha256': pin['sha256']})
            self.assertEqual(set(artifact['signature']), PUBLISHER_SIGNATURE_FIELDS)
            path = self.output / 'release' / name
            self.assertEqual((artifact['bytes'], artifact['sha256']), (path.stat().st_size, release.digest(path)))
            record = provenance['signing'][platform]
            self.assertEqual((record['status'], record['installerSha256'], record['certificateSha1'], record['certificateSha256']),
                             ('self-signed-stable', artifact['sha256'], pin['sha1'], pin['sha256']))
            if platform.startswith('darwin'):
                self.assertEqual(record['designatedRequirement'],
                                 'designated => identifier "ai.scarlett.node" and certificate leaf = H"%s"' % pin['sha1'])
            else:
                self.assertNotIn('designatedRequirement', record)
            self.assertEqual(record['verifiedWith']['evidenceSha256'],
                             release.digest(self.output / 'evidence' / ('%s.evidence.json' % platform)))
        self.assertEqual(set(provenance), {'version', 'source', 'workflowRun', 'components', 'signing'})
        self.assertEqual((provenance['version'], provenance['source'], provenance['workflowRun']), (VERSION, manifest['source'], RUN))
        self.assertEqual(provenance['components'], {'codex': '0.159.2', 'claude': '2.1.286', 'modelApi': '0.1.32'})
        self.assertEqual(set(provenance['signing']), set(release.PLATFORMS))
        self.assertLess((self.output / 'release/manifest.json').stat().st_size, 16384)

    def test_rehearsal_evidence_or_components_never_assemble(self):
        self.edit_evidence('darwin-amd64', lambda e: e.update(rehearsal=True))
        self.rejected('Rehearsal')
        self.edit_evidence('darwin-amd64', lambda e: e.pop('rehearsal'))
        self.edit_components('windows-amd64', lambda c: c['releaseSigning'].update(rehearsal=True))
        self.rejected('finalized with the pinned')

    def test_rehearsal_identities_never_assemble(self):
        override = self.folder / 'rehearsal.json'
        override.write_text(identities.DEFAULT.read_text())
        self.rejected('Rehearsal identities', environ={'SCARLETT_SIGNING_REHEARSAL': '1'})
        self.rejected('Rehearsal identities', environ={'SCARLETT_SIGNING_REHEARSAL': '1', 'SCARLETT_SIGNING_IDENTITIES': str(override)})
        # Without the flag, the override is ignored and the committed pins apply.
        self.assemble(environ={'SCARLETT_SIGNING_IDENTITIES': str(override)})

    def test_installer_hash_or_length_mismatch_rejected(self):
        installer = next(p for p in self.inputs['darwin-arm64'].iterdir() if p.suffix == '.dmg')
        installer.write_bytes(installer.read_bytes() + b'!')
        self.rejected('Signing evidence differs')

    def test_wrong_or_crossed_pins_rejected(self):
        mac, windows = PINS['macos'], PINS['windows']
        cases = [
            ('darwin-arm64', lambda e: e.update(certificateSha256='c' * 64)),
            ('darwin-amd64', lambda e: e.update(certificateSha1=windows['sha1'], certificateSha256=windows['sha256'])),
            ('windows-amd64', lambda e: e.update(publisherThumbprint=mac['sha1'].upper(), certificateSha1=mac['sha1'],
                                                 certificateSha256=mac['sha256'])),
            ('windows-amd64', lambda e: e.update(publisherThumbprint=windows['sha1'])),
            ('darwin-arm64', lambda e: e.update(designatedRequirement=e['designatedRequirement'].replace('ai.scarlett.node', 'ai.other'))),
        ]
        for platform, change in cases:
            with self.subTest(platform=platform):
                path = self.evidence_path(platform)
                before = path.read_text()
                self.edit_evidence(platform, change)
                self.rejected('Signing evidence differs')
                path.write_text(before)

    def test_other_signatures_and_missing_checks_rejected(self):
        cases = [
            ('darwin-arm64', lambda e: e.update(signature='developer-id-notarized')),
            ('darwin-arm64', lambda e: e.update(signature='unsigned')),
            ('darwin-amd64', lambda e: e.update(target='aarch64-apple-darwin')),
            ('darwin-amd64', lambda e: e.update(notarization='accepted')),
            ('windows-amd64', lambda e: e.update(signature='authenticode')),
            ('windows-amd64', lambda e: e.update(trustResult='0x00000000')),
            ('windows-amd64', lambda e: e.pop('trustResult')),
            ('windows-amd64', lambda e: e.update(installedFromThisInstaller='separate acceptance required')),
            ('windows-amd64', lambda e: e.update(sourceCommit='2' * 40)),
            ('windows-amd64', lambda e: e.update(extra=True)),
        ]
        for index, (platform, change) in enumerate(cases):
            with self.subTest(case=index):
                path = self.evidence_path(platform)
                before = path.read_text()
                self.edit_evidence(platform, change)
                self.rejected('Signing evidence differs')
                path.write_text(before)

    def test_component_manifest_must_be_the_signed_reviewed_runtime(self):
        cases = [
            ('darwin-arm64', lambda c: c.update(target='x86_64-apple-darwin'), 'another platform'),
            ('windows-amd64', lambda c: c.update(codexVersion='0.159.1'), 'reviewed provider'),
            ('darwin-amd64', lambda c: c.update(modelApiVersion='0.1.30'), 'reviewed provider'),
            ('darwin-amd64', lambda c: c.update(modelApiVersion='0.1.31'), 'reviewed provider'),
            ('darwin-arm64', lambda c: c['sidecars'].pop(), 'three signed sidecars'),
            ('darwin-arm64', lambda c: c['sidecars'][0].update(sha256=c['sidecars'][0]['unsignedSha256']), 'three signed sidecars'),
            ('darwin-arm64', lambda c: c.pop('releaseSigning'), 'finalized'),
            ('darwin-arm64', lambda c: c['releaseSigning'].update(scheme='developer-id'), 'finalized'),
            ('windows-amd64', lambda c: c['releaseSigning'].update(publisherThumbprint=PINS['windows']['sha1']), 'finalized'),
        ]
        for index, (platform, change, pattern) in enumerate(cases):
            with self.subTest(case=index):
                path = self.inputs[platform] / 'COMPONENTS.json'
                before, evidence = path.read_text(), self.evidence_path(platform).read_text()
                self.edit_components(platform, change)
                self.rejected(pattern)
                path.write_text(before)
                self.evidence_path(platform).write_text(evidence)
        # A component manifest that is not the one the evidence measured.
        self.edit(self.inputs['darwin-arm64'] / 'COMPONENTS.json', lambda c: c.update(note='changed'))
        self.rejected('Signing evidence differs')

    def test_platform_directories_hold_exactly_the_signed_outputs(self):
        extra = self.inputs['windows-amd64'] / 'notes.txt'
        extra.write_text('unexpected')
        self.rejected('exactly its installer')
        extra.unlink()
        second = self.inputs['darwin-arm64'] / 'second.dmg'
        second.write_bytes(b'another installer')
        self.rejected('exactly its installer')
        second.unlink()
        (self.inputs['darwin-amd64'] / 'COMPONENTS.json').unlink()
        self.rejected('exactly its installer')

    def test_linked_inputs_rejected(self):
        installer = next(p for p in self.inputs['windows-amd64'].iterdir() if p.suffix == '.exe')
        target = self.folder / 'outside.exe'
        installer.rename(target)
        try:
            installer.symlink_to(target)
        except OSError:
            self.skipTest('This user cannot create symbolic links')
        self.rejected('regular files')

    def test_platform_set_and_identical_installers_rejected(self):
        self.rejected('three reviewed platforms', inputs={k: v for k, v in self.inputs.items() if k != 'darwin-amd64'})
        self.rejected('three reviewed platforms', inputs=dict(self.inputs, **{'linux-amd64': self.inputs['darwin-amd64']}))
        self.rejected('absolute directory', inputs=dict(self.inputs, **{'darwin-arm64': Path('relative')}))

    def test_release_identity_inputs_are_exact(self):
        self.rejected('reviewed desktop version', version='9.9.9')
        self.rejected('semantic versions', version='v' + VERSION)
        self.rejected('stable or preview', channel='beta')
        self.rejected('exact lowercase commit', node_commit=NODE.upper())
        self.rejected('exact lowercase commit', node_commit=NODE[:39])
        self.rejected('open-agent-api', model_api_commit='2' * 40)
        self.rejected('workflow run', workflow_run='https://github.com/teslashibe/scarlett-node/actions/runs/1')
        self.rejected('workflow run', workflow_run='http://github.com/teslashibe/scarlett-node/actions/runs/1/attempts/1')

    def test_release_version_requires_every_manifest_and_lockfile_to_agree(self):
        manifests = ['desktop/src-tauri/tauri.conf.json', 'desktop/package.json', 'desktop/package-lock.json',
                     'desktop/src-tauri/Cargo.toml', 'desktop/src-tauri/Cargo.lock']
        repository = self.folder / 'repository'
        for path in manifests:
            (repository / path).parent.mkdir(parents=True, exist_ok=True)
            (repository / path).write_bytes((release.REPOSITORY / path).read_bytes())
        original = release.REPOSITORY
        release.REPOSITORY = repository
        self.addCleanup(setattr, release, 'REPOSITORY', original)
        self.assertEqual(release.check_version(VERSION), VERSION)
        stale = '9.9.9'
        lock = repository / 'desktop/package-lock.json'
        data = json.loads(lock.read_text())
        data['packages']['']['version'] = stale
        lock.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'reviewed desktop version'):
            release.check_version(VERSION)
        lock.write_bytes((original / 'desktop/package-lock.json').read_bytes())
        cargo = repository / 'desktop/src-tauri/Cargo.lock'
        text = cargo.read_text()
        marker = 'name = "scarlett-node-desktop"\nversion = "%s"' % VERSION
        self.assertIn(marker, text)
        cargo.write_text(text.replace(marker, 'name = "scarlett-node-desktop"\nversion = "%s"' % stale))
        with self.assertRaisesRegex(ValueError, 'reviewed desktop version'):
            release.check_version(VERSION)

    def test_output_is_new_and_failures_leave_nothing(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, 'new absolute output'):
            self.assemble()
        self.assertEqual(list(self.output.iterdir()), [])
        self.output.rmdir()
        self.rejected('new absolute output', output=Path('relative-release'))
        original = release.copy_exact

        def corrupt(source, destination, sha256):
            original(source, destination, sha256)
            if destination.name.endswith('.exe'):
                raise ValueError('Input changed while it was copied')
        release.copy_exact = corrupt
        try:
            self.rejected('changed while it was copied')
        finally:
            release.copy_exact = original

    def test_command_line_assembles_and_checks_the_version(self):
        script = str(Path(__file__).with_name('release-manifest.py'))
        environment = {k: v for k, v in os.environ.items() if not k.startswith('SCARLETT_SIGNING_')}
        result = subprocess.run([sys.executable, script, 'check-version', VERSION], capture_output=True, text=True, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run([sys.executable, script, 'check-version', '9.9.9'], capture_output=True, text=True, env=environment)
        self.assertEqual(result.returncode, 1)
        self.assertIn('reviewed desktop version', result.stderr)
        arguments = [sys.executable, script, 'assemble', '--version', VERSION, '--channel', 'stable', '--node-commit', NODE,
                     '--model-api-commit', release.MODEL_API_COMMIT, '--workflow-run', RUN, '--output', str(self.output)]
        for platform, directory in self.inputs.items():
            arguments += ['--' + platform, str(directory)]
        result = subprocess.run(arguments, capture_output=True, text=True, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.output / 'release/manifest.json').is_file())
        result = subprocess.run(arguments, capture_output=True, text=True, env=environment)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
