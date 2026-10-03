import importlib.util
import json
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mac_signing', Path(__file__).with_name('sign-macos-bundle.py'))
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class MacSigningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.app = Path(self.temporary.name) / 'Scarlett Node.app'
        self.contents = self.app / 'Contents'
        self.runtime = self.contents / 'Resources' / 'runtime'
        self.runtime.mkdir(parents=True)
        (self.contents / 'MacOS').mkdir()
        (self.contents / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'ai.scarlett.node', 'CFBundleExecutable': 'scarlett-node-desktop'}))
        self.vendor = self.runtime / 'vendor'
        self.vendor.write_bytes(b'\xcf\xfa\xed\xfe' + b'untouched pinned vendor')
        self.metadata = {'schemaVersion': 1, 'target': 'aarch64-apple-darwin',
                         'files': [{'path': 'vendor', 'bytes': self.vendor.stat().st_size, 'sha256': signing.digest(self.vendor)}],
                         'sidecars': []}
        for name in sorted(signing.SIDECARS):
            path = self.contents / 'MacOS' / name
            path.write_bytes(b'synthetic unsigned ' + name.encode())
            self.metadata['sidecars'].append({'name': name, 'bytes': path.stat().st_size, 'sha256': signing.digest(path)})
        (self.contents / 'MacOS' / 'scarlett-node-desktop').write_bytes(b'synthetic desktop')
        self.manifest = self.runtime / 'COMPONENTS.json'
        self.save()

    def save(self):
        self.manifest.write_text(json.dumps(self.metadata))

    def test_input_tamper_never_calls_signer(self):
        self.vendor.write_bytes(b'changed provider')
        with patch.object(signing, 'run') as execute:
            with self.assertRaisesRegex(ValueError, 'Runtime bytes'):
                signing.sign_app(self.app, 'Developer ID Application: Fixture', 'ABCDEFGHIJ')
            execute.assert_not_called()

    def test_sidecar_tamper_never_calls_signer(self):
        (self.contents / 'MacOS' / 'scarlett-node').write_bytes(b'changed sidecar')
        with patch.object(signing, 'run') as execute:
            with self.assertRaisesRegex(ValueError, 'Sidecar bytes'):
                signing.sign_app(self.app, 'Developer ID Application: Fixture', 'ABCDEFGHIJ')
            execute.assert_not_called()

    def test_inventory_addition_or_duplicate_rejected(self):
        (self.runtime / 'extra').write_text('not in pinned inventory')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            signing.verify_input(self.app)
        (self.runtime / 'extra').unlink()
        self.metadata['files'].append(dict(self.metadata['files'][0]))
        self.save()
        with self.assertRaisesRegex(ValueError, 'inventory'):
            signing.verify_input(self.app)

    def test_runtime_symlink_rejected(self):
        (self.runtime / 'link').symlink_to(self.vendor)
        with self.assertRaisesRegex(ValueError, 'links'):
            signing.verify_input(self.app)

    def test_wrong_product_rejected(self):
        (self.contents / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': 'another.app'}))
        with self.assertRaisesRegex(ValueError, 'identity'):
            signing.verify_input(self.app)

    def test_vendor_signature_failure_precedes_all_mutations(self):
        before = self.manifest.read_bytes()
        with patch.object(signing, 'verify_signature', side_effect=ValueError('bad signature')), patch.object(signing, 'run') as execute:
            with self.assertRaisesRegex(ValueError, 'bad signature'):
                signing.sign_app(self.app, 'Developer ID Application: Fixture', 'ABCDEFGHIJ')
            execute.assert_not_called()
        self.assertEqual(before, self.manifest.read_bytes())

    def test_signed_sidecars_frozen_before_outer_seal_and_vendor_unchanged(self):
        original_vendor = self.vendor.read_bytes()
        original_sidecars = json.loads(json.dumps(self.metadata['sidecars']))
        operations = []

        def execute(args, timeout=60):
            operations.append(args)
            if '--force' in args:
                target = Path(args[-1])
                if target == self.app:
                    frozen = json.loads(self.manifest.read_text())
                    for item in frozen['sidecars']:
                        self.assertEqual(item['sha256'], signing.digest(self.contents / 'MacOS' / item['name']))
                else:
                    target.write_bytes(target.read_bytes() + b' synthetic signature')
            return '', ''

        with patch.object(signing, 'run', side_effect=execute), patch.object(signing, 'verify_signature') as verify:
            signed = signing.sign_app(self.app, 'Developer ID Application: Fixture', 'ABCDEFGHIJ')
        self.assertEqual(original_vendor, self.vendor.read_bytes())
        self.assertEqual(self.metadata['files'], signed['files'])
        for original, final in zip(original_sidecars, signed['sidecars']):
            self.assertEqual(original['sha256'], final['unsignedSha256'])
            self.assertEqual(original['bytes'], final['unsignedBytes'])
            self.assertNotEqual(original['sha256'], final['sha256'])
        forced = [args for args in operations if '--force' in args]
        self.assertEqual(len(forced), 5)
        self.assertEqual(forced[-1][-1], str(self.app))
        self.assertTrue(all('--deep' not in args for args in forced))
        verify.assert_any_call(self.vendor)
        verify.assert_any_call(self.app, 'ABCDEFGHIJ')
        with self.assertRaisesRegex(ValueError, 'already has release signing'):
            signing.verify_input(self.app)

    def test_signing_failure_does_not_publish_manifest(self):
        before = self.manifest.read_bytes()
        with patch.object(signing, 'verify_signature'), patch.object(signing, 'run', side_effect=ValueError('sign failed')):
            with self.assertRaisesRegex(ValueError, 'sign failed'):
                signing.sign_app(self.app, 'Developer ID Application: Fixture', 'ABCDEFGHIJ')
        self.assertEqual(before, self.manifest.read_bytes())

    def test_unsigned_or_wrong_team_rejected_by_native_requirement(self):
        with patch.object(signing, 'run', return_value=('', 'CodeDirectory flags=0x10000(runtime)')) as execute:
            signing.verify_signature(self.vendor, 'ABCDEFGHIJ')
        requirement = execute.call_args_list[0].args[0][3]
        self.assertIn('certificate leaf[subject.OU] = "ABCDEFGHIJ"', requirement)
        self.assertIn(signing.DEVELOPER_ID, requirement)
        with patch.object(signing, 'run', return_value=('', 'CodeDirectory flags=0x0(none)')):
            with self.assertRaisesRegex(ValueError, 'hardened runtime'):
                signing.verify_signature(self.vendor)

    def test_notarization_requires_actual_accepted_response(self):
        for response in ({'status': 'Invalid', 'id': 'fixture'}, {'status': 'In Progress', 'id': 'fixture'}):
            with patch.object(signing, 'run', return_value=(json.dumps(response), '')):
                with self.assertRaisesRegex(ValueError, 'did not accept'):
                    signing.notarize(self.app, 'fixture-notary')
        with patch.object(signing, 'run', return_value=('not-json', '')):
            with self.assertRaisesRegex(ValueError, 'structured acceptance'):
                signing.notarize(self.app, 'fixture-notary')
        with patch.object(signing, 'run', return_value=(json.dumps({'status': 'Accepted', 'id': 'fixture'}), '')):
            self.assertEqual(signing.notarize(self.app, 'fixture-notary'), 'fixture')

    def test_native_failure_does_not_echo_tool_output(self):
        with patch.object(signing.subprocess, 'run', return_value=signing.subprocess.CompletedProcess([], 1, 'PRIVATE_DETAIL', 'PRIVATE_DETAIL')):
            with self.assertRaises(ValueError) as failure:
                signing.run(['/usr/bin/codesign', 'fixture'])
        self.assertNotIn('PRIVATE_DETAIL', str(failure.exception))

    def test_final_ticket_failure_never_writes_release_evidence(self):
        dmg = Path(self.temporary.name) / 'Scarlett-Node.dmg'
        evidence = dmg.with_suffix('.evidence.json')

        def execute(args, timeout=60):
            self.assertFalse(evidence.exists())
            if Path(args[0]).name == 'hdiutil':
                dmg.write_bytes(b'synthetic disk image')
            if args[1:3] == ['stapler', 'validate'] and args[-1] == str(dmg):
                raise ValueError('invalid disk ticket')
            return '', ''

        with patch.object(signing.sys, 'platform', 'darwin'), patch.object(sys, 'argv', ['sign', str(self.app), str(dmg)]), patch.dict(signing.os.environ, {'APPLE_SIGNING_IDENTITY': 'Developer ID Application: Fixture', 'SCARLETT_APPLE_TEAM_ID': 'ABCDEFGHIJ', 'SCARLETT_NOTARY_KEYCHAIN_PROFILE': 'fixture-notary'}, clear=True), patch.object(signing, 'sign_app'), patch.object(signing, 'notarize', return_value='fixture-submission'), patch.object(signing, 'run', side_effect=execute):
            with self.assertRaisesRegex(ValueError, 'invalid disk ticket'):
                signing.main()
        self.assertTrue(dmg.exists())
        self.assertFalse(evidence.exists())

    def test_existing_evidence_or_output_inside_app_is_rejected_before_signing(self):
        for dmg in (self.app / 'output.dmg', Path(self.temporary.name) / 'previous.dmg'):
            if dmg.name == 'previous.dmg':
                dmg.with_suffix('.evidence.json').write_text('previous evidence')
            with patch.object(signing.sys, 'platform', 'darwin'), patch.object(sys, 'argv', ['sign', str(self.app), str(dmg)]), patch.object(signing, 'sign_app') as sign:
                with self.assertRaises(ValueError):
                    signing.main()
                sign.assert_not_called()


if __name__ == '__main__':
    unittest.main()
