"""Signing provenance/packaging contracts; these tests do not prove OS trust."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('windows_signing', Path(__file__).with_name('sign-windows-bundle.py'))
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class WindowsSigningContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / 'src-tauri'
        for directory in ('runtime/codex', 'runtime/claude', 'binaries', 'target/release'):
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        entries = []
        for name in ('codex/provider.exe', 'claude/provider.exe', 'browser-reader-NOTICES.txt'):
            file = self.root / 'runtime' / name
            file.write_bytes(b'synthetic unchanged vendor bytes')
            entries.append({'path': name, 'bytes': file.stat().st_size, 'sha256': signing.digest(file)})
        sidecars = []
        for name in sorted(signing.SIDECARS):
            file = signing.sidecar(self.root, name)
            file.write_bytes(b'MZ synthetic native input ' + name.encode())
            sidecars.append({'name': name, 'bytes': file.stat().st_size, 'sha256': signing.digest(file)})
        (self.root / 'target/release/scarlett-node-desktop.exe').write_bytes(b'MZ synthetic desktop')
        self.metadata = {'schemaVersion': 1, 'target': signing.TARGET, 'codexVersion': '0.159.2',
                         'claudeVersion': '2.1.286', 'modelApiVersion': '0.1.29', 'files': entries, 'sidecars': sidecars}
        self.write_metadata()

    def tearDown(self):
        self.temporary.cleanup()

    def write_metadata(self):
        (self.root / 'runtime/COMPONENTS.json').write_text(json.dumps(self.metadata))

    def test_complete_inventory_accepted_without_mutation(self):
        before = signing.digest(self.root / 'runtime/COMPONENTS.json')
        self.assertEqual(signing.verify_inputs(self.root), self.metadata)
        self.assertEqual(before, signing.digest(self.root / 'runtime/COMPONENTS.json'))

    def test_changed_vendor_rejected(self):
        (self.root / 'runtime/codex/provider.exe').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'Runtime bytes'):
            signing.verify_inputs(self.root)

    def test_unknown_runtime_file_rejected(self):
        (self.root / 'runtime/extra.exe').write_bytes(b'unreviewed')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            signing.verify_inputs(self.root)

    def test_duplicate_inventory_rejected(self):
        self.metadata['files'].append(copy.deepcopy(self.metadata['files'][0]))
        self.write_metadata()
        with self.assertRaisesRegex(ValueError, 'inventory'):
            signing.verify_inputs(self.root)

    def test_runtime_symlink_rejected(self):
        file = self.root / 'runtime/codex/provider.exe'
        target = self.root / 'outside.exe'
        target.write_bytes(file.read_bytes()); file.unlink()
        try:
            file.symlink_to(target)
        except OSError:
            self.skipTest('Native CI user lacks symlink creation privilege')
        with self.assertRaisesRegex(ValueError, 'regular'):
            signing.verify_inputs(self.root)

    def test_changed_sidecar_rejected(self):
        signing.sidecar(self.root, 'scarlett-node').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'Sidecar bytes'):
            signing.verify_inputs(self.root)

    def test_wrong_platform_or_versions_rejected(self):
        for key, value in [('target', 'aarch64-apple-darwin'), ('modelApiVersion', 'old'), ('claudeVersion', 'old')]:
            with self.subTest(key=key):
                old = self.metadata[key]; self.metadata[key] = value; self.write_metadata()
                with self.assertRaises(ValueError): signing.verify_inputs(self.root)
                self.metadata[key] = old

    def test_signed_inventory_requires_fresh_build(self):
        self.metadata['releaseSigning'] = {'publisherThumbprint': 'a' * 40}
        self.write_metadata()
        with self.assertRaisesRegex(ValueError, 'unsigned'):
            signing.verify_inputs(self.root)

    def test_signed_hashes_retain_unsigned_history_and_vendors(self):
        original = copy.deepcopy(self.metadata)
        for name in signing.SIDECARS:
            with signing.sidecar(self.root, name).open('ab') as file:
                file.write(b'synthetic signature bytes')
        result = signing.finalize_metadata(self.root, original, 'a' * 40)
        self.assertEqual(original, self.metadata)
        self.assertEqual(result['files'], original['files'])
        for entry in result['sidecars']:
            previous = next(e for e in original['sidecars'] if e['name'] == entry['name'])
            self.assertEqual(entry['unsignedSha256'], previous['sha256'])
            self.assertEqual(entry['unsignedBytes'], previous['bytes'])
            self.assertEqual(entry['sha256'], signing.digest(signing.sidecar(self.root, entry['name'])))
        self.assertTrue(result['releaseSigning']['vendorBytesPreserved'])

    def test_vendor_mutation_blocks_hash_refresh(self):
        (self.root / 'runtime/claude/provider.exe').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'runtime bytes'):
            signing.finalize_metadata(self.root, self.metadata, 'a' * 40)

    def test_sign_callback_keeps_spaces_as_one_argument(self):
        file = Path('C:/Scarlett Release/scripts/sign-windows-file.ps1')
        callback = signing.signing_config(file)['bundle']['windows']['signCommand']
        self.assertEqual(callback['cmd'], 'powershell.exe')
        self.assertEqual(callback['args'][-3:], [str(file), '-File', '%1'])


if __name__ == '__main__':
    unittest.main()
