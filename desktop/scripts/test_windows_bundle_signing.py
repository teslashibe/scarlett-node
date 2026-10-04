"""Signing provenance/packaging contracts; these tests do not prove OS trust."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('windows_signing', Path(__file__).with_name('sign-windows-bundle.py'))
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)
PINNED = signing.signing_identities.load({})['windows']
SELF_SIGNED = signing.release_signing('self-signed-stable', PINNED['sha1'], PINNED['sha256'])


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
                         'claudeVersion': '2.1.286', 'modelApiVersion': '0.1.32', 'files': entries, 'sidecars': sidecars}
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
        for key, value in [('target', 'aarch64-apple-darwin'), ('modelApiVersion', 'old'),
                           ('modelApiVersion', '0.1.29'), ('modelApiVersion', '0.1.30'),
                           ('modelApiVersion', '0.1.31'), ('claudeVersion', 'old')]:
            with self.subTest(key=key, value=value):
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
        result = signing.finalize_metadata(self.root, original, SELF_SIGNED)
        self.assertEqual(original, self.metadata)
        self.assertEqual(result['files'], original['files'])
        for entry in result['sidecars']:
            previous = next(e for e in original['sidecars'] if e['name'] == entry['name'])
            self.assertEqual(entry['unsignedSha256'], previous['sha256'])
            self.assertEqual(entry['unsignedBytes'], previous['bytes'])
            self.assertEqual(entry['sha256'], signing.digest(signing.sidecar(self.root, entry['name'])))
        self.assertEqual(result['releaseSigning'], {
            'scheme': 'self-signed-stable', 'publisherThumbprint': PINNED['sha1'].upper(),
            'certificateSha256': PINNED['sha256'], 'vendorBytesPreserved': True})
        self.assertIsNot(result['releaseSigning'], SELF_SIGNED)

    def test_vendor_mutation_blocks_hash_refresh(self):
        (self.root / 'runtime/claude/provider.exe').write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'runtime bytes'):
            signing.finalize_metadata(self.root, self.metadata, SELF_SIGNED)

    def test_sign_callback_keeps_spaces_as_one_argument(self):
        file = Path('C:/Scarlett Release/scripts/sign-windows-file.ps1')
        callback = signing.signing_config(file)['bundle']['windows']['signCommand']
        self.assertEqual(callback['cmd'], 'powershell.exe')
        self.assertEqual(callback['args'][-3:], [str(file), '-File', '%1'])

    def test_nsis_temp_context_is_child_only_and_cleaned_after_packaging(self):
        env = {'TMP': 'original-tmp', 'TEMP': 'original-temp', 'unrelated': 'preserved'}
        original = dict(env)
        directory = self.root / 'target/release/nsis-signing-temp'
        with signing.nsis_signing_environment(self.root, env) as child:
            self.assertTrue(directory.is_dir())
            self.assertEqual(child['TMP'], str(directory))
            self.assertEqual(child['TEMP'], str(directory))
            self.assertEqual(child['SCARLETT_WINDOWS_NSIS_TEMP'], str(directory))
            self.assertEqual(child['unrelated'], 'preserved')
            self.assertEqual(env, original)
            (directory / 'nstFFFF.tmp').write_bytes(b'synthetic generated uninstaller')
        self.assertFalse(directory.exists())
        self.assertEqual(env, original)

    def test_nsis_temp_context_cleanup_on_packaging_failure(self):
        directory = self.root / 'target/release/nsis-signing-temp'
        with self.assertRaisesRegex(ValueError, 'synthetic packaging failure'):
            with signing.nsis_signing_environment(self.root, {}):
                (directory / 'nst1.tmp').write_bytes(b'synthetic uninstaller')
                raise ValueError('synthetic packaging failure')
        self.assertFalse(directory.exists())

    def test_nsis_temp_context_refuses_existing_directory(self):
        directory = self.root / 'target/release/nsis-signing-temp'
        directory.mkdir()
        retained = directory / 'retained.txt'
        retained.write_bytes(b'not owned by this run')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            with signing.nsis_signing_environment(self.root, {}):
                self.fail('Existing directory became a signing context')
        self.assertEqual(retained.read_bytes(), b'not owned by this run')

    def test_nsis_temp_context_reparse_never_cleans_external_files(self):
        directory = self.root / 'target/release/nsis-signing-temp'
        outside = self.root / 'outside'
        outside.mkdir()
        retained = outside / 'nst1.tmp'
        retained.write_bytes(b'external file')
        try:
            directory.symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest('Native CI user lacks symlink creation privilege')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            with signing.nsis_signing_environment(self.root, {}):
                self.fail('Link became a signing context')
        directory.unlink()
        with self.assertRaisesRegex(ValueError, 'changed ownership'):
            with signing.nsis_signing_environment(self.root, {}):
                directory.rmdir()
                directory.symlink_to(outside, target_is_directory=True)
        self.assertEqual(retained.read_bytes(), b'external file')


class WindowsReleaseIdentityContracts(unittest.TestCase):
    """The scheme and both pins come from the environment and must equal identities.json."""

    def identity(self, **values):
        environ = {'SCARLETT_SIGNING_SCHEME': 'self-signed-stable', 'SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT': PINNED['sha1']}
        environ.update(values)
        environ = {k: v for k, v in environ.items() if v is not None}
        return signing.release_identity(environ, signing.signing_identities.load({}))

    def test_self_signed_identity_comes_from_the_pinned_file(self):
        for thumbprint in (PINNED['sha1'], PINNED['sha1'].upper()):
            for supplied in (None, PINNED['sha256']):
                with self.subTest(thumbprint=thumbprint, supplied=supplied):
                    self.assertEqual(self.identity(SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT=thumbprint, SCARLETT_WINDOWS_CERT_SHA256=supplied),
                                     ('self-signed-stable', PINNED['sha1'].upper(), PINNED['sha256'], 'http://timestamp.digicert.com'))

    def test_mismatched_environment_and_file_pins_rejected(self):
        for values in ({'SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT': 'f' * 40},
                       {'SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT': signing.signing_identities.load({})['macos']['sha1']},
                       {'SCARLETT_WINDOWS_CERT_SHA256': '0' * 64},
                       {'SCARLETT_WINDOWS_CERT_SHA256': signing.signing_identities.load({})['macos']['sha256']}):
            with self.subTest(values=values):
                with self.assertRaisesRegex(ValueError, 'pinned self-signed'):
                    self.identity(**values)

    def test_malformed_pins_rejected(self):
        for values in ({'SCARLETT_WINDOWS_CERT_SHA256': PINNED['sha256'].upper()},
                       {'SCARLETT_WINDOWS_CERT_SHA256': PINNED['sha256'][:63]},
                       {'SCARLETT_WINDOWS_CERT_SHA256': PINNED['sha256'] + '0'},
                       {'SCARLETT_WINDOWS_CERT_SHA256': PINNED['sha256'][:62] + 'zz'},
                       {'SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT': PINNED['sha1'][:39]},
                       {'SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT': None}):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    self.identity(**values)

    def test_scheme_has_no_default(self):
        for scheme in (None, '', 'unsigned', 'developer-id', 'Self-Signed-Stable'):
            with self.subTest(scheme=scheme):
                with self.assertRaisesRegex(ValueError, 'SCARLETT_SIGNING_SCHEME'):
                    self.identity(SCARLETT_SIGNING_SCHEME=scheme)

    def test_authenticode_names_a_different_trusted_certificate(self):
        other = ('ab' * 20, 'cd' * 32)
        self.assertEqual(self.identity(SCARLETT_SIGNING_SCHEME='authenticode', SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT=other[0],
                                       SCARLETT_WINDOWS_CERT_SHA256=other[1]),
                         ('authenticode', other[0].upper(), other[1], 'http://timestamp.digicert.com'))
        for thumbprint, certificate in ((other[0], None), (PINNED['sha1'], other[1]), (other[0], PINNED['sha256'])):
            with self.subTest(thumbprint=thumbprint, certificate=certificate):
                with self.assertRaises(ValueError):
                    self.identity(SCARLETT_SIGNING_SCHEME='authenticode', SCARLETT_WINDOWS_PUBLISHER_THUMBPRINT=thumbprint,
                                  SCARLETT_WINDOWS_CERT_SHA256=certificate)

    def test_release_signing_shape_and_rehearsal_marker(self):
        self.assertEqual(signing.release_signing('self-signed-stable', PINNED['sha1'], PINNED['sha256']), {
            'scheme': 'self-signed-stable', 'publisherThumbprint': PINNED['sha1'].upper(),
            'certificateSha256': PINNED['sha256'], 'vendorBytesPreserved': True})
        self.assertIs(signing.release_signing('self-signed-stable', PINNED['sha1'], PINNED['sha256'], True)['rehearsal'], True)


class FailureDiagnostics(unittest.TestCase):
    """Failures name the operation and reason, never a native message, path or secret."""

    def child(self, code, stdout='', stderr='', seconds=60, name='child.py'):
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / name
            script.write_text('import sys\nsys.stdout.write(%r)\nsys.stderr.write(%r)\nraise SystemExit(%d)\n' % (stdout, stderr, code))
            with self.assertRaises(signing.ChildFailure) as caught:
                signing.run('Signing scarlett-node', [sys.executable, str(script)], folder, None, seconds)
        return str(caught.exception)

    def test_literal_powershell_reason_is_reported_with_exit_code(self):
        reasons = signing.powershell_reasons()
        for reason in ('Reviewed publisher thumbprint required', 'SignTool could not sign with the publisher key',
                       'WinVerifyTrust must report only CERT_E_UNTRUSTEDROOT',
                       'The signing key must be a non-exportable current-user CNG software key'):
            self.assertIn(reason, reasons)
        stderr = 'Windows release signing failed; artifact is not approved for publication\nReviewed publisher thumbprint required\n'
        self.assertEqual(self.child(1, stderr=stderr),
                         'Signing scarlett-node failed with exit code 1: Reviewed publisher thumbprint required')

    def test_signtool_hresult_follows_only_a_literal_reason(self):
        coded = 'SignTool could not sign with the publisher key (0x80090008)'
        self.assertTrue(self.child(1, stderr='summary\n' + coded + '\n').endswith(': ' + coded))
        for line in ('SignTool could not sign with the publisher key (0x80090008) extra',
                     'SignTool could not sign with the publisher key (0x8009000g)',
                     'SignTool could not sign with the publisher key (0x80090008',
                     'Unknown reason (0x80090008)'):
            with self.subTest(line=line):
                self.assertEqual(self.child(1, stderr=line), 'Signing scarlett-node failed with exit code 1')

    def test_native_messages_and_paths_are_never_reported(self):
        for stderr in ('Cannot find path \'D:\\a\\_temp\\signing\\identity.pfx\' because it does not exist.',
                       'At D:\\a\\scarlett-node\\desktop\\scripts\\sign-windows-file.ps1:196 char:13',
                       'The specified network password is not correct.',
                       'Reviewed publisher thumbprint required: D:\\a'):
            with self.subTest(stderr=stderr):
                self.assertEqual(self.child(1, stderr=stderr), 'Signing scarlett-node failed with exit code 1')

    def test_python_checker_reports_script_line_and_exception_class(self):
        traceback = ('Traceback (most recent call last):\n'
                     '  File "D:\\a\\scarlett-node\\desktop\\scripts\\check-complete-bundle.py", line 83, in <module>\n'
                     '    assert time.monotonic() < deadline\n'
                     'AssertionError: Bundled model API did not become ready\n')
        self.assertEqual(self.child(1, stderr=traceback),
                         'Signing scarlett-node failed with exit code 1: check-complete-bundle.py line 83, '
                         'AssertionError: Bundled model API did not become ready')
        private = traceback.replace('Bundled model API did not become ready', "'D:\\\\private\\\\value'")
        self.assertEqual(self.child(1, stderr=private),
                         'Signing scarlett-node failed with exit code 1: check-complete-bundle.py line 83, AssertionError')

    def test_installed_acceptance_reports_only_line_numbers(self):
        stdout = 'Installed acceptance: started\n{"realProviderJobs":0,"acceptanceFailureLines":[1092,1210]}\n'
        self.assertEqual(self.child(1, stdout=stdout, stderr='native text D:\\a\n'),
                         'Signing scarlett-node failed with exit code 1: check-windows-install.ps1 lines 1092,1210')

    def test_unavailable_or_slow_children_name_the_operation(self):
        with self.assertRaises(signing.ChildFailure) as caught:
            signing.run('Tauri CLI version', [str(Path(tempfile.gettempdir()) / 'scarlett-missing-tool.exe')], None, None)
        self.assertEqual(str(caught.exception), 'Tauri CLI version could not start')
        with self.assertRaises(signing.ChildFailure) as caught:
            signing.run('NSIS packaging and callback signing', [sys.executable, '-c', 'import time; time.sleep(30)'], None, None, 1)
        self.assertEqual(str(caught.exception), 'NSIS packaging and callback signing timed out after 1 seconds')

    def test_failure_reason_prints_only_our_literals_numbers_and_class_names(self):
        self.assertEqual(signing.failure_reason(ValueError('Sign only a clean reviewed source checkout')),
                         'Sign only a clean reviewed source checkout')
        self.assertEqual(signing.failure_reason(ValueError('Signing pins are lowercase hex SHA-1 and SHA-256')),
                         'Signing pins are lowercase hex SHA-1 and SHA-256')
        self.assertEqual(signing.failure_reason(ValueError('D:\\a\\secret')), 'ValueError')
        self.assertEqual(signing.failure_reason(json.JSONDecodeError('Expecting value', 'secret document', 0)), 'JSONDecodeError')
        self.assertEqual(signing.failure_reason(KeyError('files')), "Missing field 'files'")
        self.assertEqual(signing.failure_reason(KeyError('D:\\a\\secret')), 'KeyError')
        self.assertEqual(signing.failure_reason(FileNotFoundError(2, 'No such file', 'D:\\a\\secret.pfx')), 'FileNotFoundError errno 2')
        self.assertEqual(signing.failure_reason(TypeError('secret')), 'TypeError')
        self.assertEqual(signing.failure_reason(RuntimeError('D:\\a\\secret')), 'RuntimeError')
        failure = signing.ChildFailure('Signing scarlett-node failed with exit code 1')
        self.assertEqual(signing.failure_reason(failure), 'Signing scarlett-node failed with exit code 1')

    def test_literal_reasons_carry_no_paths_or_values(self):
        for reason in signing.powershell_reasons():
            with self.subTest(reason=reason):
                self.assertNotRegex(reason, r'[\\$`{}]|[A-Za-z]:/')


if __name__ == '__main__':
    unittest.main()
