from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import plistlib
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mac_signing', Path(__file__).with_name('sign-macos-bundle.py'))
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)
identities = signing.signing_identities


class AppFixture(unittest.TestCase):
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


class MacSigningTests(AppFixture):
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
        self.assertEqual(signing.failure_summary(failure.exception), '[phase=validation] Native release operation failed: codesign (exit 1)')

    def test_validation_diagnostic_does_not_echo_exception_payload(self):
        for error in (ValueError('PRIVATE_DETAIL'), KeyError('PRIVATE_DETAIL'), OSError('PRIVATE_DETAIL'), TypeError('PRIVATE_DETAIL')):
            diagnostic = signing.failure_summary(error)
            self.assertNotIn('PRIVATE_DETAIL', diagnostic)
            self.assertIn(type(error).__name__, diagnostic)

    def test_phase_preserves_inner_operation_without_private_payload(self):
        with self.assertRaises(ValueError) as failure:
            with signing.release_phase('inventory'):
                with signing.release_phase('vendor-signature'):
                    raise ValueError('PRIVATE_DETAIL')
        self.assertEqual(signing.failure_summary(failure.exception), '[phase=vendor-signature] Release validation failed: ValueError')
        failure.exception.release_phase = 'PRIVATE_DETAIL'
        self.assertEqual(signing.failure_summary(failure.exception), '[phase=validation] Release validation failed: ValueError')

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

        with patch.object(signing.sys, 'platform', 'darwin'), patch.object(sys, 'argv', ['sign', str(self.app), str(dmg)]), patch.dict(signing.os.environ, {'SCARLETT_SIGNING_SCHEME': 'developer-id', 'APPLE_SIGNING_IDENTITY': 'Developer ID Application: Fixture', 'SCARLETT_APPLE_TEAM_ID': 'ABCDEFGHIJ', 'SCARLETT_NOTARY_KEYCHAIN_PROFILE': 'fixture-notary'}, clear=True), patch.object(signing, 'sign_app'), patch.object(signing, 'notarize', return_value='fixture-submission'), patch.object(signing, 'run', side_effect=execute):
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



def committed_certificate(name):
    return ssl.PEM_cert_to_DER_cert((identities.REPOSITORY / identities.load({})[name]['certificate']).read_text().strip())


class SelfSignedMacSigningTests(AppFixture):
    """The self-signed-stable path, with codesign/security modelled by a fake."""

    def setUp(self):
        super().setUp()
        self.identity = identities.load({})['macos']
        self.keychain = Path(self.temporary.name) / 'release-signing.keychain-db'
        self.keychain.write_bytes(b'synthetic keychain file')
        self.dmg = Path(self.temporary.name) / 'Scarlett-Node-0.1.0-darwin-arm64.dmg'
        self.evidence = self.dmg.with_suffix('.evidence.json')
        self.original_search = ['/Users/fixture/Library/Keychains/login.keychain-db']
        self.search = list(self.original_search)
        self.calls = []
        self.signed = {}
        self.certificates = [committed_certificate('macos')]
        self.team = 'TeamIdentifier=not set'
        self.listed = self.identity['sha1'].upper()
        self.fail_on_sign = None

    def environment(self, **extra):
        values = {'SCARLETT_SIGNING_SCHEME': 'self-signed-stable', 'SCARLETT_MAC_KEYCHAIN': str(self.keychain)}
        values.update(extra)
        return {k: v for k, v in values.items() if v is not None}

    def fake(self, args, timeout=60):
        args = list(args)
        self.calls.append(args)
        tool = Path(args[0]).name
        if tool == 'security':
            if args[1] == 'find-identity':
                return '  1) %s "Scarlett Node Self-Signed macOS" (CSSMERR_TP_NOT_TRUSTED)\n     1 identities found\n' % self.listed, ''
            if args[1] == 'list-keychains' and '-s' in args:
                self.search = args[args.index('-s') + 1:]
                return '', ''
            if args[1] == 'list-keychains':
                return ''.join('    "%s"\n' % k for k in self.search), ''
        if tool == 'codesign':
            target = args[-1]
            if '--force' in args:
                if self.fail_on_sign and target.endswith(self.fail_on_sign):
                    raise ValueError('synthetic signing failure')
                self.signed[target] = (args[args.index('--identifier') + 1], '--options' in args)
                if Path(target).is_file() and not target.endswith('.dmg'):
                    Path(target).write_bytes(Path(target).read_bytes() + b' synthetic signature')
                return '', ''
            if '-r-' in args:
                return 'designated => identifier "%s" and certificate leaf = H"%s"\n' % (self.signed[target][0], self.identity['sha1']), ''
            extract = [a for a in args if a.startswith('--extract-certificates=')]
            if extract:
                for index, certificate in enumerate(self.certificates):
                    Path(extract[0].split('=', 1)[1] + str(index)).write_bytes(certificate)
                return '', ''
            if '--verbose=4' in args:
                if target not in self.signed:
                    return '', 'CodeDirectory v=20500 flags=0x10000(runtime)\n'
                identifier, runtime = self.signed[target]
                flags = '0x10000(runtime)' if runtime else '0x0(none)'
                return '', 'Identifier=%s\nCodeDirectory v=20500 flags=%s\nAuthority=Scarlett Node Self-Signed macOS\n%s\n' % (identifier, flags, self.team)
            return '', ''
        if tool == 'hdiutil':
            Path(args[-1]).write_bytes(b'synthetic disk image')
        return '', ''

    def release(self, **extra):
        with patch.object(signing.sys, 'platform', 'darwin'), \
                patch.object(sys, 'argv', ['sign', str(self.app), str(self.dmg)]), \
                patch.dict(signing.os.environ, self.environment(**extra), clear=True), \
                patch.object(signing, 'run', side_effect=self.fake), redirect_stdout(io.StringIO()):
            signing.main()

    def sign_calls(self):
        return [args for args in self.calls if Path(args[0]).name == 'codesign' and '--sign' in args]

    def test_self_signed_release_never_notarizes_staples_or_assesses(self):
        self.release()
        tools = {part for args in self.calls for part in args}
        self.assertFalse({'notarytool', 'stapler', '/usr/sbin/spctl', '/usr/bin/xcrun'} & tools)
        self.assertTrue(self.evidence.exists())

    def test_every_sign_call_is_pinned_identified_and_untimestamped(self):
        self.release()
        sign = self.sign_calls()
        macos = self.contents / 'MacOS'
        expected = {str(macos / name): 'ai.scarlett.node.' + name for name in signing.SIDECARS}
        expected.update({str(macos / 'scarlett-node-desktop'): 'ai.scarlett.node', str(self.app): 'ai.scarlett.node',
                         str(self.dmg): 'ai.scarlett.node.dmg'})
        self.assertEqual(sorted(args[-1] for args in sign), sorted(expected))
        for args in sign:
            identifier = expected[args[-1]]
            self.assertEqual(args[args.index('--sign') + 1], self.identity['sha1'])
            self.assertEqual(args[args.index('--keychain') + 1], str(self.keychain))
            self.assertEqual(args[args.index('--identifier') + 1], identifier)
            self.assertIn('--timestamp=none', args)
            self.assertNotIn('--timestamp', args)
            self.assertNotIn('--deep', args)
            self.assertIn('-r=' + identities.designated_requirement(identifier, self.identity['sha1']), args)
            self.assertEqual('--options' in args, args[-1] != str(self.dmg))
        self.assertEqual(sign[-1][-1], str(self.dmg))
        self.assertEqual(sign[-2][-1], str(self.app))

    def test_vendors_keep_developer_id_while_scarlett_code_uses_the_pin(self):
        self.release()
        verified = {}
        for args in self.calls:
            if Path(args[0]).name == 'codesign' and '--verify' in args:
                for requirement in [a[3:] for a in args if a.startswith('-R=')]:
                    verified.setdefault(args[-1], []).append(requirement)
        self.assertEqual(verified[str(self.vendor)], [signing.DEVELOPER_ID])
        pin = 'certificate leaf = H"%s"' % self.identity['sha1']
        for path in [self.contents / 'MacOS' / name for name in signing.SIDECARS] + [self.app, self.dmg]:
            self.assertTrue(verified[str(path)])
            for requirement in verified[str(path)]:
                self.assertIn(pin, requirement)
                self.assertNotIn('anchor apple', requirement)

    def test_release_signing_and_evidence_shapes(self):
        self.release()
        requirement = self.identity['designatedRequirement']
        components = json.loads(self.manifest.read_text())
        self.assertEqual(components['releaseSigning'], {
            'scheme': 'self-signed-stable', 'certificateSha1': self.identity['sha1'],
            'certificateSha256': self.identity['sha256'], 'designatedRequirement': requirement,
            'vendorBytesPreserved': True})
        evidence = json.loads(self.evidence.read_text())
        self.assertEqual(evidence, {
            'schemaVersion': 1, 'signature': 'self-signed-stable', 'certificateSha1': self.identity['sha1'],
            'certificateSha256': self.identity['sha256'], 'designatedRequirement': requirement,
            'notarization': 'not-performed', 'gatekeeper': 'user-approval-required', 'target': 'aarch64-apple-darwin',
            'componentManifestSha256': signing.digest(self.manifest), 'bytes': self.dmg.stat().st_size,
            'sha256': signing.digest(self.dmg), 'vendorBytesPreserved': True})
        self.assertEqual(self.search, self.original_search)

    def test_keychain_joins_the_search_list_only_while_signing(self):
        self.release()
        changes = [args for args in self.calls if args[1:2] == ['list-keychains'] and '-s' in args]
        self.assertEqual(changes[0][changes[0].index('-s') + 1:], [str(self.keychain)] + self.original_search)
        self.assertEqual(changes[-1][changes[-1].index('-s') + 1:], self.original_search)
        first, last = self.calls.index(changes[0]), self.calls.index(changes[-1])
        signs = [self.calls.index(args) for args in self.sign_calls()]
        self.assertTrue(first < min(signs) and max(signs) < last)

    def test_search_list_restored_when_signing_fails(self):
        self.fail_on_sign = 'scarlett-prover'
        with self.assertRaisesRegex(ValueError, 'synthetic signing failure'):
            self.release()
        self.assertEqual(self.search, self.original_search)
        self.assertEqual(self.calls[-1][-len(self.original_search) - 1:], ['-s'] + self.original_search)
        self.assertFalse(self.dmg.exists() or self.evidence.exists())
        self.assertNotIn('releaseSigning', json.loads(self.manifest.read_text()))

    def rejected(self, pattern, **extra):
        with self.assertRaisesRegex(ValueError, pattern):
            self.release(**extra)
        self.assertFalse(self.evidence.exists())
        self.assertEqual(self.search, self.original_search)

    def test_wrong_embedded_certificate_hash_rejected(self):
        self.certificates = [committed_certificate('windows')]
        self.rejected('Embedded certificate')

    def test_extra_chain_certificate_rejected(self):
        self.certificates.append(committed_certificate('windows'))
        self.rejected('only the pinned')

    def test_team_identifier_rejected(self):
        self.team = 'TeamIdentifier=ABCDEFGHIJ'
        self.rejected('no team')

    def test_designated_requirement_drift_rejected(self):
        original = self.fake

        def drifted(args, timeout=60):
            output, detail = original(args, timeout)
            if '-r-' in args:
                output = output.replace('certificate leaf = H', 'anchor apple generic or certificate leaf = H')
            return output, detail
        self.fake = drifted
        self.rejected('designated requirement')

    def test_missing_or_unusable_keychain_rejected_before_codesign(self):
        login = Path(self.temporary.name) / 'login.keychain-db'
        login.write_bytes(b'not a temporary keychain')
        for keychain in (None, '', 'relative.keychain-db', str(self.keychain) + '.missing', str(login)):
            with self.subTest(keychain=keychain):
                self.calls.clear()
                self.rejected('temporary keychain', SCARLETT_MAC_KEYCHAIN=keychain)
                self.assertFalse(self.sign_calls())
        self.calls.clear()
        self.listed = 'F' * 40
        self.rejected('pinned signing identity')
        self.assertFalse(self.sign_calls())

    def test_signing_scheme_has_no_default(self):
        for scheme in (None, '', 'unsigned', 'Self-Signed-Stable'):
            with self.subTest(scheme=scheme):
                self.rejected('SCARLETT_SIGNING_SCHEME', SCARLETT_SIGNING_SCHEME=scheme)
                self.assertFalse(self.calls)

    def test_rehearsal_override_is_ignored_without_the_flag(self):
        other = Path(self.temporary.name) / 'other-identities.json'
        other.write_text('{"not": "used"}')
        self.release(SCARLETT_SIGNING_IDENTITIES=str(other))
        evidence = json.loads(self.evidence.read_text())
        self.assertNotIn('rehearsal', evidence)
        self.assertEqual(evidence['certificateSha256'], self.identity['sha256'])
        self.assertTrue(all(args[args.index('--sign') + 1] == self.identity['sha1'] for args in self.sign_calls()))

    @unittest.skipUnless(shutil.which('openssl'), 'openssl creates the ephemeral rehearsal certificate')
    def test_rehearsal_identity_marks_every_record(self):
        folder = Path(self.temporary.name)
        # The release extensions make a v3 certificate with LibreSSL (/usr/bin/openssl) as well as OpenSSL 3.
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(folder / 'key.pem'),
                        '-out', str(folder / 'cert.pem'), '-subj', '/O=Scarlett Rehearsal/CN=Fixture', '-days', '1',
                        '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature',
                        '-addext', 'extendedKeyUsage=critical,codeSigning'],
                       check=True, capture_output=True)
        (folder / 'key.pem').unlink()
        rehearsal = identities.rehearsal_identities(folder / 'cert.pem')
        path = folder / 'rehearsal-identities.json'
        path.write_text(json.dumps(rehearsal))
        self.identity = rehearsal['macos']
        self.listed = self.identity['sha1'].upper()
        self.certificates = [ssl.PEM_cert_to_DER_cert((folder / 'cert.pem').read_text())]
        self.release(SCARLETT_SIGNING_REHEARSAL='1', SCARLETT_SIGNING_IDENTITIES=str(path))
        self.assertIs(json.loads(self.evidence.read_text())['rehearsal'], True)
        self.assertIs(json.loads(self.manifest.read_text())['releaseSigning']['rehearsal'], True)
        self.assertEqual(hashlib.sha1(self.certificates[0]).hexdigest(), json.loads(self.evidence.read_text())['certificateSha1'])


@unittest.skipUnless(sys.platform == 'darwin', 'the launch smoke runs only on a Mac')
class SmokeEvidenceGateTests(unittest.TestCase):
    """smoke-macos-dmg.sh refuses a disk image its evidence does not pin, before mounting or launching it."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        folder = Path(self.temporary.name)
        self.dmg = folder / 'Scarlett-Node-0.1.0-darwin-arm64.dmg'
        self.dmg.write_bytes(b'synthetic disk image, never mounted')
        self.work = folder / 'smoke'
        sha1 = identities.load({})['macos']['sha1']
        self.evidence = {'signature': 'self-signed-stable', 'certificateSha1': sha1,
                         'designatedRequirement': identities.designated_requirement('ai.scarlett.node', sha1),
                         'sha256': signing.digest(self.dmg)}

    def smoke(self, evidence, verify_only=False, ci=True):
        if evidence is not None:
            self.dmg.with_suffix('.evidence.json').write_text(json.dumps(evidence))
        environment = {k: v for k, v in signing.os.environ.items() if not k.startswith('SCARLETT_') and k != 'GITHUB_ACTIONS'}
        if ci:
            environment['GITHUB_ACTIONS'] = 'true'
        mode = ['--verify-only'] if verify_only else []
        result = subprocess.run(['/bin/bash', str(Path(__file__).with_name('smoke-macos-dmg.sh'))] + mode + [str(self.dmg), str(self.work)],
                                capture_output=True, text=True, env=environment, timeout=60)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.work.exists(), 'nothing may be mounted or copied for a refused disk image')
        return result.stderr

    def test_missing_evidence_refused(self):
        self.assertIn('no neighbouring signing evidence', self.smoke(None))

    def test_changed_disk_image_refused(self):
        self.assertIn('differs from its signing evidence', self.smoke(dict(self.evidence, sha256='0' * 64)))

    def test_launch_outside_ci_refused(self):
        self.assertIn('run it only on a disposable CI runner', self.smoke(self.evidence, ci=False))

    def test_verify_only_keeps_the_evidence_gates_outside_ci(self):
        # local-release.sh verifies on a developer Mac: no CI guard, same checks, no launch.
        self.assertIn('no neighbouring signing evidence', self.smoke(None, verify_only=True, ci=False))
        self.assertIn('differs from its signing evidence', self.smoke(dict(self.evidence, sha256='0' * 64), verify_only=True, ci=False))

    def test_unpinned_or_other_scheme_refused(self):
        other = 'f' * 40
        for evidence in (dict(self.evidence, signature='developer-id-notarized'), dict(self.evidence, certificateSha1=other),
                         dict(self.evidence, certificateSha1=self.evidence['certificateSha1'].upper()),
                         dict(self.evidence, designatedRequirement=self.evidence['designatedRequirement'].replace('ai.scarlett.node', 'ai.other'))):
            with self.subTest(evidence=evidence):
                self.assertIn('one pinned self-signed certificate', self.smoke(evidence))


if __name__ == '__main__':
    unittest.main()
