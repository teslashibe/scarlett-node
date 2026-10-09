"""Contracts for the committed self-signed release identities and their loader."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('signing_identities', Path(__file__).with_name('signing_identities.py'))
identities = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identities)

# Reviewed copies of the four public pins. k8s-control and network-site carry
# the same values; changing one is a deliberate change in all three repositories.
REVIEWED = {
    'macos': ('32c7bb094412d12a95de7dfb5e6ed87c10348944', 'c7cbee31549b04dcac129277b1e77ff5f0c14f630c142caa5e2042d1ac581dcc'),
    'windows': ('2a7528535206c0fcf64d43ecb7313948c3a335f4', '040353aabcc26f03d2f584af857d78afaf7d278ab1927f80f05b4c85eee831fa'),
}


def committed():
    return json.loads(identities.DEFAULT.read_text())


def openssl_certificate(folder, subject='/O=Scarlett Rehearsal/CN=Scarlett Node Rehearsal macOS'):
    folder = Path(folder)
    # The release extensions make a v3 certificate with LibreSSL (/usr/bin/openssl) as well as OpenSSL 3.
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(folder / 'key.pem'),
                    '-out', str(folder / 'cert.pem'), '-subj', subject, '-days', '1',
                    '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'keyUsage=critical,digitalSignature',
                    '-addext', 'extendedKeyUsage=critical,codeSigning'], check=True, capture_output=True)
    (folder / 'key.pem').unlink()
    return folder / 'cert.pem'


class SigningIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)

    def test_committed_identities_match_reviewed_pins(self):
        loaded = identities.load({})
        self.assertIs(loaded['rehearsal'], False)
        for name, (sha1, sha256) in REVIEWED.items():
            self.assertEqual((loaded[name]['sha1'], loaded[name]['sha256']), (sha1, sha256))
            self.assertEqual(loaded[name]['notAfter'], '2046-09-28T21:16:51Z')
        self.assertEqual(loaded['macos']['subject'], 'O=Scarlett, CN=Scarlett Node Self-Signed macOS')
        self.assertEqual(loaded['windows']['subject'], 'O=Scarlett, CN=Scarlett Node Self-Signed Windows')
        self.assertEqual(loaded['macos']['designatedRequirement'],
                         'designated => identifier "ai.scarlett.node" and certificate leaf = H"%s"' % REVIEWED['macos'][0])
        self.assertEqual(loaded['windows']['timestampUrl'], 'http://timestamp.digicert.com')

    def test_committed_certificates_are_public_only(self):
        for name in ('macos', 'windows'):
            text = (identities.REPOSITORY / committed()[name]['certificate']).read_text()
            self.assertEqual(text.count('-----BEGIN CERTIFICATE-----'), 1)
            self.assertNotIn('KEY', text)
        signing = identities.REPOSITORY / 'desktop' / 'signing'
        self.assertEqual(sorted(p.name for p in signing.iterdir()),
                         ['identities.json', 'macos-codesign.cert.pem', 'windows-authenticode.cert.pem'])

    @unittest.skipUnless(shutil.which('openssl'), 'openssl is the independent certificate parser')
    def test_certificate_description_agrees_with_openssl(self):
        for name in ('macos', 'windows'):
            path = identities.REPOSITORY / committed()[name]['certificate']
            output = subprocess.run(['openssl', 'x509', '-in', str(path), '-noout', '-subject', '-issuer', '-enddate',
                                     '-nameopt', 'RFC2253'], check=True, capture_output=True, text=True).stdout
            # LibreSSL prints "subject= CN=..."; OpenSSL 3 prints "subject=CN=...".
            output = output.replace('subject= ', 'subject=').replace('issuer= ', 'issuer=')
            details = identities.describe(identities.certificate_der(path))
            # RFC 2253 prints the most specific attribute first.
            reversed_subject = ','.join(reversed(details['subject'].split(', ')))
            self.assertIn('subject=' + reversed_subject, output)
            self.assertIn('issuer=' + reversed_subject, output)
            self.assertIn('notAfter=Sep 28 21:16:51 2046 GMT', output)

    def test_pin_drift_and_malformed_hashes_rejected(self):
        cases = [('macos', 'sha256', 'c' * 64), ('windows', 'sha1', REVIEWED['windows'][0].upper()),
                 ('macos', 'sha1', REVIEWED['macos'][0][:39]), ('windows', 'sha256', REVIEWED['windows'][1] + '0'),
                 ('windows', 'sha1', REVIEWED['macos'][0])]
        for name, field, value in cases:
            with self.subTest(name=name, field=field):
                record = committed()
                record[name][field] = value
                with self.assertRaises(ValueError):
                    identities.validate(record)

    def test_fixed_fields_rejected_when_changed(self):
        changes = [
            lambda r: r.update(scheme='developer-id'),
            lambda r: r.update(schemaVersion=2),
            lambda r: r['macos']['identifiers'].update(app='ai.scarlett.other'),
            lambda r: r['macos'].update(designatedRequirement=r['macos']['designatedRequirement'].replace('ai.scarlett.node', 'ai.other')),
            lambda r: r['macos'].update(subject='O=Scarlett, CN=Someone Else'),
            lambda r: r['windows'].update(notAfter='2045-09-28T21:16:51Z'),
            lambda r: r['windows'].update(timestampUrl='https://timestamp.digicert.com'),
            lambda r: r['windows'].update(timestampUrl='http://timestamp.example.com'),
            lambda r: r['windows'].update(extra=True),
            lambda r: r.pop('windows'),
            lambda r: r['macos'].update(certificate='desktop/signing/windows-authenticode.cert.pem'),
            lambda r: r['macos'].update(certificate='desktop/signing/../signing/macos-codesign.cert.pem'),
            lambda r: r['macos'].update(certificate=str(identities.REPOSITORY / 'desktop/signing/macos-codesign.cert.pem')),
        ]
        for index, change in enumerate(changes):
            with self.subTest(case=index):
                record = committed()
                change(record)
                with self.assertRaises((ValueError, KeyError)):
                    identities.validate(record)

    def test_private_key_or_bundle_is_never_accepted_as_a_certificate(self):
        pem = (identities.REPOSITORY / committed()['macos']['certificate']).read_text()
        for name, text in (('key.pem', pem + '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'),
                           ('bundle.pem', pem + pem), ('empty.pem', '')):
            with self.subTest(name=name):
                (self.folder / name).write_text(text)
                with self.assertRaises(ValueError):
                    identities.certificate_der(self.folder / name)

    def test_rehearsal_override_requires_the_flag(self):
        missing = str(self.folder / 'missing.json')
        loaded = identities.load({'SCARLETT_SIGNING_IDENTITIES': missing})
        self.assertIs(loaded['rehearsal'], False)
        self.assertEqual(loaded['macos']['sha1'], REVIEWED['macos'][0])
        with self.assertRaises(ValueError):
            identities.load({'SCARLETT_SIGNING_IDENTITIES': missing, 'SCARLETT_SIGNING_REHEARSAL': '1'})
        with self.assertRaises(ValueError):
            identities.load({'SCARLETT_SIGNING_IDENTITIES': 'relative.json', 'SCARLETT_SIGNING_REHEARSAL': '1'})
        for flag in ('0', 'true', 'yes'):
            with self.assertRaises(ValueError):
                identities.load({'SCARLETT_SIGNING_REHEARSAL': flag})
        # The flag alone keeps the committed pins but still marks the run.
        self.assertIs(identities.load({'SCARLETT_SIGNING_REHEARSAL': '1'})['rehearsal'], True)

    @unittest.skipUnless(shutil.which('openssl'), 'openssl creates the ephemeral rehearsal certificate')
    def test_rehearsal_identities_substitute_only_the_ephemeral_certificate(self):
        certificate = openssl_certificate(self.folder)
        rehearsal = identities.rehearsal_identities(certificate)
        self.assertEqual(rehearsal['windows'], committed()['windows'])
        self.assertNotEqual(rehearsal['macos']['sha256'], REVIEWED['macos'][1])
        self.assertEqual(rehearsal['macos']['subject'], 'O=Scarlett Rehearsal, CN=Scarlett Node Rehearsal macOS')
        path = self.folder / 'rehearsal.json'
        path.write_text(json.dumps(rehearsal))
        loaded = identities.load({'SCARLETT_SIGNING_IDENTITIES': str(path), 'SCARLETT_SIGNING_REHEARSAL': '1'})
        self.assertIs(loaded['rehearsal'], True)
        self.assertEqual(loaded['macos']['sha1'], rehearsal['macos']['sha1'])
        # A rehearsal file is never valid release input.
        with self.assertRaises(ValueError):
            identities.validate(copy.deepcopy(rehearsal))
        self.assertEqual(identities.load({'SCARLETT_SIGNING_IDENTITIES': str(path)})['macos']['sha1'], REVIEWED['macos'][0])

    @unittest.skipUnless(shutil.which('openssl'), 'openssl creates the ephemeral rehearsal certificate')
    def test_rehearsal_record_must_match_its_certificate(self):
        certificate = openssl_certificate(self.folder)
        rehearsal = identities.rehearsal_identities(certificate)
        rehearsal['macos']['notAfter'] = '2099-01-01T00:00:00Z'
        with self.assertRaisesRegex(ValueError, 'expiry'):
            identities.validate(rehearsal, rehearsal=True)

    def test_command_line_prints_only_public_values(self):
        script = str(Path(__file__).with_name('signing_identities.py'))
        environment = {k: v for k, v in os.environ.items() if not k.startswith('SCARLETT_SIGNING_')}
        result = subprocess.run([sys.executable, script, 'get', 'windows.sha1'], capture_output=True, text=True, env=environment)
        self.assertEqual((result.returncode, result.stdout), (0, REVIEWED['windows'][0] + '\n'))
        result = subprocess.run([sys.executable, script, 'get', 'macos.identifiers'], capture_output=True, text=True, env=environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

if __name__ == '__main__':
    unittest.main()


class UpdaterKeyTests(unittest.TestCase):
    """The auto-updater's minisign pins (identities.json updater.minisign)."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        updater = identities.updater_signatures
        self.lines = [updater.public_line_for_tests(bytes([n]) * 32, bytes([n + 1]) * 8) for n in (1, 3, 5)]
        self.keys = [updater.parse_public_key(line) for line in self.lines]

    def section(self, *indexes, roles=('primary', 'backup')):
        return {'minisign': [{'role': role, 'keyId': self.keys[i]['keyId'], 'publicKey': self.lines[i]}
                             for role, i in zip(roles, indexes)]}

    def test_updater_pins_are_a_primary_then_a_backup(self):
        base = committed()
        for section in ({'minisign': []}, self.section(0), self.section(0, 1)):
            identities.validate(dict(copy.deepcopy(base), updater=section))
        for section in (self.section(0, 1, 2, roles=('primary', 'backup', 'backup')), self.section(0, roles=('backup',)),
                        self.section(0, 0), {'minisign': [{'role': 'primary', 'keyId': self.keys[1]['keyId'], 'publicKey': self.lines[0]}]},
                        {'minisign': [{'role': 'primary', 'keyId': 'X', 'publicKey': 'not a key'}]}, {}, {'minisign': {}}):
            with self.subTest(section=section):
                with self.assertRaises(ValueError):
                    identities.validate(dict(copy.deepcopy(base), updater=section))
        without = copy.deepcopy(base)
        del without['updater']
        with self.assertRaises(ValueError):
            identities.validate(without)

    def test_go_pins_are_generated_from_the_identities(self):
        loaded = identities.load({})
        self.assertEqual(identities.GO_PINS.read_text(), identities.go_pins(loaded))
        generated = identities.go_pins(dict(copy.deepcopy(committed()), updater=self.section(0, 1)))
        self.assertIn('\t"%s", // primary %s\n' % (self.lines[0], self.keys[0]['keyId']), generated)
        self.assertIn('\t"%s", // backup %s\n' % (self.lines[1], self.keys[1]['keyId']), generated)
        self.assertIn('releaseMacCertificateSHA1       = "%s"' % REVIEWED['macos'][0], generated)

    def test_set_updater_keys_accepts_only_public_key_files(self):
        updater = identities.updater_signatures
        primary = self.folder / 'updater-minisign.key.pub'
        # The base64-wrapped file `tauri signer generate` writes.
        box = 'untrusted comment: minisign public key: %s\n%s\n' % (self.keys[0]['keyId'], self.lines[0])
        primary.write_text(__import__('base64').b64encode(box.encode()).decode())
        self.assertEqual(updater.parse_public_key(primary.read_text())['keyId'], self.keys[0]['keyId'])
        secret = self.folder / 'updater-minisign.key'
        secret.write_text('secret material')
        saved_identities, saved_pins = identities.DEFAULT.read_text(), identities.GO_PINS.read_text()
        try:
            with self.assertRaises(ValueError):
                identities.set_updater_keys(secret)
            self.assertEqual(identities.DEFAULT.read_text(), saved_identities)
            keys = identities.set_updater_keys(primary)
            self.assertEqual(keys, [{'role': 'primary', 'keyId': self.keys[0]['keyId'], 'publicKey': self.lines[0]}])
            self.assertIn(self.lines[0], identities.GO_PINS.read_text())
            self.assertEqual(identities.load({})['updater']['minisign'], keys)
        finally:
            identities.DEFAULT.write_text(saved_identities)
            identities.GO_PINS.write_text(saved_pins)
