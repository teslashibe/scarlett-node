"""Static release-workflow contracts: pinned actions, no caches, secrets only at import.

Runner images have no YAML library, so this reads the workflow text with a
small step splitter. Each workflow file is also parsed by a YAML parser locally
and by GitHub itself; these checks are about the security-relevant shape.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github' / 'workflows'
RELEASE = WORKFLOWS / 'desktop-release.yml'
COMPLETE = WORKFLOWS / 'desktop-complete.yml'
USES = re.compile(r'^\s*(?:- )?uses: (\S+)@(\S+?)(?: # (v\d+\.\d+\.\d+))?$', re.MULTILINE)
SECRETS = {'SCARLETT_MAC_P12_BASE64', 'SCARLETT_MAC_P12_PASSWORD', 'SCARLETT_WINDOWS_PFX_BASE64', 'SCARLETT_WINDOWS_PFX_PASSWORD'}
UPDATER_SECRETS = {'TAURI_SIGNING_PRIVATE_KEY': 'SCARLETT_UPDATER_MINISIGN_KEY',
                   'TAURI_SIGNING_PRIVATE_KEY_PASSWORD': 'SCARLETT_UPDATER_MINISIGN_PASSWORD'}


def steps(text):
    """Return (job, step text) for each step, using the workflow's fixed indentation."""
    result, job, current = [], None, None
    for line in text.splitlines():
        top = re.match(r'^  ([a-z_]+):$', line)
        if top:
            job, current = top.group(1), None
            continue
        if line.startswith('      - '):
            current = [line]
            result.append((job, current))
        elif current is not None and (line.startswith('        ') or not line.strip()):
            current.append(line)
        else:
            current = None
    return [(job, '\n'.join(lines)) for job, lines in result]


def named(text, name):
    found = [body for _, body in steps(text) if re.search(r'^      - name: ' + re.escape(name), body, re.MULTILINE)]
    assert len(found) == 1, name
    return found[0]


def run_blocks(text):
    """The script text of every run: step (block or single line)."""
    blocks = []
    for _, body in steps(text):
        match = re.search(r'^        run: (\|\n((?:          .*\n?|\s*\n)*)|.*)$', body, re.MULTILINE)
        if match:
            blocks.append(match.group(2) if match.group(2) is not None else match.group(1))
    return blocks


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.release = RELEASE.read_text()
        self.complete = COMPLETE.read_text()

    def test_every_action_is_pinned_and_matches_pr_ci(self):
        tested = {}
        for action, ref, tag in USES.findall(self.complete):
            self.assertRegex(ref, '^[0-9a-f]{40}$', action)
            self.assertTrue(tag, action)
            self.assertEqual(tested.setdefault(action, (ref, tag)), (ref, tag), action)
        released = USES.findall(self.release)
        self.assertTrue(released)
        for action, ref, tag in released:
            with self.subTest(action=action):
                self.assertIn(action, tested, 'release actions are ones PR CI already runs')
                self.assertEqual((ref, tag), tested[action])

    def test_release_runs_only_by_dispatch_from_main(self):
        trigger = re.search(r'^on:\n((?:  .*\n)+)', self.release, re.MULTILINE).group(1)
        self.assertRegex(trigger, r'^  workflow_dispatch:\n')
        self.assertEqual(re.findall(r'^  ([a-z_]+):', trigger, re.MULTILINE), ['workflow_dispatch'])
        jobs = re.findall(r'^  ([a-z_]+):\n((?:    .*\n|\s*\n)+)', self.release.split('\njobs:\n', 1)[1], re.MULTILINE)
        self.assertEqual([name for name, _ in jobs], ['sign', 'headless_linux', 'updater_sign', 'assemble'])
        for name, body in jobs:
            with self.subTest(job=name):
                self.assertIn("\n    if: github.ref == 'refs/heads/main'\n", '\n' + body)
                self.assertIn('test "$GITHUB_REF" = refs/heads/main', body)
        body = dict(jobs)
        for name in ('sign', 'updater_sign'):
            self.assertIn('\n    environment: release-signing\n', '\n' + body[name])
        self.assertEqual(self.release.count('environment:'), 2)
        self.assertNotIn('environment:', body['headless_linux'] + body['assemble'])
        self.assertIn('\n    needs: [sign, headless_linux]\n', '\n' + body['updater_sign'])
        self.assertIn('\n    needs: [sign, headless_linux, updater_sign]\n', '\n' + body['assemble'])
        self.assertIn('\n    timeout-minutes: 90\n', '\n' + jobs[0][1])
        for runner, platform in (('macos-15', 'darwin-arm64'), ('macos-15-intel', 'darwin-amd64'), ('windows-2025', 'windows-amd64')):
            self.assertIn('- runner: %s\n            platform: %s\n' % (runner, platform), self.release)

    def test_read_only_token_and_serialized_runs(self):
        self.assertIn('\npermissions:\n  contents: read\nconcurrency:\n  group: desktop-release\n  cancel-in-progress: false\n', self.release)
        self.assertEqual(self.release.count('permissions:'), 1)
        self.assertIn('\nconcurrency:\n  group: desktop-complete-${{ github.ref }}\n  cancel-in-progress: true\n', self.complete)
        for workflow in WORKFLOWS.glob('*.yml'):
            self.assertNotIn('pull_request_target', workflow.read_text(), workflow.name)

    def test_release_uses_no_cache(self):
        for text in (self.release, '\n'.join(body for _, body in steps(self.release))):
            self.assertNotIn('actions/cache', text)
            self.assertNotIn('rust-cache', text)
            self.assertNotRegex(text, r'cache: (?!false)')
        for body in self.steps_using('actions/setup-go'):
            self.assertIn('cache: false', body)
        for body in self.steps_using('actions/setup-node'):
            self.assertIn('package-manager-cache: false', body)
        self.assertNotIn('cache-dependency-path', self.release)

    def steps_using(self, action):
        found = [body for _, body in steps(self.release) if 'uses: ' + action + '@' in body]
        self.assertTrue(found, action)
        return found

    def test_checkouts_do_not_persist_credentials(self):
        checkouts = [body for _, body in steps(self.release) if 'uses: actions/checkout@' in body]
        self.assertEqual(len(checkouts), 4)
        for body in checkouts:
            self.assertIn('persist-credentials: false', body)

    def test_secrets_reach_only_the_import_steps(self):
        with_secrets = [(job, body) for job, body in steps(self.release) if 'secrets.' in body]
        self.assertEqual([(job, re.search(r'name: (.+)', body).group(1)) for job, body in with_secrets],
                         [('sign', 'Import the Mac signing key into a temporary keychain'),
                          ('sign', 'Import the Windows signing key without export rights'),
                          ('updater_sign', 'Sign the installers and headless bundles for the updater')])
        referenced = set(re.findall(r'\$\{\{ secrets\.([A-Z0-9_]+) \}\}', self.release))
        self.assertEqual(referenced, SECRETS | set(UPDATER_SECRETS.values()))
        # Every secret reference is an env value on those steps, never script text.
        self.assertEqual(self.release.count('${{ secrets.'), 6)
        for name in SECRETS:
            self.assertIn('          %s: ${{ secrets.%s }}\n' % (name, name), self.release)
        # The updater key reaches only the tauri signer, in one Linux job.
        for variable, secret in UPDATER_SECRETS.items():
            self.assertIn('          %s: ${{ secrets.%s }}\n' % (variable, secret), with_secrets[2][1])
        self.assertIn('npx --no-install tauri signer sign --app-version "$RELEASE_VERSION"', with_secrets[2][1])
        jobs = dict(re.findall(r'^  ([a-z_]+):\n((?:    .*\n|\s*\n)+)', self.release.split('\njobs:\n', 1)[1], re.MULTILINE))
        self.assertIn('runs-on: ubuntu-latest', jobs['updater_sign'])
        for name in UPDATER_SECRETS:
            self.assertNotIn(name, self.complete)
        outside = '\n'.join(line for line in self.release.splitlines() if not line.startswith('      '))
        self.assertNotIn('${{ secrets.', outside)
        self.assertNotIn('secrets: inherit', self.release)
        self.assertNotIn('GITHUB_TOKEN', self.release)

    def test_release_builds_headless_bundles_and_assembles_updater_signatures(self):
        mac = named(self.release, 'Build and test the headless Mac bundle')
        linux = named(self.release, 'Build and test the headless Linux bundle')
        for body in (mac, linux):
            self.assertIn('scripts/package.sh "$RELEASE_VERSION" "$RUNNER_TEMP/headless"', body)
            self.assertIn('scripts/test-install.sh "$RUNNER_TEMP/headless"', body)
        self.assertIn("if: runner.os == 'macOS'", mac)
        verify = named(self.release, 'Verify the updater signatures against the pinned keys')
        self.assertNotIn('secrets.', verify)
        self.assertIn('release-manifest.py verify-signatures', verify)
        assemble = named(self.release, 'Assemble the release from pinned signing evidence')
        for platform in ('linux-amd64', 'darwin-arm64', 'darwin-amd64'):
            self.assertIn('--headless-%s "$RUNNER_TEMP/signed/headless-%s"' % (platform, platform), assemble)
        self.assertIn('signatures=(--signatures "$RUNNER_TEMP/updater/updater-signatures")', assemble)

    def test_scripts_never_interpolate_expressions(self):
        for workflow in (self.release, self.complete):
            for block in run_blocks(workflow):
                self.assertNotIn('${{', block)

    def test_keys_are_removed_by_always_cleanup_after_signing(self):
        names = [re.search(r'name: (.+)', body).group(1) if 'name:' in body else body.strip().split('\n')[0]
                 for job, body in steps(self.release) if job == 'sign']
        mac = named(self.release, 'Remove the Mac signing keychain')
        windows = named(self.release, 'Remove the Windows signing key')
        self.assertIn("if: always() && runner.os == 'macOS'", mac)
        self.assertIn('security delete-keychain', mac)
        self.assertIn("if: always() && runner.os == 'Windows'", windows)
        self.assertIn('Remove-Item -LiteralPath $path -DeleteKey', windows)
        order = {name: index for index, name in enumerate(names)}
        for cleanup in ('Remove the Mac signing keychain', 'Remove the Windows signing key'):
            self.assertGreater(order[cleanup], order['Sign the Mac app and disk image'])
            self.assertGreater(order[cleanup], order['Sign, package and accept the Windows installer'])
            self.assertLess(order[cleanup], order['Launch the signed Mac app from its disk image'])

    def test_keys_are_imported_without_export_or_trust(self):
        windows = named(self.release, 'Import the Windows signing key without export rights')
        self.assertIn('& desktop/scripts/import-windows-identity.ps1 -Pfx $pfx -Thumbprint $pin', windows)
        self.assertIn("if ($LASTEXITCODE -ne 0) { throw 'The Windows signing identity was not imported' }", windows)
        # The step itself imports nothing; the shared importer does.
        self.assertNotIn('Import-PfxCertificate -', windows)
        self.assertNotIn('-Exportable', windows.replace('without -Exportable', ''))
        self.assertIn('Remove-Item -LiteralPath $pfx', windows)
        importer = (ROOT / 'desktop/scripts/import-windows-identity.ps1').read_text()
        self.assertIn('Import-PfxCertificate -FilePath $file -CertStoreLocation Cert:\\CurrentUser\\My -Password $password', importer)
        self.assertNotRegex(importer, r'(?m)^[^#\n]*Import-PfxCertificate[^\n]*-Exportable')
        # The imported key must be a non-exportable current-user CNG software key.
        self.assertIn("'Microsoft Software Key Storage Provider'", importer)
        self.assertIn('AllowPlaintextExport', importer)
        self.assertIn('-not $key.Key.IsMachineKey', importer)
        self.assertIn("Remove-Item -LiteralPath $Path -Force", importer)
        self.assertIn("'Cert:\\CurrentUser\\Root\\', 'Cert:\\LocalMachine\\Root\\'", importer)
        mac = named(self.release, 'Import the Mac signing key into a temporary keychain')
        self.assertIn('desktop/scripts/import-macos-identity.sh', mac)
        importer = (ROOT / 'desktop/scripts/import-macos-identity.sh').read_text()
        self.assertIn('-T /usr/bin/codesign', importer)
        self.assertIn('rm -P "$p12"', importer)
        for path in [RELEASE, COMPLETE] + sorted((ROOT / 'desktop/scripts').glob('*')):
            if path.is_file() and path.suffix in ('.yml', '.sh', '.ps1', '.py') and path.resolve() != Path(__file__).resolve():
                text = path.read_text()
                with self.subTest(path=path.name):
                    self.assertNotIn('add-trusted-cert', text)
                    self.assertNotIn('Import-Certificate ', text)
                    self.assertNotRegex(text, r'(?i)CertStoreLocation\s+Cert:\\\w+\\Root')
                    self.assertNotIn('TAURI_SKIP_SIDECAR_SIGNATURE_CHECK', text)

    def test_signing_uses_the_pinned_scheme_and_shared_build(self):
        for name in ('Sign the Mac app and disk image', 'Sign, package and accept the Windows installer'):
            self.assertIn('SCARLETT_SIGNING_SCHEME: self-signed-stable', named(self.release, name))
        self.assertNotIn('SCARLETT_SIGNING_REHEARSAL', self.release)
        self.assertNotIn('SCARLETT_SIGNING_IDENTITIES', self.release)
        # PR CI builds the runtime once for its native checks and once for the
        # Windows release rehearsal; both use the release workflow's command.
        for workflow, count in ((self.release, 1), (self.complete, 2)):
            self.assertEqual(workflow.count('desktop/scripts/build-complete-runtime.sh "$NATIVE_PLATFORM" "$RUNNER_TEMP/scarlett-runtime"'), count)
            self.assertNotIn('npm pack', workflow)
            self.assertNotIn('prepare-complete-bundle.mjs', workflow)
        assemble = named(self.release, 'Assemble the release from pinned signing evidence')
        self.assertIn('--channel stable', assemble)
        self.assertIn('--node-commit "$GITHUB_SHA"', assemble)

    def test_pr_ci_rehearses_both_platforms_without_secrets(self):
        self.assertNotIn('secrets.', self.complete)
        self.assertNotIn('environment:', self.complete)
        rehearsal = named(self.complete, 'Rehearse self-signed Mac release signing and launch, without secrets')
        self.assertIn("if: runner.os == 'macOS'", rehearsal)
        self.assertIn('desktop/scripts/rehearse-macos-signing.sh', rehearsal)
        self.assertIn('desktop/scripts/smoke-macos-dmg.sh', rehearsal)
        windows = named(self.complete, 'Validate Windows signatures, including an ephemeral self-signed certificate')
        self.assertIn('test-windows-signatures.ps1', windows)
        fixture = (ROOT / 'desktop/scripts/test-windows-signatures.ps1').read_text()
        self.assertIn('New-SelfSignedCertificate -Type CodeSigningCert', fixture)
        self.assertIn('-CertStoreLocation Cert:\\CurrentUser\\My -KeyAlgorithm RSA -KeyLength 3072', fixture)
        self.assertIn('-DeleteKey', fixture)

    def test_pr_ci_rehearses_the_windows_release_job(self):
        jobs = {}
        for job, body in steps(self.complete):
            jobs.setdefault(job, []).append(body)
        rehearsal = '\n'.join(jobs['windows_release_rehearsal'])
        release = '\n'.join(body for job, body in steps(self.release) if job == 'sign')
        self.assertNotIn('secrets.', rehearsal)
        self.assertNotRegex(rehearsal, r'cache: (?!false)')
        self.assertNotIn('rust-cache', rehearsal)
        self.assertIn('persist-credentials: false', rehearsal)
        # The same build commands as the release Windows job.
        for name in ('Install pinned Rust', 'Build reviewed components and prepare the complete native runtime',
                     'Install desktop build dependencies', 'Build the unsigned Windows release executable'):
            with self.subTest(step=name):
                ours = [b for b in jobs['windows_release_rehearsal'] if re.search(r'^      - name: ' + re.escape(name) + '$', b, re.MULTILINE)]
                theirs = [b for j, b in steps(self.release) if j == 'sign' and re.search(r'^      - name: ' + re.escape(name) + '$', b, re.MULTILINE)]
                self.assertEqual(len(ours), 1)
                self.assertEqual(len(theirs), 1)
                run = lambda body: re.search(r'^        run: (.*)$', body, re.MULTILINE).group(1)
                self.assertEqual(run(ours[0]), run(theirs[0]))
        self.assertIn('desktop/scripts/rehearse-windows-signing.ps1', rehearsal)
        self.assertIn('desktop/scripts/import-windows-identity.ps1', release)
        script = (ROOT / 'desktop/scripts/rehearse-windows-signing.ps1').read_text()
        # The release importer and signer, an OpenSSL 3 default PKCS#12 export and
        # pins injected only through the rehearsal override.
        self.assertIn("& (Join-Path $scripts 'import-windows-identity.ps1') -Pfx $pfx -Thumbprint $sha1", script)
        self.assertIn("python (Join-Path $scripts 'sign-windows-bundle.py') $Desktop $evidence", script)
        self.assertIn("$env:SCARLETT_SIGNING_REHEARSAL = '1'", script)
        self.assertIn("'rsa_keygen_bits:3072'", script)
        for extension in ('basicConstraints = critical,CA:FALSE', 'keyUsage = critical,digitalSignature',
                          'extendedKeyUsage = critical,codeSigning'):
            self.assertIn(extension, script)
        self.assertIn("'pkcs12', '-export'", script)
        for option in ('-legacy', '-keypbe', '-certpbe', '-macalg'):
            self.assertNotIn("'%s'" % option, script)
        self.assertIn("$record.rehearsal -ne $true", script)
        self.assertIn("$record.trustResult -cne '0x800B0109'", script)
        self.assertIn('-DeleteKey', script)
        self.assertNotRegex(script, r'(?i)CertStoreLocation\s+Cert:\\\w+\\Root')


if __name__ == '__main__':
    unittest.main()
