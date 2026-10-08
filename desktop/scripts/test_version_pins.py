"""The reviewed native runtime pins are duplicated on purpose; every copy must agree.

prepare-complete-bundle.mjs writes the canonical versions into COMPONENTS.json.
Each other copy (the shared build script, the signers, the release assembler,
the bundle checks, the tests and the README) is compared with it here, so a
version bump that misses one copy fails before any native build or release.
"""
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = 'desktop/scripts/'
SEMVER = r'(\d+\.\d+\.\d+)'

# (file, pattern with one capture group, component). Each pattern must match at
# least once and every capture must equal the canonical pin.
SITES = [
    (SCRIPTS + 'build-complete-runtime.sh', r'@openai/codex@' + SEMVER, 'codex'),
    (SCRIPTS + 'build-complete-runtime.sh', r'@anthropic-ai/claude-code-\$platform@' + SEMVER, 'claude'),
    (SCRIPTS + 'build-complete-runtime.sh', r'open-agent-api@v' + SEMVER, 'modelApi'),
    (SCRIPTS + 'verify-provider-archive.mjs', r'@openai/codex@' + SEMVER, 'codex'),
    (SCRIPTS + 'verify-provider-archive.mjs', r'@anthropic-ai/claude-code-[a-z0-9-]+@' + SEMVER, 'claude'),
    (SCRIPTS + 'prepare-complete-bundle.mjs', r"codex-cli " + SEMVER, 'codex'),
    (SCRIPTS + 'prepare-complete-bundle.mjs', r"version !== `" + SEMVER + r"-\$\{platform\}`", 'codex'),
    (SCRIPTS + 'prepare-complete-bundle.mjs', r"claudeMeta\.version !== '" + SEMVER + "'", 'claude'),
    (SCRIPTS + 'prepare-complete-bundle.mjs', SEMVER + r" \(Claude Code\)", 'claude'),
    (SCRIPTS + 'prepare-complete-bundle.mjs', r'open-agent-api\\tv' + SEMVER, 'modelApi'),
    (SCRIPTS + 'prepare-complete-bundle.mjs', r"'v" + SEMVER + " '", 'modelApi'),
    (SCRIPTS + 'check-complete-bundle.py', r"'codex-cli " + SEMVER + "'", 'codex'),
    (SCRIPTS + 'check-complete-bundle.py', r"'" + SEMVER + r" \(Claude Code\)'", 'claude'),
    (SCRIPTS + 'sign-windows-bundle.py', r"!= \['" + SEMVER + r"', '\d+\.\d+\.\d+', '\d+\.\d+\.\d+'\]", 'codex'),
    (SCRIPTS + 'sign-windows-bundle.py', r"!= \['\d+\.\d+\.\d+', '" + SEMVER + r"', '\d+\.\d+\.\d+'\]", 'claude'),
    (SCRIPTS + 'sign-windows-bundle.py', r"!= \['\d+\.\d+\.\d+', '\d+\.\d+\.\d+', '" + SEMVER + r"'\]", 'modelApi'),
    (SCRIPTS + 'sign-windows-file.ps1', r"codexVersion -cne '" + SEMVER + "'", 'codex'),
    (SCRIPTS + 'sign-windows-file.ps1', r"claudeVersion -cne '" + SEMVER + "'", 'claude'),
    (SCRIPTS + 'sign-windows-file.ps1', r"modelApiVersion -cne '" + SEMVER + "'", 'modelApi'),
    (SCRIPTS + 'test-windows-signatures.ps1', r"codexVersion = '" + SEMVER + "'", 'codex'),
    (SCRIPTS + 'test-windows-signatures.ps1', r"claudeVersion = '" + SEMVER + "'", 'claude'),
    (SCRIPTS + 'test-windows-signatures.ps1', r"modelApiVersion = '" + SEMVER + "'", 'modelApi'),
    (SCRIPTS + 'test_windows_bundle_signing.py', r"'codexVersion': '" + SEMVER + "'", 'codex'),
    (SCRIPTS + 'test_windows_bundle_signing.py', r"'claudeVersion': '" + SEMVER + "'", 'claude'),
    (SCRIPTS + 'test_windows_bundle_signing.py', r"'modelApiVersion': '" + SEMVER + "'", 'modelApi'),
    (SCRIPTS + 'release-manifest.py', r"^CODEX_VERSION = '" + SEMVER + "'", 'codex'),
    (SCRIPTS + 'release-manifest.py', r"^CLAUDE_VERSION = '" + SEMVER + "'", 'claude'),
    (SCRIPTS + 'release-manifest.py', r"^MODEL_API_VERSION = '" + SEMVER + "'", 'modelApi'),
    (SCRIPTS + 'test_release_manifest.py', r"'codexVersion': '" + SEMVER + "'", 'codex'),
    (SCRIPTS + 'test_release_manifest.py', r"'claudeVersion': '" + SEMVER + "'", 'claude'),
    (SCRIPTS + 'test_release_manifest.py', r"'modelApiVersion': '" + SEMVER + "'", 'modelApi'),
    ('desktop/src-tauri/src/node.rs', r'const CLI_VERSION: &str = "codex-cli ' + SEMVER + '"', 'codex'),
    ('desktop/src-tauri/src/claude_auth.rs', r'"claudeVersion"\)\?\.as_str\(\)\? != "' + SEMVER + '"', 'claude'),
    ('desktop/README.md', r'Codex CLI ' + SEMVER, 'codex'),
    ('desktop/README.md', r'Claude CLI ' + SEMVER, 'claude'),
    ('desktop/README.md', r'`open-agent-api` v' + SEMVER, 'modelApi'),
    ('go.mod', r'github\.com/teslashibe/open-agent-api v' + SEMVER, 'modelApi'),
    ('.github/workflows/desktop-release.yml', r"open-agent-api\.git 'refs/tags/v" + SEMVER + r"\^\{\}'", 'modelApi'),
]


# The web browser runtime pins: CPython, its python-build-standalone release,
# Scrapling, and Chrome for Testing. scripts/prepare-web-runtime.mjs and
# chrome-for-testing.json are canonical; every other copy must agree.
WEB_SITES = [
    ('scripts/prepare-web-runtime.mjs', r"python = '(\d+\.\d+\.\d+)'", 'python'),
    ('scripts/prepare-web-runtime.mjs', r"release = '(\d{8})'", 'pbs'),
    ('scripts/prepare-web-runtime.mjs', r"scrapling = '(\d+\.\d+\.\d+(?:\+[a-z0-9.]+)?)'", 'scrapling'),
    ('scripts/prepare-web-runtime.mjs', r"browsers\.version !== '(\d+\.\d+\.\d+\.\d+)'", 'cft'),
    ('scripts/verify-web-runtime.mjs', r"pythonVersion !== '(\d+\.\d+\.\d+)'", 'python'),
    ('scripts/verify-web-runtime.mjs', r"scraplingVersion !== '(\d+\.\d+\.\d+(?:\+[a-z0-9.]+)?)'", 'scrapling'),
    ('scripts/verify-web-runtime.mjs', r"browserVersion !== '(\d+\.\d+\.\d+\.\d+)'", 'cft'),
    # The fork's wheel URL spells the local version's + as %2B.
    ('third_party/web-browser/requirements.in', r'^scrapling\[fetchers\] @ https://github\.com/teslashibe/Scrapling/releases/download/v[0-9a-z.-]+/scrapling-(\d+\.\d+\.\d+%2B[a-z0-9.]+)-py3-none-any\.whl$', 'scrapling'),
    ('third_party/web-browser/requirements.lock', r'^scrapling @ https://github\.com/teslashibe/Scrapling/releases/download/v[0-9a-z.-]+/scrapling-(\d+\.\d+\.\d+%2B[a-z0-9.]+)-py3-none-any\.whl ', 'scrapling'),
    ('third_party/web-browser/scarlett_web_helper.py', r'^SCRAPLING_VERSION = "(\d+\.\d+\.\d+(?:\+[a-z0-9.]+)?)"$', 'scrapling'),
    ('third_party/web-browser/NOTICE.md', r'^\| scrapling \| (\d+\.\d+\.\d+(?:\+[a-z0-9.]+)?) \|', 'scrapling'),
    ('third_party/web-browser/NOTICE.md', r'CPython, from python-build-standalone release `(\d{8})`', 'pbs'),
    ('third_party/web-browser/NOTICE.md', r'\| (\d+\.\d+\.\d+) \| PSF License', 'python'),
    ('third_party/web-browser/NOTICE.md', r'Chrome for Testing (\d+\.\d+\.\d+\.\d+) is downloaded', 'cft'),
    ('internal/webruntime/archive.go', r'pythonVersion\s+= "(\d+\.\d+\.\d+)"', 'python'),
    ('internal/webruntime/archive.go', r'scraplingVersion\s+= "(\d+\.\d+\.\d+(?:\+[a-z0-9.]+)?)"', 'scrapling'),
    ('internal/webruntime/useragent.go', r'PinnedVersion = "(\d+\.\d+\.\d+\.\d+)"', 'cft'),
    ('internal/webruntime/useragent.go', r'Engine = "scrapling/(\d+\.\d+\.\d+(?:\+[a-z0-9.]+)?)"', 'scrapling'),
]


def text(path):
    return (ROOT / path).read_text(encoding='utf-8')


def canonical():
    match = re.search(r"codexVersion:'([^']+)',claudeVersion:'([^']+)',modelApiVersion:'([^']+)'",
                      text(SCRIPTS + 'prepare-complete-bundle.mjs'))
    return dict(zip(('codex', 'claude', 'modelApi'), match.groups()))


class VersionPinTests(unittest.TestCase):
    def test_every_runtime_pin_copy_agrees(self):
        pins = canonical()
        for path, pattern, component in SITES:
            with self.subTest(path=path, pattern=pattern):
                found = re.findall(pattern, text(path), re.MULTILINE)
                self.assertTrue(found, 'pin copy missing')
                self.assertEqual(set(found), {pins[component]})

    def test_no_stray_provider_package_versions(self):
        # Any provider package reference, anywhere in the release scripts and
        # workflows, names the canonical version.
        pins = canonical()
        patterns = {r'@openai/codex@' + SEMVER: 'codex', r'claude-code-[$a-z0-9{}-]+@' + SEMVER: 'claude',
                    r'open-agent-api(?:/cmd/open-agent-api)?@v' + SEMVER: 'modelApi'}
        files = sorted((ROOT / 'desktop/scripts').glob('*')) + sorted((ROOT / '.github/workflows').glob('*.yml'))
        for file in files:
            if not file.is_file() or file.suffix not in ('.sh', '.mjs', '.py', '.ps1', '.yml'):
                continue
            for pattern, component in patterns.items():
                for version in re.findall(pattern, file.read_text(encoding='utf-8')):
                    with self.subTest(file=file.name, component=component):
                        self.assertEqual(version, pins[component])

    def test_model_api_commit_matches_the_reviewed_build_input(self):
        accepted = re.findall(r'vcs\.revision=([0-9a-f]{40})', text(SCRIPTS + 'prepare-complete-bundle.mjs'))
        assembled = re.findall(r"^MODEL_API_COMMIT = '([0-9a-f]{40})'", text(SCRIPTS + 'release-manifest.py'), re.MULTILINE)
        self.assertEqual(len(accepted), 1)
        self.assertEqual(assembled, accepted)

    def test_web_runtime_pins_agree(self):
        prepare = text('scripts/prepare-web-runtime.mjs')
        pins = {
            'python': re.search(r"python = '([^']+)'", prepare).group(1),
            'pbs': re.search(r"release = '([^']+)'", prepare).group(1),
            'scrapling': re.search(r"scrapling = '([^']+)'", prepare).group(1),
            'cft': json.loads(text('third_party/web-browser/chrome-for-testing.json'))['version'],
        }
        self.assertEqual(pins, {'python': '3.13.16', 'pbs': '20261003', 'scrapling': '0.4.15+scarlett.1', 'cft': '155.0.8059.39'})
        for path, pattern, component in WEB_SITES:
            with self.subTest(path=path, pattern=pattern):
                found = [f.replace('%2B', '+') for f in re.findall(pattern, text(path), re.MULTILINE)]
                self.assertTrue(found, 'pin copy missing')
                self.assertEqual(set(found), {pins[component]})
        major = pins['cft'].split('.')[0]
        self.assertEqual(re.findall(r'PinnedMajor\s+= (\d+)', text('internal/webruntime/useragent.go')), [major])
        for platform, entry in json.loads(text('third_party/web-browser/chrome-for-testing.json'))['platforms'].items():
            with self.subTest(platform=platform):
                self.assertIn('/' + pins['cft'] + '/', entry['url'])

    def test_desktop_version_agrees_across_manifests(self):
        tauri = json.loads(text('desktop/src-tauri/tauri.conf.json'))['version']
        package = json.loads(text('desktop/package.json'))['version']
        lock = json.loads(text('desktop/package-lock.json'))
        cargo = re.search(r'^\[package\]\nname = "scarlett-node-desktop"\nversion = "([^"]+)"$',
                          text('desktop/src-tauri/Cargo.toml'), re.MULTILINE)
        locked = re.search(r'^name = "scarlett-node-desktop"\nversion = "([^"]+)"$',
                           text('desktop/src-tauri/Cargo.lock'), re.MULTILINE)
        versions = {tauri, package, lock['version'], lock['packages']['']['version'],
                    cargo.group(1) if cargo else None, locked.group(1) if locked else None}
        self.assertEqual(versions, {tauri})


if __name__ == '__main__':
    unittest.main()
