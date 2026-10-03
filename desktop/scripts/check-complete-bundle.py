#!/usr/bin/env python3
"""Native package evidence only: no account login, pairing or provider requests."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

if len(sys.argv) != 3:
    raise SystemExit('Supply the installed executable directory and installed resource directory')
binaries = Path(sys.argv[1]).resolve()
runtime = Path(sys.argv[2]).resolve() / 'runtime'
metadata = json.loads((runtime / 'COMPONENTS.json').read_text())
assert metadata['schemaVersion'] == 1
suffix = '.exe' if os.name == 'nt' else ''
expected_target = {'darwin': {'arm64': 'aarch64-apple-darwin', 'x86_64': 'x86_64-apple-darwin'}, 'win32': {'AMD64': 'x86_64-pc-windows-msvc'}}
import platform
assert metadata['target'] == expected_target[sys.platform][platform.machine()]
assert {x['path'] for x in metadata['files']} == {str(p.relative_to(runtime)).replace('\\','/') for p in runtime.rglob('*') if p.is_file() and p.name != 'COMPONENTS.json'}
for item in metadata['files']:
    file = runtime / item['path']
    assert not file.is_symlink() and file.is_file()
    assert file.resolve().is_relative_to(runtime)
    assert file.stat().st_size == item['bytes']
    assert hashlib.sha256(file.read_bytes()).hexdigest() == item['sha256']
assert {x['name'] for x in metadata['sidecars']} == {'scarlett-node', 'scarlett-prover', 'open-agent-api'}
for item in metadata['sidecars']:
    file = binaries / (item['name'] + suffix)
    assert not file.is_symlink() and file.is_file()
    assert file.stat().st_size == item['bytes']
    assert hashlib.sha256(file.read_bytes()).hexdigest() == item['sha256']

with tempfile.TemporaryDirectory(prefix='scarlett-bundle-smoke-') as temporary:
    home = Path(temporary)
    (home / 'codex').mkdir(mode=0o700)
    (home / 'claude').mkdir(mode=0o700)
    env = {k: os.environ[k] for k in ('SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'PATH') if k in os.environ}
    env.update(HOME=str(home), USERPROFILE=str(home), CODEX_HOME=str(home / 'codex'), CLAUDE_CONFIG_DIR=str(home / 'claude'))
    versions = [('codex', runtime / 'codex' / 'bin' / ('codex' + suffix), 'codex-cli 0.159.2'), ('claude', runtime / 'claude' / ('claude' + suffix), '2.1.286 (Claude Code)')]
    for name, file, expected in versions:
        assert subprocess.check_output([str(file), '--version'], cwd=home, env=env, timeout=15, text=True).strip() == expected
    token = os.urandom(32).hex()
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    env.update(GATEWAY_BEARER_SECRET=token, GATEWAY_PROVIDERS='codex,claude',
        CODEX_AUTH_PATH=str(home / 'codex' / 'auth.json'), CODEX_CLIENTS='',
        CODEX_PROFILE_PATH=str(runtime / 'codex_profile.json'), CODEX_SCAFFOLD_PATH=str(runtime / 'codex_scaffold.json'),
        CODEX_USAGE_HISTORY_PATH=str(home / 'usage.json'),
        CLAUDE_EXECUTABLE=str(runtime / 'claude' / ('claude' + suffix)), CLAUDE_RUN_DIR=str(home / 'claude-runs'))
    process = subprocess.Popen([str(binaries / ('open-agent-api' + suffix)), '--host', '127.0.0.1', '--port', str(port)], cwd=home, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    def request(path, authorized=False):
        client = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
        try:
            client.request('GET', path, headers={'Authorization': 'Bearer ' + token} if authorized else {})
            response = client.getresponse()
            body = response.read(1048576)
            return response.status, body
        finally:
            client.close()
    try:
        deadline = time.monotonic() + 20
        while True:
            assert process.poll() is None, 'Bundled model API exited before readiness'
            try:
                if request('/health/ready')[0] == 200:
                    break
            except (ConnectionError, OSError, http.client.HTTPException):
                pass
            assert time.monotonic() < deadline, 'Bundled model API did not become ready'
            time.sleep(.1)
        assert request('/v1/models')[0] == 401, 'Local model routes must require a bearer'
        status, body = request('/v1/models', True)
        assert status == 200
        models = json.loads(body)['data']
        assert all(x['owned_by'] == 'open-agent-api' for x in models)
        ids = {x['id'] for x in models}
        assert 'gpt-6.1-sol' in ids
        assert any(x.startswith('claude-') for x in ids)
        model_count = len(models)
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise AssertionError('Bundled model API did not stop')
print(json.dumps({'bundleIntegrity': 'passed', 'nativeProviderVersions': 'passed', 'loopbackReadiness': 'passed', 'bearerRequired': 'passed', 'modelAliasCount': model_count, 'providerJobs': 0, 'accountProfiles': 'disposable only'}))
