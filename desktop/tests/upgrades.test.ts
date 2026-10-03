import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { completeUpgradeConfig, upgradeConfig } from '../scripts/prepare-upgrade-fixture.mjs';

test('complete bundle overlay inherits the actual base identity and security policy', () => {
  const base = JSON.parse(readFileSync(new URL('../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
  const overlay = { bundle: { targets: ['nsis'], externalBin: ['node', 'prover', 'api'], resources: { 'runtime/': 'runtime/' } } };
  const before = structuredClone({ base, overlay });
  const next = completeUpgradeConfig(base, overlay);
  assert.equal(next.version, '0.1.1');
  assert.equal(next.identifier, base.identifier);
  assert.deepEqual(next.app, base.app);
  assert.deepEqual(next.build, base.build);
  assert.deepEqual(next.bundle.resources, overlay.bundle.resources);
  assert.deepEqual(next.bundle.externalBin, overlay.bundle.externalBin);
  assert.deepEqual(next.bundle.icon, base.bundle.icon);
  assert.deepEqual({ base, overlay }, before);
  assert.throws(() => completeUpgradeConfig(base, { ...overlay, identifier: 'foreign.app' }));
});

test('installation version variants retain identity, runtime and security configuration', () => {
  const config = { version: '0.1.0', identifier: 'ai.scarlett.node',
    app: { security: { csp: "default-src 'self'" } },
    bundle: { externalBin: ['node', 'prover', 'api'], resources: ['runtime/'], windows: { allowDowngrades: true } } };
  const next = upgradeConfig(config);
  assert.equal(next.version, '0.1.1');
  assert.deepEqual({ ...next, version: config.version }, config);
  assert.equal(config.version, '0.1.0');
  next.bundle.resources.push('synthetic');
  assert.deepEqual(config.bundle.resources, ['runtime/']);
});

test('installation round trip rejects previews, foreign identity and blocked downgrades', () => {
  for (const version of ['0.1.0-preview', '../0.1.0', '01.0.0', '0.1.65535', '65536.0.0']) {
    assert.throws(() => upgradeConfig({ version, identifier: 'ai.scarlett.node' }));
  }
  assert.throws(() => upgradeConfig({ version: '0.1.0', identifier: 'foreign.app' }));
  assert.throws(() => upgradeConfig({ version: '0.1.0', identifier: 'ai.scarlett.node', bundle: { windows: { allowDowngrades: false } } }));
});

test('fixture command refuses operator machines before creating installation files', () => {
  const parent = mkdtempSync(join(tmpdir(), 'scarlett-upgrade-guard-'));
  try {
    const output = join(parent, 'uncreated');
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/prepare-upgrade-fixture.mjs', import.meta.url)), output], {
      env: { ...process.env, GITHUB_ACTIONS: 'false', RUNNER_OS: 'Windows' }, encoding: 'utf8', timeout: 10000,
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /disposable native Windows runner/);
    assert.equal(existsSync(output), false);
  } finally { rmSync(parent, { recursive: true }); }
});
