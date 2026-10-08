import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdtempSync, readFileSync, writeFileSync, rmSync, truncateSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {gzipSync} from 'node:zlib';
import {verify, readTar} from './verify-web-runtime.mjs';
import {parseArgs, pins} from './prepare-web-runtime.mjs';

const sha256 = b => createHash('sha256').update(b).digest('hex');

function header(name, size, mode = 0o644, type = '0') {
 const h = Buffer.alloc(512);
 h.write(name, 0, 100);
 h.write(mode.toString(8).padStart(7, '0') + '\0', 100);
 h.write('0000000\0', 108); h.write('0000000\0', 116);
 h.write(size.toString(8).padStart(11, '0') + '\0', 124);
 h.write('00000000000\0', 136);
 h.write(type, 156);
 h.write('ustar\0', 257); h.write('00', 263);
 h.fill(32, 148, 156);
 let sum = 0; for (const b of h) sum += b;
 h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
 return h;
}

function tar(entries) {
 const parts = [];
 for (const {name, data, mode, type} of entries) {
  parts.push(header(name, data.length, mode, type), data, Buffer.alloc((512 - data.length % 512) % 512));
 }
 parts.push(Buffer.alloc(1024));
 return Buffer.concat(parts);
}

// A synthetic packaged runtime shaped like prepare-web-runtime.mjs output.
function fixture({platform = 'linux-amd64', mutate, order} = {}) {
 const dir = mkdtempSync(join(tmpdir(), 'scarlett-web-runtime-test-'));
 const site = platform.startsWith('windows-') ? 'python/Lib/site-packages' : 'python/lib/python3.13/site-packages';
 const interpreter = platform.startsWith('windows-') ? 'python/python.exe' : 'python/bin/python3.13';
 const cft = {'darwin-arm64': 'mac-arm64', 'darwin-amd64': 'mac-x64', 'windows-amd64': 'win64', 'linux-amd64': 'linux64'}[platform];
 const inventory = Buffer.from('{"files":[],"links":[]}\n');
 const pin = Buffer.from(JSON.stringify({version: '155.0.8059.39', platform, url: `https://storage.googleapis.com/chrome-for-testing-public/155.0.8059.39/${cft}/chrome-${cft}.zip`,
  sha256: 'b'.repeat(64), bytes: 10, executable: 'chrome/chrome', inventory_sha256: sha256(inventory), unpacked_bytes: 1}));
 const files = new Map([[interpreter, Buffer.from('#!python')], [`${site}/scarlett_web_helper.py`, Buffer.from('helper')],
  [`${site}/scrapling/__init__.py`, Buffer.from('__version__ = "0.4.15+scarlett.1"')], ['browser/pin.json', pin], ['browser/inventory.json', inventory],
  ['notices/NOTICE.md', Buffer.from('notices')]]);
 const manifest = {schemaVersion: 1, platform, pythonVersion: '3.13.16', pbsRelease: '20261003', scraplingVersion: '0.4.15+scarlett.1', lockSha256: 'a'.repeat(64),
  driverNode: {path: 'x-login-runtime/node', sha256: 'c'.repeat(64), version: '22.23.3'}, interpreter, browserVersion: '155.0.8059.39',
  files: [...files].map(([path, data]) => ({path, sha256: sha256(data), bytes: data.length, ...(path === interpreter && !platform.startsWith('windows-') ? {exec: true} : {})}))};
 mutate?.(files, manifest);
 const manifestRaw = Buffer.from(JSON.stringify(manifest));
 let entries = [{name: 'manifest.json', data: manifestRaw}, ...[...files].map(([name, data]) => ({name, data, mode: manifest.files.find(f => f.path === name)?.exec ? 0o755 : 0o644}))];
 if (order) entries = order(entries);
 const archive = gzipSync(tar(entries));
 const name = `web-runtime-${platform}.tar.gz`;
 writeFileSync(join(dir, name), archive);
 writeFileSync(join(dir, 'web-runtime.json'), JSON.stringify({schemaVersion: 1, platform, archive: name, archiveSha256: sha256(archive), archiveBytes: archive.length,
  manifestSha256: sha256(manifestRaw), unpackedBytes: [...files.values()].reduce((s, d) => s + d.length, 0), files: files.size,
  pythonVersion: '3.13.16', scraplingVersion: '0.4.15+scarlett.1', browserVersion: '155.0.8059.39', browserZipSha256: 'b'.repeat(64)}));
 return {dir, name};
}

test('a well-formed archive verifies for its platform only', () => {
 const {dir} = fixture();
 try {
  assert.equal(verify(dir, 'linux-amd64').manifest.files.length, 6);
  assert.throws(() => verify(dir, 'darwin-arm64'), /Incompatible/);
 } finally { rmSync(dir, {recursive: true, force: true}); }
});

test('tampered, unordered, unlisted, missing and oversized archives are refused', () => {
 const cases = {
  'manifest not first': {order: e => [e[1], e[0], ...e.slice(2)]},
  'unlisted entry': {order: e => [...e, {name: 'python/extra.py', data: Buffer.from('x')}]},
  'missing entry': {order: e => e.slice(0, -1)},
  'changed byte': {order: e => e.map(x => x.name.endsWith('helper.py') ? {...x, data: Buffer.from('Helper')} : x)},
  'mode': {order: e => e.map(x => x.name === 'python/bin/python3.13' ? {...x, mode: 0o644} : x)},
  'symlink': {order: e => [...e, {name: 'python/link', data: Buffer.alloc(0), type: '2'}]},
  'traversal path': {mutate: (files, m) => { m.files.push({path: 'python/../../etc', sha256: 'd'.repeat(64), bytes: 0}); }},
  'pin for another browser': {mutate: (files, m) => {
   const pin = JSON.parse(files.get('browser/pin.json')); pin.sha256 = 'e'.repeat(64);
   files.set('browser/pin.json', Buffer.from(JSON.stringify(pin)));
   m.files.find(f => f.path === 'browser/pin.json').sha256 = sha256(files.get('browser/pin.json'));
   m.files.find(f => f.path === 'browser/pin.json').bytes = files.get('browser/pin.json').length;
  }},
 };
 for (const [name, opts] of Object.entries(cases)) {
  const {dir} = fixture(opts);
  try { assert.throws(() => verify(dir, 'linux-amd64'), undefined, name); } finally { rmSync(dir, {recursive: true, force: true}); }
 }
 const {dir, name} = fixture();
 try {
  truncateSync(join(dir, name), 60000001);
  const pinsPath = join(dir, 'web-runtime.json');
  const raw = JSON.parse(readFileSync(pinsPath, 'utf8'));
  raw.archiveBytes = 60000001;
  writeFileSync(pinsPath, JSON.stringify(raw));
  assert.throws(() => verify(dir, 'linux-amd64'), /size/);
 } finally { rmSync(dir, {recursive: true, force: true}); }
});

function paxRecord(key, value) {
 const body = ` ${key}=${value}\n`;
 let length = body.length + 1;
 while (String(length).length + body.length !== length) length = String(length).length + body.length;
 return Buffer.from(`${length}${body}`);
}

test('readTar honours PAX paths and refuses other extended keys', () => {
 const long = 'python/lib/python3.13/site-packages/' + 'x'.repeat(120) + '.py';
 const record = `path=${long}\n`;
 let size = record.length + 4; const line = `${size} ${record}`; size = Buffer.byteLength(line) === size ? size : Buffer.byteLength(line);
 const pax = Buffer.from(`${size} ${record}`);
 const entries = readTar(tar([{name: 'PaxHeaders/x', data: pax, type: 'x'}, {name: 'short', data: Buffer.from('ok')}]));
 assert.equal(entries[0].path, long);
 const bad = paxRecord('uid', '99999999');
 assert.throws(() => readTar(tar([{name: 'PaxHeaders/x', data: bad, type: 'x'}, {name: 'short', data: Buffer.from('ok')}])));
});

test('prepare accepts exactly the four Node-style platforms on their own host', () => {
 assert.deepEqual(Object.keys(pins).sort(), ['darwin-arm64', 'darwin-x64', 'linux-x64', 'win32-x64']);
 for (const [platform, goPlatform] of [['darwin-arm64', 'darwin-arm64'], ['darwin-x64', 'darwin-amd64'], ['win32-x64', 'windows-amd64'], ['linux-x64', 'linux-amd64']])
  assert.equal(parseArgs([platform, '/out', '/x-login'], platform).goPlatform, goPlatform);
 for (const platform of ['linux-arm64', 'darwin-amd64', 'windows-amd64', 'linux-amd64', ''])
  assert.throws(() => parseArgs([platform, '/out', '/x-login'], platform));
 assert.throws(() => parseArgs(['linux-x64', '/out', '/x-login'], 'darwin-arm64'), /native platform/);
 assert.throws(() => parseArgs(['linux-x64', 'out', '/x-login'], 'linux-x64'));
 assert.throws(() => parseArgs(['linux-x64', '/out'], 'linux-x64'));
});
