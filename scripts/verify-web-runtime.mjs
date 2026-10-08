// Build-time integrity verification of the packaged web browser runtime
// archive; never extracts it and never starts Python or a browser.
import {createHash} from 'node:crypto';
import {readFileSync, lstatSync, realpathSync} from 'node:fs';
import {join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';

export const goPlatforms = ['darwin-arm64', 'darwin-amd64', 'windows-amd64', 'linux-amd64'];
export const maxArchiveBytes = 60000000;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const hex64 = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);

export function cleanPath(path) {
 return typeof path === 'string' && path.length > 0 && path.length <= 1024 && !path.startsWith('/') && !/[\\:\0]/.test(path) &&
  path.split('/').every(part => part && part !== '.' && part !== '..');
}

function octal(block, at, length) {
 const text = block.subarray(at, at + length).toString('latin1').replace(/\0.*$/s, '').trim();
 if (!/^[0-7]+$/.test(text)) throw Error('Archive header number invalid');
 return parseInt(text, 8);
}

// Entries of an uncompressed POSIX/PAX tar: regular files only, in order.
export function readTar(tar) {
 const entries = [];
 let at = 0, pax = null;
 while (at + 512 <= tar.length) {
  const block = tar.subarray(at, at + 512);
  if (block.every(b => b === 0)) break;
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : block[i];
  if (sum !== octal(block, 148, 8)) throw Error('Archive header checksum invalid');
  const size = octal(block, 124, 12), type = String.fromCharCode(block[156] || 48);
  const data = tar.subarray(at + 512, at + 512 + size);
  if (data.length !== size) throw Error('Archive truncated');
  at += 512 + Math.ceil(size / 512) * 512;
  if (type === 'x') {
   pax = {};
   for (let text = data.toString('utf8'); text;) {
    const space = text.indexOf(' '), length = parseInt(text.slice(0, space), 10);
    if (!(length > 0) || space < 0) throw Error('Archive extended header invalid');
    const record = text.slice(space + 1, length - 1), eq = record.indexOf('=');
    pax[record.slice(0, eq)] = record.slice(eq + 1);
    text = text.slice(length);
   }
   continue;
  }
  if (type !== '0') throw Error('Archive holds a non-regular entry');
  const name = block.subarray(0, 100).toString('utf8').replace(/\0.*$/s, ''), prefix = block.subarray(345, 500).toString('utf8').replace(/\0.*$/s, '');
  const path = pax?.path ?? (prefix ? `${prefix}/${name}` : name);
  if (pax && Object.keys(pax).some(key => key !== 'path')) throw Error('Archive extended header carries more than a path');
  pax = null;
  entries.push({path, mode: octal(block, 100, 8), data});
 }
 if (pax) throw Error('Archive ends inside an entry');
 return entries;
}

// Checks web-runtime.json, the archive digest and size, the manifest-first
// inventory (exact sizes and hashes, nothing unlisted or missing) and the
// pinned browser files. Returns {pins, manifest}.
export function verify(dir, expectedPlatform) {
 const pinsPath = join(dir, 'web-runtime.json');
 if (!lstatSync(pinsPath).isFile() || lstatSync(pinsPath).size > 65536) throw Error('Web runtime pins invalid');
 const pins = JSON.parse(readFileSync(pinsPath, 'utf8'));
 if (pins.schemaVersion !== 1 || !goPlatforms.includes(pins.platform) || (expectedPlatform && pins.platform !== expectedPlatform) ||
  pins.archive !== `web-runtime-${pins.platform}.tar.gz` || !hex64(pins.archiveSha256) || !hex64(pins.manifestSha256) || !hex64(pins.browserZipSha256) ||
  pins.pythonVersion !== '3.13.16' || pins.scraplingVersion !== '0.4.15+scarlett.2' || pins.browserVersion !== '155.0.8059.39') throw Error('Incompatible web runtime pins');
 const archivePath = join(dir, pins.archive), info = lstatSync(archivePath);
 if (!info.isFile() || info.size !== pins.archiveBytes || info.size > maxArchiveBytes) throw Error('Web runtime archive size invalid');
 const archive = readFileSync(archivePath);
 if (sha256(archive) !== pins.archiveSha256) throw Error('Web runtime archive checksum mismatch');
 const entries = readTar(gunzipSync(archive));
 if (!entries.length || entries[0].path !== 'manifest.json' || sha256(entries[0].data) !== pins.manifestSha256) throw Error('Web runtime manifest must come first and match its pin');
 const manifest = JSON.parse(entries[0].data.toString('utf8'));
 if (manifest.schemaVersion !== 1 || manifest.platform !== pins.platform || manifest.pythonVersion !== pins.pythonVersion ||
  manifest.scraplingVersion !== pins.scraplingVersion || !Array.isArray(manifest.files) || manifest.files.length !== pins.files) throw Error('Incompatible web runtime manifest');
 const listed = new Map();
 for (const file of manifest.files) {
  if (!cleanPath(file.path) || file.path === 'manifest.json' || listed.has(file.path) || !hex64(file.sha256) || !Number.isSafeInteger(file.bytes) || file.bytes < 0) throw Error('Invalid web runtime inventory');
  listed.set(file.path, file);
 }
 let unpacked = 0;
 for (const entry of entries.slice(1)) {
  const file = listed.get(entry.path);
  if (!file || file.bytes !== entry.data.length || file.sha256 !== sha256(entry.data) || entry.mode !== (file.exec ? 0o755 : 0o644)) throw Error('Unlisted or modified web runtime resource');
  listed.delete(entry.path);
  unpacked += entry.data.length;
 }
 if (listed.size || unpacked !== pins.unpackedBytes) throw Error('Missing web runtime resources');
 const byPath = new Map(entries.map(entry => [entry.path, entry.data]));
 const windows = pins.platform.startsWith('windows-');
 const site = windows ? 'python/Lib/site-packages' : 'python/lib/python3.13/site-packages';
 if (manifest.interpreter !== (windows ? 'python/python.exe' : 'python/bin/python3.13')) throw Error('Web runtime interpreter path invalid');
 for (const path of [manifest.interpreter, `${site}/scarlett_web_helper.py`, `${site}/scrapling/__init__.py`, 'browser/pin.json', 'browser/inventory.json', 'notices/NOTICE.md'])
  if (!byPath.has(path)) throw Error('Required web runtime resource missing');
 const pin = JSON.parse(byPath.get('browser/pin.json').toString('utf8'));
 if (pin.version !== pins.browserVersion || pin.platform !== pins.platform || pin.sha256 !== pins.browserZipSha256 ||
  pin.inventory_sha256 !== sha256(byPath.get('browser/inventory.json')) || !cleanPath(pin.executable) ||
  pin.url !== `https://storage.googleapis.com/chrome-for-testing-public/${pin.version}/${cftName(pin.platform)}/chrome-${cftName(pin.platform)}.zip`) throw Error('Pinned browser files invalid');
 return {pins, manifest};
}

export function cftName(goPlatform) {
 return {'darwin-arm64': 'mac-arm64', 'darwin-amd64': 'mac-x64', 'windows-amd64': 'win64', 'linux-amd64': 'linux64'}[goPlatform];
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) {
 if (process.argv.length !== 3 && process.argv.length !== 4) throw Error('Supply the directory holding web-runtime.json and an optional Go platform');
 verify(resolve(process.argv[2]), process.argv[3]);
 console.log('Web runtime archive verified');
}
