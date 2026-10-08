// Developer-only pin tool; release jobs never run it. It downloads the four
// Chrome for Testing zips of one version, records each zip's sha256 and size,
// and writes the exact extracted tree (regular files and the macOS framework
// symlinks) as third_party/web-browser/chrome-inventory/<platform>.json. The
// node downloads the zip itself and accepts only that tree (internal/webruntime).
//
// usage: node scripts/pin-chrome-for-testing.mjs <version>
//   PIN_CFT_DOWNLOAD_DIR  absolute directory for the zips (default: the OS temp directory)
//   PIN_CFT_KEEP=1        keep each zip after it is inventoried
import {createHash} from 'node:crypto';
import {createWriteStream, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync, mkdirSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve, isAbsolute, posix} from 'node:path';
import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {fileURLToPath} from 'node:url';
import {crc32, inflateRawSync} from 'node:zlib';

export const platforms = {
 'darwin-arm64': ['mac-arm64', 'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'],
 'darwin-amd64': ['mac-x64', 'chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'],
 'windows-amd64': ['win64', 'chrome-win64/chrome.exe'],
 'linux-amd64': ['linux64', 'chrome-linux64/chrome'],
};

// A path inside the tree: relative, forward slashes, no empty, '.' or '..' part.
export function cleanPath(path) {
 return typeof path === 'string' && path.length > 0 && path.length <= 1024 && !path.startsWith('/') && !/[\\:\0]/.test(path) &&
  path.split('/').every(part => part && part !== '.' && part !== '..');
}

// A symlink target must be relative and resolve inside the tree.
export function insideLink(path, target) {
 if (typeof target !== 'string' || !target || target.startsWith('/') || /[\\:\0]/.test(target)) return false;
 const joined = posix.normalize(posix.join(posix.dirname(path), target));
 return joined !== '..' && !joined.startsWith('../') && joined !== '.' && cleanPath(joined);
}

function u16(b, o) { return b.readUInt16LE(o); }
function u32(b, o) { return b.readUInt32LE(o); }
function u64(b, o) { const v = b.readBigUInt64LE(o); if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Zip field too large'); return Number(v); }

// Reads the central directory of a whole zip held in memory. Supports zip64,
// stored and deflated entries, and checks every CRC.
export function readZip(buf) {
 let eocd = -1;
 for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (u32(buf, i) === 0x06054b50) { eocd = i; break; }
 if (eocd < 0) throw Error('Zip end record missing');
 let count = u16(buf, eocd + 10), cdOffset = u32(buf, eocd + 16);
 if (count === 0xffff || cdOffset === 0xffffffff) {
  const locator = eocd - 20;
  if (locator < 0 || u32(buf, locator) !== 0x07064b50) throw Error('Zip64 locator missing');
  const record = u64(buf, locator + 8);
  if (u32(buf, record) !== 0x06064b50) throw Error('Zip64 end record missing');
  count = u64(buf, record + 32); cdOffset = u64(buf, record + 48);
 }
 const entries = [];
 let p = cdOffset;
 for (let n = 0; n < count; n++) {
  if (u32(buf, p) !== 0x02014b50) throw Error('Zip central header invalid');
  const madeBy = u16(buf, p + 4) >> 8, flags = u16(buf, p + 8), method = u16(buf, p + 10), crc = u32(buf, p + 16);
  let csize = u32(buf, p + 20), usize = u32(buf, p + 24), local = u32(buf, p + 42);
  const nameLen = u16(buf, p + 28), extraLen = u16(buf, p + 30), commentLen = u16(buf, p + 32), external = u32(buf, p + 38);
  const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
  let e = p + 46 + nameLen;
  const extraEnd = e + extraLen;
  while (e + 4 <= extraEnd) {
   const id = u16(buf, e), size = u16(buf, e + 2);
   if (id === 1) {
    let q = e + 4;
    if (usize === 0xffffffff) { usize = u64(buf, q); q += 8; }
    if (csize === 0xffffffff) { csize = u64(buf, q); q += 8; }
    if (local === 0xffffffff) { local = u64(buf, q); q += 8; }
   }
   e += 4 + size;
  }
  if (flags & 1) throw Error('Encrypted zip entry');
  entries.push({name, madeBy, method, crc, csize, usize, local, mode: madeBy === 3 ? external >>> 16 : 0});
  p = extraEnd + commentLen;
 }
 return entries.map(entry => ({...entry, data() {
  const at = entry.local;
  if (u32(buf, at) !== 0x04034b50) throw Error('Zip local header invalid');
  const start = at + 30 + u16(buf, at + 26) + u16(buf, at + 28);
  const raw = buf.subarray(start, start + entry.csize);
  const out = entry.method === 0 ? raw : entry.method === 8 ? inflateRawSync(raw) : null;
  if (!out) throw Error('Unsupported zip compression');
  if (out.length !== entry.usize || crc32(out) !== entry.crc) throw Error('Zip entry size or CRC mismatch');
  return out;
 }}));
}

// The exact tree a zip extracts to. Directory entries must be ancestors of a
// listed path; anything else (devices, unknown types, unsafe names) is refused.
export function inventory(buf) {
 const files = [], links = [], dirs = new Set(), seen = new Set();
 for (const entry of readZip(buf)) {
  const isDir = entry.name.endsWith('/');
  const path = isDir ? entry.name.slice(0, -1) : entry.name;
  if (!cleanPath(path) || seen.has(path)) throw Error(`Unsafe or duplicate zip path`);
  seen.add(path);
  const type = entry.mode & 0o170000;
  if (isDir) { if (type && type !== 0o040000) throw Error('Zip directory type invalid'); dirs.add(path); continue; }
  const data = entry.data();
  if (type === 0o120000) {
   const target = data.toString('utf8');
   if (!insideLink(path, target)) throw Error('Zip symlink leaves the tree');
   links.push({path, target});
  } else if (type === 0o100000 || type === 0) {
   files.push({path, sha256: createHash('sha256').update(data).digest('hex'), bytes: data.length, mode: entry.mode & 0o111 ? '0755' : '0644'});
  } else throw Error('Zip entry is not a regular file or symlink');
 }
 const parents = new Set();
 for (const {path} of [...files, ...links]) { const parts = path.split('/'); for (let i = 1; i < parts.length; i++) parents.add(parts.slice(0, i).join('/')); }
 for (const dir of dirs) if (!parents.has(dir)) throw Error('Zip holds an empty directory the inventory cannot express');
 const byPath = (a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0;
 return {files: files.sort(byPath), links: links.sort(byPath)};
}

// One entry per line so a pin bump diffs readably; the node hashes these bytes.
export function serializeInventory(inv) {
 const lines = [...inv.files.map(f => JSON.stringify({path: f.path, sha256: f.sha256, bytes: f.bytes, mode: f.mode}))];
 const links = inv.links.map(l => JSON.stringify({path: l.path, target: l.target}));
 return `{"files":[\n${lines.join(',\n')}\n],"links":[${links.length ? '\n' + links.join(',\n') + '\n' : ''}]}\n`;
}

async function download(url, path) {
 const response = await fetch(url, {redirect: 'error', signal: AbortSignal.timeout(900000)});
 if (!response.ok) throw Error(`Download failed: ${response.status}`);
 await pipeline(Readable.fromWeb(response.body), createWriteStream(path, {flags: 'wx'}));
}

async function main(version) {
 if (!/^\d+\.\d+\.\d+\.\d+$/.test(version || '')) throw Error('Supply one Chrome for Testing version, such as 155.0.8059.39');
 const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'), out = join(root, 'third_party', 'web-browser');
 const base = process.env.PIN_CFT_DOWNLOAD_DIR || tmpdir();
 if (!isAbsolute(base)) throw Error('PIN_CFT_DOWNLOAD_DIR must be absolute');
 const work = mkdtempSync(join(base, 'scarlett-cft-'));
 const pins = {version, platforms: {}};
 try {
  mkdirSync(join(out, 'chrome-inventory'), {recursive: true});
  for (const [goPlatform, [cft, executable]] of Object.entries(platforms)) {
   const url = `https://storage.googleapis.com/chrome-for-testing-public/${version}/${cft}/chrome-${cft}.zip`;
   const zip = join(work, `chrome-${cft}.zip`);
   await download(url, zip);
   const buf = readFileSync(zip);
   const inv = inventory(buf);
   const exe = inv.files.find(f => f.path === executable);
   if (!exe || (!goPlatform.startsWith('windows-') && exe.mode !== '0755')) throw Error(`Pinned executable missing for ${goPlatform}`);
   const text = serializeInventory(inv);
   writeFileSync(join(out, 'chrome-inventory', `${goPlatform}.json`), text);
   pins.platforms[goPlatform] = {url, sha256: createHash('sha256').update(buf).digest('hex'), bytes: buf.length, executable,
    inventory_sha256: createHash('sha256').update(text).digest('hex'),
    unpacked_bytes: inv.files.reduce((s, f) => s + f.bytes, 0), files: inv.files.length, links: inv.links.length};
   console.log(`${goPlatform} zip sha256 ${pins.platforms[goPlatform].sha256} bytes ${buf.length} inventory sha256 ${pins.platforms[goPlatform].inventory_sha256}`);
   if (process.env.PIN_CFT_KEEP !== '1') rmSync(zip);
  }
  writeFileSync(join(out, 'chrome-for-testing.json'), JSON.stringify(pins, null, 2) + '\n');
 } finally {
  if (process.env.PIN_CFT_KEEP !== '1') rmSync(work, {recursive: true, force: true});
 }
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) await main(process.argv[2]);
