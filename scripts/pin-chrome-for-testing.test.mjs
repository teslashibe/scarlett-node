import {test} from 'node:test';
import assert from 'node:assert/strict';
import {crc32, deflateRawSync} from 'node:zlib';
import {inventory, serializeInventory, insideLink, cleanPath} from './pin-chrome-for-testing.mjs';

// A minimal zip writer for synthetic fixtures: unix "made by", one deflated or
// stored entry per item, with the unix mode in the external attributes.
function zip(items) {
 const locals = [], centrals = [];
 let offset = 0;
 for (const {name, mode, data = Buffer.alloc(0), store = false} of items) {
  const raw = Buffer.from(data), packed = store ? raw : deflateRawSync(raw), method = store ? 0 : 8, nameBuf = Buffer.from(name);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(method, 8);
  local.writeUInt32LE(crc32(raw), 14); local.writeUInt32LE(packed.length, 18); local.writeUInt32LE(raw.length, 22); local.writeUInt16LE(nameBuf.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE((3 << 8) | 20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(method, 10);
  central.writeUInt32LE(crc32(raw), 16); central.writeUInt32LE(packed.length, 20); central.writeUInt32LE(raw.length, 24); central.writeUInt16LE(nameBuf.length, 28);
  central.writeUInt32LE((mode << 16) >>> 0, 38); central.writeUInt32LE(offset, 42);
  locals.push(local, nameBuf, packed); centrals.push(central, nameBuf);
  offset += local.length + nameBuf.length + packed.length;
 }
 const cd = Buffer.concat(centrals), end = Buffer.alloc(22);
 end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(items.length, 8); end.writeUInt16LE(items.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
 return Buffer.concat([...locals, cd, end]);
}

test('inventory records files, modes and in-tree framework links in path order', () => {
 const buf = zip([
  {name: 'chrome-mac/', mode: 0o040755},
  {name: 'chrome-mac/App.app/Contents/MacOS/App', mode: 0o100755, data: 'binary'},
  {name: 'chrome-mac/App.app/Contents/Frameworks/F.framework/Versions/1/F', mode: 0o100644, data: 'framework', store: true},
  {name: 'chrome-mac/App.app/Contents/Frameworks/F.framework/Versions/Current', mode: 0o120755, data: '1'},
  {name: 'chrome-mac/App.app/Contents/Frameworks/F.framework/F', mode: 0o120755, data: 'Versions/Current/F'},
 ]);
 const inv = inventory(buf);
 assert.deepEqual(inv.files.map(f => [f.path, f.mode, f.bytes]), [
  ['chrome-mac/App.app/Contents/Frameworks/F.framework/Versions/1/F', '0644', 9],
  ['chrome-mac/App.app/Contents/MacOS/App', '0755', 6]]);
 assert.deepEqual(inv.links, [
  {path: 'chrome-mac/App.app/Contents/Frameworks/F.framework/F', target: 'Versions/Current/F'},
  {path: 'chrome-mac/App.app/Contents/Frameworks/F.framework/Versions/Current', target: '1'}]);
 const text = serializeInventory(inv);
 assert.deepEqual(JSON.parse(text), inv);
 assert.ok(text.endsWith(']}\n'));
});

test('inventory refuses traversal, absolute names, escaping links, devices and empty directories', () => {
 for (const items of [
  [{name: '../evil', mode: 0o100644, data: 'x'}],
  [{name: '/abs', mode: 0o100644, data: 'x'}],
  [{name: 'a\\b', mode: 0o100644, data: 'x'}],
  [{name: 'a/link', mode: 0o120777, data: '../../outside'}],
  [{name: 'a/link', mode: 0o120777, data: '/etc/passwd'}],
  [{name: 'a/fifo', mode: 0o010644}],
  [{name: 'a/', mode: 0o040755}, {name: 'b/file', mode: 0o100644, data: 'x'}],
  [{name: 'a/x', mode: 0o100644, data: 'x'}, {name: 'a/x', mode: 0o100644, data: 'y'}],
 ]) assert.throws(() => inventory(zip(items)));
 const corrupt = zip([{name: 'a/x', mode: 0o100644, data: 'payload', store: true}]);
 corrupt[30 + 3] ^= 1; // flip one stored byte; the CRC check must catch it
 assert.throws(() => inventory(corrupt));
});

test('path and link rules', () => {
 assert.ok(cleanPath('a/b/c'));
 for (const bad of ['', 'a//b', './a', 'a/..', 'C:/x', 'a\\b', '/a']) assert.equal(cleanPath(bad), false);
 assert.ok(insideLink('a/b/link', '../c'));
 assert.equal(insideLink('a/link', '../../c'), false);
 assert.equal(insideLink('link', '..'), false);
});
