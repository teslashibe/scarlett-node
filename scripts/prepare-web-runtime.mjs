// Explicit release preparation of the web browser runtime. It downloads the
// pinned CPython build and installs hash-locked wheels with that CPython's own
// pip, then writes one deterministic archive plus web-runtime.json. It never
// downloads the browser: the node fetches the pinned Chrome for Testing itself.
//
// usage: node scripts/prepare-web-runtime.mjs <darwin-arm64|darwin-x64|win32-x64|linux-x64> <absolute out dir> <absolute x-login-runtime dir>
// output: <out>/web-runtime-<goPlatform>.tar.gz and <out>/web-runtime.json
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {copyFileSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync, realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, isAbsolute, join, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {verify, maxArchiveBytes, cftName} from './verify-web-runtime.mjs';

const release = '20261003', python = '3.13.16', scrapling = '0.4.15', nodeVersion = '22.23.3';
// Node-style platform → [python-build-standalone triple, asset sha256, Go platform].
export const pins = {
 'darwin-arm64': ['aarch64-apple-darwin', '9e01f63bbb08576cd9c8bc2d0564d098cb30c8453a0cd4bcf6aef458f6d2a147', 'darwin-arm64'],
 'darwin-x64': ['x86_64-apple-darwin', 'b4dad38ba6a344555ccb71a1b08caad0a6c0dda88c5803658bc95bd7f04e9f5c', 'darwin-amd64'],
 'win32-x64': ['x86_64-pc-windows-msvc', 'ec43f1a85c29f147d7ae2d13218c52c70b24a983a82ab22d6c607c0593060e10', 'windows-amd64'],
 'linux-x64': ['x86_64-unknown-linux-gnu', '4595c5589fff7bf0cb158d9a88a797e0d791fa33830770fcb7bf3f4b104feeae', 'linux-amd64'],
};
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

export function parseArgs(argv, host = `${process.platform}-${process.arch}`) {
 const [platform, out, xlogin] = argv;
 if (argv.length !== 3 || !Object.hasOwn(pins, platform) || platform !== host || !isAbsolute(out) || !isAbsolute(xlogin))
  throw Error('Supply the native platform (darwin-arm64, darwin-x64, win32-x64 or linux-x64), an absolute output directory and the prepared x-login runtime');
 return {platform, out, xlogin, goPlatform: pins[platform][2]};
}

async function main() {
 const {platform, out, xlogin, goPlatform} = parseArgs(process.argv.slice(2));
 const [triple, pbsSha] = pins[platform];
 const windows = platform === 'win32-x64';
 const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'), source = join(root, 'third_party', 'web-browser');
 // The driver runs on the x-login runtime's pinned, publisher-signed Node.
 const nodeName = windows ? 'node.exe' : 'node';
 const xManifest = JSON.parse(readFileSync(join(xlogin, 'manifest.json'), 'utf8'));
 const nodeEntry = xManifest.files?.find(f => f.path === nodeName);
 if (xManifest.nodeVersion !== nodeVersion || xManifest.platform !== goPlatform || !nodeEntry || sha256(readFileSync(join(xlogin, nodeName))) !== nodeEntry.sha256)
  throw Error('Prepare and verify the x-login runtime first');
 const archiveName = `web-runtime-${goPlatform}.tar.gz`;
 if (existsSync(join(out, archiveName)) || existsSync(join(out, 'web-runtime.json'))) throw Error('Remove the previous generated web runtime first');
 const browsers = JSON.parse(readFileSync(join(source, 'chrome-for-testing.json'), 'utf8')), browser = browsers.platforms?.[goPlatform];
 const inventory = readFileSync(join(source, 'chrome-inventory', `${goPlatform}.json`));
 if (browsers.version !== '155.0.8059.39' || !browser || sha256(inventory) !== browser.inventory_sha256 ||
  browser.url !== `https://storage.googleapis.com/chrome-for-testing-public/${browsers.version}/${cftName(goPlatform)}/chrome-${cftName(goPlatform)}.zip`)
  throw Error('Pinned Chrome for Testing inputs are inconsistent');
 const work = mkdtempSync(join(tmpdir(), 'scarlett-web-runtime-')), scratch = mkdtempSync(join(tmpdir(), 'scarlett-web-runtime-home-'));
 let wrote = false;
 try {
  const url = `https://github.com/astral-sh/python-build-standalone/releases/download/${release}/cpython-${python}%2B${release}-${triple}-install_only_stripped.tar.gz`;
  const response = await fetch(url, {signal: AbortSignal.timeout(300000)});
  if (!response.ok) throw Error('Pinned CPython download failed');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (sha256(bytes) !== pbsSha) throw Error('Pinned CPython archive checksum mismatch');
  writeFileSync(join(work, 'cpython.tar.gz'), bytes);
  // Fixed system tar, never PATH on Windows (Git's GNU tar misreads drive letters).
  const tar = windows ? join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
  execFileSync(tar, ['-xzf', join(work, 'cpython.tar.gz'), '-C', work]);
  unlinkSync(join(work, 'cpython.tar.gz'));
  const runtime = join(work, 'python');
  const py = windows ? join(runtime, 'python.exe') : join(runtime, 'bin', 'python3.13');
  const lib = windows ? join(runtime, 'Lib') : join(runtime, 'lib', 'python3.13');
  const site = join(lib, 'site-packages');
  const env = {PATH: process.env.PATH || '', TMPDIR: scratch, TEMP: scratch, TMP: scratch, HOME: scratch, USERPROFILE: scratch,
   ...(windows ? {SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR} : {})};
  // Release-time install only: the bundled pip, hash-locked wheels, no sdists, no build or install scripts.
  execFileSync(py, ['-I', '-B', '-m', 'pip', 'install', '--no-cache-dir', '--disable-pip-version-check', '--require-hashes', '--no-deps',
   '--only-binary=:all:', '--no-compile', '--no-warn-script-location', '-r', join(source, 'requirements.lock')], {stdio: 'inherit', env});
  copyFileSync(join(source, 'scarlett_web_helper.py'), join(site, 'scarlett_web_helper.py'));
  // Prune: links, build and development surfaces, Tk, pip, console scripts
  // (their shebangs are build paths) and both drivers' bundled Node copies.
  const rm = path => rmSync(path, {recursive: true, force: true});
  (function unlinkLinks(dir) { for (const name of readdirSync(dir)) { const path = join(dir, name), info = lstatSync(path); if (info.isSymbolicLink()) unlinkSync(path); else if (info.isDirectory()) unlinkLinks(path); } })(runtime);
  for (const path of ['include', 'share', 'libs', 'tcl', 'Scripts', join('lib', 'pkgconfig')]) rm(join(runtime, path));
  const natives = windows ? join(runtime, 'DLLs') : join(runtime, 'lib');
  for (const name of readdirSync(natives)) if (/^(itcl|tcl|tk|thread|libtcl|libtk|libpython)|^_tkinter|^t(cl|k)\d+t?\.dll$/.test(name)) rm(join(natives, name));
  if (!windows) for (const name of readdirSync(join(runtime, 'bin'))) if (name !== 'python3.13') rm(join(runtime, 'bin', name));
  for (const name of readdirSync(lib)) if (/^(config-3\.13-|idlelib$|tkinter$|turtledemo$|turtle\.py$|ensurepip$|pydoc_data$)/.test(name)) rm(join(lib, name));
  if (!windows) for (const name of readdirSync(join(lib, 'lib-dynload'))) if (name.startsWith('_tkinter')) rm(join(lib, 'lib-dynload', name));
  for (const name of readdirSync(site)) if (/^pip(-|$)/.test(name)) rm(join(site, name));
  for (const name of readdirSync(site)) if (name.endsWith('.dist-info')) rm(join(site, name, 'RECORD'));
  for (const pkg of ['playwright', 'patchright']) { rm(join(site, pkg, 'driver', nodeName)); rm(join(site, pkg, 'driver', 'package', 'lib', 'tools', 'skills')); }
  (function dropCaches(dir) { for (const name of readdirSync(dir)) { const path = join(dir, name); if (!lstatSync(path).isDirectory()) continue; if (name === '__pycache__') rm(path); else dropCaches(path); } })(runtime);
  // Unchecked-hash bytecode: used regardless of file times, never rewritten
  // (the helper runs with -I -B), and byte-reproducible because -s/-p keep
  // the random build directory out of every code object.
  execFileSync(py, ['-I', '-B', '-m', 'compileall', '-f', '-q', '-j0', '--invalidation-mode', 'unchecked-hash', '-s', work, '-p', '/web-runtime', lib], {stdio: ['ignore', 'ignore', 'inherit'], env});
  // Import, option-set and driver smoke on the build host only.
  const smoke = {...env, PLAYWRIGHT_NODEJS_PATH: join(xlogin, nodeName), PLAYWRIGHT_BROWSERS_PATH: join(scratch, 'none'), PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1'};
  const check = JSON.parse(execFileSync(py, ['-I', '-B', '-X', 'utf8', '-m', 'scarlett_web_helper', '--self-check'], {env: smoke, encoding: 'utf8'}));
  if (check.self_check !== 'passed' || check.python !== python || check.scrapling !== scrapling || check.patchright !== '1.63.0' || check.playwright !== '1.63.0')
   throw Error('Web runtime self-check failed');
  if (execFileSync(py, ['-I', '-B', '-m', 'patchright', '--version'], {env: smoke, encoding: 'utf8'}).trim() !== 'Version 1.63.0') throw Error('Patchright driver check failed');
  // The pinned browser: where to download it and the exact tree it extracts to.
  mkdirSync(join(work, 'browser'));
  writeFileSync(join(work, 'browser', 'pin.json'), JSON.stringify({version: browsers.version, platform: goPlatform, url: browser.url, sha256: browser.sha256,
   bytes: browser.bytes, executable: browser.executable, inventory_sha256: browser.inventory_sha256, unpacked_bytes: browser.unpacked_bytes}) + '\n');
  writeFileSync(join(work, 'browser', 'inventory.json'), inventory);
  mkdirSync(join(work, 'notices'));
  for (const name of ['NOTICE.md', 'wafer-LICENSE.txt']) copyFileSync(join(source, name), join(work, 'notices', name));
  if (readdirSync(work).sort().join(',') !== 'browser,notices,python') throw Error('Unexpected entries in the runtime tree');
  const files = [];
  (function record(dir) {
   for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name), info = lstatSync(path);
    if (info.isSymbolicLink()) throw Error('Runtime symlink');
    if (info.isDirectory()) { record(path); continue; }
    if (!info.isFile()) throw Error('Runtime nonregular resource');
    files.push({path: relative(work, path).replaceAll('\\', '/'), sha256: sha256(readFileSync(path)), bytes: info.size, ...(!windows && (info.mode & 0o111) ? {exec: true} : {})});
   }
  })(work);
  const manifest = {schemaVersion: 1, platform: goPlatform, pythonVersion: python, pbsRelease: release, scraplingVersion: scrapling,
   lockSha256: sha256(readFileSync(join(source, 'requirements.lock'))), driverNode: {path: `x-login-runtime/${nodeName}`, sha256: nodeEntry.sha256, version: nodeVersion},
   interpreter: windows ? 'python/python.exe' : 'python/bin/python3.13', browserVersion: browsers.version, files};
  writeFileSync(join(work, 'manifest.json'), JSON.stringify(manifest, null, 1) + '\n');
  // Deterministic archive written by the pinned interpreter's own tarfile:
  // manifest first, recorded order, mtime 0, uid and gid 0, modes 0755/0644.
  mkdirSync(out, {recursive: true});
  const archive = join(out, archiveName);
  wrote = true;
  execFileSync(py, ['-I', '-B', '-c', `
import gzip, json, os, sys, tarfile
work, archive = sys.argv[1], sys.argv[2]
m = json.load(open(os.path.join(work, 'manifest.json'), encoding='utf-8'))
with open(archive, 'xb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', compresslevel=9, mtime=0) as gz, tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
    for f in [{'path': 'manifest.json'}] + m['files']:
        rel = f['path']
        info = tarfile.TarInfo(rel)
        info.size = os.path.getsize(os.path.join(work, *rel.split('/')))
        info.mtime, info.uid, info.gid, info.uname, info.gname = 0, 0, 0, '', ''
        info.mode = 0o755 if f.get('exec') else 0o644
        with open(os.path.join(work, *rel.split('/')), 'rb') as data:
            tar.addfile(info, data)
`, work, archive], {env});
  const archiveBytes = statSync(archive).size;
  if (archiveBytes > maxArchiveBytes) throw Error(`Web runtime archive exceeds ${maxArchiveBytes} bytes`);
  const result = {schemaVersion: 1, platform: goPlatform, archive: archiveName, archiveSha256: sha256(readFileSync(archive)), archiveBytes,
   manifestSha256: sha256(readFileSync(join(work, 'manifest.json'))), unpackedBytes: files.reduce((sum, f) => sum + f.bytes, 0), files: files.length,
   pythonVersion: python, scraplingVersion: scrapling, browserVersion: browsers.version, browserZipSha256: browser.sha256};
  writeFileSync(join(out, 'web-runtime.json'), JSON.stringify(result, null, 2) + '\n');
  verify(out, goPlatform);
  console.log(`Prepared verified web browser runtime for ${goPlatform}: ${archiveBytes} bytes, sha256 ${result.archiveSha256}`);
 } catch (error) {
  if (wrote) { rmSync(join(out, archiveName), {force: true}); rmSync(join(out, 'web-runtime.json'), {force: true}); }
  throw error;
 } finally {
  rmSync(work, {recursive: true, force: true});
  rmSync(scratch, {recursive: true, force: true});
 }
}

if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))) await main();
