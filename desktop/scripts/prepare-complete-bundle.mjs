// Developer build tooling. Uses explicitly reviewed binaries and vendor packages;
// never reads account profiles, downloads software or calls a model provider.
import {execFileSync} from 'node:child_process';
import {copyFileSync, cpSync, lstatSync, readdirSync, readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {dirname, resolve, join, isAbsolute, relative} from 'node:path';
import {fileURLToPath} from 'node:url';

const desktop = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const [node, prover, api, codexPackage, claudePackage] = process.argv.slice(2);
if (process.argv.length !== 7) throw new Error('Supply absolute native node, prover and model API binaries, then the official unpacked Codex and Claude package directories');
const targets = {
  'darwin-arm64': 'aarch64-apple-darwin',
  'darwin-x64': 'x86_64-apple-darwin',
  'win32-x64': 'x86_64-pc-windows-msvc',
};
const platform = `${process.platform}-${process.arch}`;
const triple = targets[platform];
if (!triple) throw new Error('Build on a supported native Mac or Windows x64 host');
const suffix = process.platform === 'win32' ? '.exe' : '';
const native = execFileSync('rustc', ['+1.95', '-vV'], {encoding:'utf8'}).match(/^host: (.+)$/m)?.[1];
if (triple !== native) throw new Error('Rust and native provider runtimes must have the same target');

function regular(path) {
  if (!isAbsolute(path) || !lstatSync(path).isFile()) throw new Error('Supply an absolute regular binary or metadata file');
}
function checkTree(path) {
  if (!isAbsolute(path)) throw new Error('Vendor paths must be absolute');
  const info = lstatSync(path);
  if (info.isSymbolicLink() || (!info.isFile() && !info.isDirectory())) throw new Error('Vendor trees must contain only regular files and directories');
  if (info.isDirectory()) for (const entry of readdirSync(path)) checkTree(join(path, entry));
}
for (const path of [node, prover, api]) regular(path);
for (const [binary, expectedPath] of [[node,'github.com/teslashibe/scarlett-node'], [api,'github.com/teslashibe/open-agent-api/cmd/open-agent-api']]) {
  const info = execFileSync('go',['version','-m',binary],{encoding:'utf8'});
  if (!info.includes(`\tpath\t${expectedPath}\n`) ||
      !info.includes(`\tbuild\tGOOS=${process.platform === 'win32' ? 'windows' : 'darwin'}\n`) ||
      !info.includes(`\tbuild\tGOARCH=${process.arch === 'x64' ? 'amd64' : 'arm64'}\n`)) throw new Error('Go sidecar package or native target mismatch');
  if (binary === api && !info.includes('\tmod\tgithub.com/teslashibe/open-agent-api\tv0.1.32\th1:mlJKms7JWjCv1rc85kJdhlWUVF1tBZ9KYm1LrQKnu1Y=\n') &&
      !(info.includes('\tbuild\tvcs.revision=3a2559dbe65c85a051de40e2bbafc2639fb99e73\n') && info.includes('\tbuild\tvcs.modified=false\n'))) throw new Error('The model API must come from the reviewed v0.1.32 source');
}
for (const path of [codexPackage, claudePackage]) checkTree(path);
const codexMeta = JSON.parse(readFileSync(join(codexPackage,'package.json'),'utf8'));
const claudeMeta = JSON.parse(readFileSync(join(claudePackage,'package.json'),'utf8'));
if (codexMeta.name !== '@openai/codex' || codexMeta.version !== `0.159.2-${platform}` ||
    claudeMeta.name !== `@anthropic-ai/claude-code-${platform}` || claudeMeta.version !== '2.1.286') throw new Error('Unexpected pinned native provider package');
const vendor = join(codexPackage, 'vendor', triple);
const codexExe = join(vendor, 'bin', 'codex' + suffix);
const claudeExe = join(claudePackage, 'claude' + suffix);
for (const path of [codexExe, claudeExe, join(claudePackage, 'LICENSE.md')]) regular(path);
if (execFileSync(codexExe, ['--version'], {encoding:'utf8', timeout:10000}).trim() !== 'codex-cli 0.159.2' ||
    execFileSync(claudeExe, ['--version'], {encoding:'utf8', timeout:10000}).trim() !== '2.1.286 (Claude Code)') throw new Error('Native provider executable version mismatch');

const module = execFileSync('go', ['list', '-m', '-f', '{{.Version}} {{.Dir}}', 'github.com/teslashibe/open-agent-api'], {cwd:resolve(desktop,'..'),encoding:'utf8'}).trim();
if (!module.startsWith('v0.1.32 ')) throw new Error('The shared Codex package must be pinned to v0.1.32');
const moduleDir = module.slice('v0.1.32 '.length);
const runtime = join(desktop, 'src-tauri', 'runtime');
if (existsSync(runtime)) throw new Error('Generated runtime already exists; preserve it or remove only this generated directory before preparing a new build');
mkdirSync(runtime, {recursive:true});
// Keep the browser reader's dependency notices with the packaged Go binary.
copyFileSync(join(desktop, '..', 'third_party', 'browserx', 'NOTICES.txt'), join(runtime, 'browser-reader-NOTICES.txt'));
// Preserve the complete Codex vendor layout, including helper executables,
// dylibs, package metadata and third-party notices needed by the native CLI.
cpSync(vendor, join(runtime,'codex'), {recursive:true, dereference:false});
copyFileSync(join(codexPackage,'package.json'), join(runtime,'codex','vendor-package.json'));
// Keep the Anthropic binary unmodified, together with its full package/license.
cpSync(claudePackage, join(runtime,'claude'), {recursive:true, dereference:false});
for (const file of ['codex_profile.json', 'codex_scaffold.json']) {
  copyFileSync(join(moduleDir,file), join(runtime,file));
  // Go's module cache is read-only; generated bundle inputs must be writable
  // so Tauri can safely update its own payload directory on subsequent builds.
  chmodSync(join(runtime,file),0o644);
}
const binaries = join(desktop, 'src-tauri', 'binaries');
mkdirSync(binaries, {recursive:true});
for (const [name, source] of [['scarlett-node',node], ['scarlett-prover',prover], ['open-agent-api',api]]) {
  const destination = join(binaries, `${name}-${triple}${suffix}`);
  copyFileSync(source,destination);
  if (!suffix) chmodSync(destination,0o755);
}
const sidecars = [['scarlett-node',node], ['scarlett-prover',prover], ['open-agent-api',api]].map(([name,source]) => ({name,bytes:lstatSync(source).size,sha256:createHash('sha256').update(readFileSync(source)).digest('hex')}));
const files = [];
function record(directory) {
  for (const name of readdirSync(directory).sort()) {
    const path = join(directory,name);
    if (lstatSync(path).isDirectory()) record(path);
    else files.push({path:relative(runtime,path).replaceAll('\\','/'),bytes:lstatSync(path).size,sha256:createHash('sha256').update(readFileSync(path)).digest('hex')});
  }
}
record(runtime);
writeFileSync(join(runtime,'COMPONENTS.json'),JSON.stringify({schemaVersion:1,target:triple,
  codexVersion:'0.159.2',claudeVersion:'2.1.286',modelApiVersion:'0.1.32',sidecars,files},null,2)+'\n');
const config = {bundle:{targets: suffix ? ['nsis'] : ['app','dmg'],
  externalBin:['binaries/scarlett-node','binaries/scarlett-prover','binaries/open-agent-api'],
  resources:{'runtime/':'runtime/'}}};
writeFileSync(join(desktop,'src-tauri','tauri.complete.generated.json'),JSON.stringify(config,null,2)+'\n');
console.log(`Prepared all native runtime components for ${triple}; acceptance tests and signing are still required`);
