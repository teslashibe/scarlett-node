// Explicit release preparation downloads pinned Node bytes and npm dependencies.
// No provider calls, accounts or browser downloads are performed.
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdirSync,mkdtempSync,cpSync,writeFileSync,readFileSync,readdirSync,lstatSync,chmodSync,existsSync,rmSync,realpathSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve,dirname,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {verify} from './verify-x-login-runtime.mjs';
const version='22.23.3';
const pins={
 'darwin-arm64':['node-v22.23.3-darwin-arm64.tar.gz','23b25245dcfb9af7262f8ff142e9e2e0af025368117329e7a7458a51e5922f53','darwin-arm64'],
 'darwin-x64':['node-v22.23.3-darwin-x64.tar.gz','8a677b0219178efd6eb0e475457c4afb452b521a92f6e67845a73bd85727f2a8','darwin-amd64'],
 'linux-x64':['node-v22.23.3-linux-x64.tar.gz','1084aa36196bba4c3a5e69a1ee388a6e4ff729dad09445fbcd434b28fe3c24af','linux-amd64'],
 'linux-arm64':['node-v22.23.3-linux-arm64.tar.gz','5ced2d48d1d7198739b7f86804de0171aefb6823b684b12341d3321afc3cb0b2','linux-arm64'],
 'win32-x64':['win-x64/node.exe','9c9245166b4a8e182e0b797da9c20136117ff24368eaff1fec8343a123c8db0e','windows-amd64'],
};
const [platform,destination]=process.argv.slice(2);if(process.argv.length!==4 || !pins[platform] || platform!==`${process.platform}-${process.arch}` || !isAbsolute(destination))throw Error('Supply supported native platform and absolute output runtime directory');
if(existsSync(destination))throw Error('Preserve or remove the existing generated runtime before preparing');
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),source=join(root,'third_party','social-login');
// Snapshot validation checks original/modified source pins before any install.
execFileSync(process.execPath,[join(root,'scripts','verify-social-login.mjs')],{stdio:'inherit'});
const work=mkdtempSync(join(tmpdir(),'scarlett-x-runtime-'));
try {
 const [archive,sha,goPlatform]=pins[platform],url=`https://nodejs.org/dist/v${version}/${archive}`;
 const response=await fetch(url,{signal:AbortSignal.timeout(120000)});if(!response.ok)throw Error('Pinned Node download failed');const bytes=Buffer.from(await response.arrayBuffer());if(createHash('sha256').update(bytes).digest('hex')!==sha)throw Error('Pinned Node archive checksum mismatch');
 mkdirSync(destination,{recursive:true});
 const nodePath=join(destination,platform.startsWith('win32')?'node.exe':'node');
 if(platform.startsWith('win32'))writeFileSync(nodePath,bytes);else {const tar=join(work,'node.tar.gz');writeFileSync(tar,bytes);execFileSync('tar',['-xzf',tar,'-C',work]);const nodeRoot=join(work,archive.replace('.tar.gz',''));cpSync(join(nodeRoot,'bin','node'),nodePath);cpSync(join(nodeRoot,'LICENSE'),join(destination,'NODE-LICENSE.txt'));chmodSync(nodePath,0o755);}
 if(platform.startsWith('win32')){const license=await fetch(`https://raw.githubusercontent.com/nodejs/node/v${version}/LICENSE`);if(!license.ok)throw Error('Node license unavailable');writeFileSync(join(destination,'NODE-LICENSE.txt'),await license.text());}
 if(execFileSync(nodePath,['--version'],{encoding:'utf8'}).trim()!==`v${version}`)throw Error('Native Node executable version mismatch');
 const service=join(destination,'social-login');cpSync(source,service,{recursive:true,filter:path=>!path.includes('node_modules')&&!path.includes('/.git')});
 // npm lock integrity pins Playwright's exact package bytes. Ignore all scripts,
 // optional native dependencies and command shims; runtime launches fixed Chrome.
 const npmCLI=process.platform==='win32'?join(dirname(process.execPath),'node_modules','npm','bin','npm-cli.js'):realpathSync(join(dirname(process.execPath),'npm'));
 if(!existsSync(npmCLI))throw Error('Build host must supply npm alongside its explicit Node installation');
 execFileSync(process.execPath,[npmCLI,'ci','--omit=dev','--omit=optional','--ignore-scripts','--no-bin-links'],{cwd:service,stdio:'inherit',env:{...process.env,PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD:'1'}});
 const files=[];function record(dir){for(const name of readdirSync(dir).sort()){const path=join(dir,name),info=lstatSync(path);if(info.isSymbolicLink())throw Error('Runtime symlink');if(info.isDirectory()){record(path);continue;}if(!info.isFile())throw Error('Runtime nonregular resource');files.push({path:relative(destination,path).replaceAll('\\','/'),sha256:createHash('sha256').update(readFileSync(path)).digest('hex')});}}record(destination);
 writeFileSync(join(destination,'manifest.json'),JSON.stringify({schemaVersion:1,platform:goPlatform,nodeVersion:version,files},null,2)+'\n');verify(destination,goPlatform);console.log(`Prepared verified X login runtime for ${goPlatform}`);
} catch(error){rmSync(destination,{recursive:true,force:true});throw error;} finally {rmSync(work,{recursive:true,force:true});}
