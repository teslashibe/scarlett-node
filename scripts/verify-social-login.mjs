// Verify tracked source bytes and the exact upstream/patch provenance.
import {readFileSync,readdirSync,lstatSync} from 'node:fs';
import {join,resolve,dirname,relative} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../third_party/social-login');
const upstream=JSON.parse(readFileSync(join(root,'UPSTREAM.json')));
const patched=JSON.parse(readFileSync(join(root,'PATCHED.json')));
if(upstream.revision!=='11e2ffafe3e7f32f531af7b08b677430af0bf7d4'||upstream.tag!=='v0.2.20'||patched.upstream_revision!==upstream.revision)throw Error('Unrecognized social-login source pin');
const found=new Set();
function walk(dir){for(const name of readdirSync(dir)){if(name==='node_modules')continue;const file=join(dir,name),info=lstatSync(file);if(info.isSymbolicLink())throw Error('Snapshot symlink');if(info.isDirectory()){walk(file);continue;}const rel=relative(root,file).replaceAll('\\','/');if(rel==='PATCHED.json')continue;const hash=createHash('sha256').update(readFileSync(file)).digest('hex');if(patched.sha256[rel]!==hash)throw Error(`Snapshot resource missing from manifest or modified: ${rel}`);found.add(rel);}}
walk(root);if(found.size!==Object.keys(patched.sha256).length)throw Error('Snapshot resource missing');
for(const file of Object.keys(upstream.original_sha256))if(!found.has(file))throw Error('Missing upstream source');
console.log('Pinned social-login source and patch verified');
