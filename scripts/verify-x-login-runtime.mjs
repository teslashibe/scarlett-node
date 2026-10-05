// Build-time integrity verification only; never reads operator profiles.
import {createHash} from 'node:crypto';
import {readFileSync, readdirSync, lstatSync, realpathSync} from 'node:fs';
import {resolve, join, relative} from 'node:path';
import {fileURLToPath} from 'node:url';
export function verify(root, expectedPlatform) {
 const rootInfo=lstatSync(root);if(!rootInfo.isDirectory()||rootInfo.isSymbolicLink())throw Error('Runtime directory invalid');
 function inspect(dir){for(const name of readdirSync(dir)){const path=join(dir,name),info=lstatSync(path);if(info.isSymbolicLink()||(!info.isDirectory()&&!info.isFile()))throw Error('Runtime resources must be regular');if(info.isDirectory())inspect(path);}}
 inspect(root);if(lstatSync(join(root,'manifest.json')).size>1048576)throw Error('Runtime manifest too large');
 const manifest=JSON.parse(readFileSync(join(root,'manifest.json'),'utf8'));
 if(manifest.schemaVersion!==1 || manifest.nodeVersion!=='22.23.3' || (expectedPlatform && manifest.platform!==expectedPlatform))throw Error('Incompatible browser runtime manifest');
 const inventory=new Map();
 for(const item of manifest.files){
  if(!item.path || item.path==='manifest.json' || item.path.includes('\\') || item.path.includes(':') || item.path.startsWith('/') || item.path.split('/').some(p=>!p || p==='..' || p==='.') || inventory.has(item.path))throw Error('Invalid browser runtime inventory');
  inventory.set(item.path,item.sha256);
 }
 function walk(dir){for(const name of readdirSync(dir)){const path=join(dir,name),info=lstatSync(path);if(info.isSymbolicLink())throw Error('Symlink in runtime');if(info.isDirectory()){walk(path);continue;}if(!info.isFile())throw Error('Nonregular resource');const rel=relative(root,path).replaceAll('\\','/');if(rel==='manifest.json')continue;if(inventory.get(rel)!==createHash('sha256').update(readFileSync(path)).digest('hex'))throw Error('Unlisted or modified resource');inventory.delete(rel);}}
 walk(root);if(inventory.size)throw Error('Missing browser runtime resources');
 const paths=new Set(manifest.files.map(f=>f.path));
 for(const path of [manifest.platform.startsWith('windows-')?'node.exe':'node','social-login/src/server.js','social-login/node_modules/playwright/package.json','social-login/UPSTREAM.json'])if(!paths.has(path))throw Error('Required runtime resource missing');
 return manifest;
}
if(process.argv[1] && realpathSync(process.argv[1])===fileURLToPath(import.meta.url)){if(process.argv.length!==3 && process.argv.length!==4)throw Error('Supply runtime root and optional fixed platform');verify(resolve(process.argv[2]),process.argv[3]);console.log('Browser runtime inventory verified');}
