import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdtempSync,mkdirSync,cpSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
test('source snapshot verifier rejects changed or missing runtime bytes',()=>{
 const root=mkdtempSync(join(tmpdir(),'scarlett-source-pin-'));try{
 mkdirSync(join(root,'scripts'));mkdirSync(join(root,'third_party'));
 cpSync('scripts/verify-social-login.mjs',join(root,'scripts/verify-social-login.mjs'));
 cpSync('third_party/social-login',join(root,'third_party/social-login'),{recursive:true,filter:path=>!path.includes('node_modules')});
 const verify=()=>execFileSync(process.execPath,[join(root,'scripts/verify-social-login.mjs')],{stdio:'pipe'});
 assert.doesNotThrow(verify);
 const server=join(root,'third_party/social-login/src/server.js');writeFileSync(server,'tampered source');assert.throws(verify);rmSync(server);assert.throws(verify);
 }finally{rmSync(root,{recursive:true,force:true});}
});
