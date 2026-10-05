import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {verify} from './verify-x-login-runtime.mjs';
test('runtime inventory rejects tampering, unlisted bytes and missing prerequisites',()=>{
 const root=mkdtempSync(join(tmpdir(),'scarlett-runtime-fixture-'));
 try {
 const names=['node','social-login/src/server.js','social-login/node_modules/playwright/package.json','social-login/UPSTREAM.json'];
 const files=names.map(path=>{mkdirSync(dirname(join(root,path)),{recursive:true});const bytes=Buffer.from('synthetic');writeFileSync(join(root,path),bytes);return {path,sha256:createHash('sha256').update(bytes).digest('hex')}});
 const manifest={schemaVersion:1,platform:'darwin-arm64',nodeVersion:'22.23.3',files};writeFileSync(join(root,'manifest.json'),JSON.stringify(manifest));assert.equal(verify(root,'darwin-arm64').files.length,4);assert.throws(()=>verify(root,'windows-amd64'));
 writeFileSync(join(root,'node'),'changed');assert.throws(()=>verify(root));writeFileSync(join(root,'node'),'synthetic');writeFileSync(join(root,'extra'),'extra');assert.throws(()=>verify(root));rmSync(join(root,'extra'));rmSync(join(root,'social-login','src','server.js'));assert.throws(()=>verify(root));
 }finally {rmSync(root,{recursive:true,force:true})}
});

test('CLI verifier runs through an OS path alias and rejects changed bytes', async()=>{
 const {symlinkSync}=await import('node:fs');const {execFileSync}=await import('node:child_process');const {fileURLToPath}=await import('node:url');
 const parent=mkdtempSync(join(tmpdir(),'scarlett-runtime-alias-')),root=join(parent,'runtime');mkdirSync(root);
 try{
  const names=['node','social-login/src/server.js','social-login/node_modules/playwright/package.json','social-login/UPSTREAM.json'];
  const files=names.map(path=>{mkdirSync(dirname(join(root,path)),{recursive:true});writeFileSync(join(root,path),'synthetic');return{path,sha256:createHash('sha256').update('synthetic').digest('hex')}});
  writeFileSync(join(root,'manifest.json'),JSON.stringify({schemaVersion:1,platform:'darwin-arm64',nodeVersion:'22.23.3',files}));
  const alias=join(parent,'verify.mjs');symlinkSync(fileURLToPath(new URL('./verify-x-login-runtime.mjs',import.meta.url)),alias);
  execFileSync(process.execPath,[alias,root],{stdio:'pipe'});
  writeFileSync(join(root,'node'),'tampered');assert.throws(()=>execFileSync(process.execPath,[alias,root],{stdio:'pipe'}));
 }finally{rmSync(parent,{recursive:true,force:true})}
});
