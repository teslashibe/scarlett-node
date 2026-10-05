import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
const base = fs.mkdtempSync(path.join(os.tmpdir(), "scarlett-interactive-x-"));
process.env.CAP_PROFILE_BASE = base;
process.env.CAP_HEADLESS = "true";
process.env.SOCIAL_LOGIN_MAX_CONCURRENCY = "1";
process.env.SOCIAL_LOGIN_QUEUE_TIMEOUT_MS = "100";
const { chromium } = await import("playwright");
const { SocialLoginService } = await import("../src/service.js");
const { __test: runtime } = await import("../src/runtime/legacy.js");
const launch = chromium.launchPersistentContext.bind(chromium);
const req = (key = "fixture") => ({ platform: "x", profile_key: key, username: "synthetic-user", password: "synthetic-password", operation_owner: "owner".repeat(10), connection_id: "connection", generation: "1", revision: "1", recovery_claim: "claim", budget: { max_browser_attempts: 1, max_credential_attempts: 1, max_solver_attempts: 0, deadline_at: new Date(Date.now()+40000).toISOString() } });
const continuation = (input, challenge, code) => ({ ...input, username: "", password: "", challenge_id: challenge.id, verification_code: code, budget: { max_browser_attempts: 0, max_credential_attempts: 0, max_solver_attempts: 0 } });

async function fixture(t) {
 const observed = { navigations: 0, passwords: 0, codes: [], launches: 0, closes: 0, requests: [], context: null, page: null };
 t.mock.method(chromium, "launchPersistentContext", async (dir, options) => {
  observed.launches++;
  const context = await launch(dir, options); observed.context = context;
  context.once("close", () => observed.closes++);
  await context.exposeFunction("recordPassword", () => observed.passwords++);
  await context.exposeFunction("recordCode", code => observed.codes.push(code));
  // Every provider request is intercepted. No X request can leave this test.
  await context.route("**/*", async route => {
   const request = route.request(); observed.requests.push(request.url());
   if (request.isNavigationRequest()) observed.navigations++;
   if (new URL(request.url()).pathname === "/home") {
    await context.addCookies(["auth_token", "ct0", "twid"].map(name => ({ name, value: "synthetic-"+name, domain: ".x.com", path: "/", secure: true })));
    await route.fulfill({contentType:"text/html",body:"<html><body>Authenticated fixture</body></html>"}); return;
   }
   const login = `<html><body><div id="layers"><input name="username_or_email"><button onclick="document.querySelector('#layers').innerHTML='<input name=password type=password><button onclick=submitPassword()>Log in</button>'">Next</button></div><script>
   async function submitPassword(){await window.recordPassword();document.querySelector('#layers').innerHTML='<p>Enter your verification code</p><input name=code autocomplete=one-time-code><button onclick=submitCode()>Verify</button>';}
   async function submitCode(){const code=document.querySelector('input[name=code]').value;await window.recordCode(code);if(code==='123456')location.href='/home';else document.querySelector('p').textContent='Incorrect verification code';}
   </script></body></html>`;
   const body = new URL(request.url()).pathname === "/" ? '<html><body><a href="/i/flow/login">Sign in</a></body></html>' : login;
   await route.fulfill({ contentType: "text/html", body });
  });
  const page = context.pages()[0]; observed.page = page;
  const wait = page.waitForTimeout.bind(page); page.waitForTimeout = ms => wait(Math.min(ms,10));
  return context;
 });
 return observed;
}

test.beforeEach(() => runtime.reset());
test.after(() => fs.rmSync(base,{recursive:true,force:true}));

test("real Chromium parks X and submits invalid then valid code on the same page with one password", async t => {
 const seen=await fixture(t); const service=new SocialLoginService();t.after(()=>service.shutdown(1000));
 const input=req("continue");const first=await service.login(input);
 assert.equal(first.result.failureType,"verification_required"); assert.equal(service.capabilities().interactive_x,1);
 const page=seen.page;const navigations=seen.navigations;
 assert.equal(runtime.state().holds,1);assert.equal(runtime.state().activeAdmissions,0);
 for(const change of [{operation_owner:"other".repeat(10)},{profile_key:"wrong"},{proxy_url:"http://127.0.0.1:3456",proxy_lease:"wrong"},{generation:"2"}]) {
  await assert.rejects(service.login({...continuation(input,first.result.challenge,"123456"),...change}),e=>/mismatch/.test(e.code));
 }
 await assert.rejects(service.login({...input,username:"",password:"",operation_owner:"harvest".repeat(10)}),e=>e.code==="profile_busy");
 // A held browser consumes the only capacity slot; unrelated work cannot launch.
 const other=await service.login({...req("other"),operation_owner:"other".repeat(10)}).catch(e=>e);
 assert.equal(other.code,"queue_timeout");assert.equal(seen.launches,1);
 const invalid=await service.login(continuation(input,first.result.challenge,"000000"));
 assert.equal(invalid.result.failureType,"verification_required"); assert.equal(seen.page,page);assert.equal(seen.navigations,navigations);assert.equal(seen.passwords,1);
 assert.equal(invalid.result.deadline_at,first.result.deadline_at);
 assert.deepEqual(invalid.result.attempts,{browser:1,credential:1,solver:0,complete:true});
 await assert.rejects(service.login(continuation(input,first.result.challenge,"123456")),e=>e.code==="challenge_not_found");
 const success=await service.login(continuation(input,invalid.result.challenge,"123456"));
 assert.equal(success.result.ok,true);assert.equal(success.result.session.auth_token,"synthetic-auth_token");assert.ok(success.result.session.user_agent);
 assert.deepEqual(success.result.attempts,{browser:1,credential:1,solver:0,complete:true});
 assert.equal(seen.passwords,1);assert.equal(seen.launches,1);assert.deepEqual(seen.codes,["000000","123456"]);assert.equal(seen.closes,1);
 assert.equal(runtime.state().holds,0);assert.equal(runtime.state().activeAdmissions,0);
});

for (const reason of ["cancel", "expiry", "shutdown", "crash", "budget"]) {
 test(`real Chromium ${reason} closes a parked browser and releases capacity`,async t=>{
  const seen=await fixture(t);if(reason==="budget") process.env.SOCIAL_LOGIN_MAX_OTP_ATTEMPTS="1";const service=new SocialLoginService();delete process.env.SOCIAL_LOGIN_MAX_OTP_ATTEMPTS;t.after(()=>service.shutdown(1000));
  const input=req(reason);if(reason==="expiry") input.budget.deadline_at=new Date(Date.now()+15000).toISOString();const first=await service.login(input);assert.equal(runtime.state().holds,1);
  if(reason==="cancel") {await service.cancelChallenge(input);await service.cancelChallenge(input);}
  if(reason==="expiry") {await new Promise(resolve=>setTimeout(resolve,Math.max(1,Date.parse(first.result.challenge.expires_at)-Date.now()+100)));await assert.rejects(service.login(continuation(input,first.result.challenge,"123456")),e=>e.code==="challenge_not_found");}
  if(reason==="shutdown") await service.shutdown(1000);
  if(reason==="crash") {await seen.context.close();await new Promise(resolve=>setTimeout(resolve,10));assert.throws(()=>service.challengeStatus(input),e=>e.code==="challenge_not_found");await assert.rejects(service.login(continuation(input,first.result.challenge,"123456")),e=>e.code==="challenge_not_found");}
  if(reason==="budget") {const invalid=await service.login(continuation(input,first.result.challenge,"000000"));await assert.rejects(service.login(continuation(input,invalid.result.challenge,"123456")),e=>e.code==="attempts_exhausted");}
  assert.equal(seen.closes,1);assert.equal(runtime.state().holds,0);assert.equal(runtime.state().activeAdmissions,0);assert.equal(seen.passwords,1);assert.deepEqual(seen.codes,reason==="budget"?["000000"]:[]);
 });
}


test("real Chromium warm authenticated profile returns a candidate without another password",async t=>{
 const seen=await fixture(t);const original=chromium.launchPersistentContext;
 t.mock.method(chromium,"launchPersistentContext",async(...args)=>{const context=await original(...args);await context.addCookies(["auth_token","ct0"].map(name=>({name,value:"synthetic-existing",domain:".x.com",path:"/",secure:true})));return context;});
 const service=new SocialLoginService();t.after(()=>service.shutdown(1000));const result=await service.login(req("warm"));
 assert.equal(result.result.ok,true);assert.equal(seen.passwords,0);assert.equal(seen.launches,1);assert.equal(seen.navigations,1);assert.equal(seen.closes,1);assert.equal(result.result.attempts.credential,0);
});
