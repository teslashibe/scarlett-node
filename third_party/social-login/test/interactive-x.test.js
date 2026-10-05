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
 const observed = { navigations: 0, passwords: 0, codes: [], launches: 0, closes: 0, requests: [], context: null, page: null, runtimeFailure: null };
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
   async function submitPassword(){window.fixtureState="submitting-password";await window.recordPassword();document.querySelector('#layers').innerHTML='<p>Enter your verification code</p><input name=code autocomplete=one-time-code><button onclick=submitCode()>Verify</button>';window.fixtureState="challenge";}
   async function submitCode(){window.fixtureState="submitting-code";const code=document.querySelector('input[name=code]').value;await window.recordCode(code);if(code==='123456')location.href='/home';else {document.querySelector('p').textContent='Incorrect verification code';window.fixtureState="invalid-code";}}
   </script></body></html>`;
   const body = new URL(request.url()).pathname === "/" ? '<html><body><a href="/i/flow/login">Sign in</a></body></html>' : login;
   await route.fulfill({ contentType: "text/html", body });
  });
  const page = context.pages()[0]; observed.page = page;
  const wait = page.waitForTimeout.bind(page);
  page.waitForTimeout = async ms => {
   await wait(Math.min(ms,10));
   // Decorative delays stay short, but submitted fixture work must actually settle.
   await page.waitForFunction(() => !["submitting-password", "submitting-code"].includes(window.fixtureState), null, {timeout:10000});
   if (observed.codes.at(-1) === "123456") {
    await page.waitForURL("**/home", {waitUntil:"domcontentloaded",timeout:10000});
    await page.getByText("Authenticated fixture", {exact:true}).waitFor({state:"visible",timeout:10000});
   } else if (observed.codes.length) {
    await page.getByText("Incorrect verification code", {exact:true}).waitFor({state:"visible",timeout:10000});
   } else if (observed.passwords) {
    await page.locator('input[name="code"]').waitFor({state:"visible",timeout:10000});
   }
  };
  return context;
 });
 return observed;
}

async function waitForReleased(seen) {
 const deadline = Date.now()+10000;
 while ((seen.closes !== 1 || runtime.state().holds !== 0 || runtime.state().activeAdmissions !== 0) && Date.now() < deadline) {
  await new Promise(resolve=>setTimeout(resolve,25));
 }
 assert.equal(seen.closes,1,"browser close event did not settle");
 assert.equal(runtime.state().holds,0,"browser capacity was not released");
 assert.equal(runtime.state().activeAdmissions,0,"browser admission was not released");
}

function serviceFor(t, seen, overrides={}) {
 const previous = new Map(Object.keys(overrides).map(name=>[name,process.env[name]]));
 let service;
 try {
  Object.assign(process.env,overrides);
  service = new SocialLoginService({runtime:{...runtime,async runBrowserLogin(platform,input,...args) {
   seen.runtimeFailure=null;
   try { return await runtime.runBrowserLogin(platform,input,...args); }
   catch (error) {
    const names=["TimeoutError","Error","TypeError","ServiceError","AdmissionError","AbortError"];
    const location=String(error?.stack || "").match(/^[ \t]+at [^\r\n]*[\\/](interactive-x\.test\.js|legacy\.js|login-budget\.js|service\.js):([1-9][0-9]{0,3}):([1-9][0-9]{0,2})\)?[ \t]*$/m);
    seen.runtimeFailure={stage:input.challengeHold?"continue":"start",errorName:names.includes(error?.name)?error.name:"unclassified",
     sourceBasename:location?.[1] || null,sourceLine:location?Number(location[2]):null,sourceColumn:location?Number(location[3]):null};
    throw error; // Preserve the exact production result, cancellation and retry behavior.
   }
  }}});
 } finally {
  for (const [name,value] of previous) {
   if (value === undefined) delete process.env[name]; else process.env[name]=value;
  }
 }
 t.after(async()=>{
  try {await service.shutdown(10000);if(seen.context) await waitForReleased(seen);}
  finally {if(seen.runtimeFailure) t.diagnostic("SCARLETT_X_FIXTURE_ERROR "+JSON.stringify(seen.runtimeFailure));}
 });
 return service;
}

test.beforeEach(() => runtime.reset());
test.after(() => fs.rmSync(base,{recursive:true,force:true}));

test("real Chromium parks X and submits invalid then valid code on the same page with one password", async t => {
 const seen=await fixture(t); const service=serviceFor(t,seen);
 const input=req("continue");const first=await service.login(input);
 assert.equal(first.result.failureType,"verification_required");assert.equal(Boolean(first.result.challenge?.id),true); assert.equal(service.capabilities().interactive_x,1);
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
 assert.equal(invalid.result.failureType,"verification_required");assert.equal(Boolean(invalid.result.challenge?.id),true); assert.equal(seen.page,page);assert.equal(seen.navigations,navigations);assert.equal(seen.passwords,1);
 assert.equal(invalid.result.deadline_at,first.result.deadline_at);
 assert.deepEqual(invalid.result.attempts,{browser:1,credential:1,solver:0,complete:true});
 await assert.rejects(service.login(continuation(input,first.result.challenge,"123456")),e=>e.code==="challenge_not_found");
 const success=await service.login(continuation(input,invalid.result.challenge,"123456"));
 assert.equal(success.result.ok,true);assert.equal(success.result.session.auth_token,"synthetic-auth_token");assert.ok(success.result.session.user_agent);
 assert.deepEqual(success.result.attempts,{browser:1,credential:1,solver:0,complete:true});
 await waitForReleased(seen);assert.equal(seen.passwords,1);assert.equal(seen.launches,1);assert.deepEqual(seen.codes,["000000","123456"]);assert.equal(seen.closes,1);
 assert.equal(runtime.state().holds,0);assert.equal(runtime.state().activeAdmissions,0);
});

for (const reason of ["cancel", "expiry", "shutdown", "crash", "budget"]) {
 test(`real Chromium ${reason} closes a parked browser and releases capacity`,async t=>{
  const seen=await fixture(t);
  // Constructor-only TTL begins at parking, so a slow browser launch is not the expiry under test.
  const overrides=reason==="expiry"?{SOCIAL_LOGIN_CHALLENGE_TTL_MS:"2000"}:reason==="budget"?{SOCIAL_LOGIN_MAX_OTP_ATTEMPTS:"1"}:{};
  const service=serviceFor(t,seen,overrides);
  const input=req(reason);const first=await service.login(input);
  assert.equal(first.result.failureType,"verification_required");assert.equal(Boolean(first.result.challenge?.id),true);
  assert.equal(runtime.state().holds,1);
  if(reason==="cancel") {await service.cancelChallenge(input);await service.cancelChallenge(input);}
  if(reason==="expiry") {await new Promise(resolve=>setTimeout(resolve,Math.max(1,Date.parse(first.result.challenge.expires_at)-Date.now())));await waitForReleased(seen);await assert.rejects(service.login(continuation(input,first.result.challenge,"123456")),e=>e.code==="challenge_not_found");}
  if(reason==="shutdown") await service.shutdown(10000);
  if(reason==="crash") {await seen.context.close();await waitForReleased(seen);assert.throws(()=>service.challengeStatus(input),e=>e.code==="challenge_not_found");await assert.rejects(service.login(continuation(input,first.result.challenge,"123456")),e=>e.code==="challenge_not_found");}
  if(reason==="budget") {const invalid=await service.login(continuation(input,first.result.challenge,"000000"));
   assert.equal(invalid.result.failureType,"verification_required");assert.equal(Boolean(invalid.result.challenge?.id),true);
   await assert.rejects(service.login(continuation(input,invalid.result.challenge,"123456")),e=>e.code==="attempts_exhausted");}
  await waitForReleased(seen);assert.equal(seen.closes,1);assert.equal(runtime.state().holds,0);assert.equal(runtime.state().activeAdmissions,0);assert.equal(seen.passwords,1);assert.deepEqual(seen.codes,reason==="budget"?["000000"]:[]);
 });
}


test("real Chromium warm authenticated profile returns a candidate without another password",async t=>{
 const seen=await fixture(t);const original=chromium.launchPersistentContext;
 t.mock.method(chromium,"launchPersistentContext",async(...args)=>{const context=await original(...args);await context.addCookies(["auth_token","ct0"].map(name=>({name,value:"synthetic-existing",domain:".x.com",path:"/",secure:true})));return context;});
 const service=serviceFor(t,seen);const result=await service.login(req("warm"));
 await waitForReleased(seen);assert.equal(result.result.ok,true);assert.equal(seen.passwords,0);assert.equal(seen.launches,1);assert.equal(seen.navigations,1);assert.equal(seen.closes,1);assert.equal(result.result.attempts.credential,0);
});
