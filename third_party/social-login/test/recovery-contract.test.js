import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const base = fs.mkdtempSync(path.join(os.tmpdir(), "social-login-recovery-"));
process.env.CAP_PROFILE_BASE = base;
process.env.CAP_HEADLESS = "true";
process.env.RECAPTCHA_SOLVER_API_KEY = "test-only-not-a-provider-key";
const { chromium } = await import("playwright");
const { SocialLoginService } = await import("../src/service.js");
const { __test: runtime } = await import("../src/runtime/legacy.js");
const { LoginBudget, loginBudgetScope, currentLoginBudget } = await import("../src/runtime/login-budget.js");
const { ChallengeStore } = await import("../src/runtime/challenges.js");
const { FakeClock } = await import("./fake-clock.js");
const originalLaunch = chromium.launchPersistentContext.bind(chromium);

const request = (platform, key, limits = {}) => ({
  platform, profile_key: key, username: "", password: "",
  operation_owner: "owner".repeat(10), connection_id: "connection", generation: "1", revision: "1", recovery_claim: "claim",
  budget: { max_browser_attempts: 1, max_credential_attempts: 0, max_solver_attempts: 0, ...limits },
});
const jwt = (sub) => `header.${Buffer.from(JSON.stringify({ sub, exp: Math.floor(Date.now()/1000)+3600 })).toString("base64url")}.signature`;
const cookie = (name, value, domain) => ({ name, value, domain, path: "/", secure: true, expires: Math.floor(Date.now()/1000)+3600 });

test.after(() => fs.rmSync(base, { recursive: true, force: true }));

for (const platform of ["x", "reddit"]) {
 test(`${platform} harvest uses real persistent Chromium without credential submission`, async (t) => {
  const requests = [];
  let directory;
  let closed = false;
  t.mock.method(chromium, "launchPersistentContext", async (dir, options) => {
   directory = dir;
   const context = await originalLaunch(dir, options);
   context.once("close", () => { closed = true; });
   await context.route("**/*", async (route) => {
    requests.push({ method: route.request().method(), url: route.request().url() });
    await route.fulfill({ contentType: "text/html", body: "<html><body>Local authenticated fixture</body></html>" });
   });
   const cookies = platform === "x"
    ? [cookie("auth_token", "synthetic-auth", ".x.com"), cookie("ct0", "synthetic-csrf", ".x.com"), cookie("twid", "synthetic-id", ".x.com")]
    : [cookie("reddit_session", "synthetic-session", ".reddit.com"), cookie("token_v2", jwt("t2_fixture"), ".reddit.com"), cookie("csrf_token", "synthetic-csrf", ".reddit.com")];
   await context.addCookies([...cookies, cookie("unrelated", "must-not-leak", ".example.org")]);
   return context;
  });
  const service = new SocialLoginService();
  const input = request(platform, `healthy-${platform}`);
  const { status, result } = await service.login(input);
  assert.equal(status, 200);
  assert.equal(result.ok, true);
  assert.deepEqual(result.attempts, { browser: 1, credential: 0, solver: 0, complete: true });
  assert.ok(result.session.user_agent);
  assert.ok(result.cookies[platform === "x" ? "twid" : "csrf_token"]);
  assert.equal(result.cookies.unrelated, undefined);
  assert.ok(directory.startsWith(base + path.sep));
  assert.equal(closed, true);
  assert.ok(requests.length >= 1);
  assert.ok(requests.every((r) => r.method === "GET" && !r.url.includes("/login")));
 });
}

test("anonymous Reddit browser profile is a failed harvest, with no cookie erasure or password submit", async (t) => {
 t.mock.method(chromium, "launchPersistentContext", async (dir, options) => {
  const context = await originalLaunch(dir, options);
  await context.route("**/*", (route) => route.fulfill({ contentType: "text/html", body: "<html>Logged out</html>" }));
  await context.addCookies([cookie("token_v2", jwt("loid"), ".reddit.com"), cookie("reddit_session", "stale", ".reddit.com")]);
  return context;
 });
 const service = new SocialLoginService();
 const { result } = await service.login(request("reddit", "anonymous"));
 assert.equal(result.ok, false);
 assert.equal(result.failureType, "logged_out");
 assert.equal(result.cookies.reddit_session, "stale");
 assert.deepEqual(result.attempts, { browser: 1, credential: 0, solver: 0, complete: true });
});

test("failed launch and stale-lock nested retry share one browser allowance", async (t) => {
 let launches = 0;
 t.mock.method(chromium, "launchPersistentContext", async () => {
  launches++;
  throw new Error("ProcessSingleton synthetic stale lock");
 });
 const service = new SocialLoginService();
 await assert.rejects(service.login(request("x", "stale-profile")), (error) => {
  assert.equal(error.code, "attempts_exhausted");
  assert.deepEqual(error.details.attempts, { browser: 1, credential: 0, solver: 0, complete: true });
  return true;
 });
 assert.equal(launches, 1);
});

for (const reason of ["caller", "deadline"]) {
 test(`${reason} cancellation closes actual Chromium before the profile lock is released`, async (t) => {
  let navigationStarted;
  const started = new Promise((resolve) => { navigationStarted = resolve; });
  let context;
  let closed = false;
  t.mock.method(chromium, "launchPersistentContext", async (dir, options) => {
   context = await originalLaunch(dir, options);
   context.once("close", () => { closed = true; });
   await context.route("**/*", () => { navigationStarted(); }); // no provider network leaves Chromium
   return context;
  });
  const service = new SocialLoginService();
  const controller = new AbortController();
  const input = request("x", `cancel-${reason}`, { deadline_at: new Date(Date.now() + (reason === "deadline" ? 2500 : 10000)).toISOString() });
  const operation = service.login(input, controller.signal);
  const outcome = operation.catch((error) => error);
  await started;
  await assert.rejects(service.login(input), (error) => error.code === "profile_busy" && error.details.attempts.browser === 0);
  if (reason === "caller") controller.abort();
  const error = await outcome;
  assert.equal(error.code, reason === "caller" ? "request_cancelled" : "deadline_exceeded");
  assert.equal(closed, true);
  assert.equal(context.pages().length, 0);
  assert.deepEqual(error.details.attempts, { browser: 1, credential: 0, solver: 0, complete: true });
  await assert.rejects(service.login(request("x", `cancel-${reason}`, { max_browser_attempts: 0 })), (error) => error.code === "attempts_exhausted");
 });
}

test("Reddit nested solver/POST retries count actual attempts and stop before another password submission", async (t) => {
 let solverTasks = 0;
 let passwordPosts = 0;
 t.mock.method(globalThis, "fetch", async (url) => {
  if (url.endsWith("createTask")) { solverTasks++; return { ok: true, json: async () => ({taskId:"synthetic-task"}) }; }
  return { ok: true, json: async () => ({status:"ready",solution:{gRecaptchaResponse:"synthetic-token"}}) };
 });
 const context = {
  cookies: async () => [cookie("csrf_token", "synthetic", ".reddit.com")],
  request: { post: async () => { passwordPosts++; throw new Error("synthetic transient transport failure"); } },
 };
 const budget = new LoginBudget({ max_browser_attempts: 0, max_credential_attempts: 1, max_solver_attempts: 3 });
 try {
  await assert.rejects(loginBudgetScope.run(budget, () => runtime.loginRedditViaCapSolver(context, {}, {username:"synthetic",password:"synthetic"})), (error) => error.code === "attempts_exhausted");
  assert.deepEqual(budget.attempts, {browser:0,credential:1,solver:1,complete:true});
  assert.equal(passwordPosts,1);
  assert.equal(solverTasks,1);
 } finally { await budget.dispose(); }
});

test("aggregate cancellation aborts an in-flight solver fetch and never submits credentials", async (t) => {
 let started;
 const entered = new Promise((resolve) => { started=resolve; });
 let fetchAborted = false;
 t.mock.method(globalThis, "fetch", async (_url, {signal}) => {
  started();
  return new Promise((_,reject) => signal.addEventListener("abort",()=>{fetchAborted=true;reject(signal.reason);},{once:true}));
 });
 const budget = new LoginBudget({ max_browser_attempts:0,max_credential_attempts:1,max_solver_attempts:3 });
 const operation = loginBudgetScope.run(budget, () => runtime.loginRedditViaCapSolver({}, {}, {username:"synthetic",password:"synthetic"}));
 const outcome = operation.catch((error)=>error);
 await entered;
 budget.abort();
 const error=await outcome;
 assert.equal(error.code,"request_cancelled");
 assert.equal(fetchAborted,true);
 assert.deepEqual(budget.attempts,{browser:0,credential:0,solver:1,complete:true});
 await budget.dispose();
});

test("credential service dispatch uses the injected runtime and original proxy/profile binding", async () => {
 let calls=0;
 const service=new SocialLoginService({runtime:{
  runBrowserLogin:async(platform,input,proxy,profile,signal)=>{
   calls++;
   assert.equal(platform,"reddit");assert.equal(input.username,"synthetic");assert.equal(proxy,"http://user:password@proxy.invalid:8080/");assert.match(profile,/^[a-f0-9]{64}$/);assert.equal(signal.aborted,false);
   currentLoginBudget().use("credential");
   return {ok:false,failureType:"invalid_credentials"};
  },attachLoginMeta(){}
 }});
 const {result}=await service.login({...request("reddit","injected",{max_credential_attempts:1}),username:"synthetic",password:"synthetic",proxy_url:"http://user:password@proxy.invalid:8080",proxy_lease:"fixed-lease"});
 assert.equal(calls,1);assert.equal(result.attempts.credential,1);
});

test("challenge replacement and continuation cannot extend original deadline", () => {
 const clock=new FakeClock();
 const store=new ChallengeStore({clock,ttlMs:1000});
 const identity={platform:"x",profileKey:"profile",proxyLease:"lease",proxyURL:"url",ownerToken:"owner".repeat(10),connectionID:"connection",generation:"1",revision:"1",recoveryClaim:"claim"};
 const first=store.create(identity,{username:"synthetic",password:"synthetic"},{},clock.now()+500);
 clock.advance(200);
 store.claimContinuation(first.id,identity);
 const second=store.create(identity,{username:"synthetic",password:"synthetic"},{},clock.now()+1000);
 assert.equal(second.expires_at,first.expires_at);
 clock.advance(300);
 assert.throws(()=>store.status(identity.ownerToken,identity),(error)=>error.code==="challenge_not_found");
 store.close();
});

test("ambiguous password button failure cannot multiply submissions via fallback", async () => {
 let clicks=0;
 const button={count:async()=>1,isDisabled:async()=>false,click:async()=>{clicks++;throw new Error("ambiguous click timeout");}};
 const page={getByRole:()=>({first:()=>button}),keyboard:{press:async()=>{assert.fail("keyboard fallback exceeded budget");}}};
 const budget=new LoginBudget({max_browser_attempts:0,max_credential_attempts:1,max_solver_attempts:0});
 try {
  await assert.rejects(loginBudgetScope.run(budget,()=>runtime.xClick(page,page,[/^log in$/i],()=>currentLoginBudget().use("credential"))),(error)=>error.code==="attempts_exhausted");
  assert.equal(clicks,1);
  assert.equal(budget.attempts.credential,1);
 } finally {await budget.dispose();}
});
