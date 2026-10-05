import test from "node:test";
import assert from "node:assert/strict";
import { scheduleXLoginExpiry } from "../src/x-login-expiry.ts";

test("pending login expires at its browser deadline and expiry is cancelled after completion", (t) => {
 t.mock.timers.enable({apis:["setTimeout","Date"],now:new Date("2026-10-05T16:00:00Z")});
 let expired=0;
 const cancel=scheduleXLoginExpiry("2026-10-05T16:00:30Z",()=>expired++);
 t.mock.timers.tick(29_999);assert.equal(expired,0);
 t.mock.timers.tick(1);assert.equal(expired,1);
 cancel();t.mock.timers.tick(240_000);assert.equal(expired,1);
 const completed=scheduleXLoginExpiry("2026-10-05T16:05:00Z",()=>expired++);
 completed();t.mock.timers.tick(240_000);assert.equal(expired,1);
});

test("queued expiry cannot cancel a completed or replacement login", (t) => {
 const queued: (()=>void)[]=[];
 t.mock.method(globalThis,"setTimeout",(callback: ()=>void)=>{queued.push(callback);return 1;});
 // Model a callback already queued when clearTimeout can no longer remove it.
 t.mock.method(globalThis,"clearTimeout",()=>{});
 let expired=0;
 const completed=scheduleXLoginExpiry("2026-10-05T16:00:30Z",()=>expired++);
 completed();queued[0]();assert.equal(expired,0);
 let version=1;
 scheduleXLoginExpiry("2026-10-05T16:00:30Z",()=>expired++,()=>version===1);
 version=2;queued[1]();assert.equal(expired,0);
});
