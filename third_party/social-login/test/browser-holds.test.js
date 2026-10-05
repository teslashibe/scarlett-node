import assert from "node:assert/strict";
import test from "node:test";
import { BrowserHoldRegistry } from "../src/runtime/browser-holds.js";
import { FakeClock } from "./fake-clock.js";

const identity = { platform: "linkedin", profileKey: "profile" };

test("parked hold alone protects profile and expiry closes exactly once", async () => {
  const clock = new FakeClock();
  const registry = new BrowserHoldRegistry({ clock });
  let closes = 0;
  await registry.park("owner", identity, { close: async () => { closes++; } }, 10);
  assert.equal(registry.hasProfile("linkedin", "profile"), true);
  await registry.release("owner", "expired");
  assert.equal(closes, 1);
  assert.equal(registry.size, 0);
});

test("erasure release closes hold before returning", async () => {
  const clock = new FakeClock();
  const registry = new BrowserHoldRegistry({ clock });
  const events = [];
  await registry.park("owner", identity, { close: async () => { events.push("closed"); } }, 10);
  await registry.releaseProfile("linkedin", "profile");
  events.push("delete");
  assert.deepEqual(events, ["closed", "delete"]);
  assert.equal(registry.size, 0);
});

test("shutdown and expiry race releases once and leaves zero state", async () => {
  const clock = new FakeClock();
  const registry = new BrowserHoldRegistry({ clock });
  let closes = 0;
  await registry.park("owner", identity, { close: async () => { closes++; } }, 10);
  const shutdown = registry.close();
  clock.advance(10);
  await shutdown;
  assert.equal(closes, 1);
  assert.equal(registry.size, 0);
  assert.equal(clock.pending, 0);
});

test("overlapping release paths share one close and settlement", async () => {
  const clock = new FakeClock();
  const registry = new BrowserHoldRegistry({ clock });
  let resolveClose;
  let closes = 0;
  await registry.park("owner", identity, {
    close: () => {
      closes++;
      return new Promise((resolve) => { resolveClose = resolve; });
    },
  }, 10);
  const first = registry.release("owner", "cancelled");
  const second = registry.release("owner", "shutdown");
  assert.equal(closes, 1);
  resolveClose();
  await Promise.all([first, second]);
  assert.equal(registry.size, 0);
});

test("taking a parked hold transfers close ownership", async () => {
  const clock = new FakeClock();
  const registry = new BrowserHoldRegistry({ clock });
  const session = { close: async () => {} };
  await registry.park("owner", identity, session, 10);
  assert.equal(registry.take("owner"), session);
  clock.advance(10);
  assert.equal(registry.size, 0);
});
