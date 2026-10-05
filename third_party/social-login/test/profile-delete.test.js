import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createServer } from "../src/server.js";
import { ProfileLocks, ProfileStore, profileID } from "../src/runtime/profiles.js";

async function request(server, pathname, token = "test-token") {
  if (!server.listening) await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  return fetch(`http://127.0.0.1:${port}${pathname}`, {
    method: "DELETE",
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
}

test("authenticated path deletion is idempotent and audit-safe", async (t) => {
  const calls = [];
  const server = createServer({
    erase(input) {
      calls.push(input);
      return { erased: true };
    },
  }, "test-token");
  t.after(() => new Promise((resolve) => server.close(resolve)));

  for (let index = 0; index < 2; index++) {
    const response = await request(server, `/v1/profiles/reddit/opaque-key${index ? "?request_id=audit-only" : ""}`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      version: "v1",
      ok: true,
      data: { erased: true },
    });
  }
  assert.deepEqual(calls, [
    { platform: "reddit", profile_key: "opaque-key" },
    { platform: "reddit", profile_key: "opaque-key" },
  ]);
});

test("path deletion requires bearer authentication", async (t) => {
  const server = createServer({ erase() { assert.fail("erase must not run"); } }, "test-token");
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const response = await request(server, "/v1/profiles/reddit/opaque-key", "");
  assert.equal(response.status, 401);
  assert.equal((await response.json()).error.code, "unauthorized");
});

test("profile erasure cannot race an active profile lock", async (t) => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "social-login-delete-"));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const locks = new ProfileLocks();
  const store = new ProfileStore({ base, locks });
  await store.admit("reddit", "opaque-key");
  const directory = path.join(base, profileID("reddit", "opaque-key"));
  const release = locks.acquire("reddit", "opaque-key");

  await assert.rejects(
    store.erase("reddit", "opaque-key"),
    (error) => error.code === "profile_busy" && error.status === 409,
  );
  assert.equal(fs.existsSync(directory), true);
  release();
  assert.deepEqual(await store.erase("reddit", "opaque-key"), { erased: true });
  assert.equal(fs.existsSync(directory), false);
  assert.deepEqual(await store.erase("reddit", "opaque-key"), { erased: true });
});

test("profile keys remain confined beneath the profile root", async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "social-login-confine-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = new ProfileStore({ base: path.join(root, "profiles"), locks: new ProfileLocks() });
  const sentinel = path.join(root, "sentinel");
  fs.writeFileSync(sentinel, "keep");

  await assert.rejects(
    store.erase("reddit", "../sentinel"),
    (error) => error.code === "invalid_profile_key" && error.status === 400,
  );
  assert.equal(fs.readFileSync(sentinel, "utf8"), "keep");
});
