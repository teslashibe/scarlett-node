import assert from "node:assert/strict";
import test from "node:test";
import { SocialLoginService } from "../src/service.js";

const runtime = {
  calls: 0,
  async prewarmX() { this.calls++; return { persistent: true }; },
  async readiness() { return { ok: true, reasons: [] }; },
  attachLoginMeta() {},
  async drainRuntime() {},
};

const request = {
  platform: "x",
  profile_key: "profile",
  proxy_url: "http://user:pass@proxy.example:8080",
  proxy_lease: "12345678",
  proxy_generation: 2,
  connection_id: "connection",
  claim: "claim",
};

test("prewarm rejects credentials and is idempotent with exact identity", async () => {
  const service = new SocialLoginService({ runtime });
  await assert.rejects(() => service.prewarm({ ...request, password: "secret" }), (error) => error.code === "credentials_forbidden");
  const first = await service.prewarm(request);
  const second = await service.prewarm(request);
  assert.equal(runtime.calls, 1);
  assert.equal(first.profile_key, request.profile_key);
  assert.equal(first.proxy_generation, request.proxy_generation);
  assert.equal(first.proxy_lease, request.proxy_lease);
  assert.equal(second.reused, true);
});
