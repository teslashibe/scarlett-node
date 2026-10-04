import test from "node:test";
import assert from "node:assert/strict";
import {
  canConnectCodex,
  canStart,
  codexAccountLimitReached,
  codexNote,
  MAX_CODEX_ACCOUNTS,
  statusText,
  errorMessage,
  validId,
  accountHealth,
  drainingAccounts,
  type Snapshot,
} from "../src/model.ts";
const base: Snapshot = {
  runtime_available: true,
  accounts_available: true,
  helper_available: true,
  codex_login_available: true,
  paired: true,
  supervised: false,
  login_pending: false,
  accounts: [{ id: "work", service: "codex", concurrency: 1 }],
};
test("Start requires real runtime, helper, pairing and account capabilities", () => {
  assert.equal(canStart(base), true);
  for (const key of [
    "runtime_available",
    "accounts_available",
    "helper_available",
    "paired",
  ] as const)
    assert.equal(canStart({ ...base, [key]: false }), false);
  assert.equal(canStart({ ...base, accounts: [] }), false);
  assert.equal(canStart({ ...base, supervised: true }), false);
});
test("Local configuration is not displayed as verified access or points", () => {
  assert.equal(
    accountHealth(base, base.accounts[0]),
    "Configured · access not verified",
  );
  assert.equal(
    statusText({ ...base, supervised: true }),
    "Waiting for node status",
  );
  assert.equal(
    statusText({
      ...base,
      supervised: true,
      observation: { state: "offline" },
    }),
    "Waiting for node status",
  );
  assert.equal(
    statusText({
      ...base,
      supervised: true,
      observation: { state: "running", drain_requested: true },
    }),
    "Paused · finishing accepted work",
  );
});
test("Unexpected errors do not echo raw provider output", () => {
  assert.equal(
    errorMessage("SECRET_PROVIDER_COOKIE"),
    "Scarlett could not complete that action",
  );
  assert.match(errorMessage("command_timeout"), /Check its status/);
});
test("Account IDs cannot carry a path, shell command or reserved singleton identity", () => {
  for (const id of ["../x", "x/y", "Upper", "x;command", "legacy", ""])
    assert.equal(validId(id), false);
  assert.equal(validId("work-2"), true);
});

test("An existing unsupervised node is not launched again", () => {
  const s = { ...base, observation: { state: "running" } };
  assert.equal(canStart(s), false);
  assert.equal(statusText(s), "Running outside this app");
});
test("Local API mode prevents starting a second executor for the same account pool", () => {
  assert.equal(canStart({ ...base, local_api: { available: true, running: true, ready: true, claude_enabled: false } }), false);
  assert.equal(canStart({ ...base, local_api: { available: true, running: false, ready: false, claude_enabled: false } }), true);
});
test("Removed accounts remain visible while draining and omitted snapshots clear them", () => {
  const s: Snapshot = {
    ...base,
    observation: {
      accounts: [
        { id: "work", service: "codex", state: "ready", in_flight: 1 },
        { id: "removed", service: "x_read", state: "draining", in_flight: 1 },
        { id: "old", service: "x_read", state: "ready", in_flight: 0 },
      ],
    },
  };
  assert.deepEqual(drainingAccounts(s).map((a) => a.id), ["removed"]);
  assert.deepEqual(drainingAccounts({ ...s, observation: { state: "stopped" } }), []);
});
test("Connect Codex is disabled at the node's eight-account limit with a clear reason", () => {
  const codex = (n: number) =>
    Array.from({ length: n }, (_, i) => ({
      id: `codex-${i + 1}`,
      service: "codex" as const,
      concurrency: 1,
    }));
  const x = { id: "personal-x", service: "x_read" as const, concurrency: 1 };
  assert.equal(MAX_CODEX_ACCOUNTS, 8);
  const below: Snapshot = { ...base, accounts: [...codex(7), x] };
  assert.equal(codexAccountLimitReached(below), false);
  assert.equal(canConnectCodex(below), true);
  assert.equal(codexNote(below), "Provider access is checked when it serves work");
  const full: Snapshot = { ...base, accounts: [...codex(8), x] };
  assert.equal(codexAccountLimitReached(full), true);
  assert.equal(canConnectCodex(full), false);
  assert.match(codexNote(full), /Remove a Codex account first. Up to 8 Codex accounts/);
  assert.equal(codexNote({ ...full, login_error: "login_failed" }), codexNote(full));
  // The native error has its own message, distinct from missing support.
  assert.equal(errorMessage("account_limit"), codexNote(full));
  assert.notEqual(errorMessage("account_limit"), errorMessage("accounts_unavailable"));
  for (const key of ["accounts_available", "codex_login_available"] as const)
    assert.equal(canConnectCodex({ ...below, [key]: false }), false);
  assert.equal(canConnectCodex({ ...below, login_pending: true }), false);
  assert.equal(codexNote({ ...full, login_pending: true }), "Finish login in your browser");
});
