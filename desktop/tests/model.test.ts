import test from "node:test";
import assert from "node:assert/strict";
import {
  canConnectCodex,
  canStart,
  claudeStatusText,
  codexAccountLimitReached,
  codexNote,
  MAX_CODEX_ACCOUNTS,
  statusText,
  errorMessage,
  validId,
  accountHealth,
  accountTitle,
  drainingAccounts,
  needsXReimport,
  relayState,
  statusPredates,
  xProofModes,
  X_SESSION_EXPIRED,
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

const xAccount = { id: "personal-x", service: "x_read" as const, concurrency: 2 };
const withX = (
  state: string | undefined,
  observation: Snapshot["observation"] = {},
): Snapshot => ({
  ...base,
  accounts: [...base.accounts, xAccount],
  observation: {
    state: "running",
    ...observation,
    accounts: state
      ? [
          { id: "work", service: "codex", state },
          { id: xAccount.id, service: "x_read", state },
        ]
      : [],
  },
});
test("A dead X session asks for a re-import of that account only", () => {
  const dead = withX("auth_required");
  assert.equal(accountHealth(dead, xAccount), X_SESSION_EXPIRED);
  assert.equal(X_SESSION_EXPIRED, "X session expired or revoked. Re-import the account");
  assert.equal(needsXReimport(dead, xAccount), true);
  // Codex keeps its own wording and is never offered an X re-import.
  assert.equal(accountHealth(dead, base.accounts[0]), "auth required");
  assert.equal(needsXReimport(dead, base.accounts[0]), false);
  for (const state of ["configured", "ready", "exhausted", undefined])
    assert.equal(needsXReimport(withX(state), xAccount), false);
});
test("An X account that is checking its login reads as warming up, not an error", () => {
  assert.equal(accountHealth(withX("configured"), xAccount), "Warming up · checking login");
  assert.equal(accountHealth(withX("ready"), xAccount), "ready");
  assert.equal(accountHealth(withX("configured"), base.accounts[0]), "configured");
  // Without any node status, local configuration is still not verified access.
  assert.equal(accountHealth(withX(undefined), xAccount), "Configured · access not verified");
  // A stopped node, or a status too old to trust, is not checking a login.
  for (const state of ["offline", "stopped"])
    assert.equal(accountHealth(withX("configured", { state }), xAccount), "Configured · access not verified");
  assert.equal(accountHealth(withX("configured", { state: "draining" }), xAccount), "Warming up · checking login");
  // A dead session stays visible while the node is stopped: re-import does not need it running.
  assert.equal(accountHealth(withX("auth_required", { state: "offline" }), xAccount), X_SESSION_EXPIRED);
  assert.equal(needsXReimport(withX("auth_required", { state: "offline" }), xAccount), true);
});
test("Account states written before a re-import are treated as stale", () => {
  const at = Date.parse("2026-10-03T12:00:00Z");
  assert.equal(statusPredates(withX("auth_required", { updated_at: "2026-10-03T11:59:59Z" }), at), true);
  assert.equal(statusPredates(withX("configured", { updated_at: "2026-10-03T12:00:03Z" }), at), false);
  assert.equal(statusPredates({ ...base, observation: null }, at), true);
});
test("A relay halt stays visible until the node itself reports it cleared", () => {
  // Saved halt on disk: nobody has resumed it, whatever the status says.
  assert.equal(relayState({ ...base, relay_halt_marker: true }), "halted");
  assert.equal(
    relayState({ ...base, relay_halt_marker: true, observation: { relay_halted: true } }),
    "halted",
  );
  // relay-resume removed the marker; the running node has not picked it up.
  assert.equal(
    relayState({ ...base, relay_halt_marker: false, observation: { relay_halted: true } }),
    "resume_saved",
  );
  // Only the node's own status clears the banner.
  assert.equal(relayState({ ...base, observation: { relay_halted: false } }), "");
  assert.equal(relayState(base), "");
});
test("X proof modes come from what the running node advertises", () => {
  const advertised = (proof_modes?: string[], extra: Partial<Snapshot> = {}, state = "running") => ({
    ...withX("ready", { state, services: [{ kind: "codex", state: "ready" }, { kind: "x_read", state: "ready", proof_modes }] }),
    ...extra,
  });
  assert.equal(xProofModes(advertised(["mpc", "relay"])), "MPC + relay");
  assert.equal(xProofModes(advertised(["mpc"])), "MPC only");
  assert.equal(xProofModes(advertised(undefined)), "MPC only");
  assert.equal(xProofModes(advertised(["mpc"], { relay_halt_marker: true })), "MPC only · relay paused");
  assert.equal(xProofModes(advertised(["mpc", "relay"], {}, "draining")), "MPC + relay");
  // A stopped node offers nothing, and a node without X accounts has no X service to show.
  assert.equal(xProofModes(advertised(["mpc", "relay"], {}, "offline")), "");
  assert.equal(xProofModes({ ...advertised(["mpc", "relay"]), accounts: base.accounts }), "");
});
test("Claude status is checked separately and is never mistaken for a missing runtime", () => {
  assert.equal(claudeStatusText(undefined), "Checking the bundled Claude runtime");
  const idle = { available: true, connected: false, pending: false };
  assert.equal(claudeStatusText(idle), "Claude subscription not connected");
  assert.equal(claudeStatusText({ ...idle, available: false }), "Claude login is unavailable in this build");
  assert.equal(claudeStatusText({ ...idle, pending: true }), "Finish Claude login in your browser");
  assert.equal(claudeStatusText({ ...idle, connected: true }), "Claude subscription connected on this device");
  assert.equal(claudeStatusText({ ...idle, error: "claude_login_failed" }), errorMessage("claude_login_failed"));
});
test("X rows distinguish verified handles, unverified identity and duplicate quota", () => {
  const named = { ...xAccount, username: "known_user" };
  assert.equal(accountTitle(base, named), "X · @known_user · personal-x");
  assert.equal(accountTitle(base, xAccount), "X · personal-x");
  assert.equal(accountTitle(base, base.accounts[0]), "Codex · work");
  const observed = withX("ready");
  observed.observation!.accounts![1].username = "verified_user";
  assert.equal(accountTitle(observed, xAccount), "X · @verified_user · personal-x");
  assert.match(accountHealth(withX("identity_unverified"), xAccount), /identity not verified/);
  assert.match(accountHealth(withX("duplicate_account"), xAccount), /shares quota/);
  assert.match(errorMessage("duplicate_account"), /already connected under another local name/);
});
