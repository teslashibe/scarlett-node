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
  journalNote,
  JOURNAL_FULL,
  updateNotice,
  statusPredates,
  xProofModes,
  X_SESSION_EXPIRED,
  webServingNote,
  webServingSaved,
  accountsEmptyText,
  servingNote,
  webServing,
  availableWebSlots,
  hiddenBrowser,
  type ServiceHealth,
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
  // A web node serves pages without any provider account.
  assert.equal(canStart({ ...base, accounts: [], web_enabled: true }), true);
  assert.equal(canStart({ ...base, accounts: [], web_enabled: true, paired: false }), false);
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
test("A full receipt journal is explained while the node runs", () => {
  const running = { ...base, supervised: true, observation: { state: "running", journal_full: true } };
  assert.equal(journalNote(running), JOURNAL_FULL);
  assert.match(JOURNAL_FULL, /^Receipt journal full · waiting for receipts to clear/);
  assert.equal(journalNote({ ...running, observation: { state: "draining", journal_full: true } }), JOURNAL_FULL);
  // Room in the journal, an older node without the field, or a stopped node: nothing to explain.
  assert.equal(journalNote({ ...running, observation: { state: "running", journal_full: false } }), "");
  assert.equal(journalNote({ ...running, observation: { state: "running" } }), "");
  assert.equal(journalNote({ ...running, observation: { state: "offline", journal_full: true } }), "");
  assert.equal(journalNote(base), "");
});
test("The update toast follows the coordinator's release notice", () => {
  const at = (observation: object) => ({ ...base, supervised: true, observation: { state: "running", release: "0.1.10", ...observation } });
  assert.equal(updateNotice(base), null);
  // No notice yet, or an older node without the fields: nothing to show.
  assert.equal(updateNotice(at({})), null);
  assert.equal(updateNotice(at({ latest_release: "0.1.10" })), null);
  const available = updateNotice(at({ latest_release: "0.1.11", update_available: true }));
  assert.equal(available?.level, "available");
  assert.equal(available?.latest, "0.1.11");
  assert.match(available!.text, /Scarlett Node 0\.1\.11 is available/);
  const required = updateNotice(at({ latest_release: "0.1.12", update_available: true, update_required: true }));
  assert.equal(required?.level, "required");
  assert.match(required!.text, /^Update required · this version no longer receives new jobs\. Install Scarlett Node 0\.1\.12/);
  // A stopped or offline node keeps the last notice it heard.
  assert.equal(updateNotice({ ...at({ latest_release: "0.1.12", update_required: true }), observation: { state: "offline", latest_release: "0.1.12", update_required: true } })?.level, "required");
  // Anything but a plain version is ignored rather than shown.
  assert.equal(updateNotice(at({ latest_release: "<b>0.1.12</b>", update_required: true })), null);
});
test("Serve web pages applies on the next start and says so while the node runs", () => {
  assert.equal(webServingNote({ ...base, web_enabled: true }), "");
  assert.equal(webServingNote({ ...base, supervised: true, web_enabled: true, web_restart_pending: false }), "");
  assert.match(webServingNote({ ...base, supervised: true, web_enabled: true, web_restart_pending: true }), /stop and start the node to begin serving web pages/);
  assert.match(webServingNote({ ...base, supervised: true, web_enabled: false, web_restart_pending: true }), /serves web pages until you stop and start it/);
  assert.equal(webServingSaved(true, false), "Web pages turned on. The node serves them when it starts");
  assert.equal(webServingSaved(false, false), "Web pages turned off");
  assert.equal(webServingSaved(false, true), "Web pages turned off. Stop and start the node to apply it");
  // With web on (the default) a paired node with no X account can start.
  assert.equal(canStart({ ...base, accounts: [], web_enabled: true }), true);
  assert.equal(canStart({ ...base, accounts: [], web_enabled: false }), false);
});
test("With web on, the no-account copy does not say an X account is needed to earn", () => {
  const web = { ...base, accounts: [], web_enabled: true };
  assert.equal(accountsEmptyText(web), "Web pages need no account. Connect an X account to serve X jobs too");
  assert.equal(servingNote(web), "Serve web pages, and X network jobs with the accounts connected to this device");
  // Web off, or a node that has not said: the X-only wording is unchanged.
  for (const s of [{ ...base, accounts: [], web_enabled: false }, { ...base, accounts: [] }]) {
    assert.equal(accountsEmptyText(s), "Connect an X account to start serving work");
    assert.equal(servingNote(s), "Serve X network jobs with the accounts connected to this device");
  }
});

// A paired web-only node: no X account, web on, running under this app.
const webNode = (web?: ServiceHealth, extra: Partial<NonNullable<Snapshot["observation"]>> = {}): Snapshot => ({
  ...base,
  accounts: [],
  supervised: true,
  web_enabled: true,
  observation: {
    state: "running", in_flight: 0, drain_requested: false,
    services: [
      { kind: "x_read", state: "not_added", capacity: 0, in_flight: 0 },
      ...(web ? [web] : []),
    ],
    ...extra,
  },
});
const readyWeb: ServiceHealth = {
  kind: "web", state: "ready", capacity: 4, in_flight: 1, egress: "direct",
  browser: { state: "ready", capacity: 2, in_flight: 0, version: "141.0.7390.54" },
};
test("The web tiles show what the running node serves, not only the saved setting", () => {
  assert.deepEqual(webServing(webNode(readyWeb)), { value: "On", note: "Serving on this device" });
  assert.equal(availableWebSlots(webNode(readyWeb)), 3);
  assert.deepEqual(hiddenBrowser(webNode(readyWeb)), { value: "Ready", note: "For pages behind bot checks" });
  // A configured service has not served a page yet but takes work.
  assert.equal(availableWebSlots(webNode({ ...readyWeb, state: "configured" })), 3);
  assert.equal(webServing(webNode({ ...readyWeb, state: "configured" })).value, "On");
  // Every slot busy is still on, with none free.
  assert.equal(availableWebSlots(webNode({ ...readyWeb, in_flight: 4 })), 0);
  assert.equal(availableWebSlots(webNode({ ...readyWeb, in_flight: 9 })), 0);
  // A node running outside the app reports the same way, and the app's own
  // setting never claims a restart would change it.
  assert.deepEqual(webServing({ ...webNode(readyWeb), supervised: false, web_enabled: false }), { value: "On", note: "Serving on this device" });
});
test("Web off reads as off, and a pending change says how to apply it", () => {
  // A node without web reports no egress or browser for it (services.go health).
  const off: ServiceHealth = { kind: "web", state: "not_added", capacity: 0, in_flight: 0 };
  const savedOff = { ...webNode(off), web_enabled: false };
  assert.deepEqual(webServing(savedOff), { value: "Off", note: "Turn on in Device settings" });
  assert.equal(availableWebSlots(savedOff), 0);
  assert.deepEqual(hiddenBrowser(savedOff), { value: "Off", note: "Web pages are off" });
  // Turned on while the node runs without web.
  assert.deepEqual(webServing({ ...webNode(off), web_restart_pending: true }), { value: "Off", note: "Stop and start the node to turn on" });
  // Turned off while the node still serves web.
  assert.deepEqual(webServing({ ...webNode(readyWeb), web_enabled: false, web_restart_pending: true }), { value: "On", note: "Stop and start the node to turn off" });
});
test("A stopped node shows the saved web setting and frees no slots", () => {
  for (const state of ["stopped", "offline"]) {
    const on = webNode(readyWeb, { state });
    assert.deepEqual(webServing(on), { value: "On", note: "Serves pages when the node runs" });
    assert.equal(availableWebSlots(on), 0);
    // The running node checks memory, disk and the download first, so a
    // stopped one promises nothing about the browser.
    assert.deepEqual(hiddenBrowser({ ...on, web_browser: true }), { value: "Off", note: "Checked when the node runs" });
    assert.deepEqual(hiddenBrowser(on), { value: "Off", note: "Checked when the node runs" });
    // Windows by default, or SCARLETT_WEB_BROWSER=off: the same words the
    // running node's "disabled" reason gets, so Start changes nothing.
    const relayOnly = { ...on, web_browser: false };
    assert.deepEqual(hiddenBrowser(relayOnly), { value: "Off", note: "Relay pages only on this device" });
    assert.deepEqual(hiddenBrowser(relayOnly), hiddenBrowser(webNode({ ...readyWeb, browser: { state: "unavailable", reason: "disabled" } })));
    const off = { ...on, web_enabled: false };
    assert.deepEqual(webServing(off), { value: "Off", note: "Turn on in Device settings" });
    assert.deepEqual(hiddenBrowser(off), { value: "Off", note: "Web pages are off" });
    assert.deepEqual(hiddenBrowser({ ...off, web_browser: false }), { value: "Off", note: "Web pages are off" });
  }
  // Never started: no status at all.
  const fresh: Snapshot = { ...base, accounts: [], web_enabled: true };
  assert.equal(webServing(fresh).value, "On");
  assert.equal(availableWebSlots(fresh), undefined);
  assert.deepEqual(webServing({ ...fresh, web_enabled: undefined }), { value: "Unknown", note: "Waiting for node status" });
});
test("A paused node or web service says why it takes no new pages", () => {
  const draining = webNode(readyWeb, { drain_requested: true });
  assert.deepEqual(webServing(draining), { value: "Paused", note: "Finishing accepted work" });
  assert.equal(availableWebSlots(draining), 0);
  assert.deepEqual(webServing(webNode(readyWeb, { state: "draining" })), { value: "Paused", note: "Finishing accepted work" });
  for (const [code, note] of [
    ["relay_misuse", "Relay paused on this node"],
    ["web_proxy_failed", "Proxy failed · retrying in a minute"],
    ["prover_error", "Proof helper missing"],
    ["something_new", "Not taking new pages"],
  ]) {
    const paused = webNode({ kind: "web", state: "unreachable", capacity: 0, in_flight: 0, last_error_code: code, browser: { state: "unavailable", reason: "web_unavailable" } });
    assert.deepEqual(webServing(paused), { value: "Paused", note });
    assert.equal(availableWebSlots(paused), 0);
    assert.deepEqual(hiddenBrowser(paused), { value: "Paused", note: "Waiting for web pages" });
  }
});
test("A full receipt journal pauses web without turning a node with web off on", () => {
  // The node rewrites every service, web off included, to exhausted while its
  // receipt journal is full; only an enabled web entry carries egress and browser.
  const full = { journal_full: true };
  const on = webNode({ ...readyWeb, state: "exhausted" }, full);
  assert.deepEqual(webServing(on), { value: "Paused", note: "Receipt journal full" });
  assert.equal(availableWebSlots(on), 0);
  assert.deepEqual(hiddenBrowser(on), { value: "Ready", note: "For pages behind bot checks" });
  const off = { ...webNode({ kind: "web", state: "exhausted", capacity: 0, in_flight: 0 }, full), web_enabled: false };
  assert.deepEqual(webServing(off), { value: "Off", note: "Turn on in Device settings" });
  assert.equal(availableWebSlots(off), 0);
  assert.deepEqual(hiddenBrowser(off), { value: "Off", note: "Web pages are off" });
  // Turned on while a node without web runs with a full journal.
  assert.deepEqual(webServing({ ...off, web_enabled: true, web_restart_pending: true }), { value: "Off", note: "Stop and start the node to turn on" });
  // Draining says so first; the journal clears as accepted work finishes.
  assert.deepEqual(webServing(webNode({ ...readyWeb, state: "exhausted" }, { ...full, drain_requested: true })), { value: "Paused", note: "Finishing accepted work" });
  // With room again the web entry's own state decides.
  assert.deepEqual(webServing(webNode(readyWeb, { journal_full: false })), { value: "On", note: "Serving on this device" });
});
test("Hidden browser states use plain words for every reason the node reports", () => {
  const reasons = ["disabled", "memory_low", "disk_low", "runtime_missing", "runtime_invalid", "browser_downloading",
    "browser_download_failed", "browser_invalid", "deps_missing", "sandbox_unavailable", "helper_failed"];
  for (const reason of reasons) {
    const tile = hiddenBrowser(webNode({ ...readyWeb, browser: { state: "unavailable", reason } }));
    assert.ok(["Off", "Downloading", "Unavailable"].includes(tile.value), reason);
    assert.ok(tile.note && !tile.note.endsWith(".") && !tile.note.includes("_"), reason);
  }
  assert.deepEqual(hiddenBrowser(webNode({ ...readyWeb, browser: { state: "unavailable", reason: "browser_downloading" } })), { value: "Downloading", note: "Getting the browser ready" });
  assert.deepEqual(hiddenBrowser(webNode({ ...readyWeb, browser: { state: "unavailable", reason: "disabled" } })), { value: "Off", note: "Relay pages only on this device" });
  // Unknown reasons and missing browser data never echo raw codes.
  assert.deepEqual(hiddenBrowser(webNode({ ...readyWeb, browser: { state: "unavailable", reason: "launch_failed" } })), { value: "Unavailable", note: "Browser not ready" });
  assert.equal(hiddenBrowser(webNode({ ...readyWeb, browser: undefined })).value, "Unknown");
});
test("Missing web status stays unknown instead of guessing", () => {
  const noWeb = webNode();
  assert.equal(webServing(noWeb).value, "Unknown");
  assert.equal(availableWebSlots(noWeb), undefined);
  assert.equal(hiddenBrowser(noWeb).value, "Unknown");
  for (const field of ["capacity", "in_flight", "state"] as const) {
    const web = { ...readyWeb };
    delete web[field];
    assert.equal(availableWebSlots(webNode(web)), undefined, field);
  }
});
