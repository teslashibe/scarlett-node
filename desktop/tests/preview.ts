/// <reference types="vite/client" />
import { mockIPC } from "@tauri-apps/api/mocks";
import type { InvokeArgs } from "@tauri-apps/api/core";
import type { Account, ClaudeStatus, Preferences, Snapshot, XLoginStatus } from "../src/model.ts";
import type { Diagnostics } from "../src/diagnostics.ts";
import type { UpdateStatus } from "../src/update.ts";

// This page is served by Vite for visual checks and is not a production entry.
// Every native command and event stays inside this synthetic fixture.
if (!import.meta.env.DEV || !["127.0.0.1", "localhost", "[::1]"].includes(location.hostname)) {
  throw new Error("The synthetic Node preview requires a local Vite development server");
}

const scenarios = ["ready", "unpaired", "relay-halted", "auth-required", "pending-login", "running-local-api",
  "available", "required", "downloading", "draining", "updated", "rolled-back"] as const;
type Scenario = typeof scenarios[number];
const requested = new URLSearchParams(location.search).get("scenario");
const scenario: Scenario = scenarios.includes(requested as Scenario) ? requested as Scenario : "ready";
const at = (secondsAgo = 0) => new Date(Date.now() - secondsAgo * 1000).toISOString();
let preferences: Preferences = { schema: 1, local_api_port: 8088, background: true, x_concurrency: 2, updates: "notify", resume_serving: true };
let autostart = false;
let claude: ClaudeStatus = { available: true, connected: false, pending: false };
let challenge: XLoginStatus | undefined;
const snapshot: Snapshot = {
  runtime_available: true,
  accounts_available: true,
  helper_available: true,
  codex_login_available: true,
  paired: true,
  supervised: true,
  login_pending: false,
  relay_halt_marker: false,
  accounts: [
    { id: "research-codex", service: "codex", concurrency: 2 },
    { id: "research-x", service: "x_read", concurrency: 1, username: "researchdesk" },
    { id: "markets-x", service: "x_read", concurrency: 1, username: "marketnotes" },
    { id: "signals-x", service: "x_read", concurrency: 1, username: "signalreader" },
  ],
  local_api: { available: true, running: false, ready: false, claude_enabled: false },
  observation: {
    state: "running", updated_at: at(), last_heartbeat_at: at(), in_flight: 1,
    unresolved_attempts: 0, drain_requested: false, relay_halted: false,
    accounts: [
      { id: "research-codex", service: "codex", state: "ready", in_flight: 0 },
      { id: "research-x", service: "x_read", state: "ready", in_flight: 1, username: "researchdesk" },
      { id: "markets-x", service: "x_read", state: "ready", in_flight: 0, username: "marketnotes" },
      { id: "signals-x", service: "x_read", state: "ready", in_flight: 0, username: "signalreader" },
    ],
    services: [
      { kind: "codex", state: "ready", capacity: 2, in_flight: 0 },
      { kind: "x_read", state: "ready", capacity: 2, in_flight: 1, proof_modes: ["mpc", "relay"] },
    ],
  },
};
const observation = snapshot.observation!;
const xService = observation.services!.find(service => service.kind === "x_read")!;
if (scenario === "unpaired") {
  snapshot.paired = false;
  snapshot.supervised = false;
  observation.state = "offline";
  observation.in_flight = 0;
  xService.in_flight = 0;
}
if (scenario === "relay-halted") {
  snapshot.relay_halt_marker = true;
  observation.relay_halted = true;
  observation.unresolved_attempts = 1;
  xService.proof_modes = ["mpc"];
}
if (scenario === "auth-required") {
  observation.accounts![2].state = "auth_required";
  observation.accounts![2].last_error_code = "auth_required";
}
if (scenario === "running-local-api") {
  snapshot.supervised = false;
  observation.state = "offline";
  observation.in_flight = 0;
  xService.in_flight = 0;
  snapshot.local_api = { available: true, running: true, ready: true, base_url: "http://127.0.0.1:8088/v1", claude_enabled: true };
  claude.connected = true;
}

const previewNotes = { title: "Faster X proofs", date: "2026-10-12", highlights: [
  "Relay proofs finish about a second sooner on busy nodes",
  "Paused nodes show how many accepted jobs are still finishing",
  "The changelog link opens the release's own entry",
] };
const update: UpdateStatus = { version: "0.1.13", mode: "notify", phase: "idle", required: false, can_install: true, snoozed: false, stale: false, checked_at: Date.now() - 60_000 };
if (scenario === "available") Object.assign(update, { phase: "available", latest: "0.1.14", notes: previewNotes });
if (scenario === "required") {
  Object.assign(update, { phase: "available", latest: "0.1.14", notes: previewNotes, required: true });
  Object.assign(observation, { latest_release: "0.1.14", update_available: true, update_required: true });
}
if (scenario === "downloading") Object.assign(update, { phase: "downloading", latest: "0.1.14", notes: previewNotes, progress: 45 });
if (scenario === "draining") {
  Object.assign(update, { phase: "draining", latest: "0.1.14", notes: previewNotes, in_flight: 2 });
  observation.drain_requested = true;
  observation.in_flight = 2;
}
if (scenario === "updated") update.updated = { version: "0.1.13", notes: { title: "Automatic updates", date: "2026-10-09", highlights: [
  "Turn on Install updates automatically and Scarlett installs new versions when accepted jobs finish",
  "The node starts again when Scarlett opens if it was running when it closed",
  "Updates downloaded by the app no longer need approving again on Mac or Windows",
] }, offer_automatic: true };
if (scenario === "rolled-back") update.failure = { version: "0.1.14", reason: "node_exited", rolled_back: true };

const diagnostics: Diagnostics = {
  available: true,
  snapshot: {
    version: 1, updated_at: at(),
    summaries: [
      { operation: "search", pages: 1, proof_mode: "relay", samples: 18, p50_ms: 2340, p95_ms: 4120, newest_at: at(25) },
      { operation: "profile", pages: 1, proof_mode: "mpc", samples: 7, p50_ms: 5280, p95_ms: 6910, newest_at: at(75) },
      { operation: "codex", pages: 1, proof_mode: "none", samples: 5, p50_ms: 8340, p95_ms: 12800, newest_at: at(140) },
    ],
    attempts: [
      { id: "preview-codex", operation: "codex", pages: 1, proof_mode: "none", started_at: at(140), outcome: "success", duration_ms: 8340, unclassified_ms: 0, missing_phases: [], spans: [
        { phase: "account_acquire", source: "node", exchange: 0, start_ms: 0, duration_ms: 4, outcome: "success" },
        { phase: "worker", source: "node", exchange: 0, start_ms: 4, duration_ms: 8310, outcome: "success" },
        { phase: "report_http", source: "node", exchange: 0, start_ms: 8314, duration_ms: 26, outcome: "success" },
      ] },
      { id: "preview-profile", operation: "profile", pages: 1, proof_mode: "mpc", started_at: at(75), outcome: "success", duration_ms: 5280, unclassified_ms: 0, missing_phases: [], spans: [
        { phase: "account_acquire", source: "node", exchange: 0, start_ms: 0, duration_ms: 5, outcome: "success" },
        { phase: "helper_wall", source: "node", exchange: 1, start_ms: 5, duration_ms: 5250, outcome: "success" },
        { phase: "response_first_byte", source: "helper", exchange: 1, start_ms: 4300, duration_ms: 0, outcome: "success" },
        { phase: "proof_finalize", source: "helper", exchange: 1, start_ms: 4600, duration_ms: 540, outcome: "success" },
        { phase: "report_http", source: "node", exchange: 0, start_ms: 5255, duration_ms: 25, outcome: "success" },
      ] },
      { id: "preview-search", operation: "search", pages: 1, proof_mode: "relay", started_at: at(25), outcome: "success", duration_ms: 2340, unclassified_ms: 0, missing_phases: [], spans: [
        { phase: "account_acquire", source: "node", exchange: 0, start_ms: 0, duration_ms: 5, outcome: "success" },
        { phase: "pacing_wait", source: "node", exchange: 1, start_ms: 5, duration_ms: 750, outcome: "success" },
        { phase: "helper_wall", source: "node", exchange: 1, start_ms: 755, duration_ms: 1560, outcome: "success" },
        { phase: "relay_authorization", source: "helper", exchange: 1, start_ms: 0, duration_ms: 420, outcome: "success" },
        { phase: "response_first_byte", source: "helper", exchange: 1, start_ms: 780, duration_ms: 0, outcome: "success" },
        { phase: "response_complete", source: "helper", exchange: 1, start_ms: 940, duration_ms: 0, outcome: "success" },
        { phase: "report_http", source: "node", exchange: 0, start_ms: 2315, duration_ms: 25, outcome: "success" },
      ] },
    ],
  },
};

const args = (payload?: InvokeArgs): Record<string, unknown> => payload && !Array.isArray(payload) && !(payload instanceof ArrayBuffer) ? payload as Record<string, unknown> : {};
const text = (payload: Record<string, unknown>, name: string) => String(payload[name] ?? "");
function saveX(id: string, replace: boolean) {
  if (!/^[a-z0-9_-]{1,32}$/.test(id)) throw "invalid_input";
  const found = snapshot.accounts.find(account => account.id === id && account.service === "x_read");
  if (replace && !found) throw "invalid_input";
  if (!replace && found) throw "duplicate_account";
  if (!found) snapshot.accounts.push({ id, service: "x_read", concurrency: 1, username: "previewreader" });
  const health = observation.accounts!.find(account => account.id === id && account.service === "x_read");
  if (health) { health.state = "ready"; health.last_error_code = undefined; }
  else observation.accounts!.push({ id, service: "x_read", state: "ready", in_flight: 0, username: "previewreader" });
}

mockIPC((command, payload) => {
  const data = args(payload);
  switch (command) {
    case "desktop_preferences": return structuredClone(preferences);
    case "save_desktop_preferences": preferences = structuredClone(data.data as Preferences); return null;
    case "desktop_autostart": return autostart;
    case "set_desktop_autostart": autostart = !!data.enabled; return null;
    case "desktop_status":
      observation.updated_at = new Date(Date.now() + 1).toISOString();
      return structuredClone(snapshot);
    case "desktop_diagnostics": return structuredClone(diagnostics);
    case "claude_status": return structuredClone(claude);
    case "open_network": case "quit_desktop": return null;
    case "update_status": update.mode = preferences.updates; return structuredClone(update);
    case "update_check": update.checked_at = Date.now(); return null;
    case "update_install": Object.assign(update, { phase: "downloading", progress: 0 }); return null;
    case "update_cancel": Object.assign(update, { phase: "available", progress: null, in_flight: null }); return null;
    case "update_later": update.snoozed = !update.required; return null;
    case "update_ack": return null;
    case "update_dismiss": if (text(data, "notice") === "updated") update.updated = null; else update.failure = null; return null;
    case "set_update_mode": preferences.updates = text(data, "mode") === "automatic" ? "automatic" : "notify"; return null;
    case "pair_node": if (!text(data, "code")) throw "invalid_input"; snapshot.paired = true; return null;
    case "control_node": {
      const action = text(data, "action");
      if (action === "start" && !snapshot.paired) throw "not_paired";
      if (action === "start" && snapshot.local_api?.running) throw "mode_conflict";
      if (action === "start" || action === "stop") snapshot.supervised = action === "start";
      observation.state = snapshot.supervised ? "running" : "offline";
      observation.drain_requested = action === "pause";
      if (action === "stop") {
        observation.in_flight = 0;
        for (const account of observation.accounts!) account.in_flight = 0;
        for (const service of observation.services!) service.in_flight = 0;
      }
      return null;
    }
    case "resume_relay": snapshot.relay_halt_marker = false; observation.relay_halted = false; xService.proof_modes = ["mpc", "relay"]; return null;
    case "connect_codex": snapshot.login_pending = true; return null;
    case "cancel_login": snapshot.login_pending = false; return null;
    case "connect_x": case "reconnect_x": saveX(text(data, "id"), command === "reconnect_x"); return null;
    case "browser_profiles": return [
      { id: "preview-chrome", browser: "chrome", label: "Chrome · Research profile" },
      { id: "preview-firefox", browser: "firefox", label: "Firefox · Personal profile" },
    ];
    case "import_x_profile": case "reimport_x_profile":
      if (!data.consent || !text(data, "profile")) throw "invalid_input";
      saveX(text(data, "id"), command === "reimport_x_profile"); return null;
    case "start_x_login":
      challenge = { status: "pending", id: text(data, "id"), challenge_id: "preview-challenge", method: "email", destination: "preview@example.invalid", expires_at: new Date(Date.now() + 900_000).toISOString() };
      return structuredClone(challenge);
    case "continue_x_login":
      if (!challenge || text(data, "challengeId") !== challenge.challenge_id || !text(data, "code")) throw "invalid_input";
      saveX(challenge.id!, snapshot.accounts.some(account => account.id === challenge!.id && account.service === "x_read"));
      challenge = undefined; return { status: "updated" } satisfies XLoginStatus;
    case "cancel_x_login": challenge = undefined; return null;
    case "remove_account": {
      const matches = (account: Pick<Account, "service" | "id">) => account.id === text(data, "id") && account.service === text(data, "service");
      snapshot.accounts = snapshot.accounts.filter(account => !matches(account));
      observation.accounts = observation.accounts!.filter(account => !matches(account as Account));
      return null;
    }
    case "control_local_api": {
      const running = text(data, "action") === "start";
      if (running && snapshot.supervised) throw "mode_conflict";
      const mode = data.claude as { mode?: string; key?: string } | undefined;
      snapshot.local_api = { available: true, running, ready: running, base_url: running ? `http://127.0.0.1:${Number(data.port) || 8088}/v1` : null, claude_enabled: running && (claude.connected || mode?.mode === "api_key") };
      return null;
    }
    case "control_claude": claude = { available: true, connected: false, pending: text(data, "action") === "connect" }; return null;
    case "local_api_key": return "preview-only-key-with-no-service";
    default: throw new Error(`Unmocked preview command: ${command}`);
  }
}, { shouldMockEvents: true });

type PreviewCall = { command: string; payload: unknown };
const calls: PreviewCall[] = [];
const redact = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([name, entry]) => [name, /^(code|authToken|ct0|password|key|claudeKey)$/i.test(name) ? "[redacted]" : redact(entry)]));
};
const internals = (window as unknown as { __TAURI_INTERNALS__: { invoke: (command: string, payload?: InvokeArgs) => Promise<unknown> } }).__TAURI_INTERNALS__;
const mockedInvoke = internals.invoke;
const state = document.getElementById("preview-fixture-state")!;
internals.invoke = async (command, payload) => {
  calls.push({ command, payload: redact(payload) });
  state.dataset.commandCount = String(calls.length);
  state.dataset.lastCommand = command;
  return mockedInvoke(command, payload);
};
Object.defineProperty(window, "__NODE_UI_PREVIEW__", { value: Object.freeze({ scenario, get calls() { return structuredClone(calls); }, get snapshot() { return structuredClone(snapshot); } }) });
state.dataset.scenario = scenario;

await import("../src/main.ts");
if (scenario === "pending-login") {
  // Drive the same form as a user so challenge rendering stays in main.ts.
  await new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
  for (const id of ["connect-accounts", "x-login-panel"]) {
    const panel = document.getElementById(id);
    if (panel instanceof HTMLDetailsElement) panel.open = true;
  }
  (document.getElementById("x-login-id") as HTMLInputElement).value = "research-x";
  (document.getElementById("x-login-username") as HTMLInputElement).value = "researchdesk";
  (document.getElementById("x-login-password") as HTMLInputElement).value = "synthetic-preview-password";
  (document.getElementById("x-login-reconnect") as HTMLInputElement).checked = true;
  (document.getElementById("x-login-form") as HTMLFormElement).requestSubmit();
}
state.dataset.ready = "true";
