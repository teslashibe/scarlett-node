import { listen } from "@tauri-apps/api/event";
import "./styles.css";
import { api } from "./api.ts";
import {
  accountHealth,
  canStart,
  errorMessage,
  statusText,
  validId,
  externalRuntime,
  drainingAccounts,
  type Snapshot,
} from "./model.ts";
const app = document.querySelector<HTMLDivElement>("#app")!;
// Static markup only. Provider/native text is always inserted through textContent.
app.innerHTML = `<header><span class="brand">SCARLETT <small>Node</small></span><button id="dashboard" class="quiet">Open dashboard ↗</button></header>
<main><div class="intro"><p class="eyebrow">YOUR SUPPLIER NODE</p><h1>Put your accounts to work</h1><p>Connect Codex and X on this device, then choose when your node serves jobs</p></div>
<p id="notice" role="status" aria-live="polite" hidden></p>
<section aria-labelledby="runtime-heading"><div class="section-head"><h2 id="runtime-heading">Your node</h2><strong id="status">Checking local runtime</strong></div><p id="runtime-note">Connecting to the installed node</p><div class="actions"><button id="start">Start node</button><button id="pause" class="secondary">Pause</button><button id="resume" class="secondary">Resume</button><button id="stop" class="quiet">Stop</button></div><p id="work" class="muted"></p></section>
<section aria-labelledby="pair-heading"><div class="section-head"><h2 id="pair-heading">Pair with Scarlett</h2><button id="setup" class="quiet">Open setup ↗</button></div><p>Sign in, redeem your invite and bind your wallet in your browser. Then paste the one-time pairing code here</p><form id="pair-form"><label>Pairing code<input id="pair-code" type="password" autocomplete="off" spellcheck="false" maxlength="64" required></label><button type="submit">Pair node</button></form></section>
<section aria-labelledby="accounts-heading"><div class="section-head"><h2 id="accounts-heading">Connected accounts</h2><span id="account-note" class="muted"></span></div><div id="accounts"></div><div class="account-forms">
<form id="codex-form"><h3>Connect Codex</h3><p>Your browser handles login. Scarlett keeps a separate private profile on this device</p><label>Local account ID<input id="codex-id" autocomplete="off" pattern="[a-z0-9_-]{1,32}" maxlength="32" placeholder="work-codex" required></label><label>Concurrent jobs<input id="codex-capacity" type="number" min="1" max="32" value="1" required></label><button type="submit">Connect Codex</button><button id="cancel-login" type="button" class="quiet" hidden>Cancel login</button><p id="codex-note" class="muted"></p></form>
<form id="x-form"><h3>Connect X</h3><p>Import from a browser profile or paste these two cookies. They stay on this device; the node uses X for read-only work</p><label>Local account ID<input id="x-id" autocomplete="off" pattern="[a-z0-9_-]{1,32}" maxlength="32" placeholder="personal-x" required></label><label>Concurrent jobs<input id="x-capacity" type="number" min="1" max="32" value="1" required></label><label>Browser profile<select id="x-profile" disabled><option value="">Loading browser profiles</option></select></label><label class="check"><input id="x-consent" type="checkbox">Import only X session cookies from this profile</label><button id="x-import" type="button" disabled>Import X account</button><p class="muted">Close the selected browser before importing. The OS may ask for permission; protected stores can use cookie paste</p><label>auth_token<input id="x-token" type="password" autocomplete="off" spellcheck="false" maxlength="64" required></label><label>ct0<input id="x-ct0" type="password" autocomplete="off" spellcheck="false" maxlength="160" required></label><button type="submit">Connect X</button><p id="x-import-note" class="muted"></p></form></div></section>
<section aria-labelledby="local-api-heading"><h2 id="local-api-heading">Local model API</h2><p>Connect your tools to this device using an OpenAI-compatible API. It uses the Codex accounts connected above. Stop network jobs before starting the local API</p><p id="api-status" class="muted"></p><label>Local port<input id="api-port" type="number" min="1024" max="65535" value="8088"></label><label>Claude API key (optional)<input id="claude-key" type="password" autocomplete="off" spellcheck="false" maxlength="512"></label><p class="muted">Claude uses your own Anthropic API key. The key stays in the running service and is cleared when it stops</p><div class="actions"><button id="api-start" type="button">Start local API</button><button id="api-stop" type="button" class="quiet">Stop local API</button><button id="api-show-key" type="button" class="quiet">Show local API key</button><button id="api-hide-key" type="button" class="quiet" hidden>Hide key</button></div><label id="api-key-label" hidden>Local API key<input id="api-key" type="password" readonly autocomplete="off" spellcheck="false"></label><p class="muted">Use the address above as your base URL and this private key as the bearer token. Restart the local API after adding Codex accounts</p></section>
<footer><p>Suppliers earn points only. Local status does not confirm a points award</p><p>Closing the window keeps Scarlett in your menu bar. Quit there to drain and stop the node</p><button id="settings" class="quiet">Manage node access ↗</button></footer></main>`;
const $ = <T extends HTMLElement = HTMLElement>(id: string) =>
  document.getElementById(id) as T;
let snapshot: Snapshot | undefined;
let busy = false;
let polling = false;
let browserProfilesAvailable = false;
const notice = (text: string, error = false) => {
  const n = $("notice");
  n.textContent = text;
  n.hidden = !text;
  n.className = error ? "notice error" : "notice";
};
function render(s: Snapshot) {
  snapshot = s;
  $("x-profile").toggleAttribute("disabled", busy || !browserProfilesAvailable);
  $("x-consent").toggleAttribute("disabled", busy || !browserProfilesAvailable);
  $("x-import").toggleAttribute("disabled", busy || !s.accounts_available || !browserProfilesAvailable || !$<HTMLSelectElement>("x-profile").value || !$<HTMLInputElement>("x-consent").checked);
  const local = s.local_api;
  $("api-status").textContent = local?.running ? `${local.ready ? "Ready" : "Not ready"} · ${local.base_url ?? ""} · ${local.claude_enabled ? "Codex and Claude" : "Codex"}` : local?.available ? "Stopped · listens only on this device" : "Local API controls are unavailable in this build";
  $("api-start").toggleAttribute("disabled", busy || !local?.available || local.running || s.supervised || externalRuntime(s));
  $("api-stop").toggleAttribute("disabled", busy || !local?.running);
  $("api-show-key").toggleAttribute("disabled", busy || !local?.available);
  $("api-port").toggleAttribute("disabled", busy || !!local?.running);
  $("claude-key").toggleAttribute("disabled", busy || !!local?.running);
  $("status").textContent = statusText(s);
  $("runtime-note").textContent = !s.runtime_available
    ? "This build needs the packaged node and proof helper"
    : !s.accounts_available
      ? "Account management needs the newer native node release"
      : !s.helper_available
        ? "The proof helper is missing. New work is disabled"
        : "Credentials stay on this device · current total capacity is one job per service";
  $("start").toggleAttribute("disabled", busy || !canStart(s));
  for (const name of ["pause", "resume"])
    $(name).toggleAttribute(
      "disabled",
      busy || (!s.supervised && !externalRuntime(s)),
    );
  $("stop").toggleAttribute("disabled", busy || !s.supervised);
  $("pair-form").hidden = s.paired;
  $("pair-form")
    .querySelector("button")!
    .toggleAttribute("disabled", busy || !s.runtime_available);
  $("work").textContent = s.observation
    ? `${s.observation.in_flight ?? 0} jobs in flight · ${s.observation.unresolved_attempts ?? 0} attempts awaiting reconciliation`
    : "";
  $("accounts").replaceChildren();
  for (const a of s.accounts) {
    const row = document.createElement("div");
    row.className = "account-row";
    const text = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = `${a.service === "codex" ? "Codex" : "X"} · ${a.id}`;
    const state = document.createElement("p");
    state.textContent = `${accountHealth(s, a)} · limit ${a.concurrency}`;
    text.append(title, state);
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "quiet";
    remove.textContent = "Remove";
    remove.disabled = busy;
    remove.addEventListener("click", () => {
      if (
        confirm(
          "Stop using this account for new work? Existing attempts keep their original account. Stored credentials are retained until safely removed after drain.",
        )
      )
        void act(
          () => api.remove(a.service, a.id),
          "Removal requested. The node applies it on its next scheduling check",
        );
    });
    row.append(text, remove);
    $("accounts").append(row);
  }
  for (const health of drainingAccounts(s)) {
    const row = document.createElement("div");
    row.className = "account-row";
    const text = document.createElement("p");
    text.textContent = `${health.service === "codex" ? "Codex" : "X"} · ${health.id} · removed from new work · ${health.in_flight ?? 0} jobs finishing`;
    row.append(text);
    $("accounts").append(row);
  }
  $("account-note").textContent = s.accounts_available
    ? `${s.accounts.length} local accounts`
    : "Unavailable in this node build";
  $("codex-form")
    .querySelector("button[type=submit]")!
    .toggleAttribute(
      "disabled",
      busy ||
        !s.accounts_available ||
        !s.codex_login_available ||
        s.login_pending,
    );
  $("x-form")
    .querySelector("button[type=submit]")!
    .toggleAttribute("disabled", busy || !s.accounts_available);
  $("cancel-login").hidden = !s.login_pending;
  $("codex-note").textContent = s.login_pending
    ? "Finish login in your browser"
    : !s.codex_login_available
      ? "The bundled Codex runtime is missing or incompatible"
      : s.login_error
        ? errorMessage(s.login_error)
        : "Provider access is checked when it serves work";
}
async function refresh() {
  if (polling) return;
  polling = true;
  try {
    render(await api.status());
  } catch (e) {
    notice(errorMessage(e), true);
  } finally {
    polling = false;
  }
}
async function act(fn: () => Promise<void>, success: string) {
  if (busy) return;
  busy = true;
  if (snapshot) render(snapshot);
  notice("Working…");
  try {
    await fn();
    notice(success);
  } catch (e) {
    notice(errorMessage(e), true);
  } finally {
    busy = false;
    await refresh();
  }
}
for (const id of ["setup", "dashboard", "settings"] as const)
  $(id).addEventListener("click", () => {
    void act(() => api.open(id), "Opened in your browser");
  });
for (const action of ["start", "pause", "resume", "stop"] as const)
  $(action).addEventListener("click", () => {
    void act(
      () => api.control(action),
      action === "stop"
        ? "Node stopped"
        : action === "pause"
          ? "Paused. Accepted work can finish"
          : action === "resume"
            ? "New work resumed"
            : "Node starting",
    );
  });
$("pair-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const input = $<HTMLInputElement>("pair-code");
  const code = input.value;
  input.value = "";
  void act(() => api.pair(code), "Node paired");
});
$("codex-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const id = $<HTMLInputElement>("codex-id").value;
  if (!validId(id)) {
    notice("Use a lowercase local account ID", true);
    return;
  }
  void act(
    () =>
      api.connectCodex(id, Number($<HTMLInputElement>("codex-capacity").value)),
    "Finish Codex login in your browser",
  );
});
$("cancel-login").addEventListener("click", () => {
  void act(() => api.cancelLogin(), "Login cancelled");
});
$("x-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const id = $<HTMLInputElement>("x-id").value;
  const token = $<HTMLInputElement>("x-token");
  const csrf = $<HTMLInputElement>("x-ct0");
  const auth = token.value;
  const ct0 = csrf.value;
  token.value = "";
  csrf.value = "";
  void act(
    () =>
      api.connectX(
        id,
        Number($<HTMLInputElement>("x-capacity").value),
        auth,
        ct0,
      ),
    "X account connected locally",
  );
});
$("api-start").addEventListener("click", () => {
  const key = $<HTMLInputElement>("claude-key");
  const value = key.value;
  key.value = "";
  const port = Number($<HTMLInputElement>("api-port").value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) { notice("Choose a local port between 1024 and 65535", true); return; }
  void act(() => api.localApi("start", port, value), "Local API ready");
});
$("api-stop").addEventListener("click", () => { void act(() => api.localApi("stop"), "Local API stopped"); });
$("api-show-key").addEventListener("click", () => {
  void act(async () => {
    $<HTMLInputElement>("api-key").value = await api.localKey();
    $<HTMLInputElement>("api-key").type = "text";
    $("api-key-label").hidden = false;
    $("api-hide-key").hidden = false;
  }, "Keep this key private");
});
function hideLocalKey() {
  $<HTMLInputElement>("api-key").value = "";
  $<HTMLInputElement>("api-key").type = "password";
  $("api-key-label").hidden = true;
  $("api-hide-key").hidden = true;
}
$("api-hide-key").addEventListener("click", hideLocalKey);
window.addEventListener("blur", hideLocalKey);
window.addEventListener("pagehide", () => {
  hideLocalKey();
  for (const id of ["pair-code", "x-token", "x-ct0", "claude-key"])
    $<HTMLInputElement>(id).value = "";
});
void refresh();
setInterval(() => {
  if (!busy) void refresh();
}, 3000);

void listen<string>("shutdown-error", (event) =>
  notice(
    "Scarlett could not stop safely. " + errorMessage(event.payload),
    true,
  ),
);

async function loadBrowserProfiles() {
  const select = $<HTMLSelectElement>("x-profile");
  try {
    const profiles = await api.browserProfiles();
    select.replaceChildren();
    const choose = document.createElement("option");
    choose.value = "";
    choose.textContent = profiles.length ? "Choose a browser profile" : "No profiles found, use cookie paste";
    select.append(choose);
    for (const profile of profiles) {
      const option = document.createElement("option");
      option.value = profile.id;
      option.textContent = profile.label;
      select.append(option);
    }
    browserProfilesAvailable = profiles.length > 0;
    $("x-import-note").textContent = profiles.length ? "Imported accounts are configured locally; X verifies access when work runs" : "Sign in to X in a standard browser profile, or paste the two cookies above";
  } catch {
    select.replaceChildren();
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "Browser import unavailable, use cookie paste";
    select.append(option);
  }
  if (snapshot) render(snapshot);
}
$("x-profile").addEventListener("change", () => {
  $<HTMLInputElement>("x-consent").checked = false;
  if (snapshot) render(snapshot);
});
$("x-consent").addEventListener("change", () => { if (snapshot) render(snapshot); });
$("x-import").addEventListener("click", () => {
  const profile = $<HTMLSelectElement>("x-profile").value;
  const consent = $<HTMLInputElement>("x-consent").checked;
  if (!profile || !consent) { notice("Choose a profile and allow importing its X session", true); return; }
  void act(async () => {
    await api.importX(profile, $<HTMLInputElement>("x-id").value.trim(), Number($<HTMLInputElement>("x-capacity").value), consent);
    for (const id of ["x-token", "x-ct0"]) $<HTMLInputElement>(id).value = "";
    $<HTMLInputElement>("x-consent").checked = false;
  }, "X account imported on this device");
});
void loadBrowserProfiles();
