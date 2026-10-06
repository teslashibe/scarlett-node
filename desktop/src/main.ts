import { listen } from "@tauri-apps/api/event";
import "./styles.css";
import { api } from "./api.ts";
import { scheduleXLoginExpiry } from "./x-login-expiry.ts";
import { accountRemovalConfirmation } from "./account-removal.ts";
import { diagnosticsNote, localCapacity, renderDiagnostics, type Diagnostics } from "./diagnostics.ts";
import {
  accountHealth,
  accountTitle,
  canConnectCodex,
  canStart,
  claudeStatusText,
  codexNote,
  errorMessage,
  statusText,
  externalRuntime,
  drainingAccounts,
  needsXReimport,
  relayState,
  statusPredates,
  xProofModes,
  xLoginMessage,
  type XLoginStatus,
  type Account,
  type ClaudeStatus,
  type Snapshot,
} from "./model.ts";
const app = document.querySelector<HTMLDivElement>("#app")!;
// Static markup only. Provider/native text is always inserted through textContent.
app.innerHTML = `<header><span class="brand">SCARLETT <small>Node</small></span><div class="actions"><button id="dashboard" class="quiet">Open dashboard ↗</button><button id="quit" class="quiet">Quit Scarlett</button></div></header>
<main><div class="intro"><p class="eyebrow">YOUR SUPPLIER NODE</p><h1>Put your accounts to work</h1><p>Connect Codex and X on this device, then choose when your node serves jobs</p></div>
<p id="notice" role="status" aria-live="polite" hidden></p>
<section id="relay-banner" class="relay-banner" aria-labelledby="relay-heading" hidden><h2 id="relay-heading">Keyed relay is paused on this node</h2><p id="relay-detail" tabindex="-1"></p><div class="actions"><button id="relay-resume" type="button">Resume relay</button></div></section>
<section aria-labelledby="runtime-heading"><div class="section-head"><h2 id="runtime-heading">Your node</h2><strong id="status">Checking local runtime</strong></div><p id="runtime-note">Connecting to the installed node</p><div class="actions"><button id="start">Start node</button><button id="pause" class="secondary">Pause</button><button id="resume" class="secondary">Resume</button><button id="stop" class="quiet">Stop</button></div><p id="work" class="muted"></p><p id="x-proofs" class="muted" hidden></p></section>
<section aria-labelledby="diagnostics-heading"><h2 id="diagnostics-heading" tabindex="-1">Local request measurements</h2><p id="diagnostics-note" class="muted">Checking local measurements</p><p id="diagnostics-capacity" class="muted"></p><p class="muted">Recent attempts stay on this device for 24 hours, up to 200 attempts. Times use local monotonic clocks. Helper clocks start separately for each page; spans can overlap. Handshake milestones can include protocol setup and verifier admission, and first-response timing includes transport through the proof path. Unclassified time means it has not been assigned to a measured phase</p><div id="diagnostics-history"></div></section>
<section aria-labelledby="pair-heading"><div class="section-head"><h2 id="pair-heading">Pair with Scarlett</h2><button id="setup" class="quiet">Open setup ↗</button></div><p>Sign in, redeem your invite and bind your wallet in your browser. Then paste the one-time pairing code here</p><form id="pair-form"><label>Pairing code<input id="pair-code" type="password" autocomplete="off" spellcheck="false" maxlength="64" required></label><button type="submit">Pair node</button></form></section>
<section aria-labelledby="accounts-heading"><div class="section-head"><h2 id="accounts-heading" tabindex="-1">Connected accounts</h2><span id="account-note" class="muted"></span></div><div id="accounts"></div><div class="account-forms">
<form id="codex-form"><h3>Connect Codex</h3><p>Sign in with your ChatGPT account in your browser. Scarlett creates a private profile on this device for each account</p><button type="submit">Connect Codex</button><button id="cancel-login" type="button" class="quiet" hidden>Cancel login</button><p id="codex-note" class="muted"></p></form>
<div class="x-browser-login"><form id="x-login-form"><h3>Sign in to X</h3><p>Sign in through the browser on this device, then enter any verification code here. Passwords and codes are used only for this login</p><label>Local account ID for X login<input id="x-login-id" autocomplete="off" pattern="[a-z0-9_-]{1,32}" maxlength="32" required></label><label>Concurrent jobs<input id="x-login-capacity" type="number" min="1" max="32" value="1" required></label><label class="check"><input id="x-login-reconnect" type="checkbox">Replace the session for an existing local account</label><label>X username<input id="x-login-username" autocomplete="username" maxlength="64" required></label><label>Password<input id="x-login-password" type="password" autocomplete="current-password" maxlength="1024" required></label><button id="x-login-start" type="submit">Sign in to X</button><button id="x-login-cancel" type="button" class="quiet" hidden>Cancel X login</button><p id="x-login-note" role="status" class="muted"></p></form><form id="x-challenge-form" hidden><h3>Verify your X login</h3><label>Verification code<input id="x-login-code" type="password" autocomplete="one-time-code" maxlength="128" required></label><button id="x-login-continue" type="submit">Continue login</button></form></div><form id="x-form"><h3>Connect X</h3><p>Import from a browser profile or paste these two cookies. They stay on this device; the node uses X for read-only work</p><div id="x-reimport" class="reimport" hidden><strong id="x-reimport-title"></strong><p>Choose a browser profile signed in to this X account, or paste its two cookies. The account keeps its ID and job limit.</p><button id="x-reimport-cancel" type="button" class="quiet">Cancel re-import</button></div><label>Local X account ID<input id="x-id" autocomplete="off" pattern="[a-z0-9_-]{1,32}" maxlength="32" placeholder="personal-x" required></label><label>Concurrent jobs<input id="x-capacity" type="number" min="1" max="32" value="1" required></label><label>Browser profile<select id="x-profile" disabled><option value="">Loading browser profiles</option></select></label><label class="check"><input id="x-consent" type="checkbox">Import only X session cookies from this profile</label><button id="x-import" type="button" disabled>Import X account</button><p class="muted">Close the selected browser before importing. The OS may ask for permission; protected stores can use cookie paste</p><label>auth_token<input id="x-token" type="password" autocomplete="off" spellcheck="false" maxlength="64" required></label><label>ct0<input id="x-ct0" type="password" autocomplete="off" spellcheck="false" maxlength="160" required></label><button type="submit">Connect X</button><p id="x-import-note" class="muted"></p></form></div></section>
<section aria-labelledby="local-api-heading"><h2 id="local-api-heading">Local model API</h2><p>Connect your tools to this device using an OpenAI-compatible API. It uses the Codex accounts connected above. Stop network jobs before starting the local API</p><p id="api-status" class="muted"></p><label>Local port<input id="api-port" type="number" min="1024" max="65535" value="8088"></label><h3>Connect Claude</h3><p>Your browser handles subscription login. Claude keeps this app’s credentials on this device</p><p id="claude-status" class="muted"></p><div class="actions"><button id="claude-connect" type="button">Connect Claude subscription</button><button id="claude-cancel" type="button" class="quiet" hidden>Cancel Claude login</button><button id="claude-disconnect" type="button" class="quiet">Disconnect Claude</button></div><label>Claude billing<select id="claude-mode"><option value="subscription">Claude subscription</option><option value="api_key">Anthropic API key · separate usage billing</option></select></label><label id="claude-key-label" hidden>Anthropic API key<input id="claude-key" type="password" autocomplete="off" spellcheck="false" maxlength="512"></label><p class="muted">Subscription mode uses your connected claude.ai account. API key mode bills Anthropic API usage separately; the key is cleared when the service stops. Stop the local API before changing billing mode</p><div class="actions"><button id="api-start" type="button">Start local API</button><button id="api-stop" type="button" class="quiet">Stop local API</button><button id="api-show-key" type="button" class="quiet">Show local API key</button><button id="api-hide-key" type="button" class="quiet" hidden>Hide key</button></div><label id="api-key-label" hidden>Local API key<input id="api-key" type="password" readonly autocomplete="off" spellcheck="false"></label><p class="muted">Use the address above as your base URL and this private key as the bearer token. Restart the local API after adding Codex accounts</p></section>
<section aria-labelledby="preferences-heading"><h2 id="preferences-heading">This device</h2><form id="preferences-form"><label class="check"><input id="background" type="checkbox">Keep running when the window closes</label><p class="muted">When off, closing the window drains accepted jobs and quits Scarlett. When on, use the menu bar or tray to reopen or quit</p><label>Saved local API port<input id="saved-api-port" type="number" min="1024" max="65535" required></label><button type="submit">Save device preferences</button></form><label class="check"><input id="autostart" type="checkbox" disabled>Open Scarlett when I log in</label><p class="muted">Opening Scarlett does not start network jobs or the local API. You choose when to start them</p></section>
<footer><p>Suppliers earn points only. Local status does not confirm a points award</p><p>Choose what happens when the window closes in This device. Quit drains and stops the node</p><button id="settings" class="quiet">Manage node access ↗</button></footer></main><dialog id="remove-account-dialog" aria-labelledby="remove-account-heading" aria-describedby="remove-account-detail"><h2 id="remove-account-heading"></h2><p id="remove-account-detail">This account will stop receiving new work when the node picks up the change. Accepted jobs keep their original account and finish. Saved credentials remain on this device.</p><div class="actions"><button id="remove-account-cancel" type="button" class="secondary">Keep account</button><button id="remove-account-confirm" type="button">Remove account</button></div></dialog>`;
const $ = <T extends HTMLElement = HTMLElement>(id: string) =>
  document.getElementById(id) as T;
const restoreAccountFocus = (account: Account) => {
  const title = document.getElementById(`account-${account.service}-${account.id}`);
  const remove = title?.closest(".account-row")?.querySelector<HTMLButtonElement>("button[data-remove]");
  (remove ?? $("accounts-heading")).focus();
};
const confirmRemoval = accountRemovalConfirmation({
  dialog: $<HTMLDialogElement>("remove-account-dialog"),
  heading: $("remove-account-heading"),
  cancel: $<HTMLButtonElement>("remove-account-cancel"),
  confirm: $<HTMLButtonElement>("remove-account-confirm"),
  restoreFocus: restoreAccountFocus,
});
let snapshot: Snapshot | undefined;
let claudeStatus: ClaudeStatus | undefined;
let diagnostics: Diagnostics | undefined;
let diagnosticsPolling = false;
let busy = false;
let polling: Promise<void> | undefined;
let mutationEpoch = 0;
let claudePolling = false;
let browserProfilesAvailable = false;
let preferencesAvailable = false;
let autostartAvailable = false;
// The X account being re-imported through the form below, if any, and the
// form values it replaced.
let reimport: { id: string; id_before: string; capacity_before: string } | undefined;
// When each X re-import finished. Until the node writes a newer status, its
// account state predates the new session.
const reimported = new Map<string, number>();
const REIMPORTED =
  "X account re-imported. The node checks the new login before it serves work";
const setText = (el: HTMLElement, text: string) => {
  // Live regions re-announce on every write; only write changes.
  if (el.textContent !== text) el.textContent = text;
};
const notice = (text: string, error = false) => {
  const n = $("notice");
  n.textContent = text;
  n.hidden = !text;
  n.className = error ? "notice error" : "notice";
};
const requestQuit = () => {
  void api.quit().catch((error) => notice(errorMessage(error), true));
};
$("quit").addEventListener("click", requestQuit);
// WebView2 can retain accelerator input while a web control has focus.
// Delegate to the same native drain handler used by the menu and tray.
document.addEventListener("keydown", (event) => {
  if ((event.ctrlKey || event.metaKey) && !event.altKey && !event.shiftKey && event.key.toLowerCase() === "q") {
    event.preventDefault();
    if (!event.repeat) requestQuit();
  }
}, true);
function render(s: Snapshot) {
  snapshot = s;
  setText($("diagnostics-capacity"), localCapacity(s));
  $("x-profile").toggleAttribute("disabled", busy || !browserProfilesAvailable);
  $("x-consent").toggleAttribute("disabled", busy || !browserProfilesAvailable);
  $("x-import").toggleAttribute("disabled", busy || !s.accounts_available || !browserProfilesAvailable || !$<HTMLSelectElement>("x-profile").value || !$<HTMLInputElement>("x-consent").checked);
  for (const id of ["background", "saved-api-port"]) $(id).toggleAttribute("disabled", busy || !preferencesAvailable);
  $("preferences-form").querySelector("button")!.toggleAttribute("disabled", busy || !preferencesAvailable);
  $("autostart").toggleAttribute("disabled", busy || !autostartAvailable);
  const local = s.local_api;
  $("api-status").textContent = local?.running ? `${local.ready ? "Ready" : "Not ready"} · ${local.base_url ?? ""} · ${local.claude_enabled ? "Codex and Claude" : "Codex"}` : local?.available ? "Stopped · listens only on this device" : "Local API controls are unavailable in this build";
  $("api-start").toggleAttribute("disabled", busy || !local?.available || local.running || s.supervised || externalRuntime(s));
  $("api-stop").toggleAttribute("disabled", busy || !local?.running);
  $("api-show-key").toggleAttribute("disabled", busy || !local?.available);
  $("api-port").toggleAttribute("disabled", busy || !!local?.running);
  const claude = claudeStatus;
  setText($("claude-status"), claudeStatusText(claude));
  $("claude-connect").toggleAttribute("disabled", busy || !claude?.available || !!claude?.pending || !!claude?.connected);
  $("claude-cancel").hidden = !claude?.pending;
  $("claude-cancel").toggleAttribute("disabled", busy);
  $("claude-disconnect").toggleAttribute("disabled", busy || !claude?.available || !!claude?.pending);
  $("claude-mode").toggleAttribute("disabled", busy || !!local?.running || !!claude?.pending);
  $("claude-key").toggleAttribute("disabled", busy || !!local?.running || !!claude?.pending);
  $("api-start").toggleAttribute("disabled", busy || !local?.available || local.running || s.supervised || externalRuntime(s) || !!claude?.pending);
  const relay = relayState(s);
  const banner = $("relay-banner");
  banner.hidden = !relay;
  banner.className = relay === "halted" ? "relay-banner danger" : "relay-banner";
  banner.setAttribute("role", relay === "halted" ? "alert" : "status");
  setText(
    $("relay-detail"),
    relay === "halted"
      ? "The verifier was caught misusing an X session. Contact the operator before resuming."
      : "Resume saved. Relay starts again once the node picks it up.",
  );
  $("relay-resume").hidden = relay !== "halted";
  $("relay-resume").toggleAttribute("disabled", busy);
  const proofs = xProofModes(s);
  $("x-proofs").hidden = !proofs;
  $("x-proofs").textContent = proofs ? `X proofs · ${proofs}` : "";
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
  if (reimport && !s.accounts.some((a) => a.service === "x_read" && a.id === reimport?.id))
    endReimport();
  for (const [id, at] of reimported)
    if (!statusPredates(s, at)) reimported.delete(id);
  // Rows are rebuilt off-screen and swapped in only when they changed, so the
  // 3 s poll does not drop keyboard focus or a click that is in progress.
  const rows = document.createElement("div");
  for (const a of s.accounts) {
    const row = document.createElement("div");
    row.className = "account-row";
    row.dataset.account = `${a.service}:${a.id}:${a.concurrency}`;
    const text = document.createElement("div");
    const title = document.createElement("strong");
    title.id = `account-${a.service}-${a.id}`;
    title.textContent = accountTitle(s, a);
    const state = document.createElement("p");
    const waiting = a.service === "x_read" && reimported.has(a.id);
    const expired = !waiting && needsXReimport(s, a);
    state.textContent = waiting
      ? `Re-imported · waiting for the node to check the new login · limit ${a.concurrency}`
      : expired
        ? accountHealth(s, a)
        : `${accountHealth(s, a)} · limit ${a.concurrency}`;
    text.append(title, state);
    const actions = document.createElement("div");
    actions.className = "actions";
    if (expired) {
      const again = document.createElement("button");
      again.type = "button";
      again.textContent = "Import X account again";
      // Several rows can offer this; the row title tells them apart.
      again.setAttribute("aria-describedby", title.id);
      again.disabled = busy;
      again.addEventListener("click", () => startReimport(a));
      actions.append(again);
    }
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "quiet";
    remove.textContent = "Remove";
    remove.disabled = busy;
    remove.dataset.remove = "";
    remove.setAttribute("aria-describedby", title.id);
    remove.addEventListener("click", () => {
      if (busy) return;
      void confirmRemoval(a).then((confirmed) => {
        if (confirmed)
          void act(
            () => api.remove(a.service, a.id),
            "Account removed from the saved list. The node stops new work for it when it picks up the change; accepted jobs can finish. Saved credentials remain on this device",
          ).finally(() => restoreAccountFocus(a));
      });
    });
    actions.append(remove);
    row.append(text, actions);
    rows.append(row);
  }
  for (const health of drainingAccounts(s)) {
    const row = document.createElement("div");
    row.className = "account-row";
    const text = document.createElement("p");
    text.textContent = `${health.service === "codex" ? "Codex" : "X"} · ${health.id} · removed from new work · ${health.in_flight ?? 0} jobs finishing`;
    row.append(text);
    rows.append(row);
  }
  if (rows.innerHTML !== $("accounts").innerHTML)
    $("accounts").replaceChildren(...rows.childNodes);
  $("account-note").textContent = s.accounts_available
    ? `${s.accounts.length} local ${s.accounts.length === 1 ? "account" : "accounts"}`
    : "Unavailable in this node build";
  $("codex-form")
    .querySelector("button[type=submit]")!
    .toggleAttribute("disabled", busy || !canConnectCodex(s));
  $("x-form")
    .querySelector("button[type=submit]")!
    .toggleAttribute("disabled", busy || !s.accounts_available);
  $("cancel-login").hidden = !s.login_pending;
  $("codex-note").textContent = codexNote(s);
}
async function refresh(afterMutation = false) {
  void refreshClaude();
  void refreshDiagnostics();
  if (polling) {
    if (!afterMutation) return;
    await polling;
  }
  const epoch = mutationEpoch;
  const request = (async () => {
    try {
      const status = await api.status();
      // A poll begun before a mutation must not restore the old registry rows.
      if (epoch === mutationEpoch) render(status);
    } catch (e) {
      if (epoch === mutationEpoch) notice(errorMessage(e), true);
    }
  })();
  polling = request;
  try { await request; }
  finally { if (polling === request) polling = undefined; }
}
// Claude status verifies the bundled runtime and launches its CLI. Poll it on
// its own so that cost never delays node status, such as a paired identity.
// Its result re-renders through render(), which swaps account rows only when
// they changed, so it never drops focus between the two polls either.
async function refreshClaude() {
  if (claudePolling) return;
  claudePolling = true;
  try {
    claudeStatus = await api.claudeStatus();
    if (snapshot) render(snapshot);
  } catch (e) {
    notice(errorMessage(e), true);
  } finally {
    claudePolling = false;
  }
}
// Diagnostics are optional and poll independently. A slow or older node must
// not delay account actions, node status, or replace their feedback.
async function refreshDiagnostics() {
  if (diagnosticsPolling) return;
  diagnosticsPolling = true;
  try { diagnostics = await api.diagnostics(); }
  catch { diagnostics = { available: false }; }
  finally { diagnosticsPolling = false; }
  setText($("diagnostics-note"), diagnosticsNote(diagnostics));
  renderDiagnostics($("diagnostics-history"), diagnostics);
}
async function act(fn: () => Promise<void>, success: string) {
  if (busy) return;
  busy = true;
  mutationEpoch++;
  if (snapshot) render(snapshot);
  notice("Working…");
  try {
    await fn();
    notice(success);
  } catch (e) {
    notice(errorMessage(e), true);
  } finally {
    busy = false;
    await refresh(true);
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
$("relay-resume").addEventListener("click", () => {
  if (
    !confirm(
      "Resume keyed relay on this node?\n\nOnly continue after the operator confirms the verifier has been checked. The node keeps running and its current work continues. Relay starts again once the node picks up the change.",
    )
  )
    return;
  void act(() => api.resumeRelay(), "Relay resume saved").then(() => {
    // The button is gone once the resume is saved; keep keyboard focus in the banner.
    if ($("relay-resume").hidden && !$("relay-banner").hidden) $("relay-detail").focus();
  });
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
  void act(
    () => api.connectCodex(),
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
  if (reimport) {
    const target = reimport.id;
    void act(async () => {
      await api.reconnectX(target, auth, ct0);
      finishReimport(target);
    }, REIMPORTED);
    return;
  }
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
for (const action of ["connect", "cancel", "disconnect"] as const) {
  $("claude-" + action).addEventListener("click", () => {
    void act(() => api.claude(action), action === "connect" ? "Finish Claude login in your browser" : action === "cancel" ? "Claude login cancelled" : "Claude disconnected locally");
  });
}
$("claude-mode").addEventListener("change", () => {
  $<HTMLInputElement>("claude-key").value = "";
  $("claude-key-label").hidden = $<HTMLSelectElement>("claude-mode").value !== "api_key";
});
$("api-start").addEventListener("click", () => {
  const key = $<HTMLInputElement>("claude-key");
  const value = key.value;
  key.value = "";
  const port = Number($<HTMLInputElement>("api-port").value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) { notice("Choose a local port between 1024 and 65535", true); return; }
  const mode = $<HTMLSelectElement>("claude-mode").value as "subscription" | "api_key";
  if (mode === "api_key" && !value) { notice("Enter your Anthropic API key for API usage billing", true); return; }
  void act(() => api.localApi("start", port, mode === "api_key" ? value : "", mode), "Local API ready");
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
async function loadPreferences() {
  const settings = await api.preferences();
  $<HTMLInputElement>("api-port").value = String(settings.local_api_port);
  $<HTMLInputElement>("saved-api-port").value = String(settings.local_api_port);
  $<HTMLInputElement>("background").checked = settings.background;
  preferencesAvailable = true;
  try {
    $<HTMLInputElement>("autostart").checked = await api.autostart();
    autostartAvailable = true;
    $("autostart").removeAttribute("disabled");
  } catch (e) { notice(errorMessage(e), true); }
}
$("preferences-form").addEventListener("submit", event => {
  event.preventDefault();
  const port = Number($<HTMLInputElement>("saved-api-port").value);
  const background = $<HTMLInputElement>("background").checked;
  if (!Number.isInteger(port) || port < 1024 || port > 65535) { notice("Choose a local port between 1024 and 65535", true); return; }
  void act(async () => {
    await api.savePreferences({schema: 1, local_api_port: port, background});
    if (!snapshot?.local_api?.running) $<HTMLInputElement>("api-port").value = String(port);
  }, background
    ? "Preferences saved. Closing the window keeps Scarlett running"
    : "Preferences saved. Closing the window quits Scarlett");
});
$("autostart").addEventListener("change", () => {
  const input = $<HTMLInputElement>("autostart");
  void act(async () => {
    try { await api.setAutostart(input.checked); }
    finally {
      try { input.checked = await api.autostart(); }
      catch (e) { autostartAvailable = false; input.disabled = true; throw e; }
    }
  }, "Login setting updated");
});
void loadPreferences().catch(e => notice(errorMessage(e), true));
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
  if (reimport) {
    const target = reimport.id;
    void act(async () => {
      await api.reimportX(profile, target, consent);
      for (const id of ["x-token", "x-ct0"]) $<HTMLInputElement>(id).value = "";
      $<HTMLInputElement>("x-consent").checked = false;
      finishReimport(target);
    }, REIMPORTED);
    return;
  }
  void act(async () => {
    await api.importX(profile, $<HTMLInputElement>("x-id").value.trim(), Number($<HTMLInputElement>("x-capacity").value), consent);
    for (const id of ["x-token", "x-ct0"]) $<HTMLInputElement>(id).value = "";
    $<HTMLInputElement>("x-consent").checked = false;
  }, "X account imported on this device");
});
void loadBrowserProfiles();

// Re-import reuses the X form above for the same local account ID: the ID and
// job limit stay fixed and only the saved session is replaced.
function startReimport(a: Account) {
  const id = $<HTMLInputElement>("x-id");
  const capacity = $<HTMLInputElement>("x-capacity");
  if (!reimport)
    reimport = { id: a.id, id_before: id.value, capacity_before: capacity.value };
  else reimport.id = a.id;
  id.value = a.id;
  id.readOnly = true;
  capacity.value = String(a.concurrency);
  capacity.disabled = true;
  for (const input of [id, capacity]) input.classList.add("locked");
  $<HTMLInputElement>("x-consent").checked = false;
  $("x-reimport-title").textContent = `Re-import X · ${a.id}`;
  $("x-reimport").hidden = false;
  for (const field of ["x-profile", "x-token"])
    $(field).setAttribute("aria-describedby", "x-reimport-title");
  $("x-form").scrollIntoView({ block: "start" });
  const profile = $<HTMLSelectElement>("x-profile");
  (profile.disabled ? $("x-token") : profile).focus();
  if (snapshot) render(snapshot);
}
function endReimport() {
  if (!reimport) return;
  const id = $<HTMLInputElement>("x-id");
  const capacity = $<HTMLInputElement>("x-capacity");
  id.readOnly = false;
  id.value = reimport.id_before;
  capacity.disabled = false;
  for (const input of [id, capacity]) input.classList.remove("locked");
  capacity.value = reimport.capacity_before;
  reimport = undefined;
  $("x-reimport").hidden = true;
  for (const field of ["x-profile", "x-token"]) $(field).removeAttribute("aria-describedby");
}
function finishReimport(id: string) {
  reimported.set(id, Date.now());
  endReimport();
}
$("x-reimport-cancel").addEventListener("click", () => {
  const id = reimport?.id;
  endReimport();
  if (snapshot) render(snapshot);
  // Return focus to the row button that started the re-import.
  const origin = $("accounts").querySelector<HTMLButtonElement>(
    `button[aria-describedby="account-x_read-${id}"]`,
  );
  (origin ?? $("x-id")).focus();
});

let xLoginPending: XLoginStatus | null = null;
let xLoginBusy = false;
let xLoginVersion = 0;
let xLoginCancelling = false;
let cancelXLoginExpiry = () => {};
function renderXLogin(result?: XLoginStatus) {
 if (result) {
  xLoginPending = result.status === "pending" ? result : null;
  $("x-login-note").textContent = xLoginMessage(result);
 }
 cancelXLoginExpiry();
 const operation = xLoginPending;
 const version = xLoginVersion;
 if (operation?.expires_at) {
  cancelXLoginExpiry = scheduleXLoginExpiry(operation.expires_at,
   () => { void discardXLogin({status: "error", code: "restart_login"}); },
   () => version === xLoginVersion && xLoginPending === operation);
 }
 const pending = !!xLoginPending;
 $("x-challenge-form").hidden = !pending;
 $("x-login-cancel").hidden = !pending && !xLoginBusy;
 $("x-login-start").toggleAttribute("disabled", xLoginBusy || xLoginCancelling || pending);
 $("x-login-continue").toggleAttribute("disabled", xLoginBusy || xLoginCancelling);
 $("x-login-cancel").toggleAttribute("disabled", xLoginCancelling);
 for (const id of ["x-login-id", "x-login-capacity", "x-login-reconnect", "x-login-username", "x-login-password"]) $(id).toggleAttribute("disabled", pending || xLoginBusy || xLoginCancelling);
}
async function runXLogin(action: () => Promise<XLoginStatus>) {
 if (xLoginBusy || xLoginCancelling) return;
 xLoginBusy = true;
 const version = ++xLoginVersion;
 $("x-login-note").textContent = "Waiting for the browser login";
 renderXLogin();
 try { const result = await action(); if (version === xLoginVersion) renderXLogin(result); } catch (error) { if (version === xLoginVersion) { xLoginPending = null; $("x-login-note").textContent = errorMessage(error); } }
 finally { if (version === xLoginVersion) { xLoginBusy = false; renderXLogin(); await refresh(); } }
}
$("x-login-form").addEventListener("submit", (event) => {
 event.preventDefault();
 const password = $<HTMLInputElement>("x-login-password").value;
 $<HTMLInputElement>("x-login-password").value = "";
 const id = $<HTMLInputElement>("x-login-id").value;
 const concurrency = Number($<HTMLInputElement>("x-login-capacity").value);
 const reconnect = $<HTMLInputElement>("x-login-reconnect").checked;
 const username = $<HTMLInputElement>("x-login-username").value;
 void runXLogin(() => api.startXLogin(id, concurrency, reconnect, username, password));
});
$("x-challenge-form").addEventListener("submit", (event) => {
 event.preventDefault();
 const code = $<HTMLInputElement>("x-login-code").value;
 $<HTMLInputElement>("x-login-code").value = "";
 const pending = xLoginPending;
 if (!pending?.id || !pending.challenge_id) return;
 void runXLogin(() => api.continueXLogin(pending.id!, pending.challenge_id!, code));
});
async function discardXLogin(result: XLoginStatus) {
 ++xLoginVersion;
 cancelXLoginExpiry();
 xLoginPending = null;
 xLoginCancelling = true;
 xLoginBusy = false;
 $<HTMLInputElement>("x-login-password").value = "";
 $<HTMLInputElement>("x-login-code").value = "";
 renderXLogin(result);
 try { await api.cancelXLogin(); }
 catch (error) { notice(errorMessage(error), true); }
 finally { xLoginCancelling = false; renderXLogin(); }
}
$("x-login-cancel").addEventListener("click", () => {
 void discardXLogin({ status: "cancelled" });
});
