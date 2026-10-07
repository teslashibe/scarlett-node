import { listen } from "@tauri-apps/api/event";
import "./styles.css";
import { layout, revealControl } from "./layout.ts";
import { api } from "./api.ts";
import { scheduleXLoginExpiry } from "./x-login-expiry.ts";
import { accountRemovalConfirmation } from "./account-removal.ts";
import { availableXSlots, diagnosticsNote, localCapacity, renderDiagnostics, type Diagnostics } from "./diagnostics.ts";
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
app.innerHTML = layout;
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
  const previous = snapshot;
  snapshot = s;
  setText($("diagnostics-capacity"), localCapacity(s));
  setText($("metric-accounts"), s.accounts_available ? String(s.accounts.length) : "Unknown");
  setText($("metric-capacity"), String(availableXSlots(s) ?? "Unknown"));
  setText($("metric-jobs"), String(s.observation?.in_flight ?? "Unknown"));
  setText($("metric-pending"), String(s.observation?.unresolved_attempts ?? "Unknown"));
  $("accounts-empty").hidden = s.accounts.length > 0 || drainingAccounts(s).length > 0;
  $("x-profile").toggleAttribute("disabled", busy || !browserProfilesAvailable);
  $("x-consent").toggleAttribute("disabled", busy || !browserProfilesAvailable);
  $("x-import").toggleAttribute("disabled", busy || !s.accounts_available || !browserProfilesAvailable || !$<HTMLSelectElement>("x-profile").value || !$<HTMLInputElement>("x-consent").checked);
  for (const id of ["background", "saved-api-port", "x-concurrency"]) $(id).toggleAttribute("disabled", busy || !preferencesAvailable);
  $("preferences-form").querySelector("button")!.toggleAttribute("disabled", busy || !preferencesAvailable);
  $("autostart").toggleAttribute("disabled", busy || !autostartAvailable);
  const local = s.local_api;
  setText($("api-summary"), !local?.available ? "Unavailable" : local.running ? (local.ready ? "Ready" : "Not ready") : "Stopped");
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
      ? "The node could not verify a relay request. This can happen if the connection ends before verification finishes. Check with the operator before resuming."
      : "Resume saved. Waiting for the node to confirm relay is available again.",
  );
  $("relay-resume").hidden = relay !== "halted";
  $("relay-resume").toggleAttribute("disabled", busy);
  const proofs = xProofModes(s);
  $("x-proofs").hidden = !proofs;
  $("x-proofs").textContent = proofs ? `X proofs · ${proofs}` : "";
  $("status").textContent = statusText(s);
  $("status-dot").dataset.tone = s.observation?.drain_requested || s.observation?.state === "draining"
    ? "paused" : s.observation?.state === "running" ? "running" : "stopped";
  $("runtime-note").textContent = !s.runtime_available
    ? "This build needs the packaged node and proof helper"
    : !s.accounts_available
      ? "Account management needs the newer native node release"
      : !s.helper_available
        ? "The proof helper is missing. New work is disabled"
        : "Serve network jobs with the accounts connected to this device";
  $("start").toggleAttribute("disabled", busy || !canStart(s));
  const controllable = s.supervised || externalRuntime(s);
  const paused = s.observation?.drain_requested;
  $("start").hidden = controllable;
  $("pause").hidden = !controllable || paused === true;
  $("resume").hidden = !controllable || paused === false;
  $("stop").hidden = !s.supervised;
  for (const name of ["pause", "resume"])
    $(name).toggleAttribute(
      "disabled",
      busy || (!s.supervised && !externalRuntime(s)),
    );
  $("stop").toggleAttribute("disabled", busy || !s.supervised);
  $("pair-form").hidden = s.paired;
  $("pair-section").hidden = s.paired;
  if (s.login_pending && !previous?.login_pending) revealControl($("codex-form"));
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
    text.className = "account-copy";
    const mark = document.createElement("span");
    mark.className = "provider-mark";
    mark.setAttribute("aria-hidden", "true");
    mark.textContent = a.service === "x_read" ? "X" : "C";
    const title = document.createElement("strong");
    title.id = `account-${a.service}-${a.id}`;
    title.textContent = accountTitle(s, a);
    const state = document.createElement("p");
    const waiting = a.service === "x_read" && reimported.has(a.id);
    const expired = !waiting && needsXReimport(s, a);
    state.textContent = waiting
      ? `Re-imported · waiting for the node to check the new login · one X job at a time`
      : expired
        ? accountHealth(s, a)
        : `${accountHealth(s, a)} · ${a.service === "x_read" ? "one X job at a time" : `limit ${a.concurrency}`}`;
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
    row.append(mark, text, actions);
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
      "Resume keyed relay on this node?\n\nOnly continue after the operator confirms the verifier has been checked. The node keeps running and its current work continues. Relay resumes at the next status update.",
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
  $<HTMLInputElement>("x-concurrency").value = String(settings.x_concurrency);
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
  const xConcurrency = Number($<HTMLInputElement>("x-concurrency").value);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) { notice("Choose a local port between 1024 and 65535", true); return; }
  if (!Number.isInteger(xConcurrency) || xConcurrency < 1 || xConcurrency > 8) { notice("Choose an X job limit between 1 and 8", true); return; }
  void act(async () => {
    await api.savePreferences({schema: 1, local_api_port: port, background, x_concurrency: xConcurrency});
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
    $("x-import-note").textContent = profiles.length ? "Imported accounts are configured locally; X verifies access when work runs" : "Sign in to X in a standard browser profile, or paste the two session cookies";
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
  revealControl($("x-form"));
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
 if (result?.status === "pending") {
  revealControl($("x-challenge-form"));
  $("x-login-code").focus();
 }
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
