export type Preferences = { schema: 1; local_api_port: number; background: boolean; x_concurrency: number };
export type Account = {
  id: string;
  service: "codex" | "x_read";
  concurrency: number;
  username?: string;
};
export type BrowserProfile = { id: string; browser: "chrome" | "firefox" | "safari"; label: string };
export type AccountHealth = {
  id: string;
  service: string;
  state?: string;
  in_flight?: number;
  rest_until?: string;
  last_error_code?: string;
  username?: string;
};
export type ServiceHealth = {
  kind?: string;
  state?: string;
  capacity?: number;
  in_flight?: number;
  last_error_code?: string;
  // Absent means MPC-TLS only, as for every node before the field existed.
  proof_modes?: string[];
};
export type ClaudeStatus = { available: boolean; connected: boolean; pending: boolean; error?: string | null };
export type Snapshot = {
  local_api?: { available: boolean; running: boolean; ready: boolean; base_url?: string | null; claude_enabled: boolean };
  runtime_available: boolean;
  accounts_available: boolean;
  helper_available: boolean;
  codex_login_available: boolean;
  paired: boolean;
  supervised: boolean;
  login_pending: boolean;
  login_error?: string | null;
  accounts: Account[];
  // The node's saved keyed-relay halt is still on disk.
  relay_halt_marker?: boolean;
  observation?: {
    state?: string;
    updated_at?: string;
    in_flight?: number;
    unresolved_attempts?: number;
    last_heartbeat_at?: string;
    accounts?: AccountHealth[];
    services?: ServiceHealth[];
    drain_requested?: boolean;
    relay_halted?: boolean;
    // The attempt journal alone stops new work.
    journal_full?: boolean;
  } | null;
};
// The node accepts at most eight accounts per provider (node.rs MAX_CODEX_ACCOUNTS).
export const MAX_CODEX_ACCOUNTS = 8;
export const errorMessage = (code: unknown): string =>
  ({
    invalid_input: "Check the account ID, capacity and cookie values",
    runtime_unavailable: "The node or proof helper is missing from this build",
    accounts_unavailable:
      "This node build does not support account management yet",
    identity_mismatch: "This login belongs to a different X account. Add it as a new account",
    duplicate_account: "This X account is already connected under another local name. Use the existing entry, or remove it before adding a new name",
    account_limit: `Remove a Codex account first. Up to ${MAX_CODEX_ACCOUNTS} Codex accounts are supported on this device`,
    cli_unavailable:
      "The bundled Codex runtime is missing or incompatible",
    command_failed:
      "The node could not complete that action. For pairing, check the website before requesting another code",
    command_timeout:
      "The action timed out. Check its status before trying again",
    already_running: "This app is already running the node",
    not_paired: "Pair this node first",
    login_busy: "Finish or cancel the current provider login first",
    login_failed: "Codex login did not complete. You can reconnect",
    claude_unavailable: "The bundled Claude runtime is missing or failed its integrity check",
    claude_login_failed: "Claude login did not complete. Reconnect using your subscription",
    api_unavailable: "The local model API is unavailable in this build",
    api_not_ready: "The local API did not become ready securely. Check its status before trying again",
    api_port_in_use: "The local port is unavailable. Choose another port or stop the service using it",
    api_process_exited: "The local API stopped before becoming ready. Check the bundled installation",
    autostart_unavailable: "Scarlett could not update the login setting. Check the current setting before trying again",
    mode_conflict: "Stop the other service before switching between network jobs and the local API",
    private_storage_unavailable:
      "Scarlett could not open its private local storage",
    browser_protected: "The browser or OS protected this profile. Approve access locally or paste the two X cookies",
    browser_busy: "Close the selected browser, then try importing again or use cookie paste",
    browser_invalid: "Scarlett could not read this cookie store safely. Use cookie paste",
    browser_no_x_session: "No complete X session was found in that profile. Sign in to X there or use cookie paste",
    browser_ambiguous: "This profile contains multiple X sessions. Paste the two cookies for the account you want",
    browser_unsupported: "This browser format is not supported on this device. Use cookie paste",
    windows_pending:
      "Native Windows runtime support is not available in this build",
  })[String(code)] ?? "Scarlett could not complete that action";
export function canStart(s: Snapshot): boolean {
  return (
    s.runtime_available &&
    s.helper_available &&
    s.accounts_available &&
    s.paired &&
    s.accounts.length > 0 &&
    !s.supervised &&
    !s.local_api?.running &&
    !externalRuntime(s)
  );
}
export function codexAccountLimitReached(s: Snapshot): boolean {
  return (
    s.accounts.filter((a) => a.service === "codex").length >=
    MAX_CODEX_ACCOUNTS
  );
}
export function canConnectCodex(s: Snapshot): boolean {
  return (
    s.accounts_available &&
    s.codex_login_available &&
    !s.login_pending &&
    !codexAccountLimitReached(s)
  );
}
export function codexNote(s: Snapshot): string {
  if (s.login_pending) return "Finish login in your browser";
  if (!s.codex_login_available)
    return "The bundled Codex runtime is missing or incompatible";
  if (s.accounts_available && codexAccountLimitReached(s))
    return errorMessage("account_limit");
  return s.login_error
    ? errorMessage(s.login_error)
    : "Provider access is checked when it serves work";
}
export function claudeStatusText(c: ClaudeStatus | undefined): string {
  if (!c) return "Checking the bundled Claude runtime";
  if (c.pending) return "Finish Claude login in your browser";
  if (c.connected) return "Claude subscription connected on this device";
  if (c.error) return errorMessage(c.error);
  return c.available
    ? "Claude subscription not connected"
    : "Claude login is unavailable in this build";
}
export function externalRuntime(s: Snapshot): boolean {
  return (
    !s.supervised &&
    (s.observation?.state === "running" || s.observation?.state === "draining")
  );
}
export function statusText(s: Snapshot): string {
  if (!s.runtime_available) return "Node not installed";
  if (!s.paired) return "Not paired";
  if (externalRuntime(s)) return "Running outside this app";
  if (!s.supervised) return "Stopped";
  if (s.observation?.state === "offline" || !s.observation)
    return "Waiting for node status";
  return s.observation.drain_requested
    ? "Paused · finishing accepted work"
    : "Running";
}
function observedHealth(s: Snapshot, a: Account): AccountHealth | undefined {
  return s.observation?.accounts?.find(
    (h) => h.id === a.id && h.service === a.service,
  );
}
export const X_SESSION_EXPIRED =
  "X session expired or revoked. Re-import the account";
// X reports configured until the account's client has checked its login with
// X, then ready. A failed check reports auth_required, like a dead session.
const X_STATES: Record<string, string> = {
  configured: "Warming up · checking login",
  auth_required: X_SESSION_EXPIRED,
  identity_unverified: "X identity not verified · waiting for a login check",
  duplicate_account: "Duplicate X account · shares quota with another entry · remove this local entry",
};
export function accountTitle(s: Snapshot, a: Account): string {
  if (a.service !== "x_read") return `Codex · ${a.id}`;
  const username = a.username ?? observedHealth(s, a)?.username;
  return username ? `X · @${username} · ${a.id}` : `X · ${a.id}`;
}
export function accountHealth(s: Snapshot, a: Account): string {
  const state = observedHealth(s, a)?.state;
  if (!state) return "Configured · access not verified";
  // A stopped node or stale status is not checking anything.
  if (a.service === "x_read" && state === "configured" && !nodeLive(s))
    return "Configured · access not verified";
  return (a.service === "x_read" && X_STATES[state]) || state.replaceAll("_", " ");
}
// The node wrote this status recently and is still running.
function nodeLive(s: Snapshot): boolean {
  return s.observation?.state === "running" || s.observation?.state === "draining";
}
export const JOURNAL_FULL =
  "Receipt journal full · waiting for receipts to clear before taking new work";
// The running node takes no new work because its attempt journal has no room:
// unfinished attempts, or receipts too recent to remove, fill it.
export function journalNote(s: Snapshot): string {
  return nodeLive(s) && s.observation?.journal_full === true ? JOURNAL_FULL : "";
}
export function needsXReimport(s: Snapshot, a: Account): boolean {
  return a.service === "x_read" && observedHealth(s, a)?.state === "auth_required";
}
// The node has not written a status since `since` (ms), so its account states
// predate whatever changed then, such as a re-imported X session.
export function statusPredates(s: Snapshot, since: number): boolean {
  return !(Date.parse(s.observation?.updated_at ?? "") > since);
}
// "halted": the saved halt is on disk and nobody has resumed it.
// "resume_saved": relay-resume removed it, but the node still reports the halt
// it holds in memory until it picks the change up.
export function relayState(s: Snapshot): "halted" | "resume_saved" | "" {
  if (s.relay_halt_marker) return "halted";
  return s.observation?.relay_halted === true ? "resume_saved" : "";
}
// What the running node advertises for X proofs. Empty while it is not
// running or has no X account, since nothing is being offered then.
export function xProofModes(s: Snapshot): string {
  if (!nodeLive(s)) return "";
  if (!s.accounts.some((a) => a.service === "x_read")) return "";
  const x = s.observation?.services?.find((v) => v.kind === "x_read");
  if (!x) return "";
  if (x.proof_modes?.includes("relay")) return "MPC + relay";
  return relayState(s) ? "MPC only · relay paused" : "MPC only";
}
export function drainingAccounts(s: Snapshot): AccountHealth[] {
  return (s.observation?.accounts ?? []).filter(
    (health) =>
      !s.accounts.some((a) => a.id === health.id && a.service === health.service) &&
      (health.state === "draining" || (health.in_flight ?? 0) > 0),
  );
}
export function validId(id: string): boolean {
  return /^[a-z0-9_-]{1,32}$/.test(id) && id !== "legacy";
}

export type XLoginStatus = { status: "pending" | "updated" | "cancelled" | "error"; id?: string; code?: string; challenge_id?: string; method?: string; destination?: string; expires_at?: string; retry_after?: number };
export function xLoginMessage(result: XLoginStatus): string {
 if (result.status === "updated") return "X account verified and saved on this device";
 if (result.status === "cancelled") return "X login cancelled";
 if (result.status === "pending") return `Enter the verification code${result.destination ? ` sent to ${result.destination}` : ""}. This login expires at ${new Date(result.expires_at || "").toLocaleTimeString()}`;
 return ({restart_login:"This login expired or was restarted. Start a new login",cooldown:`X requested a cooldown${result.retry_after ? ` of ${result.retry_after} seconds` : ""}. Wait before starting another login`,verification_failed:"X could not verify the requested account. Your saved session was kept",account_changed:"The account changed during login. Your saved session was kept",duplicate_account:errorMessage("duplicate_account"),identity_mismatch:errorMessage("identity_mismatch"),runtime_unavailable:"Browser login is unavailable in this build. Use browser import or cookie paste",login_busy:"Another X login is already running",invalid_input:"Check the local account ID, username and verification code"} as Record<string,string>)[result.code || ""] || "X login could not finish. Your saved session was kept";
}
