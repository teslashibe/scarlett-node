export type Preferences = { schema: 1; local_api_port: number; background: boolean };
export type Account = {
  id: string;
  service: "codex" | "x_read";
  concurrency: number;
};
export type BrowserProfile = { id: string; browser: "chrome" | "firefox" | "safari"; label: string };
export type AccountHealth = {
  id: string;
  service: string;
  state?: string;
  in_flight?: number;
  rest_until?: string;
  last_error_code?: string;
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
  observation?: {
    state?: string;
    in_flight?: number;
    unresolved_attempts?: number;
    last_heartbeat_at?: string;
    accounts?: AccountHealth[];
    drain_requested?: boolean;
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
export function accountHealth(s: Snapshot, a: Account): string {
  const health = s.observation?.accounts?.find(
    (h) => h.id === a.id && h.service === a.service,
  );
  return health?.state
    ? health.state.replaceAll("_", " ")
    : "Configured · access not verified";
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
