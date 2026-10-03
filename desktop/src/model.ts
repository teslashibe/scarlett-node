export type Account = {
  id: string;
  service: "codex" | "x_read";
  concurrency: number;
};
export type AccountHealth = {
  id: string;
  service: string;
  state?: string;
  in_flight?: number;
  rest_until?: string;
  last_error_code?: string;
};
export type Snapshot = {
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
export const errorMessage = (code: unknown): string =>
  ({
    invalid_input: "Check the account ID, capacity and cookie values",
    runtime_unavailable: "The node or proof helper is missing from this build",
    accounts_unavailable:
      "This node build does not support account management yet",
    cli_unavailable:
      "Install the reviewed Codex CLI 0.159.2 to connect an account",
    command_failed:
      "The node could not complete that action. For pairing, check the website before requesting another code",
    command_timeout:
      "The action timed out. Check its status before trying again",
    already_running: "This app is already running the node",
    not_paired: "Pair this node first",
    login_busy: "Finish or cancel the current Codex login first",
    login_failed: "Codex login did not complete. You can reconnect",
    private_storage_unavailable:
      "Scarlett could not open its private local storage",
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
    !externalRuntime(s)
  );
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
