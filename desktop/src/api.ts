import { invoke } from "@tauri-apps/api/core";
import type { Snapshot, BrowserProfile, Preferences, ClaudeStatus, XLoginStatus } from "./model.ts";
import type { Diagnostics } from "./diagnostics.ts";
import type { UpdateStatus } from "./update.ts";
export const api = {
  preferences: () => invoke<Preferences>("desktop_preferences"),
  savePreferences: (data: Preferences) => invoke<void>("save_desktop_preferences", { data }),
  // Saved at once; used from the next node start.
  setWebServing: (enabled: boolean) => invoke<void>("set_web_serving", { enabled }),
  autostart: () => invoke<boolean>("desktop_autostart"),
  setAutostart: (enabled: boolean) => invoke<void>("set_desktop_autostart", { enabled }),
  quit: () => invoke<void>("quit_desktop"),
  status: () => invoke<Snapshot>("desktop_status"),
  diagnostics: () => invoke<Diagnostics>("desktop_diagnostics"),
  claudeStatus: () => invoke<ClaudeStatus>("claude_status"),
  open: (destination: "setup" | "dashboard" | "settings" | "update" | "changelog", version?: string) =>
    invoke<void>("open_network", { destination, version }),
  updateStatus: () => invoke<UpdateStatus>("update_status"),
  updateCheck: () => invoke<void>("update_check"),
  // "Update now": the same verified, drain-safe install as automatic mode.
  updateInstall: () => invoke<void>("update_install"),
  updateCancel: () => invoke<void>("update_cancel"),
  updateLater: () => invoke<void>("update_later"),
  updateAck: () => invoke<void>("update_ack"),
  updateDismiss: (notice: "updated" | "failure") => invoke<void>("update_dismiss", { notice }),
  setUpdateMode: (mode: "notify" | "automatic") => invoke<void>("set_update_mode", { mode }),
  pair: (code: string) => invoke<void>("pair_node", { code }),
  control: (action: "start" | "pause" | "resume" | "stop") =>
    invoke<void>("control_node", { action }),
  connectX: (id: string, concurrency: number, authToken: string, ct0: string) =>
    invoke<void>("connect_x", { id, concurrency, authToken, ct0 }),
  startXLogin: (id: string, concurrency: number, reconnect: boolean, username: string, password: string) =>
    invoke<XLoginStatus>("start_x_login", { id, concurrency, reconnect, username, password }),
  continueXLogin: (id: string, challengeId: string, code: string) =>
    invoke<XLoginStatus>("continue_x_login", { id, challengeId, code }),
  cancelXLogin: () => invoke<void>("cancel_x_login"),
  browserProfiles: () => invoke<BrowserProfile[]>("browser_profiles"),
  importX: (profile: string, id: string, concurrency: number, consent: boolean) =>
    invoke<void>("import_x_profile", { profile, id, concurrency, consent }),
  // Re-import replaces only the saved session of an existing X account ID.
  reconnectX: (id: string, authToken: string, ct0: string) =>
    invoke<void>("reconnect_x", { id, authToken, ct0 }),
  reimportX: (profile: string, id: string, consent: boolean) =>
    invoke<void>("reimport_x_profile", { profile, id, consent }),
  // Runs only the bundled node's relay-resume; never drains or restarts it.
  resumeRelay: () => invoke<void>("resume_relay"),
  connectCodex: () => invoke<void>("connect_codex"),
  remove: (service: string, id: string) =>
    invoke<void>("remove_account", { service, id }),
  cancelLogin: () => invoke<void>("cancel_login"),
  localApi: (action: "start" | "stop", port?: number, claudeKey?: string, claudeMode: "subscription" | "api_key" = "subscription") => invoke<void>("control_local_api", { action, port, claude: { mode: claudeMode, key: claudeKey } }),
  claude: (action: "connect" | "cancel" | "disconnect") => invoke<void>("control_claude", { action }),
  localKey: () => invoke<string>("local_api_key"),
};
