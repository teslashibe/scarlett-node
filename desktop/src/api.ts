import { invoke } from "@tauri-apps/api/core";
import type { Snapshot, BrowserProfile, Preferences } from "./model.ts";
export const api = {
  preferences: () => invoke<Preferences>("desktop_preferences"),
  savePreferences: (data: Preferences) => invoke<void>("save_desktop_preferences", { data }),
  autostart: () => invoke<boolean>("desktop_autostart"),
  setAutostart: (enabled: boolean) => invoke<void>("set_desktop_autostart", { enabled }),
  quit: () => invoke<void>("quit_desktop"),
  status: () => invoke<Snapshot>("desktop_status"),
  open: (destination: "setup" | "dashboard" | "settings") =>
    invoke<void>("open_network", { destination }),
  pair: (code: string) => invoke<void>("pair_node", { code }),
  control: (action: "start" | "pause" | "resume" | "stop") =>
    invoke<void>("control_node", { action }),
  connectX: (id: string, concurrency: number, authToken: string, ct0: string) =>
    invoke<void>("connect_x", { id, concurrency, authToken, ct0 }),
  browserProfiles: () => invoke<BrowserProfile[]>("browser_profiles"),
  importX: (profile: string, id: string, concurrency: number, consent: boolean) =>
    invoke<void>("import_x_profile", { profile, id, concurrency, consent }),
  connectCodex: (id: string, concurrency: number) =>
    invoke<void>("connect_codex", { id, concurrency }),
  remove: (service: string, id: string) =>
    invoke<void>("remove_account", { service, id }),
  cancelLogin: () => invoke<void>("cancel_login"),
  localApi: (action: "start" | "stop", port?: number, claudeKey?: string, claudeMode: "subscription" | "api_key" = "subscription") => invoke<void>("control_local_api", { action, port, claude: { mode: claudeMode, key: claudeKey } }),
  claude: (action: "connect" | "cancel" | "disconnect") => invoke<void>("control_claude", { action }),
  localKey: () => invoke<string>("local_api_key"),
};
