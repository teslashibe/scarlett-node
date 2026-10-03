import { invoke } from "@tauri-apps/api/core";
import type { Snapshot, Preferences } from "./model.ts";
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
  connectCodex: (id: string, concurrency: number) =>
    invoke<void>("connect_codex", { id, concurrency }),
  remove: (service: string, id: string) =>
    invoke<void>("remove_account", { service, id }),
  cancelLogin: () => invoke<void>("cancel_login"),
  localApi: (action: "start" | "stop", port?: number, claudeKey?: string) => invoke<void>("control_local_api", { action, port, claudeKey }),
  localKey: () => invoke<string>("local_api_key"),
};
