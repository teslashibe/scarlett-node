import { invoke } from "@tauri-apps/api/core";
import type { Snapshot } from "./model.ts";
export const api = {
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
};
