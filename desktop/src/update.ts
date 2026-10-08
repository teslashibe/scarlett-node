// What the update notices say, from the native updater's status. Every string
// here is inserted with textContent; links are built natively from a version.
import { updateNotice, type Snapshot } from "./model.ts";

export type UpdateNotes = { title: string; date?: string; highlights: string[] };
export type UpdateStatus = {
  version: string;
  mode: string; // "notify" or "automatic"
  // idle, checking, available, downloading, verifying, ready, scheduled,
  // draining, installing or error
  phase: string;
  latest?: string | null;
  required: boolean;
  notes?: UpdateNotes | null;
  progress?: number | null;
  in_flight?: number | null;
  install_at?: number | null; // Unix ms
  error?: string | null;
  checked_at?: number | null; // Unix ms
  can_install: boolean;
  snoozed: boolean;
  stale: boolean;
  updated?: { version: string; notes?: UpdateNotes | null; offer_automatic: boolean } | null;
  failure?: { version: string; reason: string; rolled_back: boolean } | null;
};

export type UpdateAction = "install" | "download" | "cancel" | "later" | "notes" | "retry";
export type UpdateButton = { action: UpdateAction; label: string };
export type UpdateToast = {
  level: "info" | "required";
  title: string;
  detail: string;
  highlights: string[];
  buttons: UpdateButton[];
  // The release a "What's new" link opens.
  version?: string;
};

const VERSION = /^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/;
export const validVersion = (v: unknown): v is string => typeof v === "string" && v.length <= 64 && VERSION.test(v);

export function updateErrorText(code: string | null | undefined): string {
  return ({
    network: "Scarlett couldn't reach the download server. It tries again later",
    signature_invalid: "The download did not pass its signature check, so it was not installed",
    identity_mismatch: "The update is not signed with Scarlett's certificate, so it was not installed",
    requirement_changed: "This update has a new signing identity. Install it from the download page",
    disk_full: "There is not enough free disk space to download the update",
    not_writable: "Scarlett Node can't replace itself in this folder. Reinstall it in Applications (Mac) or for your user (Windows), or update from the download page",
    translocated: "Move Scarlett Node to the Applications folder to turn on updates",
    app_management: "macOS stopped Scarlett from updating itself. Allow Scarlett Node in System Settings › Privacy & Security › App Management, then try again",
    unsupported: "This build can't install updates by itself. Use the download page",
    no_update_key: "This build can't install updates by itself. Use the download page",
    busy: "Waiting for a login or the local model API to finish before updating",
    drain_timeout: "Accepted jobs are taking a long time, so the update waits. It tries again in an hour",
    cancelled: "Update cancelled",
    window_not_ready: "The new version did not open its window",
    node_not_running: "The new version's node did not start",
    node_exited: "The new version's node stopped",
    app_exited: "The new version closed while starting",
    health_timeout: "The new version did not finish starting",
    launch_failed: "The new version could not be opened",
  } as Record<string, string>)[String(code)] ?? "The update could not be installed";
}

const highlightsOf = (notes: UpdateNotes | null | undefined) =>
  (notes?.highlights ?? []).filter((h) => typeof h === "string").slice(0, 3);

/**
 * The toast, or null. Required updates cannot be dismissed. In automatic
 * mode there is no "available" toast: only the countdown, progress and
 * problems appear. Without the native updater (older shells, previews), the
 * coordinator's release notice still shows a download link.
 */
export function updateToast(u: UpdateStatus | undefined, s: Snapshot | undefined, dismissed: string, now = Date.now()): UpdateToast | null {
  if (!u) {
    const notice = s ? updateNotice(s) : null;
    if (!notice || (notice.level === "available" && dismissed === notice.latest)) return null;
    return { level: notice.level === "required" ? "required" : "info", title: notice.text, detail: "", highlights: [],
      buttons: [{ action: "download", label: "Download update ↗" }, ...(notice.level === "available" ? [{ action: "later" as const, label: "Later" }] : [])] };
  }
  const latest = validVersion(u.latest) ? u.latest : undefined;
  const notes = u.notes && latest ? u.notes : null;
  const install: UpdateButton = u.can_install ? { action: "install", label: "Update now" } : { action: "download", label: "Download ↗" };
  const whatsNew: UpdateButton[] = latest ? [{ action: "notes", label: "What's new ↗" }] : [];
  const base = { highlights: highlightsOf(notes), version: latest };
  // The coordinator's minimum is authoritative for "required": the notice
  // stays up from the first status poll, before the updater's first check
  // and while the download manifest is unreachable.
  const coordinator = s ? updateNotice(s) : null;
  const required = u.required || coordinator?.level === "required";
  switch (u.phase) {
    case "downloading":
      return { ...base, level: "info", title: `Downloading Scarlett Node ${latest ?? ""}${typeof u.progress === "number" ? ` · ${u.progress} %` : ""}`.trim(),
        detail: notes?.title ?? "", buttons: [{ action: "cancel", label: "Cancel" }] };
    case "verifying":
      return { ...base, level: "info", title: `Checking Scarlett Node ${latest ?? ""}`.trim(), detail: "Verifying its signature before anything is installed", buttons: [] };
    case "draining": {
      const n = u.in_flight ?? 0;
      return { ...base, level: "info", title: `Finishing ${n} accepted ${n === 1 ? "job" : "jobs"} before updating`,
        detail: "New jobs are paused. Accepted jobs are never interrupted", buttons: [{ action: "cancel", label: "Cancel" }] };
    }
    case "installing":
      return { ...base, level: "info", title: "Installing and restarting…", detail: `Scarlett Node ${latest ?? ""} opens by itself when it's ready`.replace("  ", " "), buttons: [] };
    case "scheduled": {
      const seconds = Math.max(0, Math.ceil(((u.install_at ?? now) - now) / 1000));
      return { ...base, level: required ? "required" : "info", title: `Installing Scarlett Node ${latest ?? ""} when current jobs finish`,
        detail: `Starts in ${seconds} s`, buttons: [{ action: "later", label: "Install later" }, ...whatsNew] };
    }
  }
  if (u.phase === "error" && latest && u.error && u.error !== "cancelled") {
    return { ...base, level: required ? "required" : "info", title: `Scarlett Node ${latest} was not installed`, detail: updateErrorText(u.error),
      buttons: [{ action: "download", label: "Download manually ↗" }, ...(u.can_install && u.error === "network" ? [{ action: "retry" as const, label: "Try again" }] : []), ...whatsNew,
        ...(required ? [] : [{ action: "later" as const, label: "Later" }])] };
  }
  if (required && latest) {
    const automatic = u.mode === "automatic" && u.can_install;
    return { ...base, level: "required", title: "Update required",
      detail: `Scarlett Node ${u.version} no longer receives new jobs; jobs it already accepted still finish. ${automatic ? `Scarlett installs ${latest} as soon as it is ready` : `Install ${latest} to keep earning`}`,
      buttons: automatic ? whatsNew : [install, ...whatsNew] };
  }
  // Required, but the updater has not (yet) found the release in the
  // download manifest: keep the notice and offer the download page.
  if (required && coordinator) {
    return { level: "required", title: "Update required", highlights: [], version: coordinator.latest,
      detail: `Scarlett Node ${u.version} no longer receives new jobs; jobs it already accepted still finish. Install ${coordinator.latest} to keep earning`,
      buttons: [{ action: "download", label: "Download update ↗" }, { action: "notes", label: "What's new ↗" }] };
  }
  if (latest && u.mode !== "automatic" && !u.snoozed && dismissed !== latest) {
    return { ...base, level: "info", title: `Scarlett Node ${latest} is available`, detail: notes?.title ?? "",
      buttons: [install, ...whatsNew, { action: "later", label: "Later" }] };
  }
  // The coordinator announced a release the download manifest has not listed
  // for an hour: offer the download page only.
  const announced = s?.observation?.latest_release;
  if (u.stale && validVersion(announced) && dismissed !== announced) {
    return { level: "info", title: `Scarlett Node ${announced} is available`, detail: "Download it from the network site", highlights: [],
      buttons: [{ action: "download", label: "Download ↗" }, { action: "later", label: "Later" }], version: announced };
  }
  return null;
}

export type UpdateBanner = { title: string; highlights: string[]; version: string; offerAutomatic: boolean };
export function updatedBanner(u: UpdateStatus | undefined): UpdateBanner | null {
  const b = u?.updated;
  if (!b || !validVersion(b.version)) return null;
  return { title: `Updated to Scarlett Node ${b.version}`, highlights: highlightsOf(b.notes), version: b.version, offerAutomatic: b.offer_automatic === true && u?.mode !== "automatic" };
}

export function failureNotice(u: UpdateStatus | undefined): { title: string; detail: string } | null {
  const f = u?.failure;
  if (!f || !validVersion(f.version)) return null;
  if (f.rolled_back)
    return { title: `Scarlett Node ${f.version} could not start`, detail: `Scarlett restored ${u!.version}. ${updateErrorText(f.reason)}. Automatic updates will skip ${f.version}; you can download it manually` };
  return { title: `Scarlett Node ${f.version} was not installed`, detail: updateErrorText(f.reason) };
}

export function updateSummary(u: UpdateStatus | undefined, s?: Snapshot): string {
  if (!u) return "Checking for updates";
  const coordinator = s ? updateNotice(s) : null;
  const latest = validVersion(u.latest) ? u.latest : coordinator?.level === "required" ? coordinator.latest : undefined;
  const required = u.required || coordinator?.level === "required";
  const state = required && latest ? `Update required: ${latest}`
    : u.phase === "checking" ? "Checking…"
    : latest ? `${latest} available`
    : u.error === "network" ? "Couldn't check"
    : "Up to date";
  const checked = typeof u.checked_at === "number"
    ? ` · checked ${new Date(u.checked_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
    : "";
  return `Version ${u.version} · ${state}${checked}`;
}
