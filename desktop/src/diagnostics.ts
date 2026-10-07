import type { Snapshot } from "./model.ts";

export type DiagnosticsOperation = "search" | "profile" | "post" | "thread" | "codex" | "other";
export type DiagnosticsProof = "relay" | "mpc" | "none";
export type DiagnosticsSpan = {
  phase: string; source: "node" | "helper"; exchange: number;
  start_ms: number; duration_ms: number; outcome: string;
};
export type DiagnosticsRecord = {
  id: string; operation: DiagnosticsOperation; pages: number; proof_mode: DiagnosticsProof;
  started_at: string; outcome: string; duration_ms?: number;
  spans: DiagnosticsSpan[]; missing_phases: string[]; unclassified_ms?: number; truncated?: boolean;
};
export type DiagnosticsSummary = {
  operation: DiagnosticsOperation; pages: number; proof_mode: DiagnosticsProof;
  samples: number; p50_ms?: number; p95_ms?: number; newest_at: string;
};
export type Diagnostics = {
  available: boolean;
  snapshot?: { version: 1; updated_at?: string; load_error?: string; attempts: DiagnosticsRecord[]; summaries: DiagnosticsSummary[] };
};
export const duration = (ms: number | undefined): string =>
  ms === undefined || !Number.isFinite(ms) || ms < 0 ? "Unknown" : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(2)} s`;
export const clockTime = (value?: string): string => {
  const date = new Date(value ?? "");
  return Number.isFinite(date.getTime()) ? date.toLocaleString() : "Unknown";
};
export const operation = (value: DiagnosticsOperation): string =>
  ({ search: "X search", profile: "X profile", post: "X post", thread: "X thread", codex: "Codex", other: "Other work" })[value];
export const proof = (value: DiagnosticsProof): string => ({ relay: "Relay", mpc: "MPC", none: "No proof" })[value];
export const groupTitle = (value: {operation: DiagnosticsOperation; pages: number; proof_mode: DiagnosticsProof}): string =>
  `${operation(value.operation)} · ${value.pages} ${value.pages === 1 ? "page" : "pages"} · ${proof(value.proof_mode)}`;
export const outcome = (value: string): string => value.replaceAll("_", " ");
const phases: Record<string, string> = {
  worker_acquire: "Worker admission", account_acquire: "Account admission", accept_http: "Accept request",
  worker: "Worker execution", client_acquire: "Get X client", client_rebuild: "Rebuild X client",
  binding_check: "Session binding check", page_wall: "Page total", pacing_wait: "Request pacing wait",
  quota_wait: "Provider quota wait", fixed_gap_wait: "Minimum request gap", jitter_wait: "Request jitter",
  quota_spread_wait: "Quota pacing spread", quota_reset_wait: "Provider quota reset wait",
  request_encode: "Encode request", proof_journal_begin: "Journal before proof",
  helper_wall: "Helper process total", helper_stdout_decode: "Decode helper output", response_decode: "Decode response",
  proof_journal_complete: "Journal after proof", journal_lock: "Journal lock", journal_scan: "Journal scan",
  journal_write: "Journal write", journal_finish: "Journal finish", journal_ready: "Journal ready",
  journal_terminal: "Journal terminal", report_prepare: "Prepare report", report_http: "Report request",
  helper_total: "Helper internal total", control_config: "Control configuration", verifier_tcp_connect: "Verifier TCP connection",
  verifier_tls: "Verifier TLS", x_tcp_connect: "X TCP connection", relay_session: "Relay session",
  x_tls_ready: "X TLS ready, includes first request flush", ot_ready: "OT ready, includes commit, preprocessing and verifier admission",
  relay_authorization: "Relay authorization, includes remaining TLS, OT and admission",
  request_sent: "Request sent", response_first_byte: "First response byte over the proof path", response_complete: "Response complete",
  opening_check: "Opening check", proof_finalize: "Finalize proof",
};
export const phase = (value: string): string => phases[value] ?? "Unknown phase";
export function diagnosticsNote(value?: Diagnostics): string {
  if (!value) return "Checking local measurements";
  if (!value.available || !value.snapshot) return "Local measurements are unavailable in this node build";
  if (value.snapshot.load_error) return "Some local measurements could not be loaded. Node work continues";
  if (!value.snapshot.attempts.length) return "No recent measurements yet. Run a network job to capture a timeline";
  return `Saved locally · updated ${clockTime(value.snapshot.updated_at)}`;
}
export function summaryCells(summary: DiagnosticsSummary): string[] {
  return [groupTitle(summary), String(summary.samples), duration(summary.p50_ms), duration(summary.p95_ms), clockTime(summary.newest_at)];
}
export const recentAttempts = (records: DiagnosticsRecord[]): DiagnosticsRecord[] => records.slice(-20).reverse();
export function outcomeCounts(records: DiagnosticsRecord[]): {outcome: string; count: number}[] {
  const counts = new Map<string, number>();
  for (const record of records) counts.set(record.outcome, (counts.get(record.outcome) ?? 0) + 1);
  return [...counts].sort(([a], [b]) => a.localeCompare(b)).map(([outcome, count]) => ({outcome, count}));
}
export function availableXSlots(s: Snapshot): number | undefined {
  const x = s.observation?.services?.find((v) => v.kind === "x_read");
  return x?.capacity === undefined || x.in_flight === undefined || x.state === undefined || s.observation?.state === undefined
    ? undefined
    : s.observation.state !== "running" || s.observation.drain_requested || (x.state !== "configured" && x.state !== "ready")
      ? 0
      : Math.max(0, x.capacity - x.in_flight);
}
export function localCapacity(s: Snapshot): string {
  const verified = s.observation?.accounts?.filter((a) => a.service === "x_read" && a.state !== "duplicate_account" && a.state !== "identity_unverified" && a.state !== "draining");
  const verifiedCount = verified?.every((a) => a.username) ? new Set(verified.map((a) => a.username!.toLowerCase())).size : undefined;
  const next = s.observation?.accounts?.map((a) => Date.parse(a.rest_until ?? "")).filter((at) => Number.isFinite(at) && at > Date.now());
  const capacity = availableXSlots(s) ?? "Unknown";
  const count = (n: number | "Unknown", singular: string) => `${n} ${singular}${n === 1 ? "" : "s"}`;
  return `${count(s.accounts.length, "saved account")} · ${count(verifiedCount ?? "Unknown", "verified X account")} · ${count(capacity, "available X slot")} · ${count(s.observation?.in_flight ?? "Unknown", "job")} in flight${next?.length ? ` · earliest cooldown end ${clockTime(new Date(Math.min(...next)).toISOString())}` : ""}${s.observation?.updated_at ? ` · status ${clockTime(s.observation.updated_at)}` : ""}`;
}

// Helper times start inside each helper process. They are never placed on the
// node's axis or summed with overlapping parent spans.
export function timelineAxes(record: DiagnosticsRecord): { label: string; spans: DiagnosticsSpan[] }[] {
  const axes = [{ label: "Node clock · time since attempt started", spans: record.spans.filter((s) => s.source === "node") }];
  for (const exchange of [1, 2, 3]) {
    const spans = record.spans.filter((s) => s.source === "helper" && s.exchange === exchange);
    if (spans.length) axes.push({ label: `Helper clock · page ${exchange} · time since helper started`, spans });
  }
  return axes;
}

export function renderDiagnostics(element: HTMLElement, value?: Diagnostics): void {
  const savedOpen = new Set(Array.from(element.querySelectorAll<HTMLDetailsElement>("details[open]")).map((el) => el.dataset.attempt));
  const focused = element.contains(document.activeElement)
    ? document.activeElement?.closest<HTMLDetailsElement>("details")?.dataset.attempt : undefined;
  const root = document.createElement("div");
  const records = value?.snapshot?.attempts ?? [];
  if (records.length) {
    const counts = document.createElement("p"); counts.className = "muted";
    counts.textContent = `Retained attempt outcomes · ${outcomeCounts(records).map((v) => `${v.count} ${outcome(v.outcome)}`).join(" · ")}`;
    root.append(counts);
  }
  const summaries = value?.snapshot?.summaries ?? [];
  if (summaries.length) {
    const table = document.createElement("table"); table.className = "diagnostics-table";
    const caption = document.createElement("caption"); caption.textContent = "Recent successful attempts by operation, page count and proof mode"; table.append(caption);
    const head = document.createElement("thead"); const row = document.createElement("tr");
    for (const label of ["Work", "Samples", "p50", "p95", "Newest sample"]) {
      const cell = document.createElement("th"); cell.scope = "col"; cell.textContent = label; row.append(cell);
    }
    head.append(row); table.append(head); const body = document.createElement("tbody");
    for (const summary of summaries) {
      const row = document.createElement("tr");
      for (const text of summaryCells(summary)) {
        const cell = document.createElement("td"); cell.textContent = text; row.append(cell);
      }
      body.append(row);
    }
    table.append(body); const scroll = document.createElement("div"); scroll.className = "diagnostics-scroll"; scroll.append(table); root.append(scroll);
  }
  for (const record of recentAttempts(records)) {
    const detail = document.createElement("details"); detail.className = "diagnostics-attempt"; detail.dataset.attempt = record.id; detail.open = savedOpen.has(record.id);
    const title = document.createElement("summary"); title.textContent = `${groupTitle(record)} · ${outcome(record.outcome)} · ${duration(record.duration_ms)} · ${clockTime(record.started_at)}`; detail.append(title);
    const note = document.createElement("p"); note.className = "muted";
    note.textContent = `Unclassified node time: ${duration(record.unclassified_ms)}${record.missing_phases.length ? ` · Missing: ${record.missing_phases.map(phase).join(", ")}` : ""}${record.truncated ? " · Timeline reached the local recording limit" : ""}`; detail.append(note);
    for (const axis of timelineAxes(record)) {
      const title = document.createElement("h3"); title.textContent = axis.label; detail.append(title);
      const list = document.createElement("ol"); list.className = "diagnostics-spans";
      for (const span of axis.spans) {
        const timing = span.duration_ms === 0 ? `milestone at ${duration(span.start_ms)}` : `starts ${duration(span.start_ms)} · lasts ${duration(span.duration_ms)}`;
        const item = document.createElement("li"); item.textContent = `${phase(span.phase)}${span.source === "node" && span.exchange ? ` · page ${span.exchange}` : ""} · ${timing} · ${outcome(span.outcome)}`; list.append(item);
      }
      if (!axis.spans.length) { const item = document.createElement("li"); item.textContent = "No measurements captured on this clock"; list.append(item); }
      detail.append(list);
    }
    root.append(detail);
  }
  if (root.innerHTML !== element.innerHTML) {
    element.replaceChildren(...root.childNodes);
    if (focused) {
      const detail = Array.from(element.querySelectorAll<HTMLDetailsElement>("details")).find((el) => el.dataset.attempt === focused);
      (detail?.querySelector<HTMLElement>("summary") ?? element.closest("section")?.querySelector<HTMLElement>("h2"))?.focus({ preventScroll: true });
    }
  }
}
