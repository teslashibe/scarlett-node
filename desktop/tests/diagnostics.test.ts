import test from "node:test";
import assert from "node:assert/strict";
import { diagnosticsNote, duration, groupTitle, localCapacity, outcomeCounts, phase, recentAttempts, summaryCells, timelineAxes, type DiagnosticsRecord } from "../src/diagnostics.ts";
import type { Snapshot } from "../src/model.ts";

const record: DiagnosticsRecord = {
  id: "a".repeat(64), operation: "search", pages: 2, proof_mode: "relay",
  started_at: "2026-10-05T10:00:00Z", outcome: "success", duration_ms: 2000,
  missing_phases: [], spans: [
    {phase:"helper_wall",source:"node",exchange:1,start_ms:100,duration_ms:900,outcome:"success"},
    {phase:"helper_total",source:"helper",exchange:1,start_ms:0,duration_ms:700,outcome:"success"},
    {phase:"helper_total",source:"helper",exchange:2,start_ms:0,duration_ms:800,outcome:"success"},
  ],
};
test("Unknown timings remain unknown and successful latency groups keep sample count and freshness", () => {
  assert.equal(duration(undefined), "Unknown"); assert.equal(duration(NaN), "Unknown");
  assert.equal(duration(-1), "Unknown"); assert.equal(duration(0), "0 ms"); assert.equal(duration(1500), "1.50 s");
  assert.equal(groupTitle(record), "X search · 2 pages · Relay");
  const cells = summaryCells({...record, samples: 3, p50_ms: 1500, newest_at: record.started_at});
  assert.deepEqual(cells.slice(0,4), ["X search · 2 pages · Relay", "3", "1.50 s", "Unknown"]);
  assert.notEqual(cells[4], "Unknown");
});
test("Helper measurements remain on their own per-page clock axes and are never added to parent time", () => {
  const axes = timelineAxes(record);
  assert.equal(axes.length, 3);
  assert.equal(axes[0].spans[0].start_ms, 100);
  for (const axis of axes.slice(1)) { assert.match(axis.label, /time since helper started/); assert.equal(axis.spans[0].start_ms, 0); }
  assert.equal(axes[1].spans[0].exchange, 1); assert.equal(axes[2].spans[0].exchange, 2);
  assert.equal(phase("SECRET_PROVIDER_DETAIL"), "Unknown phase");
});
test("Recent timelines select the newest twenty and retained outcome counts include failed prefixes", () => {
  const records = Array.from({length:25}, (_, i) => ({...record, id:i.toString(16).padStart(64,"0"),outcome:i%2 ? "success" : "prover_error"}));
  const selected = recentAttempts(records);
  assert.equal(selected.length,20); assert.equal(selected[0].id,records[24].id); assert.equal(selected[19].id,records[5].id);
  assert.equal(records[0].id,"0".repeat(64));
  assert.deepEqual(outcomeCounts(records),[{outcome:"prover_error",count:13},{outcome:"success",count:12}]);
});
test("Optional missing diagnostics and a damaged history explain availability without claiming a node failure", () => {
  assert.match(diagnosticsNote(), /Checking/);
  assert.match(diagnosticsNote({available:false}), /unavailable in this node build/);
  assert.match(diagnosticsNote({available:true,snapshot:{version:1,attempts:[],summaries:[]}}), /No recent measurements/);
  const damaged = diagnosticsNote({available:true,snapshot:{version:1,load_error:"corrupt",attempts:[],summaries:[]}});
  assert.match(damaged, /Node work continues/);
  assert.doesNotMatch(damaged, /corrupt/);
});
test("Current capacity does not count duplicate names as independent X accounts and absent measurements stay unknown", () => {
  const base: Snapshot = {runtime_available:true,accounts_available:true,helper_available:true,codex_login_available:false,paired:true,supervised:true,login_pending:false,accounts:[]};
  assert.match(localCapacity(base), /Unknown verified X accounts · Unknown available X slots · Unknown jobs/);
  const s:Snapshot={...base,accounts:[{id:"one",service:"x_read",concurrency:1},{id:"two",service:"x_read",concurrency:1}],observation:{in_flight:1,services:[{kind:"x_read",capacity:1,in_flight:1}],accounts:[{id:"one",service:"x_read",state:"ready",username:"same_user"},{id:"two",service:"x_read",state:"duplicate_account",username:"same_user"},{id:"old",service:"x_read",state:"draining",username:"removed_user"}]}};
  assert.match(localCapacity(s), /2 saved accounts · 1 verified X account · 0 available X slots · 1 job in flight/);
});
