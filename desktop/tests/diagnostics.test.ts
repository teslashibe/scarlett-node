import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { diagnosticsNote, duration, groupTitle, localCapacity, outcomeCounts, phase, recentAttempts, summaryCells, timelineAxes, xDiagnostics, type Diagnostics, type DiagnosticsRecord } from "../src/diagnostics.ts";
import type { AccountHealth, Snapshot } from "../src/model.ts";

const record: DiagnosticsRecord = {
  id: "a".repeat(64), operation: "search", pages: 2, proof_mode: "relay",
  started_at: "2026-10-05T10:00:00Z", outcome: "success", duration_ms: 2000,
  missing_phases: [], spans: [
    {phase:"helper_wall",source:"node",exchange:1,start_ms:100,duration_ms:900,outcome:"success"},
    {phase:"helper_total",source:"helper",exchange:1,start_ms:0,duration_ms:700,outcome:"success"},
    {phase:"helper_total",source:"helper",exchange:2,start_ms:0,duration_ms:800,outcome:"success"},
  ],
};
test("X-only display excludes model history without modifying retained measurements", () => {
  const value: Diagnostics = {available: true, snapshot: {version: 1,
    load_error: "partial", attempts: [record, {...record, operation: "codex"}],
    summaries: [{...record, samples: 1, newest_at: record.started_at}, {...record, operation: "codex", samples: 1, newest_at: record.started_at}],
  }};
  const before = structuredClone(value);
  const visible = xDiagnostics(value);
  assert.deepEqual(visible.snapshot?.attempts, [record]);
  assert.equal(visible.snapshot?.summaries.length, 1);
  assert.equal(visible.snapshot?.load_error, "partial");
  assert.deepEqual(value, before);
  assert.deepEqual(xDiagnostics({available: false}), {available: false});
});
test("Go-emitted pacing history keeps readable timelines across legacy and new attempts", () => {
  const snapshot = JSON.parse(readFileSync(new URL("./fixtures/pacing-diagnostics-v1.json", import.meta.url), "utf8")) as NonNullable<Diagnostics["snapshot"]>;
  assert.equal(snapshot.attempts.length, 31);
  assert.match(diagnosticsNote({available: true, snapshot}), /Saved locally/);
  const labels = new Map([
    ["fixed_gap_wait", "Minimum request gap"], ["jitter_wait", "Request jitter"],
    ["quota_spread_wait", "Quota pacing spread"], ["quota_reset_wait", "Provider quota reset wait"],
  ]);
  const jitterAttempts = snapshot.attempts.filter((r) => r.spans.some((s) => s.phase === "jitter_wait"));
  assert.equal(jitterAttempts.length, 9);
  for (const [name, label] of labels) {
    assert.equal(phase(name), label);
    assert.ok(snapshot.attempts.some((r) => timelineAxes(r)[0].spans.some((s) => s.phase === name)));
  }
  assert.equal(phase("future_pacing_wait"), "Unknown phase");
  assert.equal(recentAttempts(snapshot.attempts).length, 20);
  assert.equal(recentAttempts(snapshot.attempts)[0].id, snapshot.attempts[30].id);
});
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
  const s:Snapshot={...base,accounts:[{id:"one",service:"x_read",concurrency:1},{id:"two",service:"x_read",concurrency:1}],observation:{state:"running",in_flight:1,services:[{kind:"x_read",state:"ready",capacity:1,in_flight:1}],accounts:[{id:"one",service:"x_read",state:"ready",username:"same_user"},{id:"two",service:"x_read",state:"duplicate_account",username:"same_user"},{id:"old",service:"x_read",state:"draining",username:"removed_user"}]}};
  assert.match(localCapacity(s), /2 saved accounts · 1 verified X account · 0 available X slots · 1 job in flight/);
  s.accounts.push({id: "model", service: "codex", concurrency: 1});
  assert.match(localCapacity(s), /^2 saved accounts ·/);
});
test("Verified X account counts stay unknown when a countable account has no handle", async (t) => {
  const named: AccountHealth = {id: "named", service: "x_read", state: "ready", username: "same_user"};
  const snapshot = (accounts: AccountHealth[]): Snapshot => ({
    runtime_available: true, accounts_available: true, helper_available: true,
    codex_login_available: false, paired: true, supervised: true,
    login_pending: false, accounts: [], observation: {accounts},
  });
  for (const state of ["ready", "configured"]) {
    for (const username of [undefined, ""]) {
      await t.test(`${state} with ${username === undefined ? "a missing" : "an empty"} handle leaves the total unknown`, () => {
        const unnamed: AccountHealth = {id: "unnamed", service: "x_read", state};
        if (username !== undefined) unnamed.username = username;
        assert.match(localCapacity(snapshot([named, unnamed])), /Unknown verified X accounts ·/);
      });
    }
  }
  await t.test("a ready account without a handle leaves its count unknown while its slot remains available", () => {
    const s = snapshot([{id: "one", service: "x_read", state: "ready"}]);
    s.accounts = [{id: "one", service: "x_read", concurrency: 1}];
    s.observation = {
      ...s.observation, state: "running", in_flight: 0,
      services: [{kind: "x_read", state: "ready", capacity: 1, in_flight: 0}],
    };
    assert.match(localCapacity(s), /Unknown verified X accounts · 1 available X slot ·/);
  });
  for (const state of ["duplicate_account", "identity_unverified", "draining"]) {
    for (const username of [undefined, ""]) {
      await t.test(`${state} with ${username === undefined ? "a missing" : "an empty"} handle does not change a known total`, () => {
        const excluded: AccountHealth = {id: "excluded", service: "x_read", state};
        if (username !== undefined) excluded.username = username;
        assert.match(localCapacity(snapshot([named, excluded])), /1 verified X account ·/);
      });
    }
  }
  await t.test("only excluded rows yield zero verified accounts", () => {
    const accounts: AccountHealth[] = [
      {id: "duplicate", service: "x_read", state: "duplicate_account"},
      {id: "unverified", service: "x_read", state: "identity_unverified", username: ""},
      {id: "removed", service: "x_read", state: "draining"},
    ];
    assert.match(localCapacity(snapshot(accounts)), /0 verified X accounts ·/);
  });
  await t.test("an explicit empty account list yields zero verified accounts", () => {
    assert.match(localCapacity(snapshot([])), /0 verified X accounts ·/);
  });
  await t.test("countable named rows still deduplicate handles without regard to case", () => {
    const second: AccountHealth = {id: "second", service: "x_read", state: "configured", username: "SAME_USER"};
    assert.match(localCapacity(snapshot([named, second])), /1 verified X account ·/);
  });
});
test("Available X slots reflect whether the node can admit new work", async (t) => {
  const snapshot = (): Snapshot => ({
    runtime_available: true, accounts_available: true, helper_available: true,
    codex_login_available: false, paired: true, supervised: true,
    login_pending: false, accounts: [{id: "one", service: "x_read", concurrency: 1}],
    observation: {
      state: "running", in_flight: 0, drain_requested: false,
      services: [{kind: "x_read", state: "ready", capacity: 1, in_flight: 0}],
    },
  });
  await t.test("a healthy running service has a free slot", () => {
    assert.match(localCapacity(snapshot()), /1 available X slot ·/);
  });
  await t.test("a configured service can admit work", () => {
    const s = snapshot();
    s.observation!.services![0].state = "configured";
    assert.match(localCapacity(s), /1 available X slot ·/);
  });
  await t.test("a healthy node running outside the app has a free slot", () => {
    const s = snapshot();
    s.supervised = false;
    assert.match(localCapacity(s), /1 available X slot ·/);
  });
  for (const state of ["stopped", "offline", "draining"]) {
    await t.test(`${state} nodes cannot admit work despite saved service capacity`, () => {
      const s = snapshot();
      s.observation!.state = state;
      s.supervised = state === "draining";
      assert.match(localCapacity(s), /0 available X slots ·/);
    });
  }
  await t.test("a drain request disables admission before runtime state changes", () => {
    const s = snapshot();
    s.observation!.drain_requested = true;
    assert.match(localCapacity(s), /0 available X slots ·/);
  });
  await t.test("an exhausted X service cannot admit work despite saved capacity", () => {
    const s = snapshot();
    s.observation!.services![0].state = "exhausted";
    assert.match(localCapacity(s), /0 available X slots ·/);
  });
  for (const field of ["capacity", "in_flight"] as const) {
    await t.test(`missing ${field} keeps available slots unknown`, () => {
      const s = snapshot();
      delete s.observation!.services![0][field];
      assert.match(localCapacity(s), /Unknown available X slots ·/);
    });
  }
  await t.test("missing runtime state keeps available slots unknown", () => {
    const s = snapshot();
    delete s.observation!.state;
    assert.match(localCapacity(s), /Unknown available X slots ·/);
  });
  await t.test("missing service state keeps available slots unknown", () => {
    const s = snapshot();
    delete s.observation!.services![0].state;
    assert.match(localCapacity(s), /Unknown available X slots ·/);
  });
});
