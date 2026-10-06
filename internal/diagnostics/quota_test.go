package diagnostics

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPrivateQuotaSnapshotsBoundedPersistedAndStrict(t *testing.T) {
	s := New(privateDir(t))
	a := s.Begin(metadata("private-query-account-cookie-fixture"))
	ctx := a.Context(context.Background())
	now := time.Now().UTC()
	q := QuotaSnapshot{Exchange: 1, Operation: "search", Mode: "quota_budget", Limit: 100, Remaining: 21, Reset: now.Add(time.Minute), Complete: true, Authoritative: true, ObservedAt: now.Add(-time.Second), CapturedAt: now, NextEligibleAt: now.Add(time.Second)}
	for exchange := 1; exchange <= MaxExchanges+1; exchange++ {
		q.Exchange = exchange
		ObserveQuota(ctx, q)
	}
	q.Exchange, q.Remaining = 1, 20
	ObserveQuota(ctx, q)
	q.Operation = "cookie-private"
	ObserveQuota(ctx, q)
	a.Finish("success")
	s.Close()
	waitForClose(t, s)
	loaded := Read(s.dir)
	if loaded.LoadError != "" || len(loaded.Attempts) != 1 || len(loaded.Attempts[0].QuotaSnapshots) != MaxExchanges || loaded.Attempts[0].QuotaSnapshots[0].Remaining != 20 {
		t.Fatal("quota evidence was not bounded and retained", loaded)
	}
	raw, err := json.Marshal(loaded.Attempts[0])
	if err != nil || strings.Contains(string(raw), "private") || strings.Contains(string(raw), "fixture") {
		t.Fatal("opaque metadata reached quota diagnostics", err)
	}
	stored := history{Version: Version, UpdatedAt: now, Attempts: loaded.Attempts}
	raw, _ = json.Marshal(stored)
	var document map[string]any
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("fixture decode failed")
	}
	record := document["attempts"].([]any)[0].(map[string]any)
	snapshot := record["quota_snapshots"].([]any)[0].(map[string]any)
	delete(snapshot, "remaining")
	raw, _ = json.Marshal(document)
	if requiredHistoryFields(raw) {
		t.Fatal("missing remaining became observed zero")
	}
	snapshot["remaining"] = nil
	raw, _ = json.Marshal(document)
	if requiredHistoryFields(raw) {
		t.Fatal("null remaining became observed zero")
	}
	delete(record, "quota_snapshots")
	raw, _ = json.Marshal(document)
	if !requiredHistoryFields(raw) {
		t.Fatal("legacy history required new optional quota evidence")
	}
}

func TestQuotaSnapshotRejectsImpossibleProvenance(t *testing.T) {
	now := time.Now()
	q := QuotaSnapshot{Exchange: 1, Operation: "search", Mode: "conservative", CapturedAt: now}
	if !validQuota(q, now) {
		t.Fatal("missing provider observation must remain explicitly unknown")
	}
	q.Authoritative = true
	if validQuota(q, now) {
		t.Fatal("authoritative reset had no reset timestamp")
	}
	q.Authoritative, q.Complete = false, true
	if validQuota(q, now) {
		t.Fatal("complete headers were fabricated from decode defaults")
	}
}
