package diagnostics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const desktopPacingFixturePath = "../../desktop/tests/fixtures/pacing-diagnostics-v1.json"

// desktopPacingFixture uses only synthetic metadata and the real collector.
// Fixed clocks make its wire output reproducible without providers or sleeps.
func desktopPacingFixture(t *testing.T) Snapshot {
	t.Helper()
	s := New(privateDir(t))
	base := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	now := base
	s.wallNow = func() time.Time { return now }
	s.monoNow = func() time.Time { return now }

	for i := range 31 {
		now = base.Add(time.Duration(i) * time.Minute)
		a := s.Begin(Metadata{
			ID:        fmt.Sprintf("synthetic-desktop-pacing-attempt-%02d", i),
			Operation: "search", Pages: 1, ProofMode: "relay",
		})
		if a == nil {
			t.Fatalf("collector rejected synthetic attempt %d", i)
		}
		ctx := a.Context(context.Background())
		measure := func(phase string, exchange int, duration time.Duration) {
			end := Start(ctx, phase, exchange)
			now = now.Add(duration)
			end("success")
		}
		measure("account_acquire", 0, 5*time.Millisecond)
		measure("accept_http", 0, 15*time.Millisecond)
		endWorker := Start(ctx, "worker", 0)
		endPacing := Start(ctx, "pacing_wait", 1)
		if i < 22 {
			// Historical collectors measured this aggregate without fine phases
			// or numerical quota snapshots. Preserve that optional wire shape.
			now = now.Add(time.Duration(800+i*10) * time.Millisecond)
		} else {
			paced := i - 22
			phase, mode := "fixed_gap_wait", "conservative"
			wait, remaining := 750*time.Millisecond, 78-paced
			if paced >= 3 && paced < 6 {
				phase, mode = "quota_spread_wait", "quota_budget"
				wait, remaining = 1400*time.Millisecond, 21-paced
			} else if paced >= 6 {
				phase, mode = "quota_reset_wait", "quota_budget"
				wait, remaining = 3050*time.Millisecond, 0
			}
			captured := now
			reset := captured.Add(45 * time.Second)
			next := captured.Add(wait)
			if phase == "quota_reset_wait" {
				reset = captured.Add(3 * time.Second)
				next = reset.Add(50 * time.Millisecond)
			}
			ObserveQuota(ctx, QuotaSnapshot{
				ObservedAt: captured.Add(-200 * time.Millisecond), CapturedAt: captured,
				NextEligibleAt: next, Exchange: 1, Operation: "search", Mode: mode,
				Limit: 100, Remaining: remaining, Reset: reset,
				Complete: true, Authoritative: true,
			})
			measure(phase, 1, wait)
			measure("jitter_wait", 1, time.Duration(250+paced*25)*time.Millisecond)
		}
		endPacing("success")
		measure("request_encode", 1, time.Millisecond)
		measure("helper_wall", 1, time.Duration(1200+i*10)*time.Millisecond)
		endWorker("success")
		measure("report_http", 0, 20*time.Millisecond)
		a.Finish("success")
	}
	return s.Snapshot()
}

func TestDesktopPacingDiagnosticsFixture(t *testing.T) {
	snapshot := desktopPacingFixture(t)
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if len(raw) > MaxHistoryBytes || snapshot.LoadError != "" || snapshot.Version != Version || snapshot.UpdatedAt == nil || len(snapshot.Attempts) != 31 {
		t.Fatalf("invalid collector fixture: version=%d attempts=%d bytes=%d error=%q", snapshot.Version, len(snapshot.Attempts), len(raw), snapshot.LoadError)
	}
	if !requiredHistoryFields(raw) {
		t.Fatal("collector omitted required timing or quota fields")
	}
	seenIDs := map[string]bool{}
	fineCounts := map[string]int{}
	legacy, paced := 0, 0
	for _, record := range snapshot.Attempts {
		if !validRecord(record) || seenIDs[record.ID] || record.Truncated {
			t.Fatal("collector emitted invalid, duplicate, or truncated fixture record")
		}
		seenIDs[record.ID] = true
		hasFine := false
		jitterCount := 0
		for _, span := range record.Spans {
			switch span.Phase {
			case "fixed_gap_wait", "jitter_wait", "quota_spread_wait", "quota_reset_wait":
				hasFine = true
				fineCounts[span.Phase]++
				if span.Phase == "jitter_wait" {
					jitterCount++
				}
			}
		}
		if !hasFine {
			legacy++
			if len(record.QuotaSnapshots) != 0 {
				t.Fatal("legacy fixture fabricated quota observations")
			}
			continue
		}
		paced++
		if jitterCount != 1 || len(record.QuotaSnapshots) != 1 {
			t.Fatal("paced record lost jitter or bounded quota snapshot")
		}
		q := record.QuotaSnapshots[0]
		if q.Limit != 100 || !q.Complete || !q.Authoritative || q.ObservedAt.IsZero() || q.CapturedAt.IsZero() || q.Reset.IsZero() || q.NextEligibleAt.IsZero() {
			t.Fatal("paced record omitted numerical quota provenance")
		}
	}
	if legacy != 22 || paced != 9 || fineCounts["jitter_wait"] != 9 || fineCounts["fixed_gap_wait"] != 3 || fineCounts["quota_spread_wait"] != 3 || fineCounts["quota_reset_wait"] != 3 {
		t.Fatalf("fixture coverage changed: legacy=%d paced=%d phases=%v", legacy, paced, fineCounts)
	}
	if len(snapshot.Summaries) != 1 || snapshot.Summaries[0].Samples != 31 {
		t.Fatal("collector success summary no longer covers every fixture attempt")
	}

	// Regenerate only this synthetic fixture after a deliberate contract change:
	// SCARLETT_UPDATE_DESKTOP_DIAGNOSTICS_FIXTURE=1 go test ./internal/diagnostics -run '^TestDesktopPacingDiagnosticsFixture$'
	if os.Getenv("SCARLETT_UPDATE_DESKTOP_DIAGNOSTICS_FIXTURE") == "1" {
		if err := os.MkdirAll(filepath.Dir(desktopPacingFixturePath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(desktopPacingFixturePath, raw, 0644); err != nil {
			t.Fatal(err)
		}
	}
	fixture, err := os.ReadFile(desktopPacingFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Snapshot
	if err := strictJSON(fixture, &decoded); err != nil {
		t.Fatal("desktop fixture is not valid diagnostics snapshot JSON", err)
	}
	if !bytes.Equal(fixture, raw) {
		t.Fatal("desktop fixture differs from real collector output; regenerate with SCARLETT_UPDATE_DESKTOP_DIAGNOSTICS_FIXTURE=1")
	}
	t.Logf("diagnostics-v%d: %d synthetic attempts (%d legacy, %d paced), %d bytes", snapshot.Version, len(snapshot.Attempts), legacy, paced, len(fixture))
}

// desktopBytes is the desktop app's estimate of one retained attempt
// (desktop/src/diagnostics.ts historyBytes). The app never receives quota
// snapshots, so it counts one per page for every attempt but a web page.
func desktopBytes(r Record) int {
	total := 700 + 144*len(r.Spans)
	if r.Operation != "scrape" {
		total += quotaSnapshotBytes * r.Pages
	}
	return total
}

// The desktop app says how far back its web page count goes once the node may
// have dropped attempts it still had to keep for 24 hours. Busy web pages fill
// MaxHistoryBytes long before MaxAttempts, so the app must also tell a history
// the node trimmed for size: from the first such drop until old attempts age
// out, its estimate stays within one attempt of the bound.
func TestDesktopSeesWhenHistoryWasTrimmedForSize(t *testing.T) {
	for _, mix := range []struct {
		name  string
		xEach int
	}{{"web pages", 0}, {"web pages and X searches", 5}} {
		t.Run(mix.name, func(t *testing.T) {
			s := New(privateDir(t))
			base := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
			now := base
			s.wallNow = func() time.Time { return now }
			s.monoNow = func() time.Time { return now }
			// What the next snapshot would export, read in place: copying
			// every snapshot makes this test slow under the race detector.
			retained := func() (kept, bytes int) {
				s.mu.Lock()
				defer s.mu.Unlock()
				for _, a := range s.attempts {
					bytes += desktopBytes(a.record)
				}
				return len(s.attempts), bytes
			}
			check := func(begun int) {
				t.Helper()
				kept, bytes := retained()
				if kept < begun && kept < MaxAttempts && bytes < MaxHistoryBytes-MaxAttemptBytes {
					t.Fatalf("after %d attempts the node kept %d (%d estimated bytes), which the desktop would read as a whole day", begun, kept, bytes)
				}
			}
			for i := range 400 {
				now = base.Add(time.Duration(i) * 90 * time.Second)
				x := mix.xEach > 0 && i%mix.xEach == 0
				meta := Metadata{ID: fmt.Sprintf("desktop-trim-%03d", i), Operation: "scrape", Pages: 1, ProofMode: "relay"}
				if x {
					meta.Operation, meta.Pages = "search", 3
				}
				a := s.Begin(meta)
				if a == nil {
					t.Fatalf("collector rejected attempt %d", i)
				}
				check(i + 1)
				ctx := a.Context(context.Background())
				for range 37 {
					end := Start(ctx, "journal_write", 0)
					now = now.Add(time.Millisecond)
					end("success")
				}
				if x {
					for exchange := 1; exchange <= 3; exchange++ {
						ObserveQuota(ctx, QuotaSnapshot{
							ObservedAt: now.Add(-time.Millisecond), CapturedAt: now, NextEligibleAt: now.Add(time.Second),
							Exchange: exchange, Operation: "search", Mode: "conservative", Limit: 100, Remaining: 50,
							Reset: now.Add(time.Minute), Complete: true, Authoritative: true,
						})
					}
				}
				a.Finish("success")
				check(i + 1)
			}
			snapshot := s.Snapshot().Attempts
			bytes := 0
			for _, r := range snapshot {
				bytes += desktopBytes(r)
			}
			if kept, inPlace := retained(); len(snapshot) != kept || bytes != inPlace {
				t.Fatalf("snapshot exports %d attempts (%d bytes), store holds %d (%d bytes)", len(snapshot), bytes, kept, inPlace)
			}
			if len(snapshot) >= MaxAttempts {
				t.Fatalf("kept %d attempts; this test needs the size bound to bind first", len(snapshot))
			}
			t.Logf("kept %d of 400 attempts, %d estimated bytes for the desktop", len(snapshot), bytes)
		})
	}
}
