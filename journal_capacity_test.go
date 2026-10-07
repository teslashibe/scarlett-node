package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// dayOfReceipts is the journal a desktop node keeps after a night of buyer X
// reads: count finished receipts acknowledged over the last ten hours, all
// within Retention, mostly proven, some failed and one refused before
// acceptance.
func dayOfReceipts(count int, now time.Time) []attempts.Record {
	sent, received := uint64(106689), uint64(100322)
	records := make([]attempts.Record, count)
	for i := range records {
		at := now.Add(-10 * time.Hour).Add(time.Duration(i) * 10 * time.Hour / time.Duration(count))
		r := attempts.Record{ProviderAccountID: "browser-firefox", ProviderService: "x_read", JobID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), Attempt: fmt.Sprintf("00000000-0000-4000-9000-%012d", i), Fence: fmt.Sprintf("00000000-0000-4000-a000-%012d", i), State: "terminal", Kind: "proven", Deadline: at.Add(75 * time.Second).UTC(), UpdatedAt: at.UTC()}
		r.Fingerprint = attempts.Hash([]byte("lease " + r.JobID))
		if i == 0 {
			// Refused before acceptance: no report and no traffic.
			r.Kind = ""
		} else {
			if i%16 == 0 {
				r.Kind = "fail"
			}
			r.SubmissionSHA256 = attempts.Hash([]byte("report " + r.JobID))
			r.ProofTraffic = &attempts.ProofTraffic{Schema: 1, LeaseFingerprint: r.Fingerprint, Layer: "tcp_payload", MaxSamples: 1, WorkerFinished: true, Samples: []attempts.ProofSample{{Ordinal: 1, State: "complete", SentBytes: &sent, ReceivedBytes: &received}}}
		}
		records[i] = r
	}
	return records
}

// seedJournal writes records as an earlier node process left them.
func seedJournal(t *testing.T, stateDir string, records ...attempts.Record) {
	t.Helper()
	dir := filepath.Join(stateDir, "attempts")
	if err := localfs.EnsureDir(stateDir); err != nil {
		t.Fatal(err)
	}
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(dir, r.Key()+".json")
		// Windows privacy needs the protected write; Unix only needs 0600.
		if runtime.GOOS == "windows" {
			err = writePrivateFixture(name, raw, 0600)
		} else {
			err = os.WriteFile(name, raw, 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// heldHeartbeats records each heartbeat and holds it until the node hangs up.
// Attempt reconciliation is unavailable, so unfinished attempts stay pending.
func heldHeartbeats(t *testing.T, arrivals chan<- coordinator.Heartbeat) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/v1/heartbeat" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var h coordinator.Heartbeat
		if json.NewDecoder(r.Body).Decode(&h) != nil {
			t.Error("invalid heartbeat")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		arrivals <- h
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}
}

func firstHeartbeat(t *testing.T, arrivals <-chan coordinator.Heartbeat) coordinator.Heartbeat {
	t.Helper()
	select {
	case h := <-arrivals:
		return h
	case <-time.After(15 * time.Second):
		t.Fatal("node never heartbeated")
	}
	return coordinator.Heartbeat{}
}

func localStatus(t *testing.T, stateDir string) (runtimeStatus, string) {
	t.Helper()
	t.Setenv("SCARLETT_STATE_DIR", stateDir)
	var out bytes.Buffer
	if err := localCommand("status", &out); err != nil {
		t.Fatal(err)
	}
	var status runtimeStatus
	if err := json.Unmarshal(out.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	return status, out.String()
}

// A node that finished as many attempts as the journal once allowed, and has
// nothing running, must take work as soon as it starts. Every receipt stays
// on disk for its retention.
func TestRunLoopAdvertisesAvailableOverADayOfReceipts(t *testing.T) {
	receipts := dayOfReceipts(attempts.DefaultLimits().MaxRecords, time.Now())
	arrivals := make(chan coordinator.Heartbeat, 8)
	c, stop := startLongPollNodeWith(t, heldHeartbeats(t, arrivals), func(c *config.Config) {
		seedJournal(t, c.StateDir, receipts...)
	})
	if h := firstHeartbeat(t, arrivals); h.State != "available" {
		t.Fatalf("finished receipts held admission: heartbeat %q", h.State)
	}
	status, raw := localStatus(t, c.StateDir)
	capacity := status.JournalCapacity
	if status.JournalFull || bytes.Contains([]byte(raw), []byte("journal_full")) || capacity == nil || capacity.Records != 0 || capacity.TerminalRecords != len(receipts) || capacity.AvailableRecords != attempts.DefaultLimits().MaxRecords || status.UnresolvedAttempts != 0 {
		t.Fatalf("local status after upgrade: %s", raw)
	}
	stop()
	for _, r := range receipts {
		if _, err := os.Stat(filepath.Join(c.StateDir, "attempts", r.Key()+".json")); err != nil {
			t.Fatal("receipt removed within Retention", r.JobID, err)
		}
	}
}

// When unfinished attempts do fill the journal, the node stops advertising
// work and its local status says the journal is why.
func TestRunLoopReportsAFullJournal(t *testing.T) {
	now := time.Now()
	unresolved := attempts.Record{JobID: "00000000-0000-4000-8000-000000000001", Attempt: "00000000-0000-4000-9000-000000000001", Fence: "00000000-0000-4000-a000-000000000001", Fingerprint: attempts.Hash([]byte("synthetic lease")), Deadline: now.Add(time.Minute).UTC(), State: "started", UpdatedAt: now.UTC()}
	arrivals := make(chan coordinator.Heartbeat, 8)
	c, stop := startLongPollNodeWith(t, heldHeartbeats(t, arrivals), func(c *config.Config) {
		c.JournalLimits.MaxRecords = 1
		seedJournal(t, c.StateDir, append(dayOfReceipts(16, now), unresolved)...)
	})
	if h := firstHeartbeat(t, arrivals); h.State != "exhausted" {
		t.Fatalf("full journal advertised %q", h.State)
	}
	status, raw := localStatus(t, c.StateDir)
	if !status.JournalFull || !bytes.Contains([]byte(raw), []byte(`"journal_full":true`)) || status.UnresolvedAttempts != 1 || status.JournalCapacity == nil || status.JournalCapacity.Records != 1 || status.JournalCapacity.AvailableRecords != 0 {
		t.Fatalf("local status hides the full journal: %s", raw)
	}
	stop()
}
