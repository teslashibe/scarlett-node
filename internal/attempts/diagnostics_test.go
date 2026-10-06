package attempts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/diagnostics"
)

func diagnosticAttempt(store *diagnostics.Store, r Record) *diagnostics.Attempt {
	return store.Begin(diagnostics.Metadata{ID: r.Key(), Operation: "search", Pages: 1, ProofMode: "relay"})
}

func diagnosticRecord(t *testing.T, store *diagnostics.Store, id string) diagnostics.Record {
	t.Helper()
	for _, r := range store.Snapshot().Attempts {
		if r.ID == id {
			return r
		}
	}
	t.Fatal("missing attempt diagnostics")
	return diagnostics.Record{}
}

func TestContextJournalKeepsExactRecoveryAndProofTraffic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	store := diagnostics.New(filepath.Join(t.TempDir(), "diagnostics"))
	attempt := diagnosticAttempt(store, r)
	ctx, cancel := context.WithCancel(attempt.Context(context.Background()))
	cancel() // Diagnostic context cancellation must not change durable journal work.
	if err := j.BeginContext(ctx, r); err != nil {
		t.Fatal(err)
	}
	ordinal, err := j.BeginProofContext(ctx, r, 1)
	if err != nil || ordinal != 1 {
		t.Fatal(ordinal, err)
	}
	if err := j.CompleteProofContext(ctx, r, trafficSample(ordinal, 0, 7)); err != nil {
		t.Fatal(err)
	}
	if err := j.FinishProofTrafficContext(ctx, r); err != nil {
		t.Fatal(err)
	}
	body := []byte("{\n  \"version\": \"node-v1\", \"private\": \"synthetic\"\n}")
	ready, err := j.ReadyContext(ctx, r, "proven", body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ready.Body, body) || ready.SubmissionSHA256 != Hash(body) {
		t.Fatal("diagnostics changed exact report bytes")
	}
	j.Close()
	j = open(t, dir)
	pending, err := j.Pending()
	if err != nil || len(pending) != 1 || !bytes.Equal(pending[0].Body, body) || pending[0].ProofTraffic == nil || !pending[0].ProofTraffic.WorkerFinished || *pending[0].ProofTraffic.Samples[0].SentBytes != 0 {
		t.Fatal("instrumented writes changed recovery", err)
	}
	if err := j.BeginContext(ctx, r); !errors.Is(err, ErrExists) {
		t.Fatal("instrumented attempt became replayable", err)
	}
	if err := j.TerminalContext(ctx, pending[0]); err != nil {
		t.Fatal(err)
	}
	attempt.Finish("success")
	raw, err := os.ReadFile(filepath.Join(dir, key(r)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(`"body"`), []byte("journal_lock"), []byte("duration_ms")} {
		if bytes.Contains(raw, forbidden) {
			t.Fatal("recovery record contains removed body or diagnostics")
		}
	}
	timeline := diagnosticRecord(t, store, r.Key())
	phases := map[string]bool{}
	for _, span := range timeline.Spans {
		phases[span.Phase] = true
		if span.Source != "node" || span.Exchange != 0 || span.Outcome != "success" {
			t.Fatal("invalid journal timing attribution", span)
		}
	}
	for _, phase := range []string{"journal_lock", "journal_scan", "journal_write"} {
		if !phases[phase] {
			t.Fatal("missing journal timing", phase)
		}
	}
}

func TestContextJournalMeasuresMutexWait(t *testing.T) {
	j := open(t, filepath.Join(t.TempDir(), "attempts"))
	r := fixture()
	store := diagnostics.New(filepath.Join(t.TempDir(), "diagnostics"))
	attempt := diagnosticAttempt(store, r)
	j.mu.Lock()
	locked := true
	defer func() {
		if locked {
			j.mu.Unlock()
		}
	}()
	entered := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		close(entered)
		result <- j.BeginContext(attempt.Context(context.Background()), r)
	}()
	<-entered
	deadline := time.Now().Add(5 * time.Second)
	for {
		started := false
		for _, span := range diagnosticRecord(t, store, r.Key()).Spans {
			if span.Phase == "journal_lock" && span.Outcome == "running" {
				started = true
			}
		}
		if started {
			break
		}
		if time.Now().After(deadline) {
			j.mu.Unlock()
			locked = false
			<-result
			t.Fatal("journal lock timer never started")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-result:
		j.mu.Unlock()
		locked = false
		t.Fatal("journal bypassed existing mutex", err)
	case <-time.After(30 * time.Millisecond):
	}
	j.mu.Unlock()
	locked = false
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	attempt.Finish("success")
	for _, span := range diagnosticRecord(t, store, r.Key()).Spans {
		if span.Phase == "journal_lock" {
			if span.DurationMS < 10 {
				t.Fatal("mutex wait was omitted from journal timing", span)
			}
			return
		}
	}
	t.Fatal("missing mutex timing")
}

func TestContextJournalScanFailureHasOnlyCompletedPrefix(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	store := diagnostics.New(filepath.Join(t.TempDir(), "diagnostics"))
	attempt := diagnosticAttempt(store, r)
	if err := os.WriteFile(filepath.Join(dir, "unexpected"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := j.BeginContext(attempt.Context(context.Background()), r); err == nil {
		t.Fatal("diagnostics hid scan failure")
	}
	attempt.Finish("journal_error")
	var scanFailed bool
	for _, span := range diagnosticRecord(t, store, r.Key()).Spans {
		if span.Phase == "journal_scan" && span.Outcome == "error" {
			scanFailed = true
		}
		if span.Phase == "journal_write" {
			t.Fatal("reported a write that did not run")
		}
	}
	if !scanFailed {
		t.Fatal("missing failed scan prefix")
	}
	if _, err := os.Stat(filepath.Join(dir, key(r)+".json")); !os.IsNotExist(err) {
		t.Fatal("scan failure accepted an attempt", err)
	}
}

func TestContextJournalConcurrentAttemptsKeepTimingsSeparate(t *testing.T) {
	j := open(t, filepath.Join(t.TempDir(), "attempts"))
	store := diagnostics.New(filepath.Join(t.TempDir(), "diagnostics"))
	const count = 8
	var wg sync.WaitGroup
	for i := range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := fixture()
			r.JobID = fmt.Sprintf("diagnostic-job-%d", i)
			attempt := diagnosticAttempt(store, r)
			ctx := attempt.Context(context.Background())
			if err := j.BeginContext(ctx, r); err != nil {
				t.Error(err)
				return
			}
			body := []byte(fmt.Sprintf(`{"synthetic":%d}`, i))
			if _, err := j.ReadyContext(ctx, r, "fail", body); err != nil {
				t.Error(err)
				return
			}
			attempt.Finish("success")
		}()
	}
	wg.Wait()
	pending, err := j.Pending()
	if err != nil || len(pending) != count {
		t.Fatal("concurrent durable records lost", err)
	}
	for _, r := range pending {
		var writes int
		for _, span := range diagnosticRecord(t, store, r.Key()).Spans {
			if span.Phase == "journal_write" {
				writes++
			}
		}
		if writes != 2 {
			t.Fatal("journal writes crossed attempt contexts", r.JobID, writes)
		}
	}
}
