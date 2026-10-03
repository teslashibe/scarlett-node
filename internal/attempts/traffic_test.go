package attempts

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func trafficSample(ordinal int, sent, received uint64) ProofSample {
	return ProofSample{Ordinal: ordinal, State: "complete", SentBytes: &sent, ReceivedBytes: &received}
}

func TestProofTrafficRetainsExactReportAcrossRestartAndTerminal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	if err := j.Begin(r); err != nil {
		t.Fatal(err)
	}
	for ordinal := 1; ordinal <= 3; ordinal++ {
		got, err := j.BeginProof(r, 3)
		if err != nil || got != ordinal {
			t.Fatalf("reserve %d: %d %v", ordinal, got, err)
		}
		sample := trafficSample(ordinal, uint64(ordinal-1), 7)
		if err := j.CompleteProof(r, sample); err != nil {
			t.Fatal(err)
		}
		if err := j.CompleteProof(r, sample); err != nil {
			t.Fatal("identical callback", err)
		}
	}
	if _, err := j.BeginProof(r, 3); !errors.Is(err, ErrConflict) {
		t.Fatal("bound exceeded", err)
	}
	if err := j.FinishProofTraffic(r); err != nil {
		t.Fatal(err)
	}
	body := []byte("{\n \"version\": \"node-v1\", \"attempt\": \"a1\", \"fence\": \"f1\"\n}")
	ready, err := j.Ready(r, "proven", body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ready.Body, body) || ready.SubmissionSHA256 != Hash(body) {
		t.Fatal("telemetry changed report bytes/hash")
	}
	if err := j.CompleteProof(r, trafficSample(1, 0, 7)); !errors.Is(err, ErrConflict) {
		t.Fatal("post-ready mutation", err)
	}
	j.Close()
	j = open(t, dir)
	pending, err := j.Pending()
	if err != nil || len(pending) != 1 {
		t.Fatal(pending, err)
	}
	tm := pending[0].ProofTraffic
	if tm == nil || !tm.WorkerFinished || len(tm.Samples) != 3 || *tm.Samples[0].SentBytes != 0 || !bytes.Equal(pending[0].Body, body) {
		t.Fatal("reopen lost evidence")
	}
	if err := j.Terminal(pending[0]); err != nil {
		t.Fatal(err)
	}
	terminal, err := j.read(filepath.Join(dir, key(r)+".json"))
	if err != nil || terminal.ProofTraffic == nil || len(terminal.Body) != 0 || terminal.SubmissionSHA256 != Hash(body) {
		t.Fatal("terminal retention", err)
	}
	if _, err := j.BeginProof(r, 3); !errors.Is(err, ErrConflict) {
		t.Fatal("terminal replay", err)
	}
	if err := j.Purge(time.Now().Add(25 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, key(r)+".json")); !os.IsNotExist(err) {
		t.Fatal("retention exceeded", err)
	}
}

func TestProofTrafficInterruptedAndForeignObservations(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	if err := j.Begin(r); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*Record){
		func(r *Record) { r.Fingerprint = Hash([]byte("foreign")) },
		func(r *Record) { r.Deadline = r.Deadline.Add(time.Second) },
		func(r *Record) { r.ProviderAccountID = "foreign-account" },
		func(r *Record) { r.ProviderService = "x_read" },
		func(r *Record) { r.Fence = "foreign" },
	} {
		foreign := r
		edit(&foreign)
		if _, err := j.BeginProof(foreign, 1); err == nil {
			t.Fatal("foreign reservation accepted")
		}
	}
	if _, err := j.BeginProof(r, 1); err != nil {
		t.Fatal(err)
	}
	foreign := r
	foreign.Deadline = foreign.Deadline.Add(time.Second)
	if err := j.CompleteProof(foreign, trafficSample(1, 1, 2)); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign callback accepted", err)
	}
	if err := j.FinishProofTraffic(foreign); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign finish accepted", err)
	}
	j.Close()
	j = open(t, dir)
	pending, err := j.Pending()
	if err != nil || len(pending) != 1 || pending[0].ProofTraffic.Samples[0].State != "started" || pending[0].ProofTraffic.Samples[0].SentBytes != nil {
		t.Fatal("aborted start became zero", err)
	}
	if err := j.FinishProofTraffic(r); err != nil {
		t.Fatal(err)
	}
	if _, err := j.BeginProof(r, 1); !errors.Is(err, ErrConflict) {
		t.Fatal("finished worker replay", err)
	}
	if _, err := j.Ready(r, "fail", []byte(`{"code":"execution_uncertain"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestProofTrafficRaceAndRejectedObservations(t *testing.T) {
	j := open(t, filepath.Join(t.TempDir(), "attempts"))
	r := fixture()
	if err := j.Begin(r); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := j.BeginProof(r, 1); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrConflict) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("multiple single-helper reservations")
	}
	for _, sample := range []ProofSample{
		trafficSample(0, 1, 2), trafficSample(2, 1, 2), trafficSample(1, MaxProofBytes+1, 2),
		{Ordinal: 1, State: "complete"}, {Ordinal: 1, State: "incomplete", Reason: "private provider error"},
	} {
		if err := j.CompleteProof(r, sample); !errors.Is(err, ErrConflict) {
			t.Fatal("invalid observation", err)
		}
	}
	sample := trafficSample(1, 0, 2)
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := j.CompleteProof(r, sample); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := j.CompleteProof(r, trafficSample(1, 3, 2)); !errors.Is(err, ErrConflict) {
		t.Fatal("changed duplicate", err)
	}
}

func TestProofTrafficWriteFaultAndLegacyRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	if err := j.Begin(r); err != nil {
		t.Fatal(err)
	}
	if err := j.FinishProofTraffic(r); err != nil {
		t.Fatal("legacy no-helper record", err)
	}
	pending, err := j.Pending()
	if err != nil || pending[0].ProofTraffic != nil {
		t.Fatal("invented zero metrics", err)
	}
	// A too-small atomic record budget faults persistence after reading the old
	// record. A refused reservation must leave no helper claim on disk.
	stat, err := os.Stat(filepath.Join(dir, key(r)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	j.limits.MaxRecordBytes = int(stat.Size()) + 1
	if _, err := j.BeginProof(r, 1); err == nil {
		t.Fatal("persist fault allowed helper start")
	}
	j.limits.MaxRecordBytes = maxRecordBytes
	pending, err = j.Pending()
	if err != nil || pending[0].ProofTraffic != nil {
		t.Fatal("partial reservation committed", err)
	}
}

func TestProofTrafficCompletionWriteFaultStaysUnknown(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	if err := j.Begin(r); err != nil {
		t.Fatal(err)
	}
	if _, err := j.BeginProof(r, 1); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(filepath.Join(dir, key(r)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	j.limits.MaxRecordBytes = int(stat.Size()) + 1
	if err := j.CompleteProof(r, trafficSample(1, 41, 71)); err == nil {
		t.Fatal("completion write fault ignored")
	}
	j.limits.MaxRecordBytes = maxRecordBytes
	if err := j.FinishProofTraffic(r); err != nil {
		t.Fatal(err)
	}
	ready, err := j.Ready(r, "proven", []byte(`{"version":"node-v1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !ready.ProofTraffic.WorkerFinished || ready.ProofTraffic.Samples[0].State != "started" || ready.ProofTraffic.Samples[0].SentBytes != nil {
		t.Fatal("lost observation became complete")
	}
}
