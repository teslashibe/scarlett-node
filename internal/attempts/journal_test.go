package attempts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture() Record {
	return Record{JobID: "synthetic-job", Attempt: "a1", Fence: "f1", Fingerprint: Hash([]byte("synthetic lease")), Deadline: time.Now().Add(time.Minute).UTC()}
}
func open(t *testing.T, dir string) *Journal {
	t.Helper()
	j, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { j.Close() })
	return j
}
func TestRestartAndExactReportRetention(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	if e := j.Begin(r); e != nil {
		t.Fatal(e)
	}
	body := []byte("{\n  \"output\": \"synthetic private answer\"\n}")
	ready, e := j.Ready(r, "result", body)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = j.Ready(r, "result", []byte(`{"output":"changed"}`)); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	j.Close()
	j = open(t, dir)
	pending, e := j.Pending()
	if e != nil || len(pending) != 1 || !bytes.Equal(pending[0].Body, body) || pending[0].SubmissionSHA256 != Hash(body) {
		t.Fatalf("restart lost exact bytes: %v", e)
	}
	if e = j.Begin(r); !errors.Is(e, ErrExists) {
		t.Fatal(e)
	}
	if e = j.Terminal(ready); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, key(r)+".json"))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte(`"body"`)) {
		t.Fatal("terminal metadata retains private content")
	}
	if e = j.Purge(time.Now().Add(25 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, key(r)+".json")); !os.IsNotExist(e) {
		t.Fatal("terminal record not purged", e)
	}
}
func TestSingleProcessAndAtomicClaims(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	if second, e := Open(dir); e == nil {
		second.Close()
		t.Fatal("second process acquired journal")
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := j.Begin(r)
			if e == nil {
				wins.Add(1)
			} else if !errors.Is(e, ErrExists) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("multiple provider-call claims")
	}
	conflict := r
	conflict.Fingerprint = Hash([]byte("different lease"))
	if e := j.Begin(conflict); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	conflict = r
	conflict.Deadline = conflict.Deadline.Add(time.Second)
	if e := j.Begin(conflict); !errors.Is(e, ErrConflict) {
		t.Fatal(e)
	}
	j.Close()
	j = open(t, dir)
	if e := j.Begin(r); !errors.Is(e, ErrExists) {
		t.Fatal("restart repeated work", e)
	}
}
func TestStartedSurvivesPurgeAndPrivateBodyExpires(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	if e := j.Begin(r); e != nil {
		t.Fatal(e)
	}
	if _, e := j.Ready(r, "proven", []byte(`{"version":"node-v1"}`)); e != nil {
		t.Fatal(e)
	}
	if e := j.Purge(time.Now().Add(25 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	pending, e := j.Pending()
	if e != nil || len(pending) != 1 || pending[0].State != "started" || len(pending[0].Body) != 0 {
		t.Fatal("expired payload/uncertain metadata policy failed", e)
	}
	if e := j.Begin(r); !errors.Is(e, ErrExists) {
		t.Fatal("purge allowed provider replay", e)
	}
}
func TestUnsafeFilesAndPartialWrites(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "attempts")
	j := open(t, dir)
	r := fixture()
	if e := j.Begin(r); e != nil {
		t.Fatal(e)
	}
	j.Close()
	abandoned := filepath.Join(dir, ".write-abandoned")
	if e := os.WriteFile(abandoned, []byte("incomplete private result"), 0600); e != nil {
		t.Fatal(e)
	}
	j = open(t, dir)
	if _, e := os.Stat(abandoned); !os.IsNotExist(e) {
		t.Fatal("abandoned write retained", e)
	}
	j.Close()
	name := filepath.Join(dir, key(r)+".json")
	target := filepath.Join(root, "untrusted.json")
	os.WriteFile(target, []byte(`{}`), 0600)
	os.Remove(name)
	os.Symlink(target, name)
	if opened, e := Open(dir); e == nil {
		opened.Close()
		t.Fatal("accepted symlink record")
	}
	os.Remove(name)
	os.WriteFile(name, []byte(`{}`), 0644)
	if opened, e := Open(dir); e == nil {
		opened.Close()
		t.Fatal("accepted unsafe/malformed record")
	}
}
func TestWriteFailureAndBoundsFailClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	if e := j.Begin(r); e != nil {
		t.Fatal(e)
	}
	if _, e := j.Ready(r, "result", bytes.Repeat([]byte("x"), 131073)); e == nil {
		t.Fatal("accepted oversized report")
	}
	if e := os.Rename(dir, dir+"-moved"); e != nil {
		t.Fatal(e)
	}
	if _, e := j.Ready(r, "proven", []byte(`{}`)); e == nil {
		t.Fatal("ignored disk failure")
	}
	j.Close()
	j = open(t, dir+"-moved")
	if e := j.Begin(r); !errors.Is(e, ErrExists) {
		t.Fatal("disk failure lost provider-call boundary", e)
	}
}

func TestFullJournalRejectsNewWorkWithoutEvictingUncertainAttempts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	r.State = "started"
	r.UpdatedAt = time.Now().UTC()
	for i := range maxRecords {
		r.JobID = fmt.Sprintf("job-%d", i)
		raw, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, key(r)+".json"), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	fresh := fixture()
	fresh.JobID = "new-job"
	if e := j.Begin(fresh); e == nil {
		t.Fatal("full journal accepted work")
	}
	pending, e := j.Pending()
	if e != nil || len(pending) != maxRecords {
		t.Fatal("uncertain history evicted", e)
	}
}

func TestByteReservationStopsAdmissionAndKeepsRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	limits := Limits{MaxRecords: 4, MaxRecordBytes: maxRecordBytes, MaxTotalBytes: 2 * maxRecordBytes}
	j, err := OpenWithLimits(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	r := fixture()
	if err = j.Begin(r); err != nil {
		t.Fatal(err)
	}
	r2 := r
	r2.JobID = "second"
	if err = j.Begin(r2); err != nil {
		t.Fatal(err)
	}
	capacity, err := j.Capacity()
	if err != nil || capacity.AvailableRecords != 0 || capacity.ReservedBytes != limits.MaxTotalBytes {
		t.Fatal(capacity, err)
	}
	r3 := r
	r3.JobID = "third"
	if err = j.Begin(r3); err == nil {
		t.Fatal("accepted without room for provider report")
	}
	if _, err = j.Ready(r, "fail", []byte(`{"code":"synthetic"}`)); err != nil {
		t.Fatal(err)
	}
	if err = j.Terminal(r); err != nil {
		t.Fatal(err)
	}
	// One terminal receipt still consumes its actual bytes. The full-size
	// reservation for the second attempt remains intact.
	capacity, err = j.Capacity()
	if err != nil || capacity.ReservedBytes >= limits.MaxTotalBytes {
		t.Fatal(capacity, err)
	}
	if err = j.Purge(time.Now().Add(48 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	j.Close()
	j, err = OpenWithLimits(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	pending, err := j.Pending()
	if err != nil || len(pending) != 1 || pending[0].JobID != "second" {
		t.Fatal(pending, err)
	}
	if err = j.Begin(r2); err != ErrExists {
		t.Fatal("uncertain provider call became replayable", err)
	}
}

func TestJournalLimitsFailClosed(t *testing.T) {
	for _, limits := range []Limits{{}, {1, 1, 1}, {1000001, maxRecordBytes, 256 << 20}, {1, maxRecordBytes, maxRecordBytes - 1}} {
		if _, err := OpenWithLimits(filepath.Join(t.TempDir(), "attempts"), limits); err == nil {
			t.Fatal("invalid limits accepted", limits)
		}
	}
}

func BenchmarkJournalSyntheticCommit(b *testing.B) {
	// Includes JSON serialization, private atomic writes and file/directory
	// fsync on this machine. It does not measure proof or provider throughput.
	j, err := OpenWithLimits(filepath.Join(b.TempDir(), "attempts"), Limits{1000000, maxRecordBytes, 16 << 30})
	if err != nil {
		b.Fatal(err)
	}
	defer j.Close()
	body := []byte(`{"code":"synthetic"}`)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := fixture()
		r.JobID = fmt.Sprintf("synthetic-%d", i)
		if err := j.Begin(r); err != nil {
			b.Fatal(err)
		}
		if _, err := j.Ready(r, "fail", body); err != nil {
			b.Fatal(err)
		}
		if err := j.Terminal(r); err != nil {
			b.Fatal(err)
		}
	}
}

func TestProviderAccountBindingSurvivesRestartAndCannotBeReassigned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	r.ProviderAccountID = "local-one"
	r.ProviderService = "codex"
	if e := j.Begin(r); e != nil {
		t.Fatal(e)
	}
	j.Close()
	j = open(t, dir)
	pending, e := j.Pending()
	if e != nil || len(pending) != 1 || pending[0].ProviderAccountID != "local-one" || pending[0].ProviderService != "codex" {
		t.Fatal("account binding lost", e)
	}
	switched := r
	switched.ProviderAccountID = "local-two"
	if e = j.Begin(switched); !errors.Is(e, ErrConflict) {
		t.Fatal("replayed job switched account", e)
	}
	if _, e = j.Ready(switched, "fail", []byte(`{"code":"execution_uncertain"}`)); !errors.Is(e, ErrConflict) {
		t.Fatal("report changed account binding", e)
	}
	ready, e := j.Ready(pending[0], "fail", []byte(`{"code":"execution_uncertain"}`))
	if e != nil {
		t.Fatal(e)
	}
	if e = j.Terminal(ready); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, key(r)+".json"))
	if e != nil || !bytes.Contains(raw, []byte(`"provider_account_id":"local-one"`)) {
		t.Fatal("terminal account audit lost", e)
	}
}
