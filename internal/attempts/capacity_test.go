package attempts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// receipt is a terminal record shaped like a finished X read: account binding,
// report digest and three proof traffic samples. Its lease deadline is 75
// seconds after acknowledged.
func receipt(i int, acknowledged time.Time) Record {
	sent, received := uint64(106689), uint64(100322)
	r := Record{ProviderAccountID: "browser-firefox", ProviderService: "x_read", JobID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), Attempt: fmt.Sprintf("00000000-0000-4000-9000-%012d", i), Fence: fmt.Sprintf("00000000-0000-4000-a000-%012d", i), State: "terminal", Kind: "proven", Deadline: acknowledged.Add(75 * time.Second).UTC(), UpdatedAt: acknowledged.UTC()}
	r.Fingerprint = Hash([]byte("lease " + r.JobID))
	r.SubmissionSHA256 = Hash([]byte("report " + r.JobID))
	r.ProofTraffic = &ProofTraffic{Schema: 1, LeaseFingerprint: r.Fingerprint, Layer: "tcp_payload", MaxSamples: 3, WorkerFinished: true}
	for n := 1; n <= 3; n++ {
		r.ProofTraffic.Samples = append(r.ProofTraffic.Samples, ProofSample{Ordinal: n, State: "complete", SentBytes: &sent, ReceivedBytes: &received})
	}
	return r
}

// seed writes records as an earlier process left them. Unix fixtures skip the
// journal's fsyncs; Windows privacy needs the journal's own protected writes.
func seed(t *testing.T, dir string, records ...Record) {
	t.Helper()
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if !valid(r) {
			t.Fatal("invalid fixture", r.JobID)
		}
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Join(dir, key(r)+".json")
		if runtime.GOOS == "windows" {
			err = localfs.WriteAtomic(name, raw, true)
		} else {
			err = os.WriteFile(name, raw, 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func exists(t *testing.T, dir string, r Record) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, key(r)+".json"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

// diskBytes is what the journal's record files occupy.
func diskBytes(t *testing.T, dir string) (int, int64) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files int
	var bytes int64
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		files++
		bytes += info.Size()
	}
	return files, bytes
}

func openLimits(t *testing.T, dir string, limits Limits) *Journal {
	t.Helper()
	j, err := OpenWithLimits(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	return j
}

func capacityOf(t *testing.T, j *Journal) Capacity {
	t.Helper()
	c, err := j.Capacity()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFinishedReceiptsNeverBlockAdmission(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	limits := Limits{MaxRecords: 2, MaxRecordBytes: maxRecordBytes, MaxTotalBytes: 2 * maxRecordBytes}
	j := openLimits(t, dir, limits)
	var finished []Record
	// Five times the live ceiling, each attempt finishing before the next.
	for i := range 5 * limits.MaxRecords {
		r := fixture()
		r.JobID = fmt.Sprintf("finished-%d", i)
		if err := j.Begin(r); err != nil {
			t.Fatal(i, err)
		}
		ready, err := j.Ready(r, "proven", []byte(`{"version":"node-v1"}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Terminal(ready); err != nil {
			t.Fatal(err)
		}
		finished = append(finished, r)
	}
	if c := capacityOf(t, j); c.Records != 0 || c.Bytes != 0 || c.ReservedBytes != 0 || c.TerminalRecords != len(finished) || c.AvailableRecords != limits.MaxRecords {
		t.Fatalf("finished receipts consumed admission: %+v", c)
	}
	// Every receipt still refuses its own replay, including after a restart.
	j.Close()
	j = openLimits(t, dir, limits)
	for _, r := range finished {
		if err := j.Begin(r); !errors.Is(err, ErrExists) {
			t.Fatal("finished attempt became replayable", r.JobID, err)
		}
		changed := r
		changed.Fingerprint = Hash([]byte("a different lease"))
		if err := j.Begin(changed); !errors.Is(err, ErrConflict) {
			t.Fatal("receipt identity conflict not detected", r.JobID, err)
		}
	}
	// Live work alone fills admission.
	for _, id := range []string{"live-a", "live-b"} {
		r := fixture()
		r.JobID = id
		if err := j.Begin(r); err != nil {
			t.Fatal(err)
		}
	}
	extra := fixture()
	extra.JobID = "live-c"
	if err := j.Begin(extra); err == nil {
		t.Fatal("admitted past the live record ceiling")
	}
	if c := capacityOf(t, j); c.Records != 2 || c.AvailableRecords != 0 || c.TerminalRecords != len(finished) {
		t.Fatalf("%+v", c)
	}
}

func TestCapacityCountsLiveStatesOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	limits := Limits{MaxRecords: 8, MaxRecordBytes: maxRecordBytes, MaxTotalBytes: 5 * maxRecordBytes}
	j := openLimits(t, dir, limits)
	attempt := func(id string) Record {
		r := fixture()
		r.JobID = id
		if err := j.Begin(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	started := attempt("started")
	proving := attempt("proving")
	if _, err := j.BeginProof(proving, 1); err != nil {
		t.Fatal(err)
	}
	ready := attempt("ready")
	if _, err := j.Ready(ready, "fail", []byte(`{"code":"synthetic"}`)); err != nil {
		t.Fatal(err)
	}
	finished := attempt("finished")
	if err := j.Terminal(finished); err != nil {
		t.Fatal(err)
	}
	rejected := fixture()
	rejected.JobID, rejected.NoProvider = "rejected", true
	if err := j.Begin(rejected); err != nil {
		t.Fatal(err)
	}
	if err := j.Terminal(rejected); err != nil {
		t.Fatal(err)
	}
	size := func(r Record) int64 {
		info, err := os.Stat(filepath.Join(dir, key(r)+".json"))
		if err != nil {
			t.Fatal(err)
		}
		return info.Size()
	}
	want := Capacity{Limits: limits.withDefaults(), Records: 3, Bytes: size(started) + size(proving) + size(ready), ReservedBytes: 3 * maxRecordBytes, TerminalRecords: 2, TerminalBytes: size(finished) + size(rejected), AvailableRecords: 2}
	if c := capacityOf(t, j); c != want {
		t.Fatalf("capacity %+v, want %+v", c, want)
	}
	pending, err := j.Pending()
	if err != nil || len(pending) != 3 {
		t.Fatal("pending is not the live records", pending, err)
	}
	for _, r := range pending {
		if r.State == "terminal" {
			t.Fatal("terminal record pending", r.JobID)
		}
	}
	// The accounting kept while writing matches a fresh read of the files.
	j.Close()
	j = openLimits(t, dir, limits)
	if c := capacityOf(t, j); c != want {
		t.Fatalf("reopened capacity %+v, want %+v", c, want)
	}
}

// An upgrade finds the journal a day of work left: 1,024 finished receipts,
// as many as the old accounting allowed, all inside Retention. The new
// accounting admits the full live ceiling at once and keeps every receipt.
func TestDayOfReceiptsLeavesAdmissionOpenAfterUpgrade(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	now := time.Now()
	var receipts []Record
	for i := range maxRecords {
		r := receipt(i, now.Add(-10*time.Hour).Add(time.Duration(i)*35*time.Second))
		switch {
		case i == 0:
			// A local refusal before acceptance: no report or traffic.
			r.Kind, r.SubmissionSHA256, r.ProofTraffic = "", "", nil
		case i%16 == 0:
			r.Kind = "fail"
		}
		receipts = append(receipts, r)
	}
	seed(t, dir, receipts...)
	j := openLimits(t, dir, DefaultLimits())
	if c := capacityOf(t, j); c.Records != 0 || c.TerminalRecords != maxRecords || c.AvailableRecords != maxRecords {
		t.Fatalf("a day of receipts blocked admission: %+v", c)
	}
	if err := j.Purge(time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, r := range receipts {
		if !exists(t, dir, r) {
			t.Fatal("receipt removed within Retention", r.JobID)
		}
	}
	if err := j.Begin(receipts[maxRecords-1]); !errors.Is(err, ErrExists) {
		t.Fatal("finished attempt became replayable", err)
	}
	fresh := fixture()
	fresh.JobID = "after-upgrade"
	if err := j.Begin(fresh); err != nil {
		t.Fatal("new work refused", err)
	}
	if c := capacityOf(t, j); c.Records != 1 || c.AvailableRecords != maxRecords-1 {
		t.Fatalf("%+v", c)
	}
}

func TestTerminalPruningTakesOnlyOldReceiptsOldestFirst(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	now := time.Now()
	var old, recent []Record
	for i := range 6 {
		old = append(old, receipt(i, now.Add(-time.Duration(7-i)*time.Hour)))
	}
	for i := range 3 {
		recent = append(recent, receipt(10+i, now.Add(-time.Duration(15-5*i)*time.Minute)))
	}
	// Acknowledged hours ago, but its lease could still run for 20 minutes.
	longLease := receipt(20, now.Add(-5*time.Hour))
	longLease.Deadline = now.Add(20 * time.Minute).UTC()
	// Unfinished attempts are never pruned, however old.
	stale := receipt(30, now.Add(-30*time.Hour))
	stale.State, stale.Kind, stale.SubmissionSHA256, stale.ProofTraffic = "started", "", "", nil
	unsent := receipt(31, now.Add(-2*time.Hour))
	unsent.State, unsent.Kind, unsent.ProofTraffic = "ready", "fail", nil
	unsent.Body = []byte(`{"code":"execution_uncertain"}`)
	unsent.SubmissionSHA256 = Hash(unsent.Body)
	all := append(append(append([]Record{}, old...), recent...), longLease, stale, unsent)
	seed(t, dir, all...)

	// Ten receipts against a limit of eight: opening prunes to seven.
	limits := Limits{MaxRecords: 4, MaxRecordBytes: maxRecordBytes, MaxTotalBytes: 256 << 20, MaxTerminalRecords: 8}
	j := openLimits(t, dir, limits)
	for i, r := range old {
		if exists(t, dir, r) != (i >= 3) {
			t.Fatal("pruned out of age order", i)
		}
	}
	for _, r := range append(recent, longLease, stale, unsent) {
		if !exists(t, dir, r) {
			t.Fatal("pruned a record that may still guard a lease or need reconciliation", r.JobID, r.State)
		}
	}
	if c := capacityOf(t, j); c.TerminalRecords != 7 || c.Records != 2 || c.AvailableRecords != 2 {
		t.Fatalf("%+v", c)
	}
	pending, err := j.Pending()
	if err != nil || len(pending) != 2 {
		t.Fatal("unfinished attempts lost", pending, err)
	}
	if err := j.Begin(longLease); !errors.Is(err, ErrExists) {
		t.Fatal("receipt for a lease that can still run became replayable", err)
	}
}

func TestRecentReceiptsFillingTerminalStorageWaitToAge(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	now := time.Now()
	var recent []Record
	for i := range 4 {
		recent = append(recent, receipt(i, now.Add(-time.Duration(40-10*i)*time.Minute)))
	}
	seed(t, dir, recent...)
	limits := Limits{MaxRecords: 4, MaxRecordBytes: maxRecordBytes, MaxTotalBytes: 256 << 20, MaxTerminalRecords: 4}
	j := openLimits(t, dir, limits)
	if c := capacityOf(t, j); c.TerminalRecords != 4 || c.AvailableRecords != 0 {
		t.Fatalf("receipts within MinRetention did not hold admission: %+v", c)
	}
	fresh := fixture()
	fresh.JobID = "waiting"
	if err := j.Begin(fresh); err == nil {
		t.Fatal("admitted with terminal storage full of recent receipts")
	}
	if err := j.Purge(now); err != nil {
		t.Fatal(err)
	}
	for _, r := range recent {
		if !exists(t, dir, r) {
			t.Fatal("removed a receipt within MinRetention", r.JobID)
		}
	}
	// An hour later the oldest is pruned and admission opens again.
	if err := j.Purge(now.Add(MinRetention + time.Minute)); err != nil {
		t.Fatal(err)
	}
	if exists(t, dir, recent[0]) || !exists(t, dir, recent[1]) {
		t.Fatal("aged receipts were not pruned oldest first")
	}
	if err := j.Begin(fresh); err != nil {
		t.Fatal(err)
	}
}

func TestTerminalByteLimitPrunesOldestReceipts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempts")
	now := time.Now()
	var receipts []Record
	for i := range 300 {
		receipts = append(receipts, receipt(i, now.Add(-2*time.Hour).Add(time.Duration(i)*time.Second)))
	}
	seed(t, dir, receipts...)
	limits := Limits{MaxRecords: 4, MaxRecordBytes: maxRecordBytes, MaxTotalBytes: 256 << 20, MaxTerminalBytes: maxRecordBytes}
	j := openLimits(t, dir, limits)
	// Opening makes room below the limit; a purge trims to seven eighths.
	for _, keep := range []int64{limits.MaxTerminalBytes - 1, limits.MaxTerminalBytes - limits.MaxTerminalBytes/8} {
		c := capacityOf(t, j)
		if c.TerminalBytes > keep || c.TerminalBytes+encodedSize(t, receipt(0, now)) <= keep || c.AvailableRecords != limits.MaxRecords {
			t.Fatalf("trimmed to %d bytes, want just under %d: %+v", c.TerminalBytes, keep, c)
		}
		first := len(receipts) - c.TerminalRecords
		for i, r := range receipts {
			if exists(t, dir, r) != (i >= first) {
				t.Fatal("byte pruning out of age order", i)
			}
		}
		if files, bytes := diskBytes(t, dir); files != c.TerminalRecords || bytes != c.TerminalBytes {
			t.Fatal("accounting differs from disk", files, bytes, c)
		}
		if err := j.Purge(now); err != nil {
			t.Fatal(err)
		}
	}
}

// encodedSize bounds a fixture receipt's file size from above.
func encodedSize(t *testing.T, r Record) int64 {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return int64(len(raw)) + 16
}

func TestFailedWriteRereadsJournalBeforeAccounting(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the test user cannot write")
	}
	dir := filepath.Join(t.TempDir(), "attempts")
	j := open(t, dir)
	r := fixture()
	if err := j.Begin(r); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	_, err := j.Ready(r, "fail", []byte(`{"code":"synthetic"}`))
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err == nil {
		t.Fatal("write into a read-only journal succeeded")
	}
	if j.index != nil {
		t.Fatal("accounting trusted after a failed write")
	}
	if c := capacityOf(t, j); c.Records != 1 || c.TerminalRecords != 0 {
		t.Fatalf("%+v", c)
	}
	if _, err := j.Ready(r, "fail", []byte(`{"code":"synthetic"}`)); err != nil {
		t.Fatal(err)
	}
}

// A node finishing 50,000 attempts a day holds about that many receipts at
// once. Opening them admits the full live ceiling, a smaller terminal limit
// prunes only the oldest, and a further day of purges removes each receipt
// once it reaches Retention, while admission stays open and the files stay
// within the journal's bounds throughout.
func TestHighThroughputReceiptsStayBoundedAndAdmitting(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a day of receipts")
	}
	// CI runs the full day on Linux. Creating and removing a file costs a
	// millisecond or more on desktop filesystems, and private Windows fixtures
	// need the journal's synced writes, so those run a smaller day.
	perDay := 50000
	switch runtime.GOOS {
	case "linux":
	case "windows":
		perDay = 2000
	default:
		perDay = 5000
	}
	dir := filepath.Join(t.TempDir(), "attempts")
	now := time.Now()
	spacing := 24 * time.Hour / time.Duration(perDay)
	receipts := make([]Record, perDay)
	for i := range receipts {
		receipts[i] = receipt(i, now.Add(-time.Duration(perDay-1-i)*spacing))
	}
	seed(t, dir, receipts...)
	bounded := func(j *Journal, disk bool) Capacity {
		t.Helper()
		c := capacityOf(t, j)
		if c.Bytes+c.TerminalBytes > c.Limits.MaxTotalBytes+c.Limits.MaxTerminalBytes || c.TerminalRecords > c.Limits.MaxTerminalRecords {
			t.Fatalf("journal outside its bounds: %+v", c)
		}
		if disk {
			if files, bytes := diskBytes(t, dir); files != c.Records+c.TerminalRecords || bytes != c.Bytes+c.TerminalBytes {
				t.Fatalf("journal files %d (%d bytes) differ from accounting: %+v", files, bytes, c)
			}
		}
		if c.AvailableRecords != c.Limits.MaxRecords-c.Records {
			t.Fatalf("receipts reduced admission: %+v", c)
		}
		return c
	}

	j := openLimits(t, dir, DefaultLimits())
	if c := bounded(j, true); c.TerminalRecords != perDay || c.AvailableRecords != maxRecords {
		t.Fatalf("%+v", c)
	}
	var live []Record
	for i := range 10 {
		r := fixture()
		r.JobID = fmt.Sprintf("live-%d", i)
		if err := j.Begin(r); err != nil {
			t.Fatal(err)
		}
		ready, err := j.Ready(r, "proven", []byte(`{"version":"node-v1"}`))
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Terminal(ready); err != nil {
			t.Fatal(err)
		}
		live = append(live, r)
	}
	if c := bounded(j, true); c.TerminalRecords != perDay+len(live) {
		t.Fatalf("%+v", c)
	}
	j.Close()

	// Terminal storage smaller than a day of receipts.
	limited := DefaultLimits()
	limited.MaxTerminalRecords = perDay * 4 / 5
	j = openLimits(t, dir, limited)
	if c := bounded(j, true); c.TerminalRecords != limited.MaxTerminalRecords-1 {
		t.Fatalf("opened with %d receipts, want %d", c.TerminalRecords, limited.MaxTerminalRecords-1)
	}
	if err := j.Purge(now); err != nil {
		t.Fatal(err)
	}
	keep := limited.MaxTerminalRecords - limited.MaxTerminalRecords/8
	if c := bounded(j, true); c.TerminalRecords != keep {
		t.Fatalf("purged to %d receipts, want %d", c.TerminalRecords, keep)
	}
	first := perDay - (keep - len(live))
	for i, r := range receipts {
		if exists(t, dir, r) != (i >= first) {
			t.Fatal("pruned out of age order", i)
		}
	}
	for _, r := range live {
		if !exists(t, dir, r) {
			t.Fatal("pruned a receipt within MinRetention", r.JobID)
		}
	}
	j.Close()

	// The next day, purged hourly.
	j = openLimits(t, dir, DefaultLimits())
	for hour := 1; hour <= 25; hour++ {
		at := now.Add(time.Duration(hour) * time.Hour)
		if err := j.Purge(at); err != nil {
			t.Fatal(err)
		}
		want := 0
		for _, r := range append(receipts[first:], live...) {
			if !at.After(r.Deadline.Add(Retention)) || !at.After(r.UpdatedAt.Add(Retention)) {
				want++
			}
		}
		if c := bounded(j, hour%12 == 0); c.TerminalRecords != want {
			t.Fatalf("hour %d kept %d receipts, want %d", hour, c.TerminalRecords, want)
		}
	}
	if files, _ := diskBytes(t, dir); files != 0 {
		t.Fatal("receipts outlived Retention", files)
	}
}
