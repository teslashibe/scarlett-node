package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func privateHistoryInfo(t *testing.T, dir string) os.FileInfo {
	t.Helper()
	f, err := localfs.OpenPrivate(filepath.Join(dir, historyName))
	if err != nil {
		t.Fatal("history was not private", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func metadata(id string) Metadata {
	return Metadata{ID: id, Operation: "search", Pages: 1, ProofMode: "relay"}
}

func controlled(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s := New(privateDir(t))
	now := time.Now()
	s.monoNow = func() time.Time { return now }
	return s, &now
}

func waitForClose(t *testing.T, s *Store) {
	t.Helper()
	// Close has a bounded shutdown budget; persistence assertions need the
	// optional final flush to finish even when that budget expires.
	wait := 10 * time.Second
	if deadline, ok := t.Deadline(); ok && time.Until(deadline) < wait {
		wait = time.Until(deadline)
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-s.closeDone:
	case <-timer.C:
		t.Fatalf("diagnostics final flush did not finish within %s", wait)
	}
}

func TestAbsentContextAndInvalidTelemetry(t *testing.T) {
	var s *Store
	a := s.Begin(metadata("missing"))
	if a != nil {
		t.Fatal("disabled collector created attempt")
	}
	ctx := context.Background()
	if a.Context(ctx) != ctx {
		t.Fatal("nil attempt changed context")
	}
	a.Finish("success")
	Start(nil, "accept_http", 0)("success")
	AddHelper(nil, 1, json.RawMessage(`{"token":"private"}`))
	s = New(privateDir(t))
	if s.Begin(Metadata{ID: "x", Operation: "secret query", ProofMode: "relay"}) != nil {
		t.Fatal("unknown operation accepted")
	}
	a = s.Begin(metadata("fixture"))
	Start(a.Context(ctx), "cookie:secret", 0)("secret")
	a.Finish("raw secret error")
	r := s.Snapshot().Attempts[0]
	if r.Outcome != "error" || len(r.Spans) != 0 {
		t.Fatalf("unknown strings recorded: %+v", r)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "fixture") {
		t.Fatal("raw metadata reached export")
	}
}

func TestMonotonicDurationSurvivesWallClockJump(t *testing.T) {
	s, now := controlled(t)
	wall := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	s.wallNow = func() time.Time { return wall }
	a := s.Begin(metadata("clock"))
	stop := Start(a.Context(context.Background()), "accept_http", 0)
	*now = now.Add(25 * time.Millisecond)
	wall = wall.Add(-time.Hour)
	stop("success")
	*now = now.Add(75 * time.Millisecond)
	a.Finish("success")
	r := s.Snapshot().Attempts[0]
	if r.DurationMS == nil || *r.DurationMS != 100 || r.Spans[0].DurationMS != 25 {
		t.Fatalf("clock jump changed monotonic elapsed: %+v", r)
	}
	if len(s.Snapshot().Attempts) != 1 {
		t.Fatal("wall jump pruned active monotonic history")
	}
}

func TestUnclassifiedUsesUnionAndSeparateHelperClock(t *testing.T) {
	duration := 100.0
	r := derived(Record{DurationMS: &duration, Spans: []Span{
		{Phase: "worker", Source: "node", StartMS: 0, DurationMS: 100},
		{Phase: "page_wall", Source: "node", StartMS: 0, DurationMS: 100},
		{Phase: "accept_http", Source: "node", StartMS: 10, DurationMS: 30},
		{Phase: "journal_write", Source: "node", StartMS: 20, DurationMS: 30},
		{Phase: "helper_wall", Source: "node", StartMS: 60, DurationMS: 20},
		{Phase: "helper_total", Source: "helper", StartMS: 0, DurationMS: 100},
	}})
	if r.UnclassifiedMS == nil || *r.UnclassifiedMS != 40 {
		t.Fatalf("overlap or helper clock double-counted: %+v", r.UnclassifiedMS)
	}
}

func TestFailurePrefixAndInterruptedHistory(t *testing.T) {
	s, now := controlled(t)
	a := s.Begin(metadata("failure"))
	Start(a.Context(context.Background()), "helper_wall", 1)
	*now = now.Add(40 * time.Millisecond)
	a.Finish("cancelled")
	r := s.Snapshot().Attempts[0]
	if r.Spans[0].DurationMS != 40 || r.Spans[0].Outcome != "cancelled" || *r.DurationMS != 40 {
		t.Fatalf("lost failed prefix: %+v", r)
	}
	if len(s.Snapshot().Summaries) != 0 {
		t.Fatal("failure prefix entered success percentiles")
	}
	running := s.Begin(metadata("crash"))
	Start(running.Context(context.Background()), "accept_http", 0)
	*now = now.Add(15 * time.Millisecond)
	s.Close()
	waitForClose(t, s)
	live := Read(s.dir)
	if live.LoadError != "" || len(live.Attempts) != 2 || live.Attempts[1].Outcome != "running" {
		t.Fatal("live CLI read lost the running attempt", live.LoadError, len(live.Attempts))
	}
	restarted := New(s.dir)
	reloaded := restarted.Snapshot()
	if reloaded.LoadError != "" || len(reloaded.Attempts) != 2 {
		t.Fatalf("reload failed: %+v", reloaded)
	}
	r = reloaded.Attempts[1]
	if r.Outcome != "interrupted" || r.DurationMS != nil || r.UnclassifiedMS != nil || r.Spans[0].DurationMS != 15 {
		t.Fatalf("fabricated finished timing after crash: %+v", r)
	}
	restarted.Close()
	waitForClose(t, restarted)
	persisted := Read(s.dir)
	if persisted.LoadError != "" || len(persisted.Attempts) != 2 || persisted.Attempts[1].Outcome != "interrupted" || persisted.Attempts[1].DurationMS != nil {
		t.Fatalf("restart without jobs did not persist unknown interruption: %+v", persisted)
	}
}

func TestRecordRejectsNodeSpanBeyondOverallButKeepsHelperClockIndependent(t *testing.T) {
	s, now := controlled(t)
	a := s.Begin(metadata("node-range"))
	stop := Start(a.Context(context.Background()), "accept_http", 0)
	*now = now.Add(10 * time.Millisecond)
	stop("success")
	a.Finish("success")
	r := s.Snapshot().Attempts[0]
	r.Spans[0].StartMS = 11
	r.Spans[0].DurationMS = 1
	if validRecord(r) {
		t.Fatal("node interval beyond overall accepted")
	}
	r.Spans[0].Source = "helper"
	r.Spans[0].Phase = "x_tcp_connect"
	r.Spans[0].Exchange = 1
	if !validRecord(r) {
		t.Fatal("helper own clock was aligned to node overall")
	}
}

func TestConcurrentAttemptsNeverMix(t *testing.T) {
	s := New(privateDir(t))
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a := s.Begin(metadata(fmt.Sprintf("attempt-%d", i)))
			ctx := a.Context(context.Background())
			stop := Start(ctx, "helper_wall", 1)
			AddHelper(ctx, 1, json.RawMessage(`{"version":1,"duration_ms":5,"spans":[{"phase":"x_tcp_connect","start_ms":1,"duration_ms":2,"outcome":"success"}]}`))
			stop("success")
			a.Finish("success")
		}(i)
	}
	wg.Wait()
	snapshot := s.Snapshot()
	if len(snapshot.Attempts) != 100 {
		t.Fatalf("mixed/lost attempts: %d", len(snapshot.Attempts))
	}
	for _, r := range snapshot.Attempts {
		if len(r.Spans) != 3 || r.Spans[0].Phase != "helper_wall" || r.Spans[1].Phase != "helper_total" || r.Spans[2].Phase != "x_tcp_connect" {
			t.Fatalf("mixed spans: %+v", r)
		}
	}
}

func TestHelperStrictnessAndUnknownFields(t *testing.T) {
	bad := []string{
		`{"version":1,"outcome":"success","duration_ms":null,"spans":[]}`,
		`{"version":1,"outcome":"success","spans":[]}`,
		`{"version":1,"outcome":"success","duration_ms":10,"spans":null}`,
		`{"version":1,"outcome":"success","duration_ms":10,"spans":[{"phase":"x_tcp_connect","duration_ms":1,"outcome":"success"}]}`,
		`{"version":1,"outcome":"success","duration_ms":10,"spans":[{"phase":"x_tcp_connect","start_ms":0,"duration_ms":null,"outcome":"success"}]}`,
		`{"version":1,"duration_ms":10,"token":"secret","spans":[]}`,
		`{"version":1,"version":1,"duration_ms":10,"spans":[]}`,
		`{"version":1,"duration_ms":-1,"spans":[]}`,
		`{"version":1,"duration_ms":10,"spans":[{"phase":"query","start_ms":0,"duration_ms":1,"outcome":"success"}]}`,
		`{"version":1,"duration_ms":10,"spans":[{"phase":"x_tcp_connect","start_ms":9,"duration_ms":2,"outcome":"success"}]}`,
		`{"version":1,"duration_ms":10,"spans":[{"phase":"x_tcp_connect","start_ms":0,"duration_ms":1,"outcome":"cookie"}]}`,
	}
	for i, raw := range bad {
		s := New(privateDir(t))
		a := s.Begin(metadata(fmt.Sprint(i)))
		AddHelper(a.Context(context.Background()), 1, json.RawMessage(raw))
		if len(s.Snapshot().Attempts[0].Spans) != 0 {
			t.Fatalf("accepted invalid helper %d", i)
		}
	}
	if finiteMS(math.NaN()) || finiteMS(math.Inf(1)) {
		t.Fatal("nonfinite duration accepted")
	}
}

func TestHelperFailureOutcomeAndMissingDuration(t *testing.T) {
	s := New(privateDir(t))
	a := s.Begin(metadata("failed-helper"))
	ctx := a.Context(context.Background())
	AddHelper(ctx, 1, json.RawMessage(`{"version":1,"outcome":"error","duration_ms":5,"spans":[{"phase":"x_tcp_connect","start_ms":1,"duration_ms":4,"outcome":"error"}]}`))
	AddHelper(ctx, 2, json.RawMessage(`{"version":1,"duration_ms":5,"spans":[]}`))
	a.Finish("prover_error")
	r := s.Snapshot().Attempts[0]
	if r.Spans[0].Outcome != "error" || r.Spans[2].Outcome != "interrupted" {
		t.Fatalf("helper success fabricated from failed or unknown prefix: %+v", r.Spans)
	}
}

func TestBoundsPriorityRetentionAndLateCallbacks(t *testing.T) {
	s, now := controlled(t)
	a := s.Begin(metadata("bounded"))
	ctx := a.Context(context.Background())
	late := Start(ctx, "journal_lock", 0)
	for i := 0; i < MaxSpans+36; i++ {
		Start(ctx, "journal_scan", 0)("success")
	}
	report := Start(ctx, "report_http", 0)
	*now = now.Add(time.Millisecond)
	late("error")
	report("success")
	a.Finish("success")
	r := s.Snapshot().Attempts[0]
	if !r.Truncated || len(r.Spans) > MaxSpans {
		t.Fatalf("bounds not visible: %+v", r)
	}
	found := false
	for _, span := range r.Spans {
		if span.Phase == "report_http" {
			found = true
			if span.Outcome != "success" || span.DurationMS != 1 {
				t.Fatalf("late evicted callback mutated report: %+v", span)
			}
		}
	}
	if !found {
		t.Fatal("span limit hid terminal report")
	}
	raw, _ := json.Marshal(r)
	if len(raw) > MaxAttemptBytes {
		t.Fatalf("record wire overflow: %d", len(raw))
	}
	for i := 0; i < 350; i++ {
		b := s.Begin(metadata(fmt.Sprintf("many-%d", i)))
		for k := 0; k < 64; k++ {
			Start(b.Context(context.Background()), "journal_write", 0)("success")
		}
		b.Finish("success")
	}
	snap := s.Snapshot()
	if len(snap.Attempts) > MaxAttempts || s.retainedBytes > MaxHistoryBytes {
		t.Fatalf("memory/attempt bounds: %d %d", len(snap.Attempts), s.retainedBytes)
	}
	s.Close()
	waitForClose(t, s)
	info := privateHistoryInfo(t, s.dir)
	if info.Size() > MaxHistoryBytes {
		t.Fatalf("private bounded history exceeded size limit: %v", info)
	}
}

func TestReadBoundsRecordAfterAddingDerivedFields(t *testing.T) {
	dir := privateDir(t)
	duration := 100.0
	now := time.Now().UTC()
	record := Record{ID: strings.Repeat("a", 64), Operation: "search", Pages: 3, ProofMode: "relay", StartedAt: now, Outcome: "success", DurationMS: &duration, Spans: []Span{}, MissingPhases: []string{}}
	for i := 0; i < MaxSpans; i++ {
		record.Spans = append(record.Spans, Span{Phase: "journal_lock", Source: "node", Outcome: "success"})
	}
	// Fill a valid stored record close to its byte limit, leaving derived
	// missing-phase and unclassified fields absent as older snapshots may do.
	for i := range record.Spans {
		old := record.Spans[i]
		record.Spans[i] = Span{Phase: "proof_journal_complete", Source: "node", Outcome: "invalid_gateway_response", StartMS: 0.123456789012345, DurationMS: 0.123456789012345}
		raw, _ := json.Marshal(record)
		if len(raw) > MaxAttemptBytes {
			record.Spans[i] = old
			break
		}
	}
	stored, _ := json.Marshal(record)
	if !validRecord(record) || len(stored) > MaxAttemptBytes {
		t.Fatalf("fixture was not a valid bounded stored record: %d", len(stored))
	}
	derivedRaw, _ := json.Marshal(derived(record))
	if len(derivedRaw) <= MaxAttemptBytes {
		t.Fatalf("fixture did not exercise derivation overflow: %d -> %d", len(stored), len(derivedRaw))
	}
	file, _ := json.Marshal(history{Version: Version, UpdatedAt: now, Attempts: []Record{record}})
	if err := localfs.WriteAtomic(filepath.Join(dir, historyName), file, false); err != nil {
		t.Fatal(err)
	}
	snapshot := Read(dir)
	if snapshot.LoadError != "" || len(snapshot.Attempts) != 1 {
		t.Fatalf("valid near-limit history was rejected: %+v", snapshot)
	}
	exported := snapshot.Attempts[0]
	exportedRaw, _ := json.Marshal(exported)
	if len(exportedRaw) > MaxAttemptBytes || !exported.Truncated || !validRecord(exported) || exported.UnclassifiedMS == nil || len(exported.MissingPhases) == 0 {
		t.Fatalf("derived export escaped record limit or concealed missing observations: bytes=%d record=%+v", len(exportedRaw), exported)
	}
}

func TestCorruptOversizedPublicAndDiskFailureAreDiagnosticsOnly(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{`{"version":1,"version":1}`, "corrupt"},
		{`{"version":1,"secret":"cookie"}`, "corrupt"},
		{strings.Repeat("x", MaxHistoryBytes+1), "too_large"},
	} {
		dir := privateDir(t)
		if err := localfs.WriteAtomic(filepath.Join(dir, historyName), []byte(test.raw), false); err != nil {
			t.Fatal(err)
		}
		if snap := Read(dir); snap.LoadError != test.want || len(snap.Attempts) != 0 {
			t.Fatalf("unsafe history was not rejected as %s: %+v", test.want, snap)
		}
	}
	dir := privateDir(t)
	if err := os.WriteFile(filepath.Join(dir, historyName), []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}
	if Read(dir).LoadError == "" {
		t.Fatal("public diagnostics file read")
	}
	block := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(block, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	s := New(block)
	a := s.Begin(metadata("disk-failure"))
	Start(a.Context(context.Background()), "accept_http", 0)("success")
	a.Finish("success")
	s.Close()
	waitForClose(t, s)
	if snap := s.Snapshot(); len(snap.Attempts) != 1 || snap.Attempts[0].Outcome != "success" || snap.LoadError != "write_error" {
		t.Fatalf("disk failure affected job: %+v", snap)
	}
}

func TestRetentionAndPercentileGrouping(t *testing.T) {
	s, now := controlled(t)
	for i := 1; i <= 20; i++ {
		a := s.Begin(metadata(fmt.Sprint(i)))
		*now = now.Add(time.Duration(i) * time.Millisecond)
		a.Finish("success")
	}
	other := s.Begin(Metadata{ID: "other", Operation: "profile", Pages: 1, ProofMode: "mpc"})
	*now = now.Add(75 * time.Millisecond)
	other.Finish("success")
	snap := s.Snapshot()
	if len(snap.Summaries) != 2 {
		t.Fatalf("groups mixed: %+v", snap.Summaries)
	}
	for _, summary := range snap.Summaries {
		if summary.Operation == "search" && (summary.Samples != 20 || *summary.P50MS != 10 || *summary.P95MS != 19 || summary.NewestAt.IsZero()) {
			t.Fatalf("incorrect percentiles/freshness: %+v", summary)
		}
	}
	*now = now.Add(Retention + time.Millisecond)
	if snap = s.Snapshot(); len(snap.Attempts) != 0 || len(snap.Summaries) != 0 {
		t.Fatal("retention fabricated empty-cohort percentiles")
	}
}

func TestIdleFlushRemovesExpiredHistory(t *testing.T) {
	s, now := controlled(t)
	wall := time.Now()
	s.wallNow = func() time.Time { return wall }
	a := s.Begin(metadata("idle-expiry"))
	a.Finish("success")
	s.flush(false)
	if s.dirty {
		t.Fatal("initial history was not flushed")
	}
	*now = now.Add(Retention + time.Hour)
	wall = wall.Add(Retention + time.Hour)
	s.lastFlush = time.Now().Add(-2 * time.Second)
	s.flush(false) // The idle Run loop reaches the same flush without new work.
	if a.retained || len(s.attempts) != 0 || s.retainedBytes != 0 || s.dirty {
		t.Fatal("idle flush did not prune and publish expired history")
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, historyName))
	if err != nil {
		t.Fatal(err)
	}
	var persisted history
	if strictJSON(raw, &persisted) != nil || len(persisted.Attempts) != 0 {
		t.Fatal("expired attempt remained on disk")
	}
}

func TestRestartPublishesExpiredHistoryCleanupWithoutNewWork(t *testing.T) {
	for _, keepRecent := range []bool{false, true} {
		t.Run(fmt.Sprintf("keep-recent=%t", keepRecent), func(t *testing.T) {
			dir := privateDir(t)
			now := time.Now().UTC()
			expired := Record{ID: strings.Repeat("a", 64), Operation: "codex", ProofMode: "none", StartedAt: now.Add(-Retention - time.Hour), Outcome: "success", Spans: []Span{}, MissingPhases: []string{}}
			records := []Record{expired}
			if keepRecent {
				recent := expired
				recent.ID, recent.StartedAt = strings.Repeat("b", 64), now
				records = append(records, recent)
			}
			raw, err := json.Marshal(history{Version: Version, UpdatedAt: now, Attempts: records})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, historyName)
			if err := localfs.WriteAtomic(path, raw, false); err != nil {
				t.Fatal(err)
			}
			s := New(dir)
			want := 0
			if keepRecent {
				want = 1
			}
			s.mu.Lock()
			dirty, loadError, count := s.dirty, s.loadError, len(s.attempts)
			s.mu.Unlock()
			if !dirty || loadError != "" || count != want {
				t.Fatalf("restart did not schedule validated retention cleanup: count=%d want=%d dirty=%t load_error=%q", count, want, dirty, loadError)
			}
			beforeFlush, err := os.ReadFile(path)
			if err != nil || string(beforeFlush) != string(raw) {
				t.Fatal("startup performed synchronous history cleanup", err)
			}
			s.Close()
			waitForClose(t, s)
			cleaned, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var persisted history
			decodeErr := strictJSON(cleaned, &persisted)
			s.mu.Lock()
			dirty, loadError = s.dirty, s.loadError
			s.mu.Unlock()
			if decodeErr != nil || len(persisted.Attempts) != want || dirty || loadError != "" {
				t.Fatalf("restart without new jobs did not publish retention cleanup: count=%d want=%d dirty=%t load_error=%q decode_error=%v", len(persisted.Attempts), want, dirty, loadError, decodeErr)
			}
			if keepRecent && persisted.Attempts[0].ID != strings.Repeat("b", 64) {
				t.Fatal("retention cleanup removed the recent attempt")
			}
		})
	}
}

func TestExpiredHistoryCleanupWaitsForValidHistory(t *testing.T) {
	dir := privateDir(t)
	now := time.Now().UTC()
	expired := Record{ID: strings.Repeat("a", 64), Operation: "codex", ProofMode: "none", StartedAt: now.Add(-Retention - time.Hour), Outcome: "success", Spans: []Span{}, MissingPhases: []string{}}
	invalid := expired
	invalid.ID = "invalid"
	raw, err := json.Marshal(history{Version: Version, UpdatedAt: now, Attempts: []Record{expired, invalid}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, historyName)
	if err := localfs.WriteAtomic(path, raw, false); err != nil {
		t.Fatal(err)
	}
	s := New(dir)
	s.Close()
	waitForClose(t, s)
	if s.dirty || s.loadError != "corrupt" || len(s.attempts) != 0 {
		t.Fatal("invalid history was scheduled for retention cleanup")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(raw) {
		t.Fatal("retention cleanup rewrote invalid history", err)
	}
}

func TestCoalescedFlushAndBoundedClose(t *testing.T) {
	s := New(privateDir(t))
	a := s.Begin(metadata("flush-one"))
	a.Finish("success")
	s.flush(false)
	first, err := os.Stat(filepath.Join(s.dir, historyName))
	if err != nil {
		t.Fatal(err)
	}
	a = s.Begin(metadata("flush-two"))
	a.Finish("success")
	s.flush(false)
	second, err := os.Stat(filepath.Join(s.dir, historyName))
	if err != nil {
		t.Fatal(err)
	}
	if !first.ModTime().Equal(second.ModTime()) || !s.dirty {
		t.Fatal("diagnostics added more than one flush in a second")
	}
	s.Close()
	waitForClose(t, s)
	if len(Read(s.dir).Attempts) != 2 {
		t.Fatal("final coalesced flush lost attempt")
	}

	blocked := New(privateDir(t))
	b := blocked.Begin(metadata("blocked"))
	b.Finish("success")
	blocked.flushMu.Lock()
	started := time.Now()
	blocked.Close()
	if time.Since(started) > 2*time.Second {
		t.Fatal("blocked diagnostics prevented shutdown")
	}
	blocked.flushMu.Unlock()
	waitForClose(t, blocked)
}

// BenchmarkAttemptRecording isolates optional collector cost. Production-like
// fixture runs should add fixed provider/proof delays and compare enable/off
// medians and p95 separately; no timing threshold belongs in unit tests.
func BenchmarkAttemptRecording(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprintf("enabled=%t", enabled), func(b *testing.B) {
			var s *Store
			if enabled {
				s = New(b.TempDir())
			}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				a := s.Begin(metadata(fmt.Sprint(i)))
				ctx := a.Context(context.Background())
				for k := 0; k < 12; k++ {
					Start(ctx, "journal_write", 0)("success")
				}
				a.Finish("success")
			}
		})
	}
}

// A ten-page relay search, sized as one is measured: about 20 spans before
// the first page, 23 for each page and a quota snapshot per page. The whole
// record is kept, it stays inside its bounds on disk and on export, and
// nothing past the tenth page is recorded.
func TestTenPageSearchKeepsEveryPage(t *testing.T) {
	s := New(privateDir(t))
	if s.Begin(Metadata{ID: "eleven", Operation: "search", Pages: MaxExchanges + 1, ProofMode: "relay"}) != nil {
		t.Fatal("an eleven-page search was recorded")
	}
	a := s.Begin(Metadata{ID: "ten", Operation: "search", Pages: 10, ProofMode: "relay"})
	if a == nil {
		t.Fatal("a ten-page search was not recorded")
	}
	ctx := a.Context(context.Background())
	for _, phase := range []string{"worker_acquire", "account_acquire", "accept_http", "worker", "client_acquire", "journal_lock", "journal_scan", "journal_write", "journal_finish", "journal_ready", "report_prepare", "report_http", "binding_check", "quota_wait", "fixed_gap_wait", "jitter_wait", "journal_lock", "journal_scan", "journal_write", "journal_terminal"} {
		Start(ctx, phase, 0)("success")
	}
	pagePhases := []string{"page_wall", "pacing_wait", "request_encode", "proof_journal_begin", "helper_wall", "helper_stdout_decode", "response_decode", "proof_journal_complete"}
	now := time.Now().UTC()
	for page := 1; page <= 10; page++ {
		for k := 0; k < 23; k++ {
			Start(ctx, pagePhases[k%len(pagePhases)], page)("success")
		}
		ObserveQuota(ctx, QuotaSnapshot{Exchange: page, Operation: "search", Mode: "quota_budget", Limit: 50, Remaining: 50 - page, Reset: now.Add(15 * time.Minute), Complete: true, Authoritative: true, ObservedAt: now, CapturedAt: now})
	}
	Start(ctx, "page_wall", MaxExchanges+1)("success")
	a.Finish("success")
	s.Close()
	waitForClose(t, s)
	loaded := Read(s.dir)
	if loaded.LoadError != "" || len(loaded.Attempts) != 1 {
		t.Fatalf("ten-page history was not readable: %+v", loaded)
	}
	r := loaded.Attempts[0]
	pages := map[int]bool{}
	for _, span := range r.Spans {
		if span.Exchange > MaxExchanges {
			t.Fatalf("span past the tenth page recorded: %+v", span)
		}
		pages[span.Exchange] = true
	}
	for page := 0; page <= 10; page++ {
		if !pages[page] {
			t.Fatalf("exchange %d lost from a ten-page record", page)
		}
	}
	raw, _ := json.Marshal(r)
	if r.Pages != 10 || len(r.QuotaSnapshots) != 10 || len(r.Spans) != 20+23*10 || r.Truncated || len(raw) > MaxAttemptBytes || !validRecord(r) {
		t.Fatalf("ten-page record: pages %d, %d quota snapshots, %d spans, truncated %v, %d bytes, valid %v", r.Pages, len(r.QuotaSnapshots), len(r.Spans), r.Truncated, len(raw), validRecord(r))
	}
}
