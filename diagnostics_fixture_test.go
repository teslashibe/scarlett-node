//go:build unix

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

// This opt-in fixture includes the real worker's encoding, subprocess launch,
// helper summary decoding, proof observer, and coalesced private history writes.
// It measures local instrumentation cost, not provider or network performance.
func TestDiagnosticsWorkerFixtureOverhead(t *testing.T) {
	if os.Getenv("SCARLETT_DIAGNOSTICS_BENCHMARK") != "1" {
		t.Skip("set SCARLETT_DIAGNOSTICS_BENCHMARK=1 for the 1,000-pair worker fixture")
	}
	helper := buildDiagnosticsFixtureHelper(t)
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	seedExpiredDiagnosticsFixture(t, state)
	store := diagnostics.New(state)
	if snapshot := store.Snapshot(); snapshot.LoadError != "" || len(snapshot.Attempts) != 0 {
		t.Fatal("expired private history was retained", snapshot.LoadError, len(snapshot.Attempts))
	}
	flushCtx, stopFlush := context.WithCancel(context.Background())
	flushDone := make(chan struct{})
	go func() { defer close(flushDone); store.Run(flushCtx) }()
	defer func() { stopFlush(); <-flushDone; store.Close() }()
	monitor := watchDiagnosticsFixtureWrites(filepath.Join(state, "diagnostics-v1.json"))
	defer monitor.stop()

	c := config.Config{Executor: config.ExecutorCodexTLSN, Prover: helper, Verifier: "synthetic.invalid:7047", Profile: "standard", MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second}
	const samples = 1000
	cohorts := [2]diagnosticsFixtureCohort{{Outcomes: map[string]int{}}, {Outcomes: map[string]int{}}}
	started := time.Now()
	for i := range samples {
		// Swap order every pair so warm-up, filesystem growth and scheduling
		// variation cannot consistently favor the enabled or disabled cohort.
		for j := range 2 {
			enabled := (i+j)%2 == 1
			index := 0
			var selected *diagnostics.Store
			if enabled {
				index, selected = 1, store
			}
			lease := diagnosticsFixtureLease(t, fmt.Sprintf("synthetic-fixture-%d-%d", index, i), "synthetic-success")
			duration, code, sample := runDiagnosticsFixture(c, selected, context.Background(), lease)
			if code != "" || sample.State != "complete" || sample.SentBytes == nil || *sample.SentBytes != 19 || sample.ReceivedBytes == nil || *sample.ReceivedBytes != 31 {
				t.Fatalf("fixture changed worker or proof outcome: enabled=%t code=%q sample=%+v", enabled, code, sample)
			}
			cohorts[index].DurationsMS = append(cohorts[index].DurationsMS, float64(duration.Microseconds())/1000)
			cohorts[index].Outcomes["success"]++
		}
	}
	elapsed := time.Since(started)
	for i := range cohorts {
		cohorts[i].Samples = len(cohorts[i].DurationsMS)
		cohorts[i].P50MS = diagnosticsFixturePercentile(cohorts[i].DurationsMS, .5)
		cohorts[i].P95MS = diagnosticsFixturePercentile(cohorts[i].DurationsMS, .95)
	}
	medianChange := 100 * (cohorts[1].P50MS/cohorts[0].P50MS - 1)
	p95Change := 100 * (cohorts[1].P95MS/cohorts[0].P95MS - 1)

	// Error and cancellation retain their measured prefixes. They deliberately
	// do not enter the successful-attempt latency percentiles.
	validateDiagnosticsFixtureFailure(t, c, store, "synthetic-error", "prover_error")
	validateDiagnosticsFixtureFailure(t, c, store, "synthetic-cancel", "expired")
	validateDenseDiagnosticsFixture(t, store)
	stopFlush()
	<-flushDone
	store.Close()
	monitor.stop()
	snapshot := diagnostics.Read(state)
	if snapshot.LoadError != "" || len(snapshot.Attempts) != diagnostics.MaxAttempts {
		t.Fatal("history was not capped or could not be reopened", snapshot.LoadError, len(snapshot.Attempts))
	}
	for _, record := range snapshot.Attempts {
		raw, err := json.Marshal(record)
		if err != nil || len(raw) > diagnostics.MaxAttemptBytes || len(record.Spans) > diagnostics.MaxSpans || time.Since(record.StartedAt) > diagnostics.Retention {
			t.Fatal("attempt retention bounds exceeded", err, len(raw), len(record.Spans))
		}
	}
	info, err := os.Stat(filepath.Join(state, "diagnostics-v1.json"))
	if err != nil || info.Size() > diagnostics.MaxHistoryBytes || info.Mode().Perm() != 0600 {
		t.Fatal("private history size or mode changed", info, err)
	}
	writes, minimumGap := monitor.snapshot()
	if writes < 2 || writes > int(math.Ceil(time.Since(started).Seconds()))+2 || minimumGap < 800*time.Millisecond {
		t.Fatal("history publication was not coalesced during worker processing", writes, minimumGap)
	}

	result := struct {
		CreatedAt      time.Time                `json:"created_at"`
		Fixture        string                   `json:"fixture"`
		Scope          string                   `json:"scope"`
		GOOS           string                   `json:"goos"`
		GOARCH         string                   `json:"goarch"`
		GoVersion      string                   `json:"go_version"`
		CPUs           int                      `json:"cpus"`
		GOMAXPROCS     int                      `json:"gomaxprocs"`
		Operation      string                   `json:"operation"`
		Pages          int                      `json:"pages"`
		ProofMode      string                   `json:"proof_mode"`
		HelperDelayMS  int                      `json:"helper_delay_ms"`
		Concurrency    int                      `json:"concurrency"`
		ElapsedMS      int64                    `json:"elapsed_ms"`
		Off            diagnosticsFixtureCohort `json:"off"`
		On             diagnosticsFixtureCohort `json:"on"`
		P50ChangePct   float64                  `json:"p50_change_percent"`
		P95ChangePct   float64                  `json:"p95_change_percent"`
		Retained       int                      `json:"retained_attempts"`
		HistoryBytes   int64                    `json:"history_bytes"`
		ObservedWrites int                      `json:"observed_history_publications"`
		MinimumFlushMS int64                    `json:"minimum_observed_publication_gap_ms"`
		PrefixOutcomes []string                 `json:"separate_prefix_outcomes"`
	}{
		CreatedAt: time.Now().UTC(),
		Fixture:   "real worker.Prover with a synthetic Go helper",
		Scope:     "Go collector, contexts, helper-field validation and coalesced private flushing with matching helper output; excludes Rust tracing cost, X, cryptography, coordinator, verifier and provider timing",
		GOOS:      runtime.GOOS, GOARCH: runtime.GOARCH, GoVersion: runtime.Version(),
		CPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0),
		Operation: "codex", Pages: 0, ProofMode: "none", HelperDelayMS: 30, Concurrency: 1,
		ElapsedMS: elapsed.Milliseconds(), Off: cohorts[0], On: cohorts[1],
		P50ChangePct: medianChange, P95ChangePct: p95Change,
		Retained: len(snapshot.Attempts), HistoryBytes: info.Size(), ObservedWrites: writes,
		MinimumFlushMS: minimumGap.Milliseconds(), PrefixOutcomes: []string{"error", "cancelled"},
	}
	if path := os.Getenv("SCARLETT_DIAGNOSTICS_BENCHMARK_ARTIFACT"); path != "" {
		if !filepath.IsAbs(path) {
			t.Fatal("benchmark artifact path must be absolute")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		raw, err := json.MarshalIndent(result, "", "  ")
		if err == nil {
			err = os.WriteFile(path, raw, 0600)
		}
		if err != nil {
			t.Fatal("could not save synthetic benchmark results", err)
		}
		t.Logf("synthetic benchmark artifact: %s", path)
	}
	t.Logf("1,000 matched attempts each: off p50 %.3f ms / p95 %.3f ms; on p50 %.3f ms / p95 %.3f ms; change p50 %+.3f%% (limit +2%%), p95 %+.3f%% (limit +5%%); %d retained, %d bytes, %d coalesced publications", cohorts[0].P50MS, cohorts[0].P95MS, cohorts[1].P50MS, cohorts[1].P95MS, medianChange, p95Change, len(snapshot.Attempts), info.Size(), writes)
	if medianChange > 2 || p95Change > 5 {
		t.Fatalf("local instrumentation overhead exceeded fixture limits: p50 %+.3f%% / p95 %+.3f%%", medianChange, p95Change)
	}
}

type diagnosticsFixtureCohort struct {
	Samples     int            `json:"samples"`
	P50MS       float64        `json:"p50_ms"`
	P95MS       float64        `json:"p95_ms"`
	Outcomes    map[string]int `json:"outcomes"`
	DurationsMS []float64      `json:"durations_ms"`
}

func runDiagnosticsFixture(c config.Config, store *diagnostics.Store, ctx context.Context, lease coordinator.Lease) (time.Duration, string, attempts.ProofSample) {
	started := time.Now()
	observation := beginLeaseDiagnostics(store, lease)
	ctx = observation.Context(ctx)
	var sample attempts.ProofSample
	ctx = worker.WithProofObserver(ctx, func() (func(attempts.ProofSample) error, error) {
		return func(s attempts.ProofSample) error { sample = s; return nil }, nil
	})
	endWorker := diagnostics.Start(ctx, "worker", 0)
	code, _ := (worker.Prover{Config: c}).Run(ctx, lease)
	endWorker(diagnosticOutcome(ctx, code, nil))
	observation.Finish(diagnosticOutcome(ctx, code, nil))
	return time.Since(started), code, sample
}

func diagnosticsFixtureLease(t *testing.T, id, prompt string) coordinator.Lease {
	t.Helper()
	models := config.AvailableModelsAt(time.Now())
	if len(models) == 0 {
		t.Fatal("no reviewed executable model for synthetic lease")
	}
	payload, err := json.Marshal(map[string]any{"type": "response.create", "model": models[0], "instructions": "You are a helpful assistant.", "input": []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": prompt}}}}, "stream": true, "store": false, "reasoning": map[string]any{"effort": "low"}, "text": map[string]any{"verbosity": "low"}})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator.Lease{Version: coordinator.Version, ServiceType: "codex", JobID: id, SignedJobID: id, Attempt: "1", Fence: "synthetic-fence", Profile: "standard", ModelID: models[0], Prompt: prompt, MaxInputTokens: 100, MaxOutputTokens: 20, InputSHA256: worker.SHA(prompt), CodexPayload: payload, VerifierToken: strings.Repeat("ab", 32), LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute)}
}

func diagnosticsFixturePercentile(values []float64, quantile float64) float64 {
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	return ordered[int(math.Ceil(float64(len(ordered))*quantile))-1]
}

func validateDiagnosticsFixtureFailure(t *testing.T, c config.Config, store *diagnostics.Store, prompt, expected string) {
	t.Helper()
	for _, enabled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if prompt == "synthetic-cancel" {
			ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
		}
		var selected *diagnostics.Store
		if enabled {
			selected = store
		}
		lease := diagnosticsFixtureLease(t, fmt.Sprintf("synthetic-prefix-%s-%t", prompt, enabled), prompt)
		_, code, sample := runDiagnosticsFixture(c, selected, ctx, lease)
		cancel()
		if code != expected || sample.State != "incomplete" || sample.Reason != "helper_failed" {
			t.Fatal("error/cancellation changed the worker or proof prefix", prompt, code, sample)
		}
		if !enabled {
			continue
		}
		id := (attempts.Record{JobID: lease.JobID, Attempt: lease.Attempt, Fence: lease.Fence}).Key()
		var found, helperPrefix bool
		for _, record := range store.Snapshot().Attempts {
			if record.ID != id {
				continue
			}
			outcome := "prover_error"
			if prompt == "synthetic-cancel" {
				outcome = "cancelled"
			}
			if record.Outcome != outcome {
				t.Fatal("failed attempt outcome changed", prompt, record.Outcome)
			}
			for _, span := range record.Spans {
				if span.Phase == "helper_stdout_decode" {
					t.Fatal("failed helper fabricated a completed stdout decode")
				}
				if span.Phase == "helper_wall" {
					outcome := "error"
					if prompt == "synthetic-cancel" {
						outcome = "cancelled"
					}
					found = span.DurationMS > 0 && span.Outcome == outcome
				}
				if span.Source == "helper" {
					if prompt == "synthetic-cancel" {
						t.Fatal("killed helper fabricated reported diagnostics")
					}
					if span.Phase == "helper_total" {
						helperPrefix = span.DurationMS > 0 && span.Outcome == "error"
					}
				}
			}
		}
		if !found {
			t.Fatal("failed helper lost its measured prefix", prompt)
		}
		if prompt == "synthetic-error" && !helperPrefix {
			t.Fatal("failed helper lost its reported diagnostic prefix")
		}
	}
}

func validateDenseDiagnosticsFixture(t *testing.T, store *diagnostics.Store) {
	t.Helper()
	attempt := store.Begin(diagnostics.Metadata{ID: "synthetic-dense-three-exchanges", Operation: "search", Pages: 3, ProofMode: "relay"})
	ctx := attempt.Context(context.Background())
	for i := range 100 {
		diagnostics.Start(ctx, "request_encode", i%3+1)("success")
	}
	attempt.Finish("success")
	for _, record := range store.Snapshot().Attempts {
		if record.Operation == "search" {
			if !record.Truncated || len(record.Spans) > diagnostics.MaxSpans {
				t.Fatal("dense three-exchange diagnostic did not remain bounded", record)
			}
			return
		}
	}
	t.Fatal("missing dense diagnostic fixture")
}

func seedExpiredDiagnosticsFixture(t *testing.T, dir string) {
	t.Helper()
	old := diagnostics.Record{ID: strings.Repeat("a", 64), Operation: "codex", ProofMode: "none", StartedAt: time.Now().Add(-25 * time.Hour), Outcome: "success", Spans: []diagnostics.Span{}, MissingPhases: []string{}}
	raw, err := json.Marshal(map[string]any{"version": diagnostics.Version, "updated_at": time.Now().UTC(), "attempts": []diagnostics.Record{old}})
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, "diagnostics-v1.json"), raw, 0600)
	}
	if err != nil {
		t.Fatal("could not seed expired synthetic diagnostics", err)
	}
}

type diagnosticsFixtureWriteMonitor struct {
	mu         sync.Mutex
	writes     int
	minimumGap time.Duration
	cancel     context.CancelFunc
	done       chan struct{}
}

func watchDiagnosticsFixtureWrites(path string) *diagnosticsFixtureWriteMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	m := &diagnosticsFixtureWriteMonitor{cancel: cancel, done: make(chan struct{})}
	initial, _ := os.Stat(path)
	var previous time.Time
	if initial != nil {
		previous = initial.ModTime()
	}
	go func() {
		defer close(m.done)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		var lastPublication time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				info, err := os.Stat(path)
				if err != nil || info.ModTime().Equal(previous) {
					continue
				}
				previous = info.ModTime()
				m.mu.Lock()
				if !lastPublication.IsZero() {
					gap := previous.Sub(lastPublication)
					if m.minimumGap == 0 || gap < m.minimumGap {
						m.minimumGap = gap
					}
				}
				lastPublication = previous
				m.writes++
				m.mu.Unlock()
			}
		}
	}()
	return m
}

func (m *diagnosticsFixtureWriteMonitor) stop() { m.cancel(); <-m.done }
func (m *diagnosticsFixtureWriteMonitor) snapshot() (int, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writes, m.minimumGap
}

func buildDiagnosticsFixtureHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	source := filepath.Join(dir, "synthetic_helper.go")
	const program = `package main
import (
 "encoding/json"
 "fmt"
 "io"
 "os"
 "time"
)
func main() {
 started := time.Now()
 var in struct { Payload struct { Input []struct { Content []struct { Text string } } } }
 raw, err := io.ReadAll(os.Stdin)
 if err != nil || len(os.Args) != 2 || os.Args[1] != "prove" || json.Unmarshal(raw, &in) != nil || len(in.Payload.Input) != 1 || len(in.Payload.Input[0].Content) != 1 { os.Exit(2) }
 prompt := in.Payload.Input[0].Content[0].Text
 if prompt == "synthetic-cancel" { time.Sleep(2*time.Second); os.Exit(3) }
 time.Sleep(30*time.Millisecond)
 duration := float64(time.Since(started).Microseconds())/1000
 outcome := "success"
 if prompt == "synthetic-error" { outcome = "error" }
 measurements := map[string]any{"version":1,"duration_ms":duration,"outcome":outcome,"spans":[]any{map[string]any{"phase":"proof_finalize","start_ms":0,"duration_ms":duration,"outcome":outcome}}}
 if outcome == "error" { encoded,_ := json.Marshal(measurements); fmt.Fprintln(os.Stderr,"SCARLETT_DIAGNOSTICS="+string(encoded)); fmt.Fprintln(os.Stderr,"synthetic helper failure"); os.Exit(1) }
 json.NewEncoder(os.Stdout).Encode(map[string]any{"status":"proof_sent","verifier_sent_bytes":19,"verifier_received_bytes":31,"verifier_transport_layer":"tcp_payload","diagnostics":measurements})
}
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "synthetic-helper")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", helper, source)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build synthetic helper: %v %s", err, output)
	}
	return helper
}
