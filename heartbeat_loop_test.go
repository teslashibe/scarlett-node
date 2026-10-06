package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// The run loop treats the heartbeat as a long poll: every heartbeat asks for
// the full hold, the node heartbeats again the moment a lease or an idle hold
// is answered, and it pauses only after a failed heartbeat.
func TestRunLoopLongPollsWithoutIdleSleep(t *testing.T) {
	dir := privateTestDir(t)
	home := filepath.Join(dir, "codex")
	if err := privateFixtureMkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	// An expired local credential: the node advertises exhausted and declines
	// the offer locally, so no acceptance or report HTTP happens in this test.
	if err := writePrivateFixture(filepath.Join(home, "auth.json"), syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	// LocalFixture shortens the error backoff to one second so the test can
	// observe it; nothing else about the loop depends on it.
	c := config.Config{Executor: config.ExecutorCodexTLSN, Profile: "standard", StateDir: filepath.Join(dir, "state"), CodexHome: home, Credential: "synthetic-credential", NodeID: "synthetic-node", Concurrency: 3, Bid: 100, Verifier: "locally-configured.invalid:7047", Prover: filepath.Join(dir, "synthetic-prover-never-run"), JournalLimits: attempts.DefaultLimits(), MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second, LocalFixture: true}
	offer := testLease()
	offer.ServiceType, offer.AcceptanceRequired = "codex", true
	offer.SettlementDeadline = offer.LeaseDeadline
	offer.SignedJobID, offer.RequestSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	type call struct {
		arrived, answered time.Time
		wait              int
	}
	var mu sync.Mutex
	var calls []call
	var other int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/api/node/v1/heartbeat" {
			other++
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var h coordinator.Heartbeat
		if json.NewDecoder(r.Body).Decode(&h) != nil {
			t.Error("invalid heartbeat")
		}
		this := call{arrived: time.Now(), wait: h.WaitSeconds}
		switch len(calls) {
		case 0:
			// Offered work: the node must heartbeat again at once.
			json.NewEncoder(w).Encode(map[string]any{"lease": offer})
		case 1:
			// An idle hold: the coordinator keeps the request open, then
			// answers nothing. The node's next heartbeat follows immediately.
			time.Sleep(300 * time.Millisecond)
			io.WriteString(w, `{"lease":null}`)
		case 2:
			// A failed heartbeat earns the backoff, and nothing else does.
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			writer.Close()
			io.WriteString(w, `{"lease":null}`)
		}
		this.answered = time.Now()
		calls = append(calls, this)
	}))
	defer server.Close()
	c.Coordinator = server.URL
	c.CoordinatorCA = filepath.Join(privateTestDir(t), "synthetic-coordinator-ca.pem")
	if err := writePrivateFixture(c.CoordinatorCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runWithOwner(c, reader) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		writer.Close()
		t.Fatal("synthetic node did not stop")
	}
	mu.Lock()
	defer mu.Unlock()
	if other != 0 || len(calls) < 4 {
		t.Fatalf("heartbeats %d, other calls %d", len(calls), other)
	}
	for i, c := range calls {
		if c.wait != coordinator.HeartbeatWaitSeconds {
			t.Fatalf("heartbeat %d asked for a %ds hold, want %d", i, c.wait, coordinator.HeartbeatWaitSeconds)
		}
	}
	if gap := calls[1].arrived.Sub(calls[0].answered); gap > 500*time.Millisecond {
		t.Fatalf("heartbeat after a lease waited %v", gap)
	}
	if gap := calls[2].arrived.Sub(calls[1].answered); gap > 500*time.Millisecond {
		t.Fatalf("heartbeat after an idle hold waited %v", gap)
	}
	if gap := calls[3].arrived.Sub(calls[2].answered); gap < time.Second {
		t.Fatalf("heartbeat after a failure did not back off: %v", gap)
	}
}

// Stopping the node aborts a heartbeat the coordinator is still holding.
func TestRunLoopStopAbortsHeldHeartbeat(t *testing.T) {
	dir := privateTestDir(t)
	home := filepath.Join(dir, "codex")
	if err := privateFixtureMkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFixture(filepath.Join(home, "auth.json"), syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{Executor: config.ExecutorCodexTLSN, Profile: "standard", StateDir: filepath.Join(dir, "state"), CodexHome: home, Credential: "synthetic-credential", NodeID: "synthetic-node", Concurrency: 1, Bid: 100, Verifier: "locally-configured.invalid:7047", Prover: filepath.Join(dir, "synthetic-prover-never-run"), JournalLimits: attempts.DefaultLimits(), MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second}
	reader, writer := io.Pipe()
	defer reader.Close()
	held := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case held <- struct{}{}:
		default:
		}
		// Hold until the node hangs up; never answer. The body must be read
		// for the server to notice the hang-up and cancel the context.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer server.Close()
	c.Coordinator = server.URL
	c.CoordinatorCA = filepath.Join(privateTestDir(t), "synthetic-coordinator-ca.pem")
	if err := writePrivateFixture(c.CoordinatorCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runWithOwner(c, reader) }()
	select {
	case <-held:
	case <-time.After(5 * time.Second):
		t.Fatal("node never heartbeated")
	}
	stopped := time.Now()
	writer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(stopped) > 2*time.Second {
			t.Fatal("stop waited for the held heartbeat", time.Since(stopped))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not abort the held heartbeat")
	}
}

// startLongPollNode runs a synthetic node that advertises available against a
// coordinator served by handler, and returns its config and a stop function
// that waits for it to exit.
func startLongPollNode(t *testing.T, handler http.HandlerFunc) (config.Config, func()) {
	t.Helper()
	dir := privateTestDir(t)
	home := filepath.Join(dir, "codex")
	if err := privateFixtureMkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFixture(filepath.Join(home, "auth.json"), syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	// LocalFixture skips the local Codex admission guard, so the node
	// advertises available until something local changes.
	c := config.Config{Executor: config.ExecutorCodexTLSN, Profile: "standard", StateDir: filepath.Join(dir, "state"), CodexHome: home, Credential: "synthetic-credential", NodeID: "synthetic-node", Concurrency: 1, Bid: 100, Verifier: "locally-configured.invalid:7047", Prover: filepath.Join(dir, "synthetic-prover-never-run"), JournalLimits: attempts.DefaultLimits(), MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second, LocalFixture: true}
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	c.Coordinator = server.URL
	c.CoordinatorCA = filepath.Join(privateTestDir(t), "synthetic-coordinator-ca.pem")
	if err := writePrivateFixture(c.CoordinatorCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- runWithOwner(c, reader) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			writer.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Error("synthetic node did not stop")
			}
			reader.Close()
		})
	}
	t.Cleanup(stop)
	return c, stop
}

// An operator drain during a held heartbeat ends the hold within about a
// second, and the node heartbeats again at once, reporting the drain, instead
// of leaving the coordinator free to hand over a lease for up to the full hold.
func TestRunLoopDrainEndsHeldHeartbeat(t *testing.T) {
	type arrival struct {
		state string
		at    time.Time
	}
	type release struct {
		at        time.Time
		cancelled bool
	}
	arrivals := make(chan arrival, 8)
	releases := make(chan release, 8)
	c, stop := startLongPollNode(t, func(w http.ResponseWriter, r *http.Request) {
		var h coordinator.Heartbeat
		if r.URL.Path != "/api/node/v1/heartbeat" || json.NewDecoder(r.Body).Decode(&h) != nil {
			t.Error("unexpected request", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		arrivals <- arrival{h.State, time.Now()}
		// Hold every heartbeat for the full hold the node asked for, as an
		// idle coordinator does, unless the node hangs up first.
		_, _ = io.Copy(io.Discard, r.Body)
		this := release{}
		select {
		case <-r.Context().Done():
			this.cancelled = true
		case <-time.After(time.Duration(h.WaitSeconds) * time.Second):
			io.WriteString(w, `{"lease":null}`)
		}
		this.at = time.Now()
		releases <- this
	})
	var held arrival
	select {
	case held = <-arrivals:
	case <-time.After(5 * time.Second):
		t.Fatal("node never heartbeated")
	}
	if held.state != "available" {
		t.Fatalf("held heartbeat advertised %q", held.state)
	}
	drainedAt := time.Now()
	if err := writeLocalFile(c.StateDir, "drain", []byte("drained\n")); err != nil {
		t.Fatal(err)
	}
	var ended release
	select {
	case ended = <-releases:
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not end the held heartbeat")
	}
	if !ended.cancelled {
		t.Fatal("the coordinator answered the held heartbeat; the node never cut it short")
	}
	if took := ended.at.Sub(drainedAt); took > 1500*time.Millisecond {
		t.Fatalf("drain ended the held heartbeat after %v", took)
	}
	var after arrival
	select {
	case after = <-arrivals:
	case <-time.After(5 * time.Second):
		t.Fatal("node did not heartbeat again after the drain")
	}
	if after.state != "exhausted" {
		t.Fatalf("heartbeat after the drain advertised %q", after.state)
	}
	// No failure backoff (one second for a local fixture) before it.
	if gap := after.at.Sub(ended.at); gap > 500*time.Millisecond {
		t.Fatalf("heartbeat after the drain waited %v", gap)
	}
	stop()
}

// With nothing local changing, the node leaves a held heartbeat to the
// coordinator: the watch does not cut it short.
func TestRunLoopKeepsUnchangedHeldHeartbeat(t *testing.T) {
	const hold = 2500 * time.Millisecond // several watch intervals
	type call struct {
		state     string
		cancelled bool
	}
	calls := make(chan call, 8)
	var mu sync.Mutex
	n := 0
	_, stop := startLongPollNode(t, func(w http.ResponseWriter, r *http.Request) {
		var h coordinator.Heartbeat
		if r.URL.Path != "/api/node/v1/heartbeat" || json.NewDecoder(r.Body).Decode(&h) != nil {
			t.Error("unexpected request", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		mu.Lock()
		first := n == 0
		n++
		mu.Unlock()
		this := call{state: h.State}
		_, _ = io.Copy(io.Discard, r.Body)
		if first {
			select {
			case <-r.Context().Done():
				this.cancelled = true
			case <-time.After(hold):
				io.WriteString(w, `{"lease":null}`)
			}
		} else {
			<-r.Context().Done()
		}
		calls <- this
	})
	var first call
	select {
	case first = <-calls:
	case <-time.After(hold + 5*time.Second):
		t.Fatal("held heartbeat never ended")
	}
	if first.cancelled || first.state != "available" {
		t.Fatalf("held heartbeat advertised %q, cancelled %v", first.state, first.cancelled)
	}
	stop()
}

// A held heartbeat ends when admission or occupancy changes. Even an unchanged
// service state can carry stale in-flight counts or coordinator lease references.
func TestServiceStatesTrackOccupancyAndReferences(t *testing.T) {
	health := func(state string, capacity, inFlight int) []coordinator.ServiceHealth {
		return []coordinator.ServiceHealth{{Kind: "x_read", State: state, Capacity: capacity, InFlight: inFlight, ProofModes: []string{"mpc", "relay"}}}
	}
	for _, state := range []string{"configured", "ready", "exhausted", "unreachable", "auth_required", "not_added"} {
		if serviceStates(health(state, 2, 0)) == serviceStates(health(state, 1, 0)) {
			t.Fatalf("%s: a capacity change must end the hold", state)
		}
		if serviceStates(health(state, 2, 0)) == serviceStates(health(state, 2, 1)) {
			t.Fatalf("%s: an occupancy change must end the hold", state)
		}
		if serviceStates(health(state, 2, 1)) == serviceStates(health(state, 2, 2)) {
			t.Fatalf("%s: filling the last slot must end the hold", state)
		}
		if serviceStates(health(state, 1, 1)) == serviceStates(health(state, 1, 0)) {
			t.Fatalf("%s: freeing the last slot must end the hold", state)
		}
	}
	if serviceStates(health("ready", 1, 0)) == serviceStates(health("exhausted", 1, 0)) {
		t.Fatal("a state change must end the hold")
	}
	first := health("ready", 2, 1)
	first[0].ActiveLeases = []coordinator.ActiveLease{{JobID: "00000000-0000-4000-8000-000000000001", Attempt: "00000000-0000-4000-8000-000000000002", Fence: "00000000-0000-4000-8000-000000000003"}}
	second := health("ready", 2, 1)
	second[0].ActiveLeases = append([]coordinator.ActiveLease(nil), first[0].ActiveLeases...)
	second[0].ActiveLeases[0].Fence = "00000000-0000-4000-8000-000000000004"
	if serviceStates(first) == serviceStates(second) {
		t.Fatal("a reference change with unchanged occupancy must end the hold")
	}
}

func TestHeartbeatCompletionSignalChecksSnapshotBeforeRefreshing(t *testing.T) {
	ref := coordinator.ActiveLease{JobID: "00000000-0000-4000-8000-000000000001", Attempt: "00000000-0000-4000-8000-000000000002", Fence: "00000000-0000-4000-8000-000000000003"}
	health := func(inFlight int, refs []coordinator.ActiveLease) availability {
		return availability{services: serviceStates([]coordinator.ServiceHealth{{Kind: "x_read", State: "ready", Capacity: 2, InFlight: inFlight, ActiveLeases: refs}})}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	changes := make(chan struct{}, 1)
	// A completion just before the snapshot is already reflected by the sent
	// heartbeat. Its queued notification must not drop a concurrent offer.
	changes <- struct{}{}
	sent := health(1, []coordinator.ActiveLease{ref})
	var mu sync.Mutex
	current := sent
	checked := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchHeartbeat(ctx, cancel, sent, func() availability {
			mu.Lock()
			snapshot := current
			mu.Unlock()
			select {
			case checked <- struct{}{}:
			default:
			}
			return snapshot
		}, changes)
	}()
	select {
	case <-checked:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("queued completion did not wake the snapshot check")
	}
	select {
	case <-done:
		t.Fatal("an already reflected completion cancelled the fresh heartbeat")
	case <-time.After(150 * time.Millisecond):
	}
	mu.Lock()
	current = health(0, nil)
	mu.Unlock()
	changes <- struct{}{}
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("completion did not refresh the held heartbeat")
	}
	if context.Cause(ctx) != errHeartbeatStale {
		t.Fatal("completion did not mark active lease references stale")
	}
}

// A worker completing while the coordinator holds an exhausted heartbeat must
// advertise its freed slot immediately. The synthetic lease fails validation
// locally, so this exercises acceptance, reporting and release without calling
// a provider or launching the helper.
func TestRunLoopCompletionRefreshesFullHeldHeartbeatWithoutBackoff(t *testing.T) {
	dir := privateTestDir(t)
	home := filepath.Join(dir, "codex")
	if err := privateFixtureMkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFixture(filepath.Join(home, "auth.json"), freshSyntheticCodexAuth(), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{Executor: config.ExecutorServices, Services: []string{"codex"}, Profile: "standard", StateDir: filepath.Join(dir, "state"), AccountsFile: filepath.Join(dir, "state", "accounts.json"), CodexHome: home, Credential: "synthetic-credential", NodeID: "synthetic-node", CodexConcurrency: 1, XConcurrency: 1, Bid: 100, Verifier: "locally-configured.invalid:7047", Prover: os.Args[0], JournalLimits: attempts.DefaultLimits(), MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second, LocalFixture: true}
	offer := testLease()
	offer.ServiceType, offer.AcceptanceRequired = "codex", true
	offer.SettlementDeadline = offer.LeaseDeadline
	offer.SignedJobID, offer.RequestSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	offer.JobID = "00000000-0000-4000-8000-000000000001"
	offer.Attempt = "00000000-0000-4000-8000-000000000002"
	offer.Fence = "00000000-0000-4000-8000-000000000003"
	type arrival struct {
		heartbeat coordinator.Heartbeat
		at        time.Time
	}
	arrivals := make(chan arrival, 8)
	heldEnded := make(chan time.Time, 8)
	reportReady := make(chan struct{}, 1)
	allowReport := make(chan struct{})
	var releaseOnce sync.Once
	releaseReport := func() { releaseOnce.Do(func() { close(allowReport) }) }
	defer releaseReport()
	var mu sync.Mutex
	heartbeats := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/node/v1/heartbeat":
			var h coordinator.Heartbeat
			if json.NewDecoder(r.Body).Decode(&h) != nil {
				t.Error("invalid heartbeat")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			arrivals <- arrival{heartbeat: h, at: time.Now()}
			mu.Lock()
			first := heartbeats == 0
			heartbeats++
			mu.Unlock()
			if first {
				json.NewEncoder(w).Encode(coordinator.HeartbeatReply{Lease: &offer})
				return
			}
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			heldEnded <- time.Now()
		case strings.HasSuffix(r.URL.Path, "/accept"):
			accepted := offer
			accepted.VerifierToken = strings.Repeat("c", 64)
			json.NewEncoder(w).Encode(coordinator.LeaseAcceptance{Version: coordinator.Version, State: "leased", FundingAuthority: "production_receipt", Lease: accepted})
		case strings.HasSuffix(r.URL.Path, "/fail"):
			var failure coordinator.Failure
			if json.NewDecoder(r.Body).Decode(&failure) != nil || failure.Code != "invalid_lease" {
				t.Error("synthetic lease did not fail locally")
			}
			reportReady <- struct{}{}
			select {
			case <-allowReport:
				w.WriteHeader(http.StatusNoContent)
			case <-r.Context().Done():
			}
		default:
			t.Error("unexpected request", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(server.Close)
	c.Coordinator = server.URL
	c.CoordinatorCA = filepath.Join(privateTestDir(t), "synthetic-coordinator-ca.pem")
	if err := writePrivateFixture(c.CoordinatorCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- runWithOwner(c, reader) }()
	t.Cleanup(func() {
		releaseReport()
		writer.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("synthetic node did not stop")
		}
		reader.Close()
	})
	nextHeartbeat := func() arrival {
		t.Helper()
		select {
		case a := <-arrivals:
			return a
		case <-time.After(5 * time.Second):
			t.Fatal("node did not heartbeat")
			return arrival{}
		}
	}
	if first := nextHeartbeat(); first.heartbeat.State != "available" {
		t.Fatalf("initial heartbeat advertised %q", first.heartbeat.State)
	}
	full := nextHeartbeat()
	if full.heartbeat.State != "exhausted" || len(full.heartbeat.Services) == 0 || full.heartbeat.Services[0].InFlight != 1 {
		t.Fatalf("full heartbeat did not advertise its occupied slot: %+v", full.heartbeat)
	}
	refs := full.heartbeat.Services[0].ActiveLeases
	if len(refs) != 1 || refs[0] != (coordinator.ActiveLease{JobID: offer.JobID, Attempt: offer.Attempt, Fence: offer.Fence}) {
		t.Fatalf("full heartbeat did not bind the occupied lease: %+v", refs)
	}
	select {
	case <-reportReady:
	case <-time.After(5 * time.Second):
		t.Fatal("synthetic worker did not reach its report")
	}
	// Keep the report unacknowledged: the account must remain occupied and the
	// heartbeat must remain held until reporting finishes.
	select {
	case <-heldEnded:
		t.Fatal("full heartbeat ended before reporting finished")
	case <-time.After(150 * time.Millisecond):
	}
	releasedAt := time.Now()
	releaseReport()
	after := nextHeartbeat()
	if after.heartbeat.State != "available" || len(after.heartbeat.Services) == 0 || after.heartbeat.Services[0].InFlight != 0 || len(after.heartbeat.Services[0].ActiveLeases) != 0 {
		t.Fatalf("completion did not advertise the free slot: %+v", after.heartbeat)
	}
	// This is below both the one-second watcher interval and the fixture's
	// one-second failure backoff, so it requires the completion wakeup.
	if delay := after.at.Sub(releasedAt); delay > 500*time.Millisecond {
		t.Fatalf("completion waited %v before advertising available", delay)
	}
}
