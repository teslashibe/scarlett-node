package main

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
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
