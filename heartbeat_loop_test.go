package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/update"
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
	// An expired local credential: the node rejects the offer locally, so no
	// acceptance or report HTTP happens in this test, only the rejection.
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
	var rejects []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if controlRoute(w, r) {
			return
		}
		if r.URL.Path == "/api/node/v1/jobs/"+offer.JobID+"/reject" {
			// The expired credential cannot take the offer; the node says so
			// instead of leaving it to expire, and never accepts it.
			var body coordinator.Rejection
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			rejects = append(rejects, body.Reason)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
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
			json.NewEncoder(w).Encode(map[string]any{"leases": []coordinator.Lease{offer}})
		case 1:
			// An idle hold: the coordinator keeps the request open, then
			// answers nothing. The node's next heartbeat follows immediately.
			time.Sleep(300 * time.Millisecond)
			io.WriteString(w, `{"leases":[]}`)
		case 2:
			// A failed heartbeat earns the backoff, and nothing else does.
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			writer.Close()
			io.WriteString(w, `{"leases":[]}`)
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
	if other != 0 || len(calls) < 4 || len(rejects) != 1 || rejects[0] != coordinator.RejectNoAccount {
		t.Fatalf("heartbeats %d, other calls %d, rejections %v", len(calls), other, rejects)
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

// Stopping the node, by closing its owner pipe (the desktop app's Stop or
// Quit) or by a signal, says goodbye first and then aborts the heartbeat the
// coordinator is still holding, promptly.
func TestRunLoopStopSaysGoodbyeBeforeEndingHeldHeartbeat(t *testing.T) {
	for _, viaSignal := range []bool{false, true} {
		t.Run(map[bool]string{false: "owner-closed", true: "signal"}[viaSignal], func(t *testing.T) {
			dir := privateTestDir(t)
			home := filepath.Join(dir, "codex")
			if err := privateFixtureMkdir(home, 0700); err != nil {
				t.Fatal(err)
			}
			if err := writePrivateFixture(filepath.Join(home, "auth.json"), syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600); err != nil {
				t.Fatal(err)
			}
			c := config.Config{Executor: config.ExecutorCodexTLSN, Profile: "standard", StateDir: filepath.Join(dir, "state"), CodexHome: home, Credential: "synthetic-credential", NodeID: "synthetic-node", Concurrency: 1, Bid: 100, Verifier: "locally-configured.invalid:7047", Prover: filepath.Join(dir, "synthetic-prover-never-run"), JournalLimits: attempts.DefaultLimits(), MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second}
			fires := make(chan context.CancelFunc, 1)
			if viaSignal {
				restore := notifyStop
				notifyStop = func(parent context.Context) (context.Context, context.CancelFunc) {
					ctx, cancel := context.WithCancel(parent)
					fires <- cancel
					return ctx, cancel
				}
				t.Cleanup(func() { notifyStop = restore })
			}
			reader, writer := io.Pipe()
			defer reader.Close()
			held := make(chan struct{}, 1)
			var mu sync.Mutex
			var events []string
			record := func(event string) {
				mu.Lock()
				events = append(events, event)
				mu.Unlock()
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/node/v1/goodbye" {
					var body coordinator.Goodbye
					if json.NewDecoder(r.Body).Decode(&body) != nil || body.Version != coordinator.Version || body.NodeID != "synthetic-node" {
						t.Error("invalid goodbye")
					}
					record("goodbye:" + body.Reason)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				select {
				case held <- struct{}{}:
				default:
				}
				// Hold until the node hangs up; never answer. The body must be read
				// for the server to notice the hang-up and cancel the context.
				_, _ = io.Copy(io.Discard, r.Body)
				<-r.Context().Done()
				record("hangup")
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
			if viaSignal {
				(<-fires)()
			} else {
				writer.Close()
			}
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
			writer.Close()
			want := []string{"goodbye:" + map[bool]string{false: coordinator.GoodbyeStop, true: coordinator.GoodbyeSignal}[viaSignal], "hangup"}
			deadline := time.Now().Add(2 * time.Second)
			for {
				mu.Lock()
				got := append([]string(nil), events...)
				mu.Unlock()
				if reflect.DeepEqual(got, want) {
					break
				}
				if len(got) >= len(want) || time.Now().After(deadline) {
					t.Fatalf("coordinator saw %v, want %v", got, want)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// controlRoute answers the node's availability posts and goodbyes with 204
// and reports whether r was one, so that fake coordinators that hold
// heartbeats need not treat the node's own control traffic as unexpected.
func controlRoute(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/node/v1/availability", "/api/node/v1/goodbye":
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// testWatch is a pollWatch for one held heartbeat in a unit test: nothing
// stops, no owner pipe, no wall-clock jump and goodbyes go nowhere.
func testWatch(sent availability, current func() availability, post func(context.Context) (availability, error)) pollWatch {
	return pollWatch{stop: context.Background(), sent: sent, current: current, clock: &clockWatch{}, post: post,
		goodbye: func(string, time.Time) {}, stopReason: func() string { return coordinator.GoodbyeSignal }, drainReason: func() string { return coordinator.GoodbyeStop }}
}

// startLongPollNode runs a synthetic node that advertises available against a
// coordinator served by handler, and returns its config and a stop function
// that waits for it to exit.
func startLongPollNode(t *testing.T, handler http.HandlerFunc) (config.Config, func()) {
	t.Helper()
	return startLongPollNodeWith(t, handler, nil)
}

// startLongPollNodeWith is startLongPollNode with prepare, if set, adjusting
// the config and state directory before the node starts.
func startLongPollNodeWith(t *testing.T, handler http.HandlerFunc, prepare func(*config.Config)) (config.Config, func()) {
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
	if prepare != nil {
		prepare(&c)
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

// A drain during a held heartbeat says goodbye within about a second and then
// ends the hold, and the node heartbeats again at once, reporting the drain,
// instead of leaving the coordinator free to hand over a lease for up to the
// full hold. The goodbye says update while the desktop updater is draining
// the node for an install, else stop.
func TestRunLoopDrainSaysGoodbyeAndEndsHeldHeartbeat(t *testing.T) {
	for _, updating := range []bool{false, true} {
		t.Run(map[bool]string{false: "operator", true: "updater"}[updating], func(t *testing.T) {
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
			goodbyes := make(chan string, 8)
			var goodbyeAt atomic.Int64
			c, stop := startLongPollNode(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/node/v1/goodbye" {
					var body coordinator.Goodbye
					_ = json.NewDecoder(r.Body).Decode(&body)
					goodbyeAt.CompareAndSwap(0, time.Now().UnixNano())
					goodbyes <- body.Reason
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if controlRoute(w, r) {
					return
				}
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
					io.WriteString(w, `{"leases":[]}`)
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
			if updating {
				pending := &update.Pending{Phase: update.PhaseDraining, From: coordinator.NodeRelease, To: "99.0.0", Kind: "mac-app", DrainOwner: "updater", StartedAt: time.Now().Unix()}
				if err := (update.StateFile{Path: filepath.Join(c.StateDir, "update-state.json")}).Write(update.State{Schema: 1, Pending: pending}); err != nil {
					t.Fatal(err)
				}
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
			select {
			case reason := <-goodbyes:
				if want := map[bool]string{false: coordinator.GoodbyeStop, true: coordinator.GoodbyeUpdate}[updating]; reason != want {
					t.Fatalf("drain goodbye %q, want %q", reason, want)
				}
			default:
				t.Fatal("drain ended the hold without a goodbye")
			}
			if at := time.Unix(0, goodbyeAt.Load()); at.After(ended.at) {
				t.Fatalf("goodbye at %v came after the hold ended at %v", at, ended.at)
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
		})
	}
}

// With nothing local changing, the node leaves a held heartbeat to the
// coordinator: the watch neither cuts it short nor posts availability.
func TestRunLoopKeepsUnchangedHeldHeartbeat(t *testing.T) {
	const hold = 2500 * time.Millisecond // several watch intervals
	type call struct {
		state     string
		cancelled bool
	}
	calls := make(chan call, 8)
	var posts atomic.Int32
	var mu sync.Mutex
	n := 0
	_, stop := startLongPollNode(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/node/v1/availability" {
			posts.Add(1)
		}
		if controlRoute(w, r) {
			return
		}
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
				io.WriteString(w, `{"leases":[]}`)
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
	if first.cancelled || first.state != "available" || posts.Load() != 0 {
		t.Fatalf("held heartbeat advertised %q, cancelled %v, %d availability posts", first.state, first.cancelled, posts.Load())
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

// A completion already reflected in the held heartbeat posts nothing; a real
// change posts the new availability once and keeps the heartbeat held.
func TestHeartbeatCompletionSignalChecksSnapshotBeforePosting(t *testing.T) {
	ref := coordinator.ActiveLease{JobID: "00000000-0000-4000-8000-000000000001", Attempt: "00000000-0000-4000-8000-000000000002", Fence: "00000000-0000-4000-8000-000000000003"}
	health := func(inFlight int, refs []coordinator.ActiveLease) availability {
		return availability{services: serviceStates([]coordinator.ServiceHealth{{Kind: "x_read", State: "ready", Capacity: 2, InFlight: inFlight, ActiveLeases: refs}})}
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	changes := make(chan struct{}, 1)
	// A completion just before the snapshot is already reflected by the sent
	// heartbeat. Its queued notification must not post anything.
	changes <- struct{}{}
	sent := health(1, []coordinator.ActiveLease{ref})
	var mu sync.Mutex
	current := sent
	checked := make(chan struct{}, 1)
	posted := make(chan availability, 4)
	read := func() availability {
		mu.Lock()
		snapshot := current
		mu.Unlock()
		select {
		case checked <- struct{}{}:
		default:
		}
		return snapshot
	}
	watch := testWatch(sent, read, func(context.Context) (availability, error) {
		a := read()
		posted <- a
		return a, nil
	})
	watch.changes = changes
	done := make(chan watchResult, 1)
	go func() { done <- watchHeartbeat(ctx, cancel, watch) }()
	select {
	case <-checked:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("queued completion did not wake the snapshot check")
	}
	select {
	case a := <-posted:
		t.Fatalf("an already reflected completion posted %+v", a)
	case <-time.After(150 * time.Millisecond):
	}
	mu.Lock()
	current = health(0, nil)
	mu.Unlock()
	changes <- struct{}{}
	select {
	case a := <-posted:
		if a != health(0, nil) {
			t.Fatalf("posted %+v", a)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("completion did not post the freed slot")
	}
	select {
	case result := <-done:
		t.Fatalf("completion ended the held heartbeat: %+v", result)
	case <-time.After(300 * time.Millisecond):
	}
	if ctx.Err() != nil {
		t.Fatal("completion cancelled the held heartbeat")
	}
	cancel(nil)
	if result := <-done; result.cause != nil || result.goodbye {
		t.Fatalf("watch ended %+v", result)
	}
	select {
	case a := <-posted:
		t.Fatalf("posted again after the change was advertised: %+v", a)
	default:
	}
}

// A worker completing while the coordinator holds an exhausted heartbeat must
// advertise its freed slot immediately, as an availability post, while the
// heartbeat stays held: the node no longer cancels its own hold. The synthetic
// lease fails validation locally, so this exercises acceptance, reporting and
// release without calling a provider or launching the helper.
func TestRunLoopCompletionPostsAvailabilityWhileHeartbeatStaysHeld(t *testing.T) {
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
	posts := make(chan arrival, 8)
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
				json.NewEncoder(w).Encode(coordinator.HeartbeatReply{Leases: []coordinator.Lease{offer}})
				return
			}
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			heldEnded <- time.Now()
		case r.URL.Path == "/api/node/v1/availability":
			var a coordinator.Availability
			if json.NewDecoder(r.Body).Decode(&a) != nil {
				t.Error("invalid availability")
			}
			posts <- arrival{heartbeat: coordinator.Heartbeat{Version: a.Version, NodeID: a.NodeID, State: a.State, Capacity: a.Capacity, Services: a.Services}, at: time.Now()}
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/node/v1/goodbye":
			w.WriteHeader(http.StatusNoContent)
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
	next := func(ch <-chan arrival, what string) arrival {
		t.Helper()
		select {
		case a := <-ch:
			return a
		case <-time.After(5 * time.Second):
			t.Fatal("node did not send", what)
			return arrival{}
		}
	}
	if first := next(arrivals, "a heartbeat"); first.heartbeat.State != "available" {
		t.Fatalf("initial heartbeat advertised %q", first.heartbeat.State)
	}
	full := next(arrivals, "a heartbeat")
	if full.heartbeat.State != "exhausted" || len(full.heartbeat.Services) == 0 || full.heartbeat.Services[0].InFlight != 1 {
		t.Fatalf("full heartbeat did not advertise its occupied slot: %+v", full.heartbeat)
	}
	refs := full.heartbeat.Services[0].ActiveLeases
	if len(refs) != 1 || refs[0] != (coordinator.ActiveLease{JobID: offer.JobID, Attempt: offer.Attempt, Fence: offer.Fence}) {
		t.Fatalf("full heartbeat did not bind the occupied lease: %+v", refs)
	}
	if acks := full.heartbeat.OffersSeen; len(acks) != 1 || acks[0] != (coordinator.OfferRef{JobID: offer.JobID, Attempt: offer.Attempt}) {
		t.Fatalf("full heartbeat did not acknowledge the offer: %+v", acks)
	}
	select {
	case <-reportReady:
	case <-time.After(5 * time.Second):
		t.Fatal("synthetic worker did not reach its report")
	}
	// Keep the report unacknowledged: the account must remain occupied, so
	// there is nothing to post and the heartbeat stays held.
	select {
	case <-heldEnded:
		t.Fatal("full heartbeat ended before reporting finished")
	case a := <-posts:
		t.Fatalf("availability posted before reporting finished: %+v", a.heartbeat)
	case <-time.After(150 * time.Millisecond):
	}
	releasedAt := time.Now()
	releaseReport()
	posted := next(posts, "an availability post")
	if posted.heartbeat.State != "available" || len(posted.heartbeat.Services) == 0 || posted.heartbeat.Services[0].InFlight != 0 || len(posted.heartbeat.Services[0].ActiveLeases) != 0 || posted.heartbeat.Version != coordinator.Version {
		t.Fatalf("completion did not post the free slot: %+v", posted.heartbeat)
	}
	// This is below both the one-second watcher interval and the fixture's
	// one-second failure backoff, so it requires the completion wakeup.
	if delay := posted.at.Sub(releasedAt); delay > 500*time.Millisecond {
		t.Fatalf("completion waited %v before posting available", delay)
	}
	select {
	case at := <-heldEnded:
		t.Fatalf("the node ended its held heartbeat %v after posting", at.Sub(posted.at))
	case a := <-arrivals:
		t.Fatalf("the node heartbeated again instead of keeping the hold: %+v", a.heartbeat)
	case <-time.After(300 * time.Millisecond):
	}
}

// Failed heartbeats back off from one second, doubling to a 15-second cap with
// equal jitter whose fixed half is never under a second, so even the first
// pause is spread; an answered heartbeat resets the schedule. A Retry-After on
// a 429 or 503 is a lower bound on the pause.
func TestHeartbeatBackoffScheduleJitterAndRetryAfter(t *testing.T) {
	failure := errors.New("coordinator unavailable")
	sequence := func(b *heartbeatBackoff, n int) []time.Duration {
		var out []time.Duration
		for range n {
			out = append(out, b.next(failure))
		}
		return out
	}
	low := &heartbeatBackoff{jitter: func(time.Duration) time.Duration { return 0 }}
	if got, want := sequence(low, 7), []time.Duration{time.Second, time.Second, 2 * time.Second, 4 * time.Second, 7500 * time.Millisecond, 7500 * time.Millisecond, 7500 * time.Millisecond}; !reflect.DeepEqual(got, want) {
		t.Fatalf("least jitter: %v, want %v", got, want)
	}
	high := &heartbeatBackoff{jitter: func(n time.Duration) time.Duration { return n }}
	if got, want := sequence(high, 7), []time.Duration{1500 * time.Millisecond, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second, 15 * time.Second, 15 * time.Second}; !reflect.DeepEqual(got, want) {
		t.Fatalf("most jitter: %v, want %v", got, want)
	}
	high.reset()
	if got := high.next(failure); got != 1500*time.Millisecond {
		t.Fatalf("after a success the backoff restarted at %v", got)
	}
	// Drawn jitter stays within each step and spreads a fleet out, from the
	// first failure on.
	steps := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second}
	for i, step := range steps {
		seen := map[time.Duration]bool{}
		for range 500 {
			b := &heartbeatBackoff{}
			wait := sequence(b, i+1)[i]
			if wait < max(step/2, time.Second) || wait > max(step, time.Second+step/2) {
				t.Fatalf("step %v waited %v", step, wait)
			}
			seen[wait] = true
		}
		if len(seen) < 100 {
			t.Fatalf("step %v: only %d distinct waits", step, len(seen))
		}
	}
	// The local fixture keeps one fixed second.
	fixture := &heartbeatBackoff{fixed: time.Second}
	if got := sequence(fixture, 6); !reflect.DeepEqual(got, []time.Duration{time.Second, time.Second, time.Second, time.Second, time.Second, time.Second}) {
		t.Fatalf("fixture backoff %v", got)
	}
	// Retry-After raises the pause on 429 and 503 only, and never lowers it.
	for _, tc := range []struct {
		err      error
		min, max time.Duration
	}{
		{&coordinator.StatusError{Status: http.StatusServiceUnavailable, RetryAfter: 5 * time.Second}, 5 * time.Second, 7500 * time.Millisecond},
		{&coordinator.StatusError{Status: http.StatusTooManyRequests, RetryAfter: coordinator.MaxRetryAfter}, coordinator.MaxRetryAfter, 90 * time.Second},
		{&coordinator.StatusError{Status: http.StatusServiceUnavailable}, time.Second, 1500 * time.Millisecond},
		{&coordinator.StatusError{Status: http.StatusInternalServerError, RetryAfter: 5 * time.Second}, time.Second, 1500 * time.Millisecond},
		{fmt.Errorf("%w: %w", coordinator.ErrHeartbeatRejected, &coordinator.StatusError{Status: http.StatusRequestEntityTooLarge, RetryAfter: 5 * time.Second}), time.Second, 1500 * time.Millisecond},
	} {
		for _, b := range []*heartbeatBackoff{{}, {fixed: time.Second}} {
			if got := b.next(tc.err); got < tc.min || got > tc.max {
				t.Fatalf("%v: waited %v, want [%v, %v]", tc.err, got, tc.min, tc.max)
			}
		}
	}
	capped := &heartbeatBackoff{jitter: func(n time.Duration) time.Duration { return n }}
	sequence(capped, 5)
	if got := capped.next(&coordinator.StatusError{Status: http.StatusServiceUnavailable, RetryAfter: time.Second}); got != 15*time.Second {
		t.Fatalf("a short Retry-After lowered the backoff to %v", got)
	}
}

// A rejected heartbeat (413) is backed off and resent unchanged, never in a
// reduced shape. A 200 with no leases and a Retry-After, as from a coordinator
// shutting down, and a 503 with Retry-After pause the node at least that long.
func TestRunLoopHonoursRetryAfterAndBacksOffRejectedHeartbeat(t *testing.T) {
	dir := privateTestDir(t)
	home := filepath.Join(dir, "codex")
	if err := privateFixtureMkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFixture(filepath.Join(home, "auth.json"), freshSyntheticCodexAuth(), 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{Executor: config.ExecutorServices, Services: []string{"codex"}, Profile: "standard", StateDir: filepath.Join(dir, "state"), AccountsFile: filepath.Join(dir, "state", "accounts.json"), CodexHome: home, Credential: "synthetic-credential", NodeID: "synthetic-node", CodexConcurrency: 1, XConcurrency: 1, Bid: 100, Verifier: "locally-configured.invalid:7047", Prover: os.Args[0], JournalLimits: attempts.DefaultLimits(), MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second, LocalFixture: true}
	type arrival struct {
		services string
		at       time.Time
	}
	arrivals := make(chan arrival, 8)
	var mu sync.Mutex
	n := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if controlRoute(w, r) {
			return
		}
		var h coordinator.Heartbeat
		if r.URL.Path != "/api/node/v1/heartbeat" || json.NewDecoder(r.Body).Decode(&h) != nil {
			t.Error("unexpected request", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		services, _ := json.Marshal(h.Services)
		arrivals <- arrival{string(services), time.Now()}
		mu.Lock()
		this := n
		n++
		mu.Unlock()
		switch this {
		case 0:
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			io.WriteString(w, `{"error":{"code":"heartbeat_too_large","message":"synthetic"}}`)
		case 1:
			w.Header().Set("Retry-After", "1")
			io.WriteString(w, `{"leases":[]}`)
		case 2:
			// Answer a little after the arrival so a status save made in the
			// pause is later than it even on a coarse wall clock: Windows can
			// stamp both in one tick, and the saved time has no monotonic
			// reading to tell them apart.
			time.Sleep(50 * time.Millisecond)
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"error":{"code":"network_unavailable","message":"synthetic"}}`)
		default:
			<-r.Context().Done()
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
	var got []arrival
	for i := range 4 {
		select {
		case a := <-arrivals:
			got = append(got, a)
		case <-time.After(10 * time.Second):
			t.Fatalf("node sent %d heartbeats", len(got))
		}
		if i == 2 {
			// Inside the 503's Retry-After pause, status.json has been saved
			// again since that heartbeat, not only before it.
			time.Sleep(500 * time.Millisecond)
			raw, err := readLocalFile(filepath.Join(c.StateDir, "status.json"), 16384)
			var saved runtimeStatus
			if err != nil || json.Unmarshal(raw, &saved) != nil || !saved.UpdatedAt.After(got[2].at) {
				t.Fatalf("status during the pause was saved at %v, before the heartbeat at %v (%v)", saved.UpdatedAt, got[2].at, err)
			}
		}
	}
	if got[0].services == "null" || got[1].services != got[0].services {
		t.Fatalf("heartbeat after a rejection changed shape:\n%s\n%s", got[0].services, got[1].services)
	}
	// A gap is never shorter than its pause, so the lower bounds are exact.
	// A slow runner adds its own time on top: the status saves and the next
	// heartbeat's build and send fall outside the pause, so the upper bounds
	// carry slop for that.
	const slop = 250 * time.Millisecond
	for i, want := range []struct{ min, max time.Duration }{
		{time.Second, 1500 * time.Millisecond},     // 413: the fixture's fixed second
		{time.Second, 2 * time.Second},             // 200 with Retry-After 1: one to one and a half seconds
		{2 * time.Second, 3500 * time.Millisecond}, // 503 with Retry-After 2: two to three seconds, after the 50 ms answer
	} {
		if gap := got[i+1].at.Sub(got[i].at); gap < want.min || gap > want.max+slop {
			t.Fatalf("heartbeat %d followed after %v, want [%v, %v]", i+1, gap, want.min, want.max+slop)
		}
	}
}

// A pause between heartbeats saves status when it starts and at each interval
// while it lasts, a stop ends it at once, and an owner command or a jump of
// the wall clock ends it with what woke the node.
func TestWaitForSavesStatusAndEndsEarly(t *testing.T) {
	restore := readClock
	t.Cleanup(func() { readClock = restore })
	refreshes := 0
	started := time.Now()
	if outcome, _ := waitFor(context.Background(), 260*time.Millisecond, nil, &clockWatch{}, func() { refreshes++ }); outcome != waitElapsed {
		t.Fatal("an uninterrupted pause ended early", outcome)
	}
	if took := time.Since(started); took < 260*time.Millisecond || refreshes != 1 {
		t.Fatalf("paused %v with %d refreshes", took, refreshes)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	refreshes, started = 0, time.Now()
	if outcome, _ := waitFor(ctx, time.Minute, nil, &clockWatch{}, func() { refreshes++ }); outcome != waitStopped || time.Since(started) > time.Second || refreshes != 1 {
		t.Fatalf("stop ended the pause after %v with %d refreshes", time.Since(started), refreshes)
	}
	if outcome, _ := waitFor(ctx, time.Minute, nil, &clockWatch{}, func() { t.Error("a stopped node saved status") }); outcome != waitStopped {
		t.Fatal("a stopped node paused")
	}
	commands := make(chan ownerCommand, 2)
	commands <- ownerWake
	if outcome, reason := waitFor(context.Background(), time.Minute, commands, &clockWatch{}, func() {}); outcome != waitWake || reason != "owner" {
		t.Fatal("wake command", outcome, reason)
	}
	commands <- ownerSleep
	if outcome, _ := waitFor(context.Background(), time.Minute, commands, &clockWatch{}, func() {}); outcome != waitSleep {
		t.Fatal("sleep command", outcome)
	}
	// The wall clock runs a minute ahead of the monotonic one between ticks.
	var mu sync.Mutex
	reading := clockReading{wall: time.Now(), mono: time.Second}
	readClock = func() clockReading {
		mu.Lock()
		defer mu.Unlock()
		r := reading
		reading.wall = reading.wall.Add(time.Minute)
		reading.mono += time.Second
		return r
	}
	watch := &clockWatch{}
	watch.jumped()
	started = time.Now()
	if outcome, reason := waitFor(context.Background(), time.Minute, nil, watch, func() {}); outcome != waitWake || reason != "clock_jump" || time.Since(started) > 2*heartbeatWatchInterval {
		t.Fatal("wall-clock jump", outcome, reason, time.Since(started))
	}
}

// The run loop resets its failure schedule after any answered heartbeat: a
// failure after an answer pauses for the first step again, not the next one.
func TestRunLoopResetsBackoffAfterAnsweredHeartbeat(t *testing.T) {
	var mu sync.Mutex
	var spreads []time.Duration
	restore := newHeartbeatBackoff
	t.Cleanup(func() { newHeartbeatBackoff = restore })
	newHeartbeatBackoff = func(bool) heartbeatBackoff {
		// The full schedule at its least jitter. Each draw is offered the
		// random half of its step, which records the step reached.
		return heartbeatBackoff{jitter: func(n time.Duration) time.Duration {
			mu.Lock()
			spreads = append(spreads, n)
			mu.Unlock()
			return 0
		}}
	}
	var n atomic.Int32
	arrivals := make(chan struct{}, 8)
	_, stop := startLongPollNode(t, func(w http.ResponseWriter, r *http.Request) {
		if controlRoute(w, r) {
			return
		}
		if r.URL.Path != "/api/node/v1/heartbeat" {
			t.Error("unexpected request", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Read the body to its end, so that the server sees the node hang up
		// on a held heartbeat.
		_, _ = io.Copy(io.Discard, r.Body)
		arrivals <- struct{}{}
		switch n.Add(1) - 1 {
		case 0, 1, 3:
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"error":{"code":"network_unavailable","message":"synthetic"}}`)
		case 2:
			io.WriteString(w, `{"leases":[]}`)
		default:
			<-r.Context().Done()
		}
	})
	for i := range 5 {
		select {
		case <-arrivals:
		case <-time.After(10 * time.Second):
			t.Fatalf("node sent %d heartbeats", i)
		}
	}
	// Read before stopping: the stop aborts the held fifth heartbeat, which
	// draws once more.
	mu.Lock()
	got := append([]time.Duration(nil), spreads...)
	mu.Unlock()
	stop()
	// Two failures step from one second to two; the answer in between resets
	// the schedule, so the third failure is a one-second step again, not four.
	if want := []time.Duration{500 * time.Millisecond, time.Second, 500 * time.Millisecond}; !reflect.DeepEqual(got, want) {
		t.Fatalf("backoff steps drew %v, want %v", got, want)
	}
}

// An offer that reaches a draining node is rejected as draining, without any
// acceptance, and the next heartbeat follows after the usual drain-rejection
// pause.
func TestRunLoopRejectsOffersWhileDrainingWithoutAccepting(t *testing.T) {
	offer := testLease()
	offer.ServiceType, offer.AcceptanceRequired = "codex", true
	offer.SettlementDeadline = offer.LeaseDeadline
	offer.SignedJobID, offer.RequestSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	type arrival struct {
		state string
		at    time.Time
	}
	arrivals := make(chan arrival, 8)
	leased := make(chan time.Time, 1)
	rejected := make(chan coordinator.Rejection, 4)
	var accepts atomic.Int32
	var offered atomic.Bool
	c, stop := startLongPollNode(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/node/v1/jobs/" + offer.JobID + "/accept":
			accepts.Add(1)
			w.WriteHeader(http.StatusConflict)
			return
		case "/api/node/v1/jobs/" + offer.JobID + "/reject":
			var body coordinator.Rejection
			_ = json.NewDecoder(r.Body).Decode(&body)
			rejected <- body
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if controlRoute(w, r) {
			return
		}
		var h coordinator.Heartbeat
		if r.URL.Path != "/api/node/v1/heartbeat" || json.NewDecoder(r.Body).Decode(&h) != nil {
			t.Error("unexpected request", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		arrivals <- arrival{h.State, time.Now()}
		if h.State == "exhausted" && offered.CompareAndSwap(false, true) {
			json.NewEncoder(w).Encode(map[string]any{"leases": []coordinator.Lease{offer}})
			leased <- time.Now()
			return
		}
		<-r.Context().Done()
	})
	next := func() arrival {
		t.Helper()
		select {
		case a := <-arrivals:
			return a
		case <-time.After(10 * time.Second):
			t.Fatal("node did not heartbeat")
		}
		return arrival{}
	}
	if first := next(); first.state != "available" {
		t.Fatalf("first heartbeat advertised %q", first.state)
	}
	if err := writeLocalFile(c.StateDir, "drain", []byte("drained\n")); err != nil {
		t.Fatal(err)
	}
	if drained := next(); drained.state != "exhausted" {
		t.Fatalf("heartbeat after the drain advertised %q", drained.state)
	}
	var leasedAt time.Time
	select {
	case leasedAt = <-leased:
	case <-time.After(5 * time.Second):
		t.Fatal("the draining node was never offered the lease")
	}
	select {
	case body := <-rejected:
		if body.Reason != coordinator.RejectDraining || body.Attempt != offer.Attempt || body.Fence != offer.Fence || body.Version != coordinator.Version {
			t.Fatalf("rejection %+v", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the draining node did not reject the offer")
	}
	after := next()
	// The fixture's one-second drain-rejection pause.
	if gap := after.at.Sub(leasedAt); gap < time.Second || gap > 2500*time.Millisecond {
		t.Fatalf("heartbeat after the drain rejection followed after %v", gap)
	}
	stop()
	if got := accepts.Load(); got != 0 {
		t.Fatalf("drain rejection sent %d acceptance requests, want 0", got)
	}
}
