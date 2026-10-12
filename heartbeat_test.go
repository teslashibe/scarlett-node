package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
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
	"github.com/teslashibe/scarlett-node/internal/worker"
)

// ownedNode is a synthetic node run with an owner pipe, as `desktop run` is.
type ownedNode struct {
	c     config.Config
	owner *io.PipeWriter
	stop  func()
	// conns counts the TCP connections the coordinator accepted.
	conns *atomic.Int32
}

// startOwnedNode runs a synthetic node against handler. Without services it
// is a legacy Codex node that advertises available until something local
// changes; with services it serves Codex with a fresh credential and one slot.
func startOwnedNode(t *testing.T, handler http.HandlerFunc, services bool, prepare func(*config.Config)) *ownedNode {
	t.Helper()
	dir := privateTestDir(t)
	home := filepath.Join(dir, "codex")
	if err := privateFixtureMkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	auth := syntheticCodexAuth(time.Now().Add(-time.Hour))
	if services {
		auth = freshSyntheticCodexAuth()
	}
	if err := writePrivateFixture(filepath.Join(home, "auth.json"), auth, 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{Executor: config.ExecutorCodexTLSN, Profile: "standard", StateDir: filepath.Join(dir, "state"), CodexHome: home, Credential: "synthetic-credential", NodeID: "synthetic-node", Concurrency: 1, Bid: 100, Verifier: "locally-configured.invalid:7047", Prover: filepath.Join(dir, "synthetic-prover-never-run"), JournalLimits: attempts.DefaultLimits(), MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second, LocalFixture: true}
	if services {
		c.Executor, c.Services, c.AccountsFile, c.CodexConcurrency, c.XConcurrency, c.Prover = config.ExecutorServices, []string{"codex"}, filepath.Join(dir, "state", "accounts.json"), 1, 1, os.Args[0]
	}
	conns := &atomic.Int32{}
	server := httptest.NewUnstartedServer(handler)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	server.StartTLS()
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
	return &ownedNode{c: c, owner: writer, stop: stop, conns: conns}
}

func uuidN(group, n int) string { return fmt.Sprintf("00000000-0000-4000-%d000-%012d", 8+group, n) }

// codexOffer is a funded Codex offer that passes ValidOffer. Its worker fails
// locally after acceptance (it carries no payload), so it calls no provider.
func codexOffer(n int) coordinator.Lease {
	l := testLease()
	l.ServiceType, l.AcceptanceRequired = "codex", true
	l.SettlementDeadline = l.LeaseDeadline
	l.SignedJobID, l.RequestSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	l.JobID, l.Attempt, l.Fence = uuidN(0, n), uuidN(1, n), uuidN(2, n)
	return l
}

func receive[T any](t *testing.T, ch <-chan T, within time.Duration, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(within):
		t.Fatal("timed out waiting for", what)
	}
	var zero T
	return zero
}

func readStatus(t *testing.T, dir string) runtimeStatus {
	t.Helper()
	var out bytes.Buffer
	if err := localCommandDir(dir, "status", &out); err != nil {
		t.Fatal(err)
	}
	var s runtimeStatus
	if err := json.Unmarshal(out.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// One answer may carry several offers. The node starts what it can and
// rejects every other offer at once with its reason, never waiting for a
// slot: an offer for which no slot is free (no_slot), one that fails
// ValidOffer or does not decode (invalid_offer), and another attempt of a job
// it already runs (busy). A redelivery of the running attempt is ignored. The
// next heartbeat follows at once and acknowledges every offer once.
func TestRunLoopTakesSeveralOffersAndRejectsWithoutBlocking(t *testing.T) {
	running, full, invalid, busy := codexOffer(1), codexOffer(2), codexOffer(3), codexOffer(1)
	invalid.Version = "node-v1"
	busy.Attempt, busy.Fence = uuidN(1, 9), uuidN(2, 9)
	unreadable := fmt.Sprintf(`{"version":%q,"job_id":%q,"attempt":%q,"fence":%q,"lease_deadline":"soon"}`, coordinator.Version, uuidN(0, 4), uuidN(1, 4), uuidN(2, 4))
	type arrival struct {
		heartbeat coordinator.Heartbeat
		at        time.Time
	}
	arrivals := make(chan arrival, 8)
	answered := make(chan time.Time, 1)
	reportHeld := make(chan struct{}, 1)
	release := make(chan struct{})
	// Ends the held heartbeats once the rejections are in, so the next
	// heartbeat saves status.json (it is written once per heartbeat).
	endHolds := make(chan struct{})
	var endHoldsOnce sync.Once
	defer endHoldsOnce.Do(func() { close(endHolds) })
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var mu sync.Mutex
	rejected := map[string]string{}
	accepted := []string{}
	var heartbeats atomic.Int32
	node := startOwnedNode(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/node/v1/heartbeat":
			var h coordinator.Heartbeat
			if json.NewDecoder(r.Body).Decode(&h) != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			arrivals <- arrival{h, time.Now()}
			if heartbeats.Add(1) == 1 {
				var leases []string
				for _, l := range []coordinator.Lease{running, full, invalid, running, busy} {
					raw, _ := json.Marshal(l)
					leases = append(leases, string(raw))
				}
				fmt.Fprintf(w, `{"leases":[%s,%s],"node":{"missed_streak":0,"suspect_until":null}}`, strings.Join(leases, ","), unreadable)
				answered <- time.Now()
				return
			}
			_, _ = io.Copy(io.Discard, r.Body)
			select {
			case <-r.Context().Done():
			case <-endHolds:
				io.WriteString(w, `{"leases":[],"node":{"missed_streak":0,"suspect_until":null}}`)
			}
		case strings.HasSuffix(r.URL.Path, "/reject"):
			var body coordinator.Rejection
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			rejected[body.Attempt] = body.Reason
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/accept"):
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			accepted = append(accepted, body["attempt"])
			mu.Unlock()
			a := running
			a.VerifierToken = strings.Repeat("c", 64)
			json.NewEncoder(w).Encode(coordinator.LeaseAcceptance{Version: coordinator.Version, State: "leased", FundingAuthority: "production_receipt", Lease: a})
		case strings.HasSuffix(r.URL.Path, "/fail"):
			// Keep the slot taken until the test is done. A retried report
			// must not block here, or the server never closes.
			select {
			case reportHeld <- struct{}{}:
			default:
			}
			select {
			case <-release:
				w.WriteHeader(http.StatusNoContent)
			case <-r.Context().Done():
			}
		default:
			if !controlRoute(w, r) {
				t.Error("unexpected request", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}, true, nil)
	receive(t, arrivals, 5*time.Second, "the first heartbeat")
	answeredAt := receive(t, answered, 5*time.Second, "the offers")
	next := receive(t, arrivals, 5*time.Second, "the heartbeat after the offers")
	if gap := next.at.Sub(answeredAt); gap > 500*time.Millisecond {
		t.Fatalf("the heartbeat after several offers waited %v", gap)
	}
	want := []coordinator.OfferRef{{JobID: running.JobID, Attempt: running.Attempt}, {JobID: full.JobID, Attempt: full.Attempt}, {JobID: invalid.JobID, Attempt: invalid.Attempt}, {JobID: busy.JobID, Attempt: busy.Attempt}, {JobID: uuidN(0, 4), Attempt: uuidN(1, 4)}}
	if !reflect.DeepEqual(next.heartbeat.OffersSeen, want) {
		t.Fatalf("offers_seen %+v, want %+v", next.heartbeat.OffersSeen, want)
	}
	receive(t, reportHeld, 5*time.Second, "the running offer's report")
	deadline := time.Now().Add(5 * time.Second)
	wantRejected := map[string]string{full.Attempt: coordinator.RejectNoSlot, invalid.Attempt: coordinator.RejectInvalidOffer, busy.Attempt: coordinator.RejectBusy, uuidN(1, 4): coordinator.RejectInvalidOffer}
	for {
		mu.Lock()
		got, acceptedNow := fmt.Sprint(rejected), append([]string(nil), accepted...)
		done := reflect.DeepEqual(rejected, wantRejected)
		mu.Unlock()
		if done {
			if len(acceptedNow) != 1 || acceptedNow[0] != running.Attempt {
				t.Fatalf("accepted %v, want only the running offer", acceptedNow)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rejections %s, want %v", got, wantRejected)
		}
		time.Sleep(20 * time.Millisecond)
	}
	// status.json is saved once per heartbeat, so the counts reach it on the
	// heartbeat after the rejections: end the held one and wait for it.
	endHoldsOnce.Do(func() { close(endHolds) })
	for statusDeadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		s := readStatus(t, node.c.StateDir)
		if s.HeartbeatDiagnostics != nil && s.HeartbeatDiagnostics.RejectedOffers >= 4 {
			break
		}
		if time.Now().After(statusDeadline) {
			t.Fatalf("status did not count the rejections: %+v", s.HeartbeatDiagnostics)
		}
	}
	releaseOnce.Do(func() { close(release) })
	node.stop()
}

// The owner pipe's sleep says goodbye for sleep, then ends the held heartbeat
// and holds further heartbeats; wake heartbeats again at once on a new
// connection. Unknown and over-long lines change nothing, and a sleep with no
// wake ends after sleepPauseLimit.
func TestOwnerPipeSleepAndWake(t *testing.T) {
	restore := sleepPauseLimit
	t.Cleanup(func() { sleepPauseLimit = restore })
	sleepPauseLimit = time.Minute
	type event struct {
		kind, detail string
		at           time.Time
	}
	events := make(chan event, 32)
	node := startOwnedNode(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/node/v1/goodbye":
			var body coordinator.Goodbye
			_ = json.NewDecoder(r.Body).Decode(&body)
			events <- event{"goodbye", body.Reason, time.Now()}
			w.WriteHeader(http.StatusNoContent)
		case "/api/node/v1/heartbeat":
			events <- event{"heartbeat", "", time.Now()}
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			events <- event{"hangup", "", time.Now()}
		default:
			controlRoute(w, r)
		}
	}, false, nil)
	nextEvent := func(what string) event { return receive(t, events, 5*time.Second, what) }
	if e := nextEvent("a heartbeat"); e.kind != "heartbeat" {
		t.Fatalf("first event %+v", e)
	}
	if _, err := io.WriteString(node.owner, "hello\n"+strings.Repeat("x", 300)+"\nsleepy\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-events:
		t.Fatalf("an unknown owner line did something: %+v", e)
	case <-time.After(300 * time.Millisecond):
	}
	slept := time.Now()
	if _, err := io.WriteString(node.owner, "sleep\r\n"); err != nil {
		t.Fatal(err)
	}
	if e := nextEvent("the sleep goodbye"); e.kind != "goodbye" || e.detail != coordinator.GoodbyeSleep {
		t.Fatalf("sleep began with %+v", e)
	}
	if e := nextEvent("the hold to end"); e.kind != "hangup" || e.at.Sub(slept) > time.Second+500*time.Millisecond {
		t.Fatalf("sleep then %+v after %v", e, e.at.Sub(slept))
	}
	select {
	case e := <-events:
		t.Fatalf("the node did not hold heartbeats while asleep: %+v", e)
	case <-time.After(1500 * time.Millisecond):
	}
	before := node.conns.Load()
	woke := time.Now()
	if _, err := io.WriteString(node.owner, "wake\n"); err != nil {
		t.Fatal(err)
	}
	if e := nextEvent("a heartbeat after wake"); e.kind != "heartbeat" || e.at.Sub(woke) > 500*time.Millisecond {
		t.Fatalf("after wake %+v, %v later", e, e.at.Sub(woke))
	}
	if node.conns.Load() <= before {
		t.Fatal("the heartbeat after wake reused the old connection")
	}
	s := readStatus(t, node.c.StateDir)
	if d := s.HeartbeatDiagnostics; d == nil || d.Sleeps != 1 || d.Wakes != 1 || d.LastWake != "owner" || d.LastWakeAt == nil || d.Goodbyes != 1 {
		t.Fatalf("status diagnostics after sleep and wake: %+v", d)
	}
	// A sleep that no wake follows ends by itself.
	sleepPauseLimit = 300 * time.Millisecond
	if _, err := io.WriteString(node.owner, "sleep\n"); err != nil {
		t.Fatal(err)
	}
	if e := nextEvent("the second sleep goodbye"); e.kind != "goodbye" || e.detail != coordinator.GoodbyeSleep {
		t.Fatalf("second sleep began with %+v", e)
	}
	nextEvent("the hold to end")
	if e := nextEvent("a heartbeat after the sleep pause"); e.kind != "heartbeat" {
		t.Fatalf("after the sleep pause %+v", e)
	}
	if d := readStatus(t, node.c.StateDir).HeartbeatDiagnostics; d == nil || d.Wakes != 2 || d.LastWake != "timeout" {
		t.Fatalf("status diagnostics after a sleep pause ran out: %+v", d)
	}
	node.stop()
	if e := nextEvent("the stop goodbye"); e.kind != "hangup" && (e.kind != "goodbye" || e.detail != coordinator.GoodbyeStop) {
		t.Fatalf("stop %+v", e)
	}
}

// A jump of the wall clock ahead of the monotonic clock, which is what a sleep
// nobody announced looks like, ends the held heartbeat without a goodbye and
// heartbeats again at once on a new connection.
func TestWallClockJumpWakesTheHeldHeartbeat(t *testing.T) {
	restore := readClock
	t.Cleanup(func() { readClock = restore })
	var offset atomic.Int64
	readClock = func() clockReading {
		r := restore()
		r.wall = r.wall.Add(time.Duration(offset.Load()))
		return r
	}
	type event struct {
		kind string
		at   time.Time
	}
	events := make(chan event, 16)
	node := startOwnedNode(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/node/v1/heartbeat":
			events <- event{"heartbeat", time.Now()}
			_, _ = io.Copy(io.Discard, r.Body)
			<-r.Context().Done()
			events <- event{"hangup", time.Now()}
		case "/api/node/v1/goodbye":
			events <- event{"goodbye", time.Now()}
			w.WriteHeader(http.StatusNoContent)
		default:
			controlRoute(w, r)
		}
	}, false, nil)
	receive(t, events, 5*time.Second, "a heartbeat")
	// Let the watch take its first look before the clock moves.
	time.Sleep(1200 * time.Millisecond)
	before := node.conns.Load()
	jumped := time.Now()
	offset.Store(int64(time.Minute))
	if e := receive(t, events, 3*time.Second, "the hold to end"); e.kind != "hangup" || e.at.Sub(jumped) > heartbeatWatchInterval+500*time.Millisecond {
		t.Fatalf("after the jump %+v, %v later", e, e.at.Sub(jumped))
	}
	if e := receive(t, events, 2*time.Second, "a heartbeat after the jump"); e.kind != "heartbeat" {
		t.Fatalf("after the jump the node sent %+v", e)
	}
	if node.conns.Load() <= before {
		t.Fatal("the heartbeat after the jump reused the old connection")
	}
	if d := readStatus(t, node.c.StateDir).HeartbeatDiagnostics; d == nil || d.LastWake != "clock_jump" || d.Wakes != 1 || d.Goodbyes != 0 {
		t.Fatalf("status diagnostics after a jump: %+v", d)
	}
}

// The clock watch reports a jump only when the wall clock moved more than five
// seconds further than the monotonic clock between two looks.
func TestClockWatchSpotsWallClockJumps(t *testing.T) {
	restore := readClock
	t.Cleanup(func() { readClock = restore })
	base := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	var now clockReading
	readClock = func() clockReading { return now }
	w := &clockWatch{}
	for i, step := range []struct {
		wall, mono time.Duration
		jumped     bool
	}{
		{0, 0, false},                              // the first look sees nothing
		{time.Second, time.Second, false},          // both clocks ran
		{7 * time.Second, 2 * time.Second, false},  // five seconds ahead is not more than five
		{18 * time.Second, 3 * time.Second, true},  // ten seconds ahead: slept
		{-time.Minute, 4 * time.Second, false},     // set back
		{-time.Minute, 30 * time.Second, false},    // a stopped process: monotonic ran on
		{10 * time.Minute, 31 * time.Second, true}, // a long sleep
		{10*time.Minute + time.Second, 32 * time.Second, false},
	} {
		now = clockReading{wall: base.Add(step.wall), mono: step.mono}
		if got := w.jumped(); got != step.jumped {
			t.Fatalf("look %d: jumped %v, want %v", i, got, step.jumped)
		}
	}
}

// The owner pipe carries sleep and wake; anything else, a line too long and
// a last line without a newline are ignored, and EOF reports the close once.
func TestReadOwnerCommands(t *testing.T) {
	commands := make(chan ownerCommand, 8)
	var closed atomic.Int32
	input := "sleep\nwake\r\n  sleep  \nhello\n" + strings.Repeat("w", 1000) + "\nWAKE\n\nwake\nsleep"
	readOwner(strings.NewReader(input), commands, make(chan struct{}), func() { closed.Add(1) })
	close(commands)
	var got []ownerCommand
	for command := range commands {
		got = append(got, command)
	}
	if want := []ownerCommand{ownerSleep, ownerWake, ownerSleep, ownerWake}; !reflect.DeepEqual(got, want) || closed.Load() != 1 {
		t.Fatalf("commands %v, closed %d", got, closed.Load())
	}
	// A reader that nobody listens to any more gives up.
	blocked := make(chan ownerCommand)
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		readOwner(strings.NewReader("sleep\n"), blocked, done, func() {})
		close(finished)
	}()
	close(done)
	receive(t, finished, time.Second, "the owner reader to give up")
}

// Changes coming faster than coordinator.AvailabilityInterval are posted
// together, at most one post per interval, the last state always posted, and
// the held heartbeat is never cut short for them.
func TestWatchCoalescesAvailabilityPosts(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	var state atomic.Int32
	current := func() availability { return availability{services: fmt.Sprint(state.Load())} }
	var mu sync.Mutex
	var posts []time.Time
	var postedStates []string
	changes := make(chan struct{}, 1)
	watch := testWatch(current(), current, func(context.Context) (availability, error) {
		a := current()
		mu.Lock()
		posts, postedStates = append(posts, time.Now()), append(postedStates, a.services)
		mu.Unlock()
		return a, nil
	})
	watch.changes = changes
	done := make(chan watchResult, 1)
	go func() { done <- watchHeartbeat(ctx, cancel, watch) }()
	for i := 1; i <= 12; i++ {
		state.Store(int32(i))
		select {
		case changes <- struct{}{}:
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(coordinator.AvailabilityInterval + 200*time.Millisecond)
	mu.Lock()
	gotPosts, gotStates := append([]time.Time(nil), posts...), append([]string(nil), postedStates...)
	mu.Unlock()
	if len(gotPosts) < 2 || len(gotPosts) > 4 || gotStates[len(gotStates)-1] != "12" {
		t.Fatalf("%d posts of %v for 12 changes in 600 ms", len(gotPosts), gotStates)
	}
	for i := 1; i < len(gotPosts); i++ {
		if gap := gotPosts[i].Sub(gotPosts[i-1]); gap < coordinator.AvailabilityInterval-10*time.Millisecond {
			t.Fatalf("posts %v apart", gap)
		}
	}
	if ctx.Err() != nil {
		t.Fatal("availability changes ended the held heartbeat")
	}
	cancel(nil)
	if result := <-done; result.cause != nil {
		t.Fatalf("watch ended %+v", result)
	}
}

// Every way a watch ends the hold early: a stop, a drain, an unreadable drain
// marker and a sleep say goodbye before the cancel (and after an availability
// post already on the wire); a wake, a wall-clock jump and a failed post end
// it without one.
func TestWatchEndsTheHoldOnlyToLeave(t *testing.T) {
	restore := readClock
	t.Cleanup(func() { readClock = restore })
	for _, tc := range []struct {
		name       string
		trigger    func(stop context.CancelFunc, owner chan<- ownerCommand, current *atomic.Value, jump *atomic.Int64, changes chan<- struct{})
		failPost   bool
		cause      error
		reason     string
		wakeReason string
	}{
		{"stop", func(stop context.CancelFunc, _ chan<- ownerCommand, _ *atomic.Value, _ *atomic.Int64, _ chan<- struct{}) {
			stop()
		}, false, errPollStopping, coordinator.GoodbyeSignal, ""},
		{"drain", func(_ context.CancelFunc, _ chan<- ownerCommand, current *atomic.Value, _ *atomic.Int64, changes chan<- struct{}) {
			current.Store(availability{drained: true})
			changes <- struct{}{}
		}, false, errPollDrained, coordinator.GoodbyeUpdate, ""},
		{"unreadable drain", func(_ context.CancelFunc, _ chan<- ownerCommand, current *atomic.Value, _ *atomic.Int64, changes chan<- struct{}) {
			current.Store(availability{drainUnreadable: true})
			changes <- struct{}{}
		}, false, errPollDrained, coordinator.GoodbyeUpdate, ""},
		{"sleep", func(_ context.CancelFunc, owner chan<- ownerCommand, _ *atomic.Value, _ *atomic.Int64, _ chan<- struct{}) {
			owner <- ownerSleep
		}, false, errPollSleep, coordinator.GoodbyeSleep, ""},
		{"wake", func(_ context.CancelFunc, owner chan<- ownerCommand, _ *atomic.Value, _ *atomic.Int64, _ chan<- struct{}) {
			owner <- ownerWake
		}, false, errPollWake, "", "owner"},
		{"wall-clock jump", func(_ context.CancelFunc, _ chan<- ownerCommand, _ *atomic.Value, jump *atomic.Int64, _ chan<- struct{}) {
			jump.Store(int64(time.Hour))
		}, false, errPollWake, "", "clock_jump"},
		{"failed post", func(_ context.CancelFunc, _ chan<- ownerCommand, current *atomic.Value, _ *atomic.Int64, changes chan<- struct{}) {
			current.Store(availability{services: "changed"})
			changes <- struct{}{}
		}, true, errHeartbeatStale, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var jump atomic.Int64
			readClock = func() clockReading {
				r := restore()
				r.wall = r.wall.Add(time.Duration(jump.Load()))
				return r
			}
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			stopCtx, stop := context.WithCancel(context.Background())
			defer stop()
			owner := make(chan ownerCommand, 1)
			changes := make(chan struct{}, 1)
			var current atomic.Value
			current.Store(availability{})
			var goodbyes []string
			var goodbyeBeforeCancel, postLanded atomic.Bool
			release := make(chan struct{})
			watch := testWatch(availability{}, func() availability { return current.Load().(availability) }, func(context.Context) (availability, error) {
				if tc.failPost {
					return availability{}, errors.New("synthetic post failure")
				}
				<-release
				postLanded.Store(true)
				return current.Load().(availability), nil
			})
			watch.stop, watch.owner, watch.changes = stopCtx, owner, changes
			watch.drainReason = func() string { return coordinator.GoodbyeUpdate }
			// The watch's first look at the clocks, so the first tick compares.
			watch.clock.jumped()
			watch.goodbye = func(reason string, deadline time.Time) {
				goodbyes = append(goodbyes, reason)
				goodbyeBeforeCancel.Store(ctx.Err() == nil)
				if time.Until(deadline) > coordinator.GoodbyeTimeout || time.Until(deadline) < coordinator.GoodbyeTimeout-goodbyePostWait-100*time.Millisecond {
					t.Errorf("goodbye deadline %v away", time.Until(deadline))
				}
			}
			done := make(chan watchResult, 1)
			go func() { done <- watchHeartbeat(ctx, cancel, watch) }()
			if tc.reason != "" && !tc.failPost {
				// An availability post is on the wire when the watch decides to
				// leave; it lands before the goodbye goes out.
				current.Store(availability{services: "posting"})
				changes <- struct{}{}
				time.Sleep(50 * time.Millisecond)
				time.AfterFunc(100*time.Millisecond, func() { close(release) })
			} else {
				close(release)
			}
			tc.trigger(stop, owner, &current, &jump, changes)
			result := receive(t, done, 3*time.Second, "the watch to end the hold")
			if !errors.Is(result.cause, tc.cause) || !errors.Is(context.Cause(ctx), tc.cause) || result.wakeReason != tc.wakeReason {
				t.Fatalf("ended with %+v, cause %v", result, context.Cause(ctx))
			}
			if tc.reason == "" {
				if result.goodbye || len(goodbyes) != 0 {
					t.Fatalf("goodbye %v without leaving", goodbyes)
				}
				return
			}
			if !result.goodbye || !reflect.DeepEqual(goodbyes, []string{tc.reason}) || !goodbyeBeforeCancel.Load() {
				t.Fatalf("goodbyes %v, before the cancel %v", goodbyes, goodbyeBeforeCancel.Load())
			}
			if !tc.failPost && !postLanded.Load() {
				t.Fatal("the goodbye did not wait for the availability post on the wire")
			}
		})
	}
}

// status.json carries the last answered heartbeat, the coordinator's
// dispatch health for this node and local heartbeat counters, and the
// status command accepts them.
func TestStatusReportsHeartbeatHealth(t *testing.T) {
	suspectUntil := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	var n atomic.Int32
	node := startOwnedNode(t, func(w http.ResponseWriter, r *http.Request) {
		if controlRoute(w, r) {
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		if n.Add(1) == 1 {
			fmt.Fprintf(w, `{"leases":[],"node":{"missed_streak":3,"suspect_until":%q}}`, suspectUntil.Format(time.RFC3339))
			return
		}
		<-r.Context().Done()
	}, false, nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := readStatus(t, node.c.StateDir)
		if s.DispatchHealth != nil {
			if s.LastHeartbeatOKAt == nil || time.Since(*s.LastHeartbeatOKAt) > 5*time.Second || s.HeartbeatErrorClass != "" || s.DispatchHealth.MissedStreak != 3 || s.DispatchHealth.SuspectUntil == nil || !s.DispatchHealth.SuspectUntil.Equal(suspectUntil) {
				t.Fatalf("heartbeat health %+v %+v", s.LastHeartbeatOKAt, s.DispatchHealth)
			}
			if d := s.HeartbeatDiagnostics; d == nil || d.Polls < 1 || d.Failures != 0 || d.Reconnects != 0 {
				t.Fatalf("heartbeat diagnostics %+v", d)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("status never showed the dispatch health")
		}
		time.Sleep(20 * time.Millisecond)
	}
	node.stop()
}

func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	var buf bytes.Buffer
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(&buf, r); close(copied) }()
	var once sync.Once
	finish := func() string {
		once.Do(func() {
			os.Stderr = old
			w.Close()
			<-copied
			r.Close()
		})
		return buf.String()
	}
	t.Cleanup(func() { finish() })
	return finish
}

// A heartbeat that gets no answer keeps its transport class in the log line
// and in status.json; one the coordinator refuses keeps its code.
func TestHeartbeatFailureKeepsItsClass(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := "https://" + closed.Addr().String()
	closed.Close()
	logs := captureStderr(t)
	node := startOwnedNode(t, http.NotFound, false, func(c *config.Config) {
		c.Coordinator, c.CoordinatorCA = refused, ""
	})
	deadline := time.Now().Add(5 * time.Second)
	for readStatus(t, node.c.StateDir).HeartbeatErrorClass != "refused" {
		if time.Now().After(deadline) {
			t.Fatalf("status error class %q", readStatus(t, node.c.StateDir).HeartbeatErrorClass)
		}
		time.Sleep(20 * time.Millisecond)
	}
	node.stop()
	if out := logs(); !strings.Contains(out, "heartbeat: coordinator unavailable (refused)\n") || strings.Contains(out, closed.Addr().String()) {
		t.Fatalf("log %q", out)
	}
	if s := readStatus(t, node.c.StateDir); s.HeartbeatDiagnostics == nil || s.HeartbeatDiagnostics.Failures < 1 || s.LastHeartbeatOKAt != nil {
		t.Fatalf("status after failures %+v", s)
	}
}

// A coordinator that requires an update holds the heartbeat and answers 426
// update_required with Scarlett-Node-Update-Required: status.json shows
// update_required and the error class at once, during the failure backoff,
// and the node keeps heartbeating.
func TestUpdateRequiredReachesStatusAtOnce(t *testing.T) {
	body, err := os.ReadFile("api/fixtures/error-update-required.json")
	if err != nil {
		t.Fatal(err)
	}
	arrivals := make(chan time.Time, 8)
	node := startOwnedNode(t, func(w http.ResponseWriter, r *http.Request) {
		if controlRoute(w, r) {
			return
		}
		arrivals <- time.Now()
		w.Header().Set(coordinator.NodeLatestVersionHeader, "99.0.0")
		w.Header().Set(coordinator.NodeMinimumVersionHeader, "99.0.0")
		w.Header().Set(coordinator.NodeUpdateRequiredHeader, "true")
		w.WriteHeader(http.StatusUpgradeRequired)
		w.Write(body)
	}, false, nil)
	first := receive(t, arrivals, 5*time.Second, "a heartbeat")
	deadline := time.Now().Add(900 * time.Millisecond)
	for {
		s := readStatus(t, node.c.StateDir)
		if s.UpdateRequired && s.HeartbeatErrorClass == "update_required" && s.LatestRelease == "99.0.0" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status after 426: required %v, class %q", s.UpdateRequired, s.HeartbeatErrorClass)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if second := receive(t, arrivals, 5*time.Second, "another heartbeat"); second.Sub(first) < time.Second {
		t.Fatalf("426 did not back off: %v", second.Sub(first))
	}
	node.stop()
}

// A status file from a build on another protocol, as right after an update,
// reads as offline instead of failing the status command; the new heartbeat
// fields are bounded.
func TestLocalStatusFromAnotherProtocolAndNewFields(t *testing.T) {
	dir := privateTestDir(t)
	write := func(raw string) {
		t.Helper()
		if err := writeLocalFile(dir, "status.json", []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	write(`{"version":"node-v1","state":"running","node_id":"synthetic-node","updated_at":"` + now + `","last_heartbeat_at":"` + now + `","in_flight":0,"unresolved_attempts":0,"services":[],"drain_requested":false,"release":"0.1.16"}`)
	if s := readStatus(t, dir); s.State != "offline" || s.Version != coordinator.Version || s.Release != coordinator.NodeRelease || s.NodeID != "" {
		t.Fatalf("earlier protocol status read as %+v", s)
	}
	base := runtimeStatus{Version: coordinator.Version, State: "running", NodeID: "synthetic-node", Release: coordinator.NodeRelease, Services: []coordinator.ServiceHealth{}}
	ok := base
	at := time.Now().UTC()
	ok.LastHeartbeatOKAt, ok.HeartbeatErrorClass = &at, "connection_lost"
	ok.DispatchHealth = &coordinator.NodeHealth{MissedStreak: 2, SuspectUntil: &at}
	ok.HeartbeatDiagnostics = &heartbeatDiagnostics{Polls: 3, Wakes: 1, LastWakeAt: &at, LastWake: "clock_jump"}
	if err := saveRuntimeStatus(dir, ok); err != nil {
		t.Fatal(err)
	}
	if s := readStatus(t, dir); s.State != "running" || s.HeartbeatErrorClass != "connection_lost" || s.DispatchHealth.MissedStreak != 2 || s.HeartbeatDiagnostics.LastWake != "clock_jump" {
		t.Fatalf("status %+v", s)
	}
	for name, change := range map[string]func(*runtimeStatus){
		"class":   func(s *runtimeStatus) { s.HeartbeatErrorClass = "Bad Class" },
		"streak":  func(s *runtimeStatus) { s.DispatchHealth = &coordinator.NodeHealth{MissedStreak: -1} },
		"counter": func(s *runtimeStatus) { s.HeartbeatDiagnostics = &heartbeatDiagnostics{Polls: -1} },
		"wake": func(s *runtimeStatus) {
			s.HeartbeatDiagnostics = &heartbeatDiagnostics{LastWake: "nap", LastWakeAt: &at}
		},
	} {
		bad := base
		change(&bad)
		if err := saveRuntimeStatus(dir, bad); err != nil {
			t.Fatal(err)
		}
		if err := localCommandDir(dir, "status", io.Discard); err == nil {
			t.Fatalf("%s: invalid heartbeat status accepted", name)
		}
	}
	// The node bounds what the coordinator sends before saving it.
	var s runtimeStatus
	s.observeDispatch(coordinator.NodeHealth{MissedStreak: 1 << 20}, time.Now())
	if s.DispatchHealth.MissedStreak != maxMissedStreak {
		t.Fatalf("missed streak %d", s.DispatchHealth.MissedStreak)
	}
}

// An offer for a proof mode the node will not serve is rejected before any
// acceptance: invalid_offer for a mode it never advertised, other while keyed
// relay is halted, and no_slot for a browser job while the browser tier is
// not ready.
func TestSubmitLeaseRejectsAProofModeItDoesNotServe(t *testing.T) {
	worker.ResetRelayHaltForTests()
	t.Cleanup(worker.ResetRelayHaltForTests)
	reasons := make(chan string, 4)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body coordinator.Rejection
		if !strings.HasSuffix(r.URL.Path, "/reject") || json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("unexpected request", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		reasons <- body.Reason
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client := coordinator.New(server.URL, "synthetic-credential")
	client.HTTP = server.Client()
	c := config.Config{Executor: config.ExecutorServices, Services: []string{"x_read", "web"}, Profile: "standard", XRelay: false}
	relay := codexOffer(1)
	relay.ServiceType, relay.CodexPayload = "x_read", nil
	relay.XRequest = &coordinator.XRequest{Operation: "profile", Username: "fixture"}
	relay.XPayload = json.RawMessage(`{"type":"x.read","proof_mode":"relay","proof_policy":"x-relay-v1"}`)
	raw, err := os.ReadFile("api/fixtures/lease-web-browser-offer.json")
	if err != nil {
		t.Fatal(err)
	}
	var browser coordinator.Lease
	if err := json.Unmarshal(raw, &browser); err != nil {
		t.Fatal(err)
	}
	browser.LeaseDeadline = time.Now().Add(118 * time.Second).UTC().Truncate(time.Second)
	browser.SettlementDeadline = browser.LeaseDeadline
	for _, tc := range []struct {
		name   string
		offer  coordinator.Lease
		halted bool
		reason string
	}{
		{"relay never advertised", relay, false, coordinator.RejectInvalidOffer},
		{"relay halted", relay, true, coordinator.RejectOther},
		{"browser not ready", browser, false, coordinator.RejectNoSlot},
	} {
		if tc.halted {
			worker.HaltRelay("synthetic")
		}
		j := testJournal(t, filepath.Join(privateTestDir(t), "attempts"))
		if code, err := submitLease(context.Background(), client, c, tc.offer, nil, j); code != "invalid_lease" || err == nil {
			t.Fatalf("%s: %q %v", tc.name, code, err)
		}
		if got := receive(t, reasons, 5*time.Second, "a rejection"); got != tc.reason {
			t.Fatalf("%s: rejected %q, want %q", tc.name, got, tc.reason)
		}
		if pending, err := j.Pending(); err != nil || len(pending) != 0 {
			t.Fatalf("%s: a refused offer left a journal record", tc.name)
		}
		worker.ResetRelayHaltForTests()
	}
}
