package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// xObserved records what a cache reports to its observer.
type xObserved struct {
	mu    sync.Mutex
	codes []string
	paths []string
}

func (o *xObserved) observe(path, stamp, code string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.paths, o.codes = append(o.paths, path), append(o.codes, code)
}

func (o *xObserved) seen() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return strings.Join(o.codes, ",")
}

// xBuildDone waits for the account's build in progress, if any.
func xBuildDone(a *xAccount) {
	a.mu.Lock()
	b := a.build
	a.mu.Unlock()
	if b != nil {
		<-b.done
	}
}

func xEventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !ok(); time.Sleep(2 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for", what)
		}
	}
}

// Every build that asked X to validate the session is reported to the
// observer, with none of the cache's locks held; a build whose validation was
// replayed, and one cancelled by Stop, are not.
func TestXObserverSeesValidatedBuildOutcomes(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	seen := &xObserved{}
	clients.Observe(func(path, stamp, code string) {
		// Taking both locks here deadlocks if the caller still holds either.
		clients.account(c, c.LocalAccountID, c.XSession, nil).generation()
		seen.observe(path, stamp, code)
	})
	if code := xRun(c, l, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal(code)
	}
	if seen.seen() != "" || len(seen.paths) != 1 || seen.paths[0] != c.XSession {
		t.Fatalf("validated build reported %q for %v", seen.seen(), seen.paths)
	}
	// An override rebuild replays the validation: nothing to report.
	var plan xPlan
	if e := json.Unmarshal(l.XPayload, &plan); e != nil {
		t.Fatal(e)
	}
	plan.Exchanges[0].QueryID = "rotated-query-id"
	rotated := l
	rotated.XPayload, _ = json.Marshal(plan)
	if code := xRun(c, rotated, clients, fake, roundTripFunc(xBootstrap)); code != "" {
		t.Fatal(code)
	}
	if len(seen.paths) != 1 {
		t.Fatalf("replayed build was reported: %q", seen.seen())
	}
	// A refused session and an unreachable X are reported with their codes.
	for want, status := range map[string]int32{"auth_required": 401, "x_request_failed": -1, "x_rate_limited": 429} {
		other := NewXClients()
		other.log, other.minGap = io.Discard, time.Millisecond
		t.Cleanup(other.Stop)
		got := &xObserved{}
		other.Observe(got.observe)
		bad := &xFakeX{}
		bad.viewerStatus.Store(status)
		if code := xRun(c, l, other, bad, &xProfileProof{}); code != want || got.seen() != want {
			t.Fatalf("build against status %d: job %q, observer %q, want %q", status, code, got.seen(), want)
		}
	}
	// A build cancelled by Stop says nothing about X.
	stopping := NewXClients()
	stopping.log, stopping.minGap = io.Discard, time.Millisecond
	got := &xObserved{}
	stopping.Observe(got.observe)
	entered, hold := make(chan struct{}), make(chan struct{})
	var once sync.Once
	gate := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		once.Do(func() { close(entered) })
		select {
		case <-hold:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return xBootstrap(r)
	})
	a := stopping.account(c, "held", c.XSession, gate)
	a.mu.Lock()
	b := a.startBuild(nil, nil, "warm")
	a.mu.Unlock()
	<-entered
	stopping.Stop()
	<-b.done
	close(hold)
	if b.err == nil || len(got.paths) != 0 {
		t.Fatalf("cancelled build reported %q (err %v)", got.seen(), b.err)
	}
}

// A client built without transaction-ID material is installed but not called
// ready, and the refresher retries its bootstrap long before the refresh
// interval, without repeating the validation reads.
func TestXClientWithoutTransactionMaterialRetriesBootstrapSoon(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	c.XRefresh = time.Hour
	clients.retry = 20 * time.Millisecond
	var log strings.Builder
	var logMu sync.Mutex
	clients.log = writerFunc(func(p []byte) (int, error) {
		logMu.Lock()
		defer logMu.Unlock()
		return log.Write(p)
	})
	fake.brokenHome.Store(true)
	account := clients.account(c, "main", c.XSession, fake)
	clients.Warm(context.Background(), c, []XAccount{{"main", c.XSession}})
	logMu.Lock()
	out := log.String()
	logMu.Unlock()
	if strings.Contains(out, "ready") || !strings.Contains(out, "x client for account main has no transaction-ID material; the bootstrap will be retried") {
		t.Fatalf("warm-up log for a client without transaction material: %q", out)
	}
	if account.generation() != 1 || !account.degraded() {
		t.Fatal("client without transaction material was not installed")
	}
	// Ungated reads still work on it.
	if code := xRun(c, l, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal(code)
	}
	// Still broken: retried, with growing pauses, and never re-validated.
	xEventually(t, "a bootstrap retry", func() bool { return account.generation() >= 2 })
	fake.brokenHome.Store(false)
	xEventually(t, "transaction material", func() bool { return !account.degraded() })
	if v, _ := fake.counts(); v != 2 {
		t.Fatal("bootstrap retry repeated the validation reads", v)
	}
	// Healthy again: back to the refresh interval, no further fetches.
	healed := account.generation()
	_, before := fake.counts()
	time.Sleep(150 * time.Millisecond)
	if _, after := fake.counts(); after != before || account.generation() != healed {
		t.Fatal("refresher kept retrying a client that has its material")
	}
}

// The bootstrap retry backs off: it doubles from the base and stops growing
// at the refresh interval.
func TestXBootstrapRetryBacksOff(t *testing.T) {
	c, _, clients, fake := xWarmFixture(t, "fixture")
	c.XRefresh = time.Hour
	clients.retry = 40 * time.Millisecond
	fake.brokenHome.Store(true)
	account := clients.account(c, "main", c.XSession, fake)
	started := time.Now()
	if _, e := account.acquire(context.Background(), nil, false); e != nil {
		t.Fatal(e)
	}
	// Retries are due 40, 120 and 280 ms after the build; a fixed 40 ms pause
	// would reach the fourth build in about 120 ms.
	xEventually(t, "three bootstrap retries", func() bool { return account.generation() >= 4 })
	if took := time.Since(started); took < 250*time.Millisecond {
		t.Fatal("bootstrap retries did not back off", took)
	}
}

// xRateProof proves profile reads and answers with the given rate-limit headers.
func xRateProof(remaining, reset string, proofs *atomic.Int32) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		proofs.Add(1)
		response, e := xBootstrap(r)
		response.Header.Set("X-Rate-Limit-Limit", "50")
		response.Header.Set("X-Rate-Limit-Remaining", remaining)
		response.Header.Set("X-Rate-Limit-Reset", reset)
		return response, e
	})
}

// When X's last answer leaves no room for another read inside the lease, the
// next job fails fast as rate limited, rests the account until the reset and
// spends no proof.
func TestXJobFailsFastWhenPacingCannotFitTheLease(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	var cooled atomic.Int64
	c.AccountCooldown = func(wait time.Duration) { cooled.Store(int64(wait)) }
	var proofs atomic.Int32
	exhausted := xRateProof("0", strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10), &proofs)
	if code := xRun(c, l, clients, fake, exhausted); code != "" || cooled.Load() != 0 {
		t.Fatal("job that met the limit failed", code)
	}
	started := time.Now()
	if code := xRun(c, l, clients, fake, exhausted); code != "x_rate_limited" {
		t.Fatal("job behind an exhausted window returned", code)
	}
	if took := time.Since(started); took > time.Second || proofs.Load() != 1 {
		t.Fatal("job waited or spent a proof", took, proofs.Load())
	}
	if wait := time.Duration(cooled.Load()); wait < 9*time.Minute || wait > 10*time.Minute {
		t.Fatal("account not rested until the reset", wait)
	}
	// A wait that fits the lease is not a failure.
	c2, l2, clients2, fake2 := xWarmFixture(t, "fixture")
	var proofs2 atomic.Int32
	brief := xRateProof("1", "1", &proofs2) // one read left, window resets in a second
	for i := 0; i < 2; i++ {
		if code := xRun(c2, l2, clients2, fake2, brief); code != "" {
			t.Fatal("job with a fitting wait failed", i, code)
		}
	}
}

// A job that ends while x-go holds its read back leaves a reserved slot on
// the shared client. The client is replaced in the background, without asking
// X to validate again, so the next job does not wait behind that slot.
func TestXAbandonedPacingSlotReplacesTheClient(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	var proofs atomic.Int32
	// One read left in a window that resets in three seconds: x-go holds the
	// next read back for about that long.
	if code := xRun(c, l, clients, fake, xRateProof("1", "3", &proofs)); code != "" {
		t.Fatal(code)
	}
	account := clients.account(c, c.LocalAccountID, c.XSession, nil)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	if code := (X{Config: c, Base: fake, Proof: xRateProof("1", "3", &proofs), Clients: clients}).Run(ctx, l); code != "expired" || proofs.Load() != 1 {
		t.Fatal("job cancelled while paced returned", code, proofs.Load())
	}
	xBuildDone(account)
	if v, b := fake.counts(); account.generation() != 2 || v != 2 || b != 4 {
		t.Fatalf("abandoned slot: generation %d, %d validation reads, %d bootstrap fetches; want 2, 2, 4", account.generation(), v, b)
	}
	started := time.Now()
	if code := xRun(c, l, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal(code)
	}
	if took := time.Since(started); took > 1500*time.Millisecond {
		t.Fatal("job after an abandoned slot still waited behind it", took)
	}
}

// Retain closes and forgets the accounts the pool no longer holds: their
// refresher stops and nothing more is sent to X for them.
func TestXRetainEvictsAccountsThatAreGone(t *testing.T) {
	c, _, clients, kept := xWarmFixture(t, "fixture")
	c.XRefresh = 20 * time.Millisecond
	gone := &xFakeX{}
	other := c.XSession + ".other"
	raw, _ := json.Marshal(map[string]string{"auth_token": "other-auth", "ct0": "other-csrf"})
	if e := localfs.WriteAtomic(other, raw, true); e != nil {
		t.Fatal(e)
	}
	keptAccount := clients.account(c, "kept", c.XSession, kept)
	goneAccount := clients.account(c, "gone", other, gone)
	clients.Warm(context.Background(), c, []XAccount{{"kept", c.XSession}, {"gone", other}})
	if keptAccount.generation() == 0 || goneAccount.generation() == 0 {
		t.Fatal("accounts not warmed")
	}
	clients.Retain(map[string]bool{c.XSession: true})
	clients.mu.Lock()
	_, stillKept := clients.accounts[c.XSession]
	_, stillGone := clients.accounts[other]
	clients.mu.Unlock()
	if !stillKept || stillGone || goneAccount.generation() != 0 {
		t.Fatal("eviction kept the wrong accounts", stillKept, stillGone)
	}
	select {
	case <-goneAccount.stop:
	default:
		t.Fatal("evicted account's refresher still runs")
	}
	xBuildDone(goneAccount)
	_, before := gone.counts()
	keptBefore := keptAccount.generation()
	xEventually(t, "the kept account to keep refreshing", func() bool { return keptAccount.generation() > keptBefore+1 })
	if _, after := gone.counts(); after != before {
		t.Fatal("evicted account still sent requests to X", before, after)
	}
}

// When the timer's refresh finds that X refuses the session, the client is
// dropped, the observer hears auth_required, and nothing asks X again until
// the session file changes. A rate limit or a transport failure keeps the
// client and reports nothing.
func TestXRefreshDropsARefusedSession(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	seen := &xObserved{}
	clients.Observe(seen.observe)
	var log strings.Builder
	clients.log = &log
	if code := xRun(c, l, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal(code)
	}
	account := clients.account(c, c.LocalAccountID, c.XSession, nil)
	for _, status := range []int32{-1, 429, 404} {
		fake.viewerStatus.Store(status)
		if e := account.refreshNow(); e == nil || account.generation() != 1 {
			t.Fatal("refresh that could not ask X replaced or dropped the client", status, e)
		}
	}
	if seen.seen() != "" {
		t.Fatalf("unanswered refreshes were reported: %q", seen.seen())
	}
	fake.viewerStatus.Store(401)
	if e := account.refreshNow(); !xRefused(e) || account.generation() != 0 {
		t.Fatal("refused session kept its client", e, account.generation())
	}
	if seen.seen() != ",auth_required" {
		t.Fatalf("observer after a refused refresh: %q", seen.seen())
	}
	if out := log.String(); !strings.Contains(out, "x session for account fixture-account was refused by X") || strings.Contains(out, c.XSession) || strings.Contains(out, "synthetic") {
		t.Fatalf("log: %q", out)
	}
	// The background leaves a refused session alone.
	asked := fake.viewer.Load()
	clients.Ensure(c, []XAccount{{c.LocalAccountID, c.XSession}})
	xBuildDone(account)
	if fake.viewer.Load() != asked {
		t.Fatal("background asked X again about a refused session")
	}
	// A new session file is tried at once.
	fake.viewerStatus.Store(0)
	raw, _ := json.Marshal(map[string]string{"auth_token": "rotated-auth", "ct0": "rotated-csrf"})
	if e := localfs.WriteAtomic(c.XSession, raw, true); e != nil {
		t.Fatal(e)
	}
	clients.Ensure(c, []XAccount{{c.LocalAccountID, c.XSession}})
	xBuildDone(account)
	if account.generation() == 0 || seen.seen() != ",auth_required," {
		t.Fatalf("new session file not built in the background: %q", seen.seen())
	}
}

// Ensure builds a cold account in the background, backs off after a failure,
// and builds again once the backoff has passed; a warm account costs nothing.
func TestXEnsureKeepsAccountsWarmInTheBackground(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	clients.retry = 50 * time.Millisecond
	seen := &xObserved{}
	clients.Observe(seen.observe)
	fake.down.Store(true)
	account := clients.account(c, "main", c.XSession, fake)
	accounts := []XAccount{{"main", c.XSession}}
	returned := time.Now()
	clients.Ensure(c, accounts)
	account.mu.Lock()
	started := account.build != nil
	account.mu.Unlock()
	if !started || time.Since(returned) > time.Second {
		t.Fatal("Ensure did not start a background build, or blocked on it")
	}
	xBuildDone(account)
	if seen.seen() != "x_request_failed" || account.generation() != 0 {
		t.Fatalf("failed background build: observer %q", seen.seen())
	}
	// Inside the backoff nothing is tried, even though X is back.
	fake.down.Store(false)
	clients.Ensure(c, accounts)
	account.mu.Lock()
	started = account.build != nil
	account.mu.Unlock()
	if v, _ := fake.counts(); started || v != 0 {
		t.Fatal("Ensure retried inside the backoff", v)
	}
	time.Sleep(60 * time.Millisecond)
	clients.Ensure(c, accounts)
	xBuildDone(account)
	if v, b := fake.counts(); account.generation() != 1 || v != 2 || b != 2 || seen.seen() != "x_request_failed," {
		t.Fatalf("background build after the backoff: generation %d, %d validation reads, %d bootstrap fetches, observer %q", account.generation(), v, b, seen.seen())
	}
	// Warm: nothing more to do, and the job does only its proven read.
	clients.Ensure(c, accounts)
	account.mu.Lock()
	started = account.build != nil
	account.mu.Unlock()
	proof := &xProfileProof{}
	if code := xRun(c, l, clients, fake, proof); code != "" || started {
		t.Fatal("warm account rebuilt, or its job failed", code)
	}
	if v, b := fake.counts(); v != 2 || b != 2 || account.generation() != 1 {
		t.Fatal("job on a background-built client made unproven requests", v, b)
	}
	// A changed session file is rebuilt in the background, before any job.
	raw, _ := json.Marshal(map[string]string{"auth_token": "rotated-auth", "ct0": "rotated-csrf"})
	if e := localfs.WriteAtomic(c.XSession, raw, true); e != nil {
		t.Fatal(e)
	}
	clients.Ensure(c, accounts)
	xBuildDone(account)
	if v, _ := fake.counts(); v != 4 || account.generation() != 2 {
		t.Fatal("changed session not rebuilt in the background", v, account.generation())
	}
}

// The failure backoff doubles and is capped at the refresh interval; one call
// starts at most one build.
func TestXEnsureBackoffAndPacing(t *testing.T) {
	c, _, clients, fake := xWarmFixture(t, "fixture")
	c.XRefresh = 4 * time.Minute
	fake.down.Store(true)
	account := clients.account(c, "main", c.XSession, fake)
	_, stamp, e := readXSession(c.XSession)
	if e != nil {
		t.Fatal(e)
	}
	for _, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 4 * time.Minute} {
		account.mu.Lock()
		account.noteFailure(stamp, errors.New("synthetic"))
		got, until := account.backoff, time.Until(account.retryAt)
		account.mu.Unlock()
		if got != want || until > want || until < want-time.Second {
			t.Fatalf("backoff %v (retry in %v), want %v", got, until, want)
		}
	}
	// Another file content starts over.
	account.mu.Lock()
	account.noteFailure("other", errors.New("synthetic"))
	got := account.backoff
	account.mu.Unlock()
	if got != time.Minute {
		t.Fatal("backoff carried over to new session content", got)
	}
	// Two cold accounts, one call: one build.
	second := c.XSession + ".second"
	raw, _ := json.Marshal(map[string]string{"auth_token": "second-auth", "ct0": "second-csrf"})
	if e := localfs.WriteAtomic(second, raw, true); e != nil {
		t.Fatal(e)
	}
	pair := NewXClients()
	pair.log, pair.minGap = io.Discard, time.Millisecond
	t.Cleanup(pair.Stop)
	up := &xFakeX{}
	one, two := pair.account(c, "one", c.XSession, up), pair.account(c, "two", second, up)
	accounts := []XAccount{{"one", c.XSession}, {"two", second}}
	pair.Ensure(c, accounts)
	two.mu.Lock()
	burst := two.build != nil
	two.mu.Unlock()
	xBuildDone(one)
	if burst || one.generation() != 1 || two.generation() != 0 {
		t.Fatal("one Ensure call started more than one build")
	}
	pair.Ensure(c, accounts)
	xBuildDone(two)
	if two.generation() != 1 {
		t.Fatal("second account not built on the next call")
	}
}

// A job that waited on a timer refresh does not inherit its failure: when the
// refresh ends without a client for the job, the job builds its own.
func TestXJobDoesNotInheritARefreshFailure(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	hold := make(chan struct{})
	var holding atomic.Bool
	gate := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "abs.twimg.com" && holding.Load() {
			<-hold
		}
		return fake.RoundTrip(r)
	})
	run := func() string {
		return X{Config: c, Base: gate, Proof: &xProfileProof{}, Clients: clients}.Run(context.Background(), l)
	}
	if code := run(); code != "" {
		t.Fatal(code)
	}
	account := clients.account(c, c.LocalAccountID, c.XSession, nil)
	holding.Store(true)
	refreshed := make(chan error, 1)
	go func() { refreshed <- account.refreshNow() }()
	xEventually(t, "the refresh to reach its bootstrap", func() bool { _, b := fake.counts(); return b >= 3 })
	// The session file changes under the refresh. The job drops the stale
	// client and waits on the refresh, which then ends as dropped.
	raw, _ := json.Marshal(map[string]string{"auth_token": "rotated-auth", "ct0": "rotated-csrf"})
	if e := localfs.WriteAtomic(c.XSession, raw, true); e != nil {
		t.Fatal(e)
	}
	result := make(chan string, 1)
	go func() { result <- run() }()
	xEventually(t, "the job to drop the stale client", func() bool { return account.generation() == 0 })
	holding.Store(false)
	close(hold)
	if e := <-refreshed; !errors.Is(e, errXDropped) {
		t.Fatal("refresh under a dropped client ended with", e)
	}
	if code := <-result; code != "" {
		t.Fatal("job inherited the refresh's failure:", code)
	}
	// The job's own build validated the new session.
	if v := fake.viewer.Load(); v != 3 || account.generation() == 0 {
		t.Fatal("job did not build its own client", v, account.generation())
	}
}

// A job retries behind a failed swap at most twice; after that the swap's
// error is the job's, so it cannot loop for ever behind background builds.
func TestXAcquireBoundsInheritedFailures(t *testing.T) {
	c, _, clients, fake := xWarmFixture(t, "fixture")
	account := clients.account(c, "main", c.XSession, fake)
	// A finished, failed refresh that never leaves: the worst a job can meet.
	stuck := &xBuild{done: make(chan struct{}), kind: "refresh", err: errXDropped}
	close(stuck.done)
	account.mu.Lock()
	account.build = stuck
	account.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		_, e := account.acquire(context.Background(), nil, false)
		result <- e
	}()
	select {
	case e := <-result:
		if !errors.Is(e, errXDropped) {
			t.Fatal("job behind a stuck refresh returned", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("job looped behind failing background builds")
	}
	account.mu.Lock()
	account.build = nil
	account.mu.Unlock()
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func (o *xObserved) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.codes)
}

func xRotateSession(t *testing.T, path string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{"auth_token": "rotated-auth", "ct0": "rotated-csrf"})
	if e := localfs.WriteAtomic(path, raw, true); e != nil {
		t.Fatal(e)
	}
}

// A build's outcome is about the session file content it read. When the file
// is replaced while X answers, a refusal of the old content is not reported,
// and the new content is built and reported on its own.
func TestXStaleBuildOutcomeIsNotReported(t *testing.T) {
	c, _, clients, fake := xWarmFixture(t, "fixture")
	seen := &xObserved{}
	clients.Observe(seen.observe)
	fake.viewerStatus.Store(401)
	var replaced atomic.Bool
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/Viewer") && replaced.CompareAndSwap(false, true) {
			xRotateSession(t, c.XSession)
		}
		return fake.RoundTrip(r)
	})
	account := clients.account(c, "main", c.XSession, base)
	accounts := []XAccount{{"main", c.XSession}}
	clients.Ensure(c, accounts)
	xBuildDone(account)
	if fake.viewer.Load() != 1 || seen.count() != 0 {
		t.Fatalf("refusal of a replaced session file was reported: %d reports %q", seen.count(), seen.seen())
	}
	fake.viewerStatus.Store(0)
	clients.Ensure(c, accounts)
	xBuildDone(account)
	if account.generation() != 1 || seen.count() != 1 || seen.seen() != "" {
		t.Fatalf("new session file not built and reported: generation %d, %d reports %q", account.generation(), seen.count(), seen.seen())
	}
}

// When a replaced session file is refused, the client built from the old file
// goes with it, so neither the refresher nor Ensure asks X about the refused
// session again.
func TestXRefusedReplacementSessionIsNotAskedAboutAgain(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	seen := &xObserved{}
	clients.Observe(seen.observe)
	if code := xRun(c, l, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal(code)
	}
	account := clients.account(c, c.LocalAccountID, c.XSession, nil)
	xRotateSession(t, c.XSession)
	fake.viewerStatus.Store(401)
	accounts := []XAccount{{c.LocalAccountID, c.XSession}}
	clients.Ensure(c, accounts)
	xBuildDone(account)
	if account.generation() != 0 || seen.seen() != ",auth_required" {
		t.Fatalf("refused replacement: generation %d, observer %q", account.generation(), seen.seen())
	}
	asked := fake.viewer.Load()
	_ = account.refreshNow()
	_ = account.swap("replay")
	clients.Ensure(c, accounts)
	xBuildDone(account)
	if fake.viewer.Load() != asked || seen.seen() != ",auth_required" {
		t.Fatalf("refused session was asked about again: %d then %d Viewer reads, observer %q", asked, fake.viewer.Load(), seen.seen())
	}
}

// An exhausted window stays closed until its reset, however long ago the last
// read was: a job that cannot wait for the reset fails fast without a proof,
// and one that can waits for it before its read.
func TestXExhaustedWindowHoldsUntilItsReset(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	var cooled atomic.Int64
	c.AccountCooldown = func(wait time.Duration) { cooled.Store(int64(wait)) }
	var proofs atomic.Int32
	exhausted := xRateProof("0", "3", &proofs) // nothing left, window resets in three seconds
	if code := xRun(c, l, clients, fake, exhausted); code != "" {
		t.Fatal(code)
	}
	time.Sleep(2 * time.Second) // more than half the window
	short := c
	short.InferenceTimeout = 300 * time.Millisecond
	if code := xRun(short, l, clients, fake, exhausted); code != "x_rate_limited" || proofs.Load() != 1 {
		t.Fatal("job late in an exhausted window returned", code, proofs.Load())
	}
	if wait := time.Duration(cooled.Load()); wait <= 300*time.Millisecond || wait > time.Second+100*time.Millisecond {
		t.Fatal("account not rested until the reset", wait)
	}
	started := time.Now()
	if code := xRun(c, l, clients, fake, exhausted); code != "" || proofs.Load() != 2 {
		t.Fatal("job that could wait for the reset returned", code, proofs.Load())
	}
	if took := time.Since(started); took < 500*time.Millisecond {
		t.Fatal("read was sent into the exhausted window", took)
	}
}

// A search held back before a later page because the earlier page used up X's
// quota keeps its client, which knows that, and rests the account: the next
// job spends no proof.
func TestXExhaustedQuotaMidSearchKeepsTheClient(t *testing.T) {
	c, l, _ := xFixture(t, coordinator.XRequest{Operation: "search", Query: "bitcoin", Count: 20, Pages: 2})
	c.LocalAccountID = "fixture-account"
	clients := NewXClients()
	clients.log = io.Discard
	clients.minGap = 5 * time.Millisecond
	t.Cleanup(clients.Stop)
	fake := &xFakeX{}
	var cooled atomic.Int64
	c.AccountCooldown = func(wait time.Duration) { cooled.Store(int64(wait)) }
	var proofs atomic.Int32
	proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		proofs.Add(1)
		response := xResponse(r, 200, `{"data":{"search_by_raw_query":{"search_timeline":{"timeline":{"instructions":[{"type":"TimelineAddEntries","entries":[{"entryId":"cursor-bottom-1","content":{"entryType":"TimelineTimelineCursor","cursorType":"Bottom","value":"next"}}]}]}}}}}`)
		response.Header.Set("X-Rate-Limit-Limit", "50")
		response.Header.Set("X-Rate-Limit-Remaining", "0")
		response.Header.Set("X-Rate-Limit-Reset", "600")
		return response, nil
	})
	c.InferenceTimeout = 500 * time.Millisecond
	if code := xRun(c, l, clients, fake, proof); code != "x_rate_limited" || proofs.Load() != 1 {
		t.Fatal("search held back by an exhausted quota returned", code, proofs.Load())
	}
	if wait := time.Duration(cooled.Load()); wait < 9*time.Minute || wait > 10*time.Minute {
		t.Fatal("account not rested until the reset", wait)
	}
	account := clients.account(c, c.LocalAccountID, c.XSession, nil)
	xBuildDone(account)
	if _, b := fake.counts(); account.generation() != 1 || b != 2 {
		t.Fatal("client that knew the quota was exhausted was replaced", account.generation(), b)
	}
	started := time.Now()
	if code := xRun(c, l, clients, fake, proof); code != "x_rate_limited" || proofs.Load() != 1 || time.Since(started) > 300*time.Millisecond {
		t.Fatal("next job spent a proof or waited", code, proofs.Load(), time.Since(started))
	}
}

// A validation X answers with not-found is not a refusal: the observer hears
// a failed request, not auth_required, and the background tries again after
// its backoff. A warm account is then confirmed without asking X anything.
func TestXNotFoundValidationIsNotReportedAsRefused(t *testing.T) {
	c, _, clients, fake := xWarmFixture(t, "fixture")
	clients.retry = 30 * time.Millisecond
	seen := &xObserved{}
	clients.Observe(seen.observe)
	var log strings.Builder
	clients.log = &log
	fake.viewerStatus.Store(404)
	account := clients.account(c, "main", c.XSession, fake)
	accounts := []XAccount{{"main", c.XSession}}
	clients.Ensure(c, accounts)
	xBuildDone(account)
	if seen.seen() != "x_request_failed" || strings.Contains(log.String(), "auth_required") {
		t.Fatalf("not-found validation: observer %q, log %q", seen.seen(), log.String())
	}
	fake.viewerStatus.Store(0)
	time.Sleep(40 * time.Millisecond)
	clients.Ensure(c, accounts)
	xBuildDone(account)
	if account.generation() != 1 || seen.seen() != "x_request_failed," {
		t.Fatalf("no retry after a not-found validation: generation %d, observer %q", account.generation(), seen.seen())
	}
	asked, _ := fake.counts()
	clients.Ensure(c, accounts)
	xBuildDone(account)
	if v, _ := fake.counts(); v != asked || seen.count() != 3 || seen.seen() != "x_request_failed,," {
		t.Fatalf("warm account not confirmed without a request: %d then %d validation reads, observer %q", asked, v, seen.seen())
	}
}
