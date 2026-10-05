package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// A synthetic x.com home page and ondemand.s bundle that satisfy x-go's
// transaction-ID bootstrap, so a fixture construction makes the same four
// unproven requests as production: Viewer, UserByRestId, the home page and
// the script. Nothing here reaches a network.
const (
	xFixtureHome     = `<html><head><meta name="twitter-site-verification" content="AAAAAAAAAAA"/></head><body><svg id="loading-x-anim-0"><g><path d="M0 0 0 0 C1 2 3 4"/><path d="M0 0 0 0 C1 2 3 4 5 6 7 8 9 10 11 12"/></g></svg><script>a={,7:"ondemand.s",7:"abc123"}</script></body></html>`
	xFixtureOndemand = `(a[0], 16)(a[1], 16)`
)

// xFakeX stands in for X behind Base: it answers the construction-time reads
// and bootstrap fetches and counts them. brokenHome makes the home page 404,
// which leaves a client without transaction-ID material. viewerStatus makes
// the Viewer read answer that HTTP status instead (-1: a transport failure),
// and down fails every request at the transport.
type xFakeX struct {
	validation, viewer, bootstrap atomic.Int32
	brokenHome, down              atomic.Bool
	viewerStatus                  atomic.Int32
}

func (f *xFakeX) RoundTrip(r *http.Request) (*http.Response, error) {
	if f.down.Load() {
		return nil, errors.New("synthetic dial failure")
	}
	if r.URL.Host == "x.com" && strings.Contains(r.URL.Path, "/i/api/graphql/") {
		f.validation.Add(1)
		if strings.HasSuffix(r.URL.Path, "/Viewer") {
			f.viewer.Add(1)
			switch status := int(f.viewerStatus.Load()); {
			case status < 0:
				return nil, errors.New("synthetic dial failure")
			case status == 401:
				return xResponse(r, 401, `{"errors":[{"code":32,"message":"Could not authenticate you"}]}`), nil
			case status > 0:
				return xResponse(r, status, ""), nil
			}
		}
		return xBootstrap(r)
	}
	f.bootstrap.Add(1)
	switch {
	case r.URL.Host == "x.com" && r.URL.Path == "" || r.URL.Path == "/":
		if f.brokenHome.Load() {
			return xResponse(r, 404, ""), nil
		}
		return xResponse(r, 200, xFixtureHome), nil
	case r.URL.Host == "abs.twimg.com" && strings.HasSuffix(r.URL.Path, "/ondemand.s.abc123a.js"):
		return xResponse(r, 200, xFixtureOndemand), nil
	}
	return xResponse(r, 404, ""), nil
}

func (f *xFakeX) counts() (validation, bootstrap int32) {
	return f.validation.Load(), f.bootstrap.Load()
}

// xProfileProof is a proving transport for profile leases: it records the
// screen names it was asked to prove and the auth cookie each request carried,
// and can hold a request until released.
type xProfileProof struct {
	mu       sync.Mutex
	names    []string
	cookies  []string
	status   int
	hold     chan struct{}
	entered  chan struct{}
	proofs   atomic.Int32
	entering sync.Once
}

func (p *xProfileProof) RoundTrip(r *http.Request) (*http.Response, error) {
	if p.entered != nil {
		p.entering.Do(func() { close(p.entered) })
	}
	if p.hold != nil {
		<-p.hold
	}
	p.proofs.Add(1)
	v, _ := uniqueJSON([]byte(r.URL.Query().Get("variables")))
	name, _ := v.(map[string]any)["screen_name"].(string)
	p.mu.Lock()
	p.names = append(p.names, name)
	p.cookies = append(p.cookies, r.Header.Get("Cookie"))
	p.mu.Unlock()
	if p.status == 401 {
		return xResponse(r, 401, `{"errors":[{"code":32,"message":"Could not authenticate you"}]}`), nil
	}
	return xBootstrap(r)
}

func (p *xProfileProof) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.names...)
}

// xWarmFixture is a profile lease, a fresh cache and a fake X behind Base.
func xWarmFixture(t *testing.T, username string) (config.Config, coordinator.Lease, *XClients, *xFakeX) {
	t.Helper()
	c, l, _ := xFixture(t, coordinator.XRequest{Operation: "profile", Username: username})
	c.LocalAccountID = "fixture-account"
	clients := NewXClients()
	clients.log = io.Discard
	// The 1 s gap is x-go's and not under test here; the measurement test
	// keeps it.
	clients.minGap = 5 * time.Millisecond
	t.Cleanup(clients.Stop)
	return c, l, clients, &xFakeX{}
}

func xRun(c config.Config, l coordinator.Lease, clients *XClients, fake *xFakeX, proof http.RoundTripper) string {
	return X{Config: c, Base: fake, Proof: proof, Clients: clients}.Run(context.Background(), l)
}

// A second job on a warm account performs only its proven read: no
// session-validation reads and no bootstrap fetches reach Base.
func TestXWarmClientSecondJobDoesOnlyProvenReads(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	proof := &xProfileProof{}
	if code := xRun(c, l, clients, fake, proof); code != "" {
		t.Fatal("first job failed", code)
	}
	validation, bootstrap := fake.counts()
	if validation != 2 || bootstrap != 2 || proof.proofs.Load() != 1 {
		t.Fatalf("cold job: %d validation reads, %d bootstrap fetches, %d proofs; want 2, 2, 1", validation, bootstrap, proof.proofs.Load())
	}
	account := clients.account(c, c.LocalAccountID, c.XSession, nil)
	if account.generation() != 1 || account.current.client.TransactionInitErr() != nil {
		t.Fatal("warm client missing or without transaction material", account.generation())
	}
	if code := xRun(c, l, clients, fake, proof); code != "" {
		t.Fatal("second job failed", code)
	}
	if v, b := fake.counts(); v != 2 || b != 2 || proof.proofs.Load() != 2 {
		t.Fatalf("warm job made unproven requests: %d validation reads, %d bootstrap fetches (was 2, 2); %d proofs", v, b, proof.proofs.Load())
	}
	if account.generation() != 1 {
		t.Fatal("warm job rebuilt the client")
	}
}

// Each job sees only its own binding: proofs for job B carry B's request, never
// A's, and a request without a binding, or with a finished construction, is refused.
func TestXBindingIsolation(t *testing.T) {
	c, lA, clients, fake := xWarmFixture(t, "alpha")
	cB, lB, _ := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "bravo"})
	// Same account (session path) for both jobs, different leases and tokens.
	cB.XSession, cB.LocalAccountID = c.XSession, c.LocalAccountID
	lB.VerifierToken = strings.Repeat("cd", 32)
	proofA, proofB := &xProfileProof{}, &xProfileProof{}
	if code := xRun(c, lA, clients, fake, proofA); code != "" {
		t.Fatal("job A failed", code)
	}
	if code := xRun(cB, lB, clients, fake, proofB); code != "" {
		t.Fatal("job B failed", code)
	}
	if a, b := proofA.seen(), proofB.seen(); len(a) != 1 || a[0] != "alpha" || len(b) != 1 || b[0] != "bravo" {
		t.Fatalf("bindings leaked between jobs: A proved %v, B proved %v", a, b)
	}
	if v, _ := fake.counts(); v != 2 {
		t.Fatal("job B revalidated the session", v)
	}
	account := clients.account(c, c.LocalAccountID, c.XSession, nil)
	path := "https://x.com/i/api/graphql/q/UserByScreenName?variables=%7B%7D&features=%7B%7D"
	// No binding, no construction: refused before any transport.
	r, _ := http.NewRequest("GET", path, nil)
	if _, e := account.board.RoundTrip(r); !errors.Is(e, errUnprovenXCall) {
		t.Fatal("unbound request passed", e)
	}
	// A construction that has finished lets nothing more through, not even
	// the reads it allowed while running.
	done := &xConstruction{}
	done.done.Store(true)
	for _, u := range []string{"https://x.com/i/api/graphql/q/Viewer?variables=%7B%7D", "https://x.com/", "https://abs.twimg.com/x.js"} {
		r, _ := http.NewRequestWithContext(withXConstruction(context.Background(), done), "GET", u, nil)
		if _, e := account.board.RoundTrip(r); !errors.Is(e, errUnprovenXCall) {
			t.Fatal("finished construction still passed", u, e)
		}
	}
	// A running construction allows each validation read once and refuses
	// other API reads.
	running := &xConstruction{}
	before, _ := fake.counts()
	for i, u := range []string{"https://x.com/i/api/graphql/q/Viewer?variables=%7B%7D", "https://x.com/i/api/graphql/q/Viewer?variables=%7B%7D", "https://x.com/i/api/graphql/q/UserByScreenName?variables=%7B%7D"} {
		r, _ := http.NewRequestWithContext(withXConstruction(context.Background(), running), "GET", u, nil)
		_, e := account.board.RoundTrip(r)
		if i == 0 && e != nil || i > 0 && !errors.Is(e, errUnprovenXCall) {
			t.Fatal("construction allowance wrong", i, e)
		}
	}
	if after, _ := fake.counts(); after != before+1 {
		t.Fatal("repeated or foreign construction read reached Base")
	}
}

// An auth failure on a proven read drops the warm client; the rebuild runs in
// the background and the next job uses the fresh client.
func TestXAuthFailureDropsClientAndRebuilds(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	if code := xRun(c, l, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal("warm-up job failed", code)
	}
	account := clients.account(c, c.LocalAccountID, c.XSession, nil)
	old := account.current
	if code := xRun(c, l, clients, fake, &xProfileProof{status: 401}); code != "auth_required" {
		t.Fatal("auth failure classified as", code)
	}
	// Dropped at once; rebuilt in the background with a real validation.
	account.mu.Lock()
	dropped, build := account.current != old, account.build
	account.mu.Unlock()
	if !dropped {
		t.Fatal("failed client still current")
	}
	if build != nil {
		<-build.done
	}
	if v, b := fake.counts(); v != 4 || b != 4 {
		t.Fatalf("rebuild made %d validation reads and %d bootstrap fetches, want 4 and 4 in total", v, b)
	}
	proof := &xProfileProof{}
	if code := xRun(c, l, clients, fake, proof); code != "" || proof.proofs.Load() != 1 {
		t.Fatal("job after rebuild failed", code)
	}
	if v, _ := fake.counts(); v != 4 || account.generation() != 2 || account.current == old {
		t.Fatal("next job did not use the rebuilt client", v, account.generation())
	}
}

// A changed session file rebuilds the client; the next job proves with the
// new cookies.
func TestXChangedSessionFileRebuildsClient(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	first := &xProfileProof{}
	if code := xRun(c, l, clients, fake, first); code != "" {
		t.Fatal("first job failed", code)
	}
	raw, _ := json.Marshal(map[string]string{"auth_token": "rotated-auth", "ct0": "rotated-csrf"})
	if e := localfs.WriteAtomic(c.XSession, raw, true); e != nil {
		t.Fatal(e)
	}
	second := &xProfileProof{}
	if code := xRun(c, l, clients, fake, second); code != "" {
		t.Fatal("job after rotation failed", code)
	}
	if v, b := fake.counts(); v != 4 || b != 4 {
		t.Fatalf("rotation rebuild: %d validation reads, %d bootstrap fetches, want 4 and 4", v, b)
	}
	if !strings.Contains(first.cookies[0], "synthetic-auth") || !strings.Contains(second.cookies[0], "rotated-auth") || strings.Contains(second.cookies[0], "synthetic-auth") {
		t.Fatal("rebuilt client did not carry the new session")
	}
	// Writing the same content again is not a change.
	if e := localfs.WriteAtomic(c.XSession, raw, true); e != nil {
		t.Fatal(e)
	}
	if code := xRun(c, l, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal(code)
	}
	if v, _ := fake.counts(); v != 4 {
		t.Fatal("unchanged content rebuilt the client", v)
	}
}

// Two concurrent jobs on one account each prove exactly their own exchanges
// and follow their own cursor chains.
func TestXConcurrentJobsOnOneAccountProveTheirOwnExchanges(t *testing.T) {
	c, l, _ := xFixture(t, coordinator.XRequest{Operation: "search", Query: "bitcoin", Count: 20, Pages: 2})
	c.LocalAccountID = "shared"
	c2, l2, _ := xFixture(t, coordinator.XRequest{Operation: "search", Query: "ethereum", Count: 20, Pages: 2})
	c2.XSession, c2.LocalAccountID = c.XSession, c.LocalAccountID
	l2.VerifierToken = strings.Repeat("cd", 32)
	clients := NewXClients()
	clients.log = io.Discard
	clients.minGap = 10 * time.Millisecond
	t.Cleanup(clients.Stop)
	fake := &xFakeX{}
	searchProof := func(tag string) (http.RoundTripper, *[]string) {
		var seen []string
		var mu sync.Mutex
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			v, _ := uniqueJSON([]byte(r.URL.Query().Get("variables")))
			vars := v.(map[string]any)
			cursor, _ := vars["cursor"].(string)
			mu.Lock()
			seen = append(seen, vars["rawQuery"].(string)+"/"+cursor)
			n := len(seen)
			mu.Unlock()
			if cursor != "" && !strings.HasPrefix(cursor, tag) {
				return nil, errors.New("cursor from another job")
			}
			body := `{"data":{"search_by_raw_query":{"search_timeline":{"timeline":{"instructions":[{"type":"TimelineAddEntries","entries":[{"entryId":"cursor-bottom-1","content":{"entryType":"TimelineTimelineCursor","cursorType":"Bottom","value":"` + tag + `-` + string(rune('0'+n)) + `"}}]}]}}}}}`
			return xResponse(r, 200, body), nil
		}), &seen
	}
	proofA, seenA := searchProof("A")
	proofB, seenB := searchProof("B")
	var wg sync.WaitGroup
	codes := make([]string, 2)
	wg.Add(2)
	go func() { defer wg.Done(); codes[0] = xRun(c, l, clients, fake, proofA) }()
	go func() { defer wg.Done(); codes[1] = xRun(c2, l2, clients, fake, proofB) }()
	wg.Wait()
	if codes[0] != "" || codes[1] != "" {
		t.Fatal("concurrent jobs failed", codes)
	}
	if len(*seenA) != 2 || len(*seenB) != 2 || (*seenA)[0] != "bitcoin/" || (*seenA)[1] != "bitcoin/A-1" || (*seenB)[0] != "ethereum/" || (*seenB)[1] != "ethereum/B-1" {
		t.Fatalf("exchanges crossed between jobs: A %v, B %v", *seenA, *seenB)
	}
	if v, b := fake.counts(); v != 2 || b != 2 {
		t.Fatal("concurrent first jobs built more than one client", v, b)
	}
}

// A background refresh rebuilds only the transaction-ID material: the job in
// flight is neither blocked nor rebound, the validation reads are not
// repeated, and the next job uses the new client with no unproven request.
func TestXRefreshNeitherBlocksNorRebindsInFlightJob(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	if code := xRun(c, l, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal("warm-up failed", code)
	}
	account := clients.account(c, c.LocalAccountID, c.XSession, nil)
	old := account.current
	held := &xProfileProof{hold: make(chan struct{}), entered: make(chan struct{})}
	result := make(chan string, 1)
	go func() { result <- xRun(c, l, clients, fake, held) }()
	<-held.entered // job A is inside its proof, holding the old client
	if e := account.refreshNow(); e != nil {
		t.Fatal("refresh failed", e)
	}
	// The timer's refresh asks X once whether the session still holds: one
	// Viewer read, while UserByRestId is answered from the last validated build.
	if v, b := fake.counts(); v != 3 || fake.viewer.Load() != 2 || b != 4 {
		t.Fatalf("refresh made %d validation reads (%d Viewer) and %d bootstrap fetches in total, want 3 (2) and 4", v, fake.viewer.Load(), b)
	}
	if account.generation() != 2 || account.current == old || account.current.client.TransactionInitErr() != nil {
		t.Fatal("refresh did not swap in a fresh client with transaction material")
	}
	select {
	case code := <-result:
		t.Fatal("job finished while its proof was held", code)
	default:
	}
	close(held.hold)
	if code := <-result; code != "" || held.proofs.Load() != 1 {
		t.Fatal("in-flight job disturbed by the refresh", code)
	}
	next := &xProfileProof{}
	if code := xRun(c, l, clients, fake, next); code != "" || next.proofs.Load() != 1 {
		t.Fatal("job after refresh failed", code)
	}
	if v, b := fake.counts(); v != 3 || b != 4 || account.generation() != 2 {
		t.Fatal("job after refresh made unproven requests", v, b)
	}
	// A refresh that would lose the transaction material keeps the current client.
	fake.brokenHome.Store(true)
	if e := account.refreshNow(); e == nil || account.generation() != 2 {
		t.Fatal("refresh without transaction material replaced a working client", e)
	}
	// A refresh that finds the session file gone drops the client and stops.
	if e := os.Rename(c.XSession, c.XSession+".away"); e != nil {
		t.Fatal(e)
	}
	if e := account.refreshNow(); !errors.Is(e, errXSession) || account.generation() != 0 {
		t.Fatal("refresh kept a client for a missing session", e, account.generation())
	}
	if e := account.refreshNow(); e != nil {
		t.Fatal("refresh without a client did something", e)
	}
	if e := os.Rename(c.XSession+".away", c.XSession); e != nil {
		t.Fatal(e)
	}
	// A client dropped while its refresh runs is not replaced by the
	// refreshed one, whose validation was only replayed.
	slow := &xFakeX{}
	slowClients := NewXClients()
	slowClients.log = io.Discard
	slowClients.minGap = time.Millisecond
	t.Cleanup(slowClients.Stop)
	hold := make(chan struct{})
	var holding atomic.Bool
	gate := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "abs.twimg.com" && holding.Load() {
			<-hold
		}
		return slow.RoundTrip(r)
	})
	if code := (X{Config: c, Base: gate, Proof: &xProfileProof{}, Clients: slowClients}).Run(context.Background(), l); code != "" {
		t.Fatal(code)
	}
	gated := slowClients.account(c, c.LocalAccountID, c.XSession, nil)
	holding.Store(true)
	refreshed := make(chan error, 1)
	go func() { refreshed <- gated.refreshNow() }()
	for {
		gated.mu.Lock()
		building := gated.build != nil
		gated.mu.Unlock()
		if building {
			break
		}
		time.Sleep(time.Millisecond)
	}
	gated.drop(gated.current)
	close(hold)
	if e := <-refreshed; !errors.Is(e, errXDropped) || gated.generation() != 0 {
		t.Fatal("refresh replaced a dropped client", e, gated.generation())
	}
	// The next job rebuilds with a real validation.
	if code := (X{Config: c, Base: gate, Proof: &xProfileProof{}, Clients: slowClients}).Run(context.Background(), l); code != "" {
		t.Fatal(code)
	}
	if v, _ := slow.counts(); v != 5 || slow.viewer.Load() != 3 {
		t.Fatal("rebuild after a dropped refresh did not validate", v)
	}
	// The timer drives the same refresh.
	fake.brokenHome.Store(false)
	c.XRefresh = 30 * time.Millisecond
	timed := NewXClients()
	timed.log = io.Discard
	t.Cleanup(timed.Stop)
	tickFake := &xFakeX{}
	if code := xRun(c, l, timed, tickFake, &xProfileProof{}); code != "" {
		t.Fatal(code)
	}
	ticking := timed.account(c, c.LocalAccountID, c.XSession, nil)
	deadline := time.Now().Add(5 * time.Second)
	for ticking.generation() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	// Each timer refresh makes its one Viewer read and never repeats UserByRestId.
	refreshes := ticking.generation()
	timed.Stop()
	if v, _ := tickFake.counts(); refreshes < 3 || tickFake.viewer.Load() < 3 || v-tickFake.viewer.Load() != 1 {
		t.Fatal("timer refresh did not run, did not ask X, or repeated the profile read", refreshes, v, tickFake.viewer.Load())
	}
}

// A lease pinning a query ID the warm client was not built with is refused
// before any proof is spent; the job rebuilds once with the override (no
// validation reads) and completes. Later leases with that ID need nothing.
func TestXLeaseQueryIDOverrideRebuildsOnceWithoutRevalidation(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	if code := xRun(c, l, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal("warm-up failed", code)
	}
	var plan xPlan
	if e := json.Unmarshal(l.XPayload, &plan); e != nil {
		t.Fatal(e)
	}
	plan.Exchanges[0].QueryID = "rotated-query-id"
	l.XPayload, _ = json.Marshal(plan)
	proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.Contains(r.URL.Path, "/rotated-query-id/UserByScreenName") {
			return nil, errors.New("wrong query id proven")
		}
		return xBootstrap(r)
	})
	if code := xRun(c, l, clients, fake, proof); code != "" {
		t.Fatal("job with a rotated query ID failed", code)
	}
	account := clients.account(c, c.LocalAccountID, c.XSession, nil)
	if v, b := fake.counts(); v != 2 || b != 4 || account.generation() != 2 {
		t.Fatalf("override rebuild: %d validation reads, %d bootstrap fetches, generation %d; want 2, 4, 2", v, b, account.generation())
	}
	if code := xRun(c, l, clients, fake, proof); code != "" {
		t.Fatal(code)
	}
	if v, b := fake.counts(); v != 2 || b != 4 || account.generation() != 2 {
		t.Fatal("second job with the override rebuilt again", v, b)
	}
}

// Warm builds each account once at start and the job path finds it ready; a
// failed warm-up is reported without secrets and leaves the account to the
// job path.
func TestXWarmBuildsAccountsAtStart(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	var log strings.Builder
	clients.log = &log
	// Warm itself uses the default transport; the entries are created first so
	// the fixture stands in for X. One account's session file is missing.
	missing := c.XSession + ".missing"
	clients.account(c, "main", c.XSession, fake)
	clients.account(c, "spare", missing, fake)
	clients.Warm(context.Background(), c, []XAccount{{"main", c.XSession}, {"spare", missing}})
	if v, b := fake.counts(); v != 2 || b != 2 {
		t.Fatal("warm-up requests", v, b)
	}
	out := log.String()
	if !strings.Contains(out, "x client ready for account main") || !strings.Contains(out, "warm-up failed for account spare: auth_required") || strings.Contains(out, "synthetic") || strings.Contains(out, c.XSession) {
		t.Fatalf("warm-up log: %q", out)
	}
	proof := &xProfileProof{}
	if code := xRun(c, l, clients, fake, proof); code != "" || proof.proofs.Load() != 1 {
		t.Fatal("first job after warm-up failed", code)
	}
	if v, b := fake.counts(); v != 2 || b != 2 {
		t.Fatal("first job after warm-up made unproven requests", v, b)
	}
}

// A transport failure while building the client is not X refusing the
// session: it reports x_request_failed, not auth_required, so the account is
// not parked until its session file changes.
func TestXBuildTransportFailureIsNotAnAuthFailure(t *testing.T) {
	c, l, clients, _ := xWarmFixture(t, "fixture")
	unreachable := roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, errors.New("synthetic dial failure") })
	if code := (X{Config: c, Base: unreachable, Proof: &xProfileProof{}, Clients: clients}).Run(context.Background(), l); code != "x_request_failed" {
		t.Fatal("unreachable X during construction classified as", code)
	}
	// X answering 401 to the validation read is an auth failure.
	refused := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/i/api/graphql/") {
			return xResponse(r, 401, `{"errors":[{"code":32,"message":"Could not authenticate you"}]}`), nil
		}
		return xResponse(r, 404, ""), nil
	})
	other := NewXClients()
	other.log = io.Discard
	other.minGap = time.Millisecond
	t.Cleanup(other.Stop)
	if code := (X{Config: c, Base: refused, Proof: &xProfileProof{}, Clients: other}).Run(context.Background(), l); code != "auth_required" {
		t.Fatal("refused session classified as", code)
	}
}

// Measurement: unproven requests and wall time per job, cold (a client per
// job, as before) against warm (one client per account). Fixture latencies
// are synthetic; the counts are the primary result.
func TestXWarmClientMeasurement(t *testing.T) {
	if testing.Short() {
		t.Skip("measurement")
	}
	c, l, _, _ := xWarmFixture(t, "fixture")
	const jobs = 3
	run := func(name string, pause time.Duration, clientsFor func(i int) *XClients) {
		fake := &xFakeX{}
		var totalV, totalB int32
		var total time.Duration
		for i := 0; i < jobs; i++ {
			if i > 0 {
				time.Sleep(pause)
			}
			v0, b0 := fake.counts()
			started := time.Now()
			if code := xRun(c, l, clientsFor(i), fake, &xProfileProof{}); code != "" {
				t.Fatal(name, "job failed", code)
			}
			took := time.Since(started)
			v1, b1 := fake.counts()
			t.Logf("%s job %d: %d unproven reads, %d bootstrap fetches, %d proof, %.2fs", name, i+1, v1-v0, b1-b0, 1, took.Seconds())
			totalV, totalB, total = totalV+v1-v0, totalB+b1-b0, total+took
			if i > 0 && clientsFor(i) == clientsFor(i-1) && (v1 != v0 || b1 != b0) {
				t.Fatal("warm job made unproven requests")
			}
		}
		t.Logf("%s total over %d jobs: %d unproven reads, %d bootstrap fetches, %.2fs (%.2fs/job)", name, jobs, totalV, totalB, total.Seconds(), total.Seconds()/jobs)
	}
	run("cold", 0, func(int) *XClients { cl := NewXClients(); cl.log = io.Discard; t.Cleanup(cl.Stop); return cl })
	warm := NewXClients()
	warm.log = io.Discard
	t.Cleanup(warm.Stop)
	run("warm back-to-back", 0, func(int) *XClients { return warm })
	// Production jobs arrive at least a heartbeat apart, past the 1 s gap.
	spaced := NewXClients()
	spaced.log = io.Discard
	t.Cleanup(spaced.Stop)
	run("warm spaced", 1100*time.Millisecond, func(int) *XClients { return spaced })
}

// The per-account cache never holds a session path or value in its log lines.
func TestXClientLogLinesCarryNoSecrets(t *testing.T) {
	c, _, clients, fake := xWarmFixture(t, "fixture")
	var log strings.Builder
	clients.log = &log
	a := clients.account(c, "acct", c.XSession, fake)
	if _, e := a.acquire(context.Background(), nil, false); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(c.XSession)
	if e := localfs.WriteAtomic(c.XSession, []byte(`{"auth_token":"second-secret","ct0":"second-csrf"}`), true); e != nil {
		t.Fatal(e)
	}
	if _, e := a.acquire(context.Background(), nil, false); e != nil {
		t.Fatal(e)
	}
	a.drop(a.current)
	a.mu.Lock()
	b := a.build
	a.mu.Unlock()
	if b != nil {
		<-b.done
	}
	out := log.String()
	for _, secret := range []string{"synthetic-auth", "synthetic-csrf", "second-secret", "second-csrf", c.XSession, string(raw)} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret in log: %q", out)
		}
	}
	if !strings.Contains(out, "changed; rebuilding") || !strings.Contains(out, "dropped after an authentication failure") {
		t.Fatalf("log: %q", out)
	}
}
