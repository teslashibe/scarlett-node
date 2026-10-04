package main

import (
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/worker"
)

// fakeX stands in for x.com during x-go client construction. It answers the
// session validation reads for any account, can hold the Viewer read until
// released, and can refuse it with a chosen status. Nothing here reaches the
// network.
type fakeX struct {
	mu       sync.Mutex
	hold     chan struct{}
	viewer   map[string]int // status for Viewer by auth token; default 200
	requests atomic.Int32
}

func (f *fakeX) RoundTrip(r *http.Request) (*http.Response, error) {
	f.requests.Add(1)
	resp := func(status int, body string) *http.Response {
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}
	}
	if !strings.Contains(r.URL.Path, "/i/api/graphql/") {
		return resp(404, ""), nil
	}
	if strings.HasSuffix(r.URL.Path, "/Viewer") {
		f.mu.Lock()
		hold := f.hold
		status := 200
		for token, s := range f.viewer {
			if strings.Contains(r.Header.Get("Cookie"), "auth_token="+token) {
				status = s
			}
		}
		f.mu.Unlock()
		if hold != nil {
			<-hold
		}
		switch status {
		case 200:
			return resp(200, `{"data":{"viewer":{"user_results":{"result":{"rest_id":"12"}}}}}`), nil
		case 401:
			return resp(401, `{"errors":[{"code":32,"message":"Could not authenticate you"}]}`), nil
		default:
			return resp(status, ""), nil
		}
	}
	return resp(200, `{"data":{"user":{"result":{"__typename":"User","rest_id":"12","legacy":{"screen_name":"fixture"}}}}}`), nil
}

func (f *fakeX) refuse(token string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.viewer == nil {
		f.viewer = map[string]int{}
	}
	f.viewer[token] = status
}

// warmPool is a single-account x_read pool whose client constructions go to fx.
func warmPool(t *testing.T, fx *fakeX) *servicePool {
	t.Helper()
	worker.ResetXClientsForTests()
	t.Cleanup(worker.ResetXClientsForTests)
	p := poolFixture(t, "x_read")
	p.xWarm, p.xBase = true, fx
	return p
}

// waitState polls the x_read service health until it reports state, within a
// few seconds; constructions take about a second because of the request gap.
func waitState(t *testing.T, p *servicePool, state string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		h := healthKind(t, p, "x_read")
		if h.State == state {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("x_read stayed %q (%s), want %q", h.State, h.LastErrorCode, state)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// The heartbeat follows the warm client: configured while credentials exist
// and the client is still being built, ready once x-go has validated the
// session and bootstrapped, and still ready while a background refresh
// rebuilds the client behind it.
func TestXHeartbeatReadyOnlyOnceTheClientIsWarm(t *testing.T) {
	fx := &fakeX{hold: make(chan struct{})}
	p := warmPool(t, fx)
	path := p.config.XSession
	if h := healthKind(t, p, "x_read"); h.State != "configured" || h.Capacity != 1 {
		t.Fatalf("before warm-up: %+v", h)
	}
	if !p.accounts["x_read:legacy"].entry.warming || worker.XClientStatus(path, time.Now()).Warm {
		t.Fatal("warm-up not started, or ready without a client")
	}
	// Still building: repeated heartbeats start nothing new and stay configured.
	for i := 0; i < 3; i++ {
		if h := healthKind(t, p, "x_read"); h.State != "configured" {
			t.Fatalf("heartbeat %d during construction: %+v", i, h)
		}
	}
	close(fx.hold)
	waitState(t, p, "ready")
	if !worker.XClientStatus(path, time.Now()).Warm || fx.requests.Load() != 3 {
		t.Fatal("ready without a warm client, or more than one construction", fx.requests.Load())
	}
	// Background refresh: the client is due, the rebuild runs behind a held
	// Viewer, and the heartbeat keeps saying ready the whole time.
	fx.mu.Lock()
	fx.hold = make(chan struct{})
	fx.mu.Unlock()
	if !worker.AgeXClientForTests(path, time.Now().Add(-31*time.Minute), time.Time{}) {
		t.Fatal("no client to age")
	}
	if h := healthKind(t, p, "x_read"); h.State != "ready" {
		t.Fatalf("refresh start flipped state: %+v", h)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !worker.XClientStatus(path, time.Now()).Building {
		if time.Now().After(deadline) {
			t.Fatal("refresh did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		if h := healthKind(t, p, "x_read"); h.State != "ready" || h.Capacity != 1 {
			t.Fatalf("heartbeat %d during refresh: %+v", i, h)
		}
	}
	fx.mu.Lock()
	close(fx.hold)
	fx.hold = nil
	fx.mu.Unlock()
	deadline = time.Now().Add(5 * time.Second)
	for st := worker.XClientStatus(path, time.Now()); st.Building; st = worker.XClientStatus(path, time.Now()) {
		if time.Now().After(deadline) {
			t.Fatal("refresh did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h := healthKind(t, p, "x_read"); h.State != "ready" || !worker.XClientStatus(path, time.Now()).Warm {
		t.Fatalf("after refresh: %+v", h)
	}
	// A disabled keeper leaves the state machine to jobs: configured until one succeeds.
	q := poolFixture(t, "x_read")
	if h := healthKind(t, q, "x_read"); h.State != "configured" || q.accounts["x_read:legacy"].entry.warming {
		t.Fatalf("warm-up ran with SCARLETT_X_WARM off: %+v", h)
	}
}

// A failed warm-up maps through the codes the coordinator already validates.
// A session X refuses is auth_required until the file changes; a transport
// failure is unreachable with the usual rest and retry; and a new session
// file brings the account back to ready without a restart.
func TestXWarmUpFailureUsesTheAccountStateMachine(t *testing.T) {
	fx := &fakeX{}
	fx.refuse("synthetic-auth", 401)
	p := warmPool(t, fx)
	path := p.config.XSession
	waitState(t, p, "auth_required")
	if h := healthKind(t, p, "x_read"); h.LastErrorCode != "auth_required" || h.Capacity != 0 {
		t.Fatalf("refused session: %+v", h)
	}
	if fx.requests.Load() != 1 || worker.XClientStatus(path, time.Now()).Warm {
		t.Fatal("a refused session sent more than Viewer, or kept a client", fx.requests.Load())
	}
	// Repeated heartbeats do not keep knocking on a dead session.
	for i := 0; i < 3; i++ {
		healthKind(t, p, "x_read")
	}
	time.Sleep(50 * time.Millisecond)
	if fx.requests.Load() != 1 {
		t.Fatal("dead session was re-validated without a credential change", fx.requests.Load())
	}
	// Signing in again writes a new session file: configured, then ready.
	if e := writePrivateFixture(path, []byte(`{"auth_token":"renewed-auth","ct0":"renewed-csrf"}`), 0600); e != nil {
		t.Fatal(e)
	}
	waitState(t, p, "ready")
	if h := healthKind(t, p, "x_read"); h.LastErrorCode != "" || h.Capacity != 1 {
		t.Fatalf("renewed session: %+v", h)
	}
	// A transport failure during a first build: unreachable, resting, retried.
	fx.refuse("transient-auth", 503)
	q := warmPool(t, fx)
	if e := writePrivateFixture(q.config.XSession, []byte(`{"auth_token":"transient-auth","ct0":"transient-csrf"}`), 0600); e != nil {
		t.Fatal(e)
	}
	waitState(t, q, "unreachable")
	s := q.accounts["x_read:legacy"].entry
	if h := healthKind(t, q, "x_read"); h.LastErrorCode != "x_request_failed" || h.Capacity != 0 || s.restUntil.IsZero() {
		t.Fatalf("transient warm-up failure: %+v rest %v", h, s.restUntil)
	}
	fx.refuse("transient-auth", 200)
	q.mu.Lock()
	s.restUntil = time.Now().Add(-time.Second)
	q.mu.Unlock()
	waitState(t, q, "ready")
}

// Per account in managed mode: each X account's state follows its own client.
func TestXManagedAccountsWarmIndependently(t *testing.T) {
	fx := &fakeX{}
	fx.refuse("second-auth", 401)
	p := warmPool(t, fx)
	dir := privateTestDir(t)
	p.config.StateDir, p.config.AccountsFile = dir, filepath.Join(dir, "accounts.json")
	p.config.XConcurrency = 2
	p.entries["x_read"].capacity = 2
	f := accountFile{Version: 1}
	for id, token := range map[string]string{"first": "first-auth", "second": "second-auth"} {
		path := filepath.Join(dir, "x_read-"+id)
		writePrivateFixture(path, []byte(`{"auth_token":"`+token+`","ct0":"`+token+`-csrf"}`), 0600)
		f.Accounts = append(f.Accounts, providerAccount{id, "x_read", path, 1})
	}
	saveAccountFixture(t, p, f)
	waitState(t, p, "ready")
	deadline := time.Now().Add(15 * time.Second)
	for {
		states := map[string]string{}
		for _, a := range p.accountStatus() {
			states[a.ID] = a.State + "/" + a.LastError
		}
		if states["first"] == "ready/" && states["second"] == "auth_required/auth_required" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("managed account states", states)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if h := healthKind(t, p, "x_read"); h.State != "ready" || h.Capacity != 1 {
		t.Fatalf("aggregate health with one dead account: %+v", h)
	}
}

// A session that dies while the account is idle is found by the background
// refresh, not by the next buyer's job: the account flips to auth_required
// and stops advertising. An account that proved a read recently is not
// re-validated at all.
func TestXIdleSessionExpiryIsFoundByTheRefresh(t *testing.T) {
	fx := &fakeX{}
	p := warmPool(t, fx)
	path := p.config.XSession
	waitState(t, p, "ready")
	// Recently active: due nothing, sends nothing.
	before := fx.requests.Load()
	fx.refuse("synthetic-auth", 401)
	worker.AgeXClientForTests(path, time.Now().Add(-31*time.Minute), time.Now().Add(-time.Minute))
	for i := 0; i < 3; i++ {
		if h := healthKind(t, p, "x_read"); h.State != "ready" {
			t.Fatalf("recently active account re-validated: %+v", h)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if fx.requests.Load() != before || !worker.XClientStatus(path, time.Now()).Warm {
		t.Fatal("recently active account was checked", fx.requests.Load()-before)
	}
	// Idle past the interval with a dead session: one Viewer read, then
	// auth_required with no client left.
	worker.AgeXClientForTests(path, time.Now().Add(-31*time.Minute), time.Time{})
	waitState(t, p, "auth_required")
	if fx.requests.Load() != before+1 || worker.XClientStatus(path, time.Now()).Warm {
		t.Fatal("idle expiry check", fx.requests.Load()-before, worker.XClientStatus(path, time.Now()))
	}
	if h := healthKind(t, p, "x_read"); h.Capacity != 0 || h.LastErrorCode != "auth_required" {
		t.Fatalf("dead session still advertised: %+v", h)
	}
}
