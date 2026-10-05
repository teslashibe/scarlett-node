package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

// keeperX stands in for X behind the warm-client cache: it answers the two
// session-validation reads and counts every request by the auth cookie it
// carried. Nothing here reaches a network. The bootstrap pages answer 404, so
// clients are built without transaction-ID material, which these tests do not
// need.
type keeperX struct {
	mu      sync.Mutex
	byToken map[string]int
	refuse  atomic.Bool
	// missing makes the Viewer read answer 404, as a rotated query ID does.
	missing atomic.Bool
}

func (k *keeperX) RoundTrip(r *http.Request) (*http.Response, error) {
	token := ""
	if c, e := r.Cookie("auth_token"); e == nil {
		token = c.Value
	}
	k.mu.Lock()
	if k.byToken == nil {
		k.byToken = map[string]int{}
	}
	k.byToken[token]++
	k.mu.Unlock()
	answer := func(status int, body string) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: r}, nil
	}
	switch {
	case !strings.Contains(r.URL.Path, "/i/api/graphql/"):
		return answer(404, "")
	case k.refuse.Load():
		return answer(401, `{"errors":[{"code":32,"message":"Could not authenticate you"}]}`)
	case strings.HasSuffix(r.URL.Path, "/Viewer") && k.missing.Load():
		return answer(404, "")
	case strings.HasSuffix(r.URL.Path, "/Viewer"):
		return answer(200, `{"data":{"viewer":{"user_results":{"result":{"rest_id":"12"}}}}}`)
	}
	return answer(200, `{"data":{"user":{"result":{"__typename":"User","rest_id":"12","legacy":{"screen_name":"fixture"}}}}}`)
}

func (k *keeperX) requests(token string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.byToken[token]
}

func keeperFixture(t *testing.T, p *servicePool, x http.RoundTripper) *worker.XClients {
	t.Helper()
	clients := worker.NewXClients()
	clients.Base = x
	clients.Observe(p.xValidated)
	stop := startXKeeper(context.Background(), p.config, clients, p, 10*time.Millisecond)
	t.Cleanup(func() { stop(); clients.Stop() })
	return clients
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for", what)
		}
	}
}

// A validated build's outcome moves the account exactly as a job's would, but
// success only promotes configured to ready and in-flight counts stay put.
func TestXValidatedAppliesBuildOutcomesToThePool(t *testing.T) {
	p := poolFixture(t, "codex", "x_read")
	session := p.config.XSession
	if s := healthKind(t, p, "x_read"); s.State != "configured" {
		t.Fatal("fixture state", s.State)
	}
	if !p.acquire("x_read") {
		t.Fatal("fixture account unavailable")
	}
	p.xValidated(session+".other", worker.XSessionStamp(session+".other"), "auth_required")
	if s := healthKind(t, p, "x_read"); s.State != "configured" {
		t.Fatal("outcome for an unknown session path applied", s.State)
	}
	p.xValidated(session, worker.XSessionStamp(session), "")
	if s := healthKind(t, p, "x_read"); s.State != "ready" || s.InFlight != 1 || s.LastErrorCode != "" {
		t.Fatalf("validated session: %+v", s)
	}
	p.finish("x_read", "")
	p.xValidated(session, worker.XSessionStamp(session), "x_request_failed")
	if s := healthKind(t, p, "x_read"); s.State != "unreachable" || s.LastErrorCode != "x_request_failed" || s.Capacity != 0 {
		t.Fatalf("unreachable X at build: %+v", s)
	}
	// A validation does not end a rest early.
	p.xValidated(session, worker.XSessionStamp(session), "")
	if s := healthKind(t, p, "x_read"); s.State != "unreachable" {
		t.Fatal("validation ended a rest", s.State)
	}
	p.mu.Lock()
	rest := time.Until(p.entries["x_read"].restUntil)
	p.mu.Unlock()
	if rest <= 0 || rest > capacityRest {
		t.Fatal("transport failure rest", rest)
	}

	limited := poolFixture(t, "x_read")
	limited.xValidated(limited.config.XSession, worker.XSessionStamp(limited.config.XSession), "x_rate_limited")
	limited.mu.Lock()
	rest = time.Until(limited.entries["x_read"].restUntil)
	limited.mu.Unlock()
	if s := healthKind(t, limited, "x_read"); s.State != "exhausted" || rest < 14*time.Minute {
		t.Fatalf("rate-limited build: %+v, rest %v", s, rest)
	}

	refused := poolFixture(t, "x_read")
	refused.xValidated(refused.config.XSession, worker.XSessionStamp(refused.config.XSession), "auth_required")
	if s := healthKind(t, refused, "x_read"); s.State != "auth_required" || s.Capacity != 0 {
		t.Fatalf("refused session: %+v", s)
	}
	if refused.acquire("x_read") {
		t.Fatal("refused session still leasable")
	}
	// Success never clears an authentication failure; only a new file does.
	refused.xValidated(refused.config.XSession, worker.XSessionStamp(refused.config.XSession), "")
	if s := healthKind(t, refused, "x_read"); s.State != "auth_required" {
		t.Fatal("validation cleared an authentication failure", s.State)
	}
	// The failure survives a restart, as a job's does.
	if s := healthKind(t, newServicePool(refused.config), "x_read"); s.State != "auth_required" {
		t.Fatal("refused session not persisted", s.State)
	}

	// Managed accounts are found by their session path.
	m := multiPool(t)
	accounts := m.xAccounts()
	m.xValidated(accounts[1].Path, worker.XSessionStamp(accounts[1].Path), "")
	states := map[string]string{}
	for _, a := range m.accountStatus() {
		states[a.Service+":"+a.ID] = a.State
	}
	if states["x_read:two"] != "ready" || states["x_read:one"] != "configured" || states["codex:two"] != "configured" {
		t.Fatalf("managed validation: %v", states)
	}
}

// The paths handed to Retain cover every X session the pool still holds,
// including a removed account that is still draining a job.
func TestXSessionPathsIncludeDrainingAccounts(t *testing.T) {
	m := multiPool(t)
	accounts := m.xAccounts()
	lease, ok := m.acquireAccount("x_read")
	if !ok {
		t.Fatal("no account")
	}
	f, e := loadAccounts(m.config.AccountsFile)
	if e != nil {
		t.Fatal(e)
	}
	kept := f.Accounts[:0]
	for _, a := range f.Accounts {
		if a.Service != "x_read" {
			kept = append(kept, a)
		}
	}
	f.Accounts = kept
	saveAccountFixture(t, m, f)
	paths := m.xSessionPaths()
	if len(paths) != 1 || !paths[lease.config.XSession] {
		t.Fatalf("draining account's session not retained: %v", paths)
	}
	if len(m.xAccounts()) != 0 {
		t.Fatal("removed accounts still offered for warming")
	}
	m.finishAccount(lease, "")
	if paths := m.xSessionPaths(); len(paths) != 0 {
		t.Fatalf("drained accounts still retained: %v (had %v)", paths, accounts)
	}
}

// The keeper warms the account at start and reports it ready without a job;
// a session X refuses is reported auth_required and not asked about again.
func TestXKeeperReportsValidatedReadiness(t *testing.T) {
	p := poolFixture(t, "x_read")
	x := &keeperX{}
	keeperFixture(t, p, x)
	eventually(t, "x_read to become ready", func() bool { return healthKind(t, p, "x_read").State == "ready" })

	refused := poolFixture(t, "x_read")
	bad := &keeperX{}
	bad.refuse.Store(true)
	keeperFixture(t, refused, bad)
	eventually(t, "x_read to report auth_required", func() bool { return healthKind(t, refused, "x_read").State == "auth_required" })
	asked := bad.requests("synthetic-auth")
	time.Sleep(100 * time.Millisecond)
	if again := bad.requests("synthetic-auth"); again != asked || asked != 1 {
		t.Fatal("refused session was asked about again", asked, again)
	}
}

// The keeper builds a client for an account that becomes usable after start,
// in the background, and evicts the client of an account that is removed.
func TestXKeeperWarmsLateAccountsAndEvictsRemovedOnes(t *testing.T) {
	m := multiPool(t)
	m.config.XRefresh = 40 * time.Millisecond
	accounts := m.xAccounts()
	// Account two starts without a usable session.
	writePrivateFixture(accounts[1].Path, []byte(`{}`), 0600)
	x := &keeperX{}
	keeperFixture(t, m, x)
	state := func(id string) string {
		for _, a := range m.accountStatus() {
			if a.Service == "x_read" && a.ID == id {
				return a.State
			}
		}
		return ""
	}
	eventually(t, "account one to become ready", func() bool { return state("one") == "ready" })
	if state("two") != "auth_required" || x.requests("late-auth") != 0 {
		t.Fatal("account without a session was built", state("two"))
	}
	writePrivateFixture(accounts[1].Path, []byte(`{"auth_token":"late-auth","ct0":"late-csrf"}`), 0600)
	eventually(t, "the late account to become ready without a job", func() bool { return state("two") == "ready" })

	// Remove account two: its refresh stops; account one's goes on.
	f, e := loadAccounts(m.config.AccountsFile)
	if e != nil {
		t.Fatal(e)
	}
	kept := f.Accounts[:0]
	for _, a := range f.Accounts {
		if a.Service != "x_read" || a.ID != "two" {
			kept = append(kept, a)
		}
	}
	f.Accounts = kept
	saveAccountFixture(t, m, f)
	eventually(t, "the removed account to leave the pool", func() bool { return state("two") == "" })
	time.Sleep(100 * time.Millisecond) // a keeper tick, and any refresh already running
	gone, live := x.requests("late-auth"), x.requests("synthetic-private-auth")
	eventually(t, "the kept account to keep refreshing", func() bool { return x.requests("synthetic-private-auth") >= live+4 })
	if after := x.requests("late-auth"); after != gone {
		t.Fatal("removed account is still refreshed against X", gone, after)
	}
}

// Stopping the keeper waits for a check that is under way, so nothing can
// reach the cache after the caller goes on to stop it.
func TestXKeeperStopWaitsForTheKeeper(t *testing.T) {
	p := poolFixture(t, "x_read")
	clients := worker.NewXClients()
	clients.Base = &keeperX{}
	t.Cleanup(clients.Stop)
	// The keeper's first pool call waits here.
	p.mu.Lock()
	stop := startXKeeper(context.Background(), p.config, clients, p, 10*time.Millisecond)
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
		p.mu.Unlock()
		t.Fatal("stop returned while the keeper was still inside a pool call")
	case <-time.After(100 * time.Millisecond):
	}
	p.mu.Unlock()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("stop never returned")
	}
}

// A build whose validation X answers with not-found rests the account like an
// unreachable X; it is not parked as refused until its session file changes.
func TestXKeeperDoesNotParkAnAccountOnANotFoundValidation(t *testing.T) {
	p := poolFixture(t, "x_read")
	x := &keeperX{}
	x.missing.Store(true)
	keeperFixture(t, p, x)
	eventually(t, "the failed build to be reported", func() bool { return healthKind(t, p, "x_read").State != "configured" })
	if s := healthKind(t, p, "x_read"); s.State != "unreachable" || s.LastErrorCode != "x_request_failed" {
		t.Fatalf("not-found validation: %+v", s)
	}
	if s := healthKind(t, newServicePool(p.config), "x_read"); s.State == "auth_required" {
		t.Fatal("not-found validation persisted as a refused session")
	}
}

// An account whose validated client is still installed is reported ready again
// once a rest ends or its session file is rewritten with the same content,
// without another request to X.
func TestXKeeperConfirmsAWarmAccountAfterARest(t *testing.T) {
	p := poolFixture(t, "x_read")
	x := &keeperX{}
	keeperFixture(t, p, x)
	ready := func() bool { return healthKind(t, p, "x_read").State == "ready" }
	eventually(t, "x_read to become ready", ready)
	asked := x.requests("synthetic-auth")
	later := time.Now().Add(time.Hour)
	if e := os.Chtimes(p.config.XSession, later, later); e != nil {
		t.Fatal(e)
	}
	eventually(t, "the touched account to be ready again", ready)
	p.mu.Lock()
	s := p.entries["x_read"]
	s.state, s.lastError, s.restUntil = "unreachable", "x_request_failed", time.Now().Add(-time.Second)
	p.mu.Unlock()
	eventually(t, "the rested account to be ready again", ready)
	if again := x.requests("synthetic-auth"); again != asked {
		t.Fatal("confirming a warm account asked X again", asked, again)
	}
}

// The observer can finish its provider work before a login but wait for the
// pool lock until after the session's atomic replacement. Neither an old
// refusal nor an old success is evidence about the new session.
func TestXValidatedFencesSessionReplacementUnderPoolLock(t *testing.T) {
	for _, test := range []struct {
		name            string
		refused, cached bool
	}{{"refused build", true, false}, {"successful build", false, false}, {"cached Ensure", false, true}} {
		t.Run(test.name, func(t *testing.T) {
			p := poolFixture(t, "x_read")
			_ = p.health()
			clients := worker.NewXClients()
			defer clients.Stop()
			fake := &keeperX{}
			fake.refuse.Store(test.refused)
			clients.Base = fake
			accounts := []worker.XAccount{{ID: "legacy", Path: p.config.XSession}}
			if test.cached {
				clients.Warm(context.Background(), p.config, accounts)
			}
			arrived := make(chan struct{})
			clients.Observe(func(path, stamp, code string) {
				close(arrived)
				p.xValidated(path, stamp, code)
			})
			p.mu.Lock()
			done := make(chan struct{})
			go func() {
				defer close(done)
				if test.cached {
					clients.Ensure(p.config, accounts)
				} else {
					clients.Warm(context.Background(), p.config, accounts)
				}
			}()
			select {
			case <-arrived:
			case <-time.After(5 * time.Second):
				p.mu.Unlock()
				t.Fatal("offline validation did not reach the observer")
			}
			err := localfs.WriteAtomic(p.config.XSession, []byte(`{"auth_token":"new-verified-synthetic-session","ct0":"new-synthetic-csrf"}`), true)
			p.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("observer did not finish")
			}
			if h := healthKind(t, p, "x_read"); h.State != "configured" || h.LastErrorCode != "" {
				t.Fatalf("old validation changed the newly replaced session: %+v", h)
			}
		})
	}
}

// The cache retains the warm pointer while the pool rests an account. Its
// autonomous timer must also consult that pool, not merely the keeper's list.
func TestXRefreshRespectsPoolCooldownAndResumes(t *testing.T) {
	p := poolFixture(t, "x_read")
	p.config.XRefresh = 40 * time.Millisecond
	clients := worker.NewXClients()
	defer clients.Stop()
	fake := &keeperX{}
	clients.Base = fake
	clients.Observe(p.xValidated)
	var blocked atomic.Int32
	clients.RefreshAdmission(func(path string) bool {
		admitted := p.xRefreshAllowed(path)
		if !admitted {
			blocked.Add(1)
		}
		return admitted
	})
	// Hold pool admission closed during initial warm-up, then prove several
	// actual timer ticks are denied while the retained client remains idle.
	p.mu.Lock()
	p.refresh(time.Now())
	a := p.accounts["x_read:legacy"]
	a.entry.state, a.entry.lastError = "exhausted", "x_rate_limited"
	a.entry.restUntil = time.Now().Add(time.Hour)
	p.mu.Unlock()
	clients.Warm(context.Background(), p.config, []worker.XAccount{{ID: "legacy", Path: p.config.XSession}})
	if len(p.xAccounts()) != 0 {
		t.Fatal("resting account remained eligible for warm-up")
	}
	before := fake.requests("synthetic-auth")
	if before == 0 {
		t.Fatal("fixture did not build a warm client")
	}
	eventually(t, "autonomous refresh admission during cooldown", func() bool { return blocked.Load() >= 3 })
	if after := fake.requests("synthetic-auth"); after != before {
		t.Fatalf("cooldown admitted background requests: %d -> %d", before, after)
	}
	p.mu.Lock()
	a.entry.restUntil = time.Now().Add(-time.Second)
	p.mu.Unlock()
	eventually(t, "background refresh after cooldown", func() bool { return fake.requests("synthetic-auth") > before })
}
