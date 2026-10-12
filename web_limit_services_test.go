package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

// limitTestHost is a host whose load the test sets.
type limitTestHost struct {
	mu   sync.Mutex
	load worker.HostLoad
}

func (h *limitTestHost) Sample(time.Time) worker.HostLoad {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.load
}

func (h *limitTestHost) set(load worker.HostLoad) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.load = load
}

// limitTestClock is the limiter's clock in these tests.
type limitTestClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *limitTestClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *limitTestClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

// autoWebPool is a pool with SCARLETT_WEB_CONCURRENCY=auto whose limiter
// starts at start and reads a test host and clock, with its availability
// signal.
func autoWebPool(t *testing.T, start int, selected ...string) (*servicePool, *limitTestHost, chan struct{}, *limitTestClock) {
	t.Helper()
	worker.ResetRelayHaltForTests()
	t.Cleanup(worker.ResetRelayHaltForTests)
	c := poolFixture(t, selected...).config
	c.WebConcurrencyAuto, c.WebConcurrency = true, config.WebAutoMax
	p := newServicePool(c)
	if p.webLimit == nil || p.webLimit.Limit() != config.WebAutoStart {
		t.Fatal("auto pool without its limiter")
	}
	host, clock := &limitTestHost{}, &limitTestClock{at: time.Now()}
	p.webLimit = worker.NewWebLimiter(worker.WebLimitOptions{Min: config.WebAutoMin, Start: start, Max: config.WebAutoMax, Host: host, Now: clock.now, OnChange: p.webLimitChanged})
	changes := make(chan struct{}, 1)
	p.availabilityChanges = changes
	return p, host, changes, clock
}

// runWebPage runs one page through the pool as the worker would: admitted,
// one proven relay hop of wall, finished.
func runWebPage(t *testing.T, p *servicePool, wall time.Duration) {
	t.Helper()
	lease, ok := p.acquireAccount("web")
	if !ok {
		t.Fatal("web slot refused")
	}
	lease.config.WebObserver.Hop("", wall, false)
	lease.config.WebObserver.Done("", false)
	p.finishAccount(lease, "")
}

// webWire applies the coordinator's checks on a web report: in_flight within
// capacity, capacity at most 32, and a browser inside both.
func webWire(t *testing.T, p *servicePool) coordinator.ServiceHealth {
	t.Helper()
	h := healthKind(t, p, "web")
	if h.InFlight < 0 || h.InFlight > h.Capacity || h.Capacity > 32 {
		t.Fatalf("web report the coordinator refuses: %+v", h)
	}
	if b := h.Browser; b != nil && (b.Capacity > h.Capacity || b.InFlight > b.Capacity) {
		t.Fatalf("browser outside web: %+v in %+v", b, h)
	}
	return h
}

func signalled(changes chan struct{}) bool {
	select {
	case <-changes:
		return true
	default:
		return false
	}
}

func TestWebAutoLimitStartsAtFourUnderItsCeiling(t *testing.T) {
	p, _, _, _ := autoWebPool(t, config.WebAutoStart, "web")
	if h := webWire(t, p); h.State != "configured" || h.Capacity != 4 || h.InFlight != 0 {
		t.Fatalf("auto web entry %+v", h)
	}
	// The heartbeat loop's slots cover the ceiling the limit may reach.
	if p.capacity() != config.WebAutoMax {
		t.Fatal("static ceiling", p.capacity())
	}
	leases := []*accountLease{}
	for i := 0; i < 4; i++ {
		lease, ok := p.acquireAccount("web")
		if !ok || lease.config.WebObserver == nil {
			t.Fatal("auto web lease", i, ok)
		}
		leases = append(leases, lease)
	}
	if p.acquire("web") {
		t.Fatal("web ran past its adaptive limit")
	}
	for _, lease := range leases {
		p.finishAccount(lease, "")
	}
	if s := p.webLimitStatus(); s == nil || *s != (webLimitStatus{Mode: "auto", Limit: 4, Reason: worker.WebLimitStart}) {
		t.Fatalf("status %+v", s)
	}
}

// Twenty healthy pages with at least half the limit running raise it by one;
// the pool admits the new count at once, health advertises it and the
// heartbeat loop is told.
func TestWebAutoLimitGrowsLiveAndIsAdvertised(t *testing.T) {
	p, _, changes, clock := autoWebPool(t, config.WebAutoStart, "web")
	before := serviceStates(p.health())
	held, ok := p.acquireAccount("web")
	if !ok {
		t.Fatal("web refused")
	}
	for i := 0; i < 19; i++ {
		runWebPage(t, p, 1500*time.Millisecond)
	}
	if signalled(changes) || webWire(t, p).Capacity != 4 {
		t.Fatal("changed before twenty pages")
	}
	runWebPage(t, p, 1500*time.Millisecond)
	if !signalled(changes) {
		t.Fatal("the heartbeat loop was not told")
	}
	if h := webWire(t, p); h.Capacity != 5 || h.InFlight != 1 {
		t.Fatalf("grown web entry %+v", h)
	}
	if serviceStates(p.health()) == before {
		t.Fatal("availability snapshot unchanged")
	}
	s := p.webLimitStatus()
	if s == nil || s.Mode != "auto" || s.Limit != 5 || s.Reason != worker.WebLimitHealthy || s.ChangedAt == nil || !s.ChangedAt.Equal(clock.now()) {
		t.Fatalf("status %+v", s)
	}
	leases := []*accountLease{held}
	for i := 0; i < 4; i++ {
		lease, ok := p.acquireAccount("web")
		if !ok {
			t.Fatal("grown slot refused", i)
		}
		leases = append(leases, lease)
	}
	if p.acquire("web") {
		t.Fatal("web ran past five")
	}
	for _, lease := range leases {
		p.finishAccount(lease, "")
	}
}

// A halving never touches running pages: they keep their slots and finish,
// health keeps capacity at in_flight while they drain, and admission returns
// only below the new limit.
func TestWebAutoLimitShrinksWithoutCancellingPages(t *testing.T) {
	p, _, changes, _ := autoWebPool(t, 8, "web")
	leases := []*accountLease{}
	for i := 0; i < 8; i++ {
		lease, ok := p.acquireAccount("web")
		if !ok {
			t.Fatal("web refused", i)
		}
		leases = append(leases, lease)
	}
	if p.acquire("web") {
		t.Fatal("web ran past eight")
	}
	for _, lease := range leases[:3] {
		lease.config.WebObserver.Hop("web_fetch_failed", 21*time.Second, true)
	}
	if !signalled(changes) || p.webLimit.Limit() != 4 {
		t.Fatal("three timeouts did not halve the limit", p.webLimit.Limit())
	}
	if h := webWire(t, p); h.Capacity != 8 || h.InFlight != 8 {
		t.Fatalf("draining web entry %+v", h)
	}
	if p.acquire("web") {
		t.Fatal("admitted above the lowered limit")
	}
	// The pages admitted under eight finish as usual. Their timeouts are not
	// new evidence against four.
	for _, lease := range leases[3:6] {
		lease.config.WebObserver.Hop("web_connect_failed", 25*time.Second, true)
	}
	if p.webLimit.Limit() != 4 {
		t.Fatal("pages from before the halving halved it again")
	}
	for _, lease := range leases[:3] {
		lease.config.WebObserver.Done("web_fetch_failed", false)
		p.finishAccount(lease, "web_fetch_failed")
	}
	if h := webWire(t, p); h.Capacity != 5 || h.InFlight != 5 || p.acquire("web") {
		t.Fatalf("five running under four: %+v", h)
	}
	for i, lease := range leases[3:5] {
		lease.config.WebObserver.Hop("", 1500*time.Millisecond, false)
		lease.config.WebObserver.Done("", false)
		p.finishAccount(lease, "")
		if h := webWire(t, p); h.Capacity != 4 || h.InFlight != 4-i {
			t.Fatalf("draining under four: %+v", h)
		}
	}
	// Three running under four: one more is admitted, and no more.
	if !p.acquire("web") {
		t.Fatal("refused below the lowered limit")
	}
	if h := webWire(t, p); h.InFlight != 4 || h.Capacity != 4 || p.acquire("web") {
		t.Fatalf("back at the limit: %+v", h)
	}
	p.finish("web", "")
	for _, lease := range leases[5:] {
		p.finishAccount(lease, "")
	}
	if h := webWire(t, p); h.InFlight != 0 || h.Capacity != 4 || h.State != "ready" {
		t.Fatalf("drained web entry %+v", h)
	}
}

// Host memory pressure lowers the limit while no page finishes: the heartbeat
// loop's own health read applies it.
func TestWebAutoMemoryPressureLowersTheLimitWithoutPages(t *testing.T) {
	p, host, changes, clock := autoWebPool(t, config.WebAutoMax, "web")
	if h := webWire(t, p); h.Capacity != 16 {
		t.Fatalf("auto web entry %+v", h)
	}
	host.set(worker.HostLoad{Memory: worker.MemoryCritical})
	if h := webWire(t, p); h.Capacity != 16 {
		t.Fatalf("the host was read again within a second: %+v", h)
	}
	clock.advance(time.Second)
	if h := webWire(t, p); h.Capacity != 8 || !signalled(changes) {
		t.Fatalf("memory pressure: %+v", h)
	}
	if s := p.webLimitStatus(); s.Reason != worker.WebLimitMemoryPressure {
		t.Fatalf("status %+v", s)
	}
}

// The browser tier stays memory-gated and inside the live web limit.
func TestWebAutoBrowserSlotsStayInsideTheWebLimit(t *testing.T) {
	p, host, _, clock := autoWebPool(t, config.WebAutoStart, "web")
	p.config.WebBrowser = true
	tier := &stubBrowser{}
	tier.set(readyBrowser(4))
	p.browser = tier
	if h := webWire(t, p); h.Capacity != 4 || h.Browser.Capacity != 4 {
		t.Fatalf("browser at four: %+v", h.Browser)
	}
	host.set(worker.HostLoad{Memory: worker.MemoryCritical})
	clock.advance(time.Second)
	if h := webWire(t, p); h.Capacity != 2 || h.Browser.Capacity != 2 {
		t.Fatalf("browser at two: %+v in %+v", h.Browser, h)
	}
	first, ok := p.acquireAccount("web", "browser")
	second, ok2 := p.acquireAccount("web", "browser")
	if !ok || !ok2 || first.config.WebObserver == nil {
		t.Fatal("browser slots refused")
	}
	if _, ok := p.acquireAccount("web", "browser"); ok {
		t.Fatal("browser ran past the web limit")
	}
	if h := webWire(t, p); h.Browser.InFlight != 2 || h.InFlight != 2 {
		t.Fatalf("occupied browser %+v in %+v", h.Browser, h)
	}
	p.finishAccount(first, "")
	p.finishAccount(second, "")
	// Memory-gated: the tier's own capacity still caps it under a higher limit.
	tier.set(readyBrowser(1))
	host.set(worker.HostLoad{})
	clock.advance(time.Second)
	if h := webWire(t, p); h.Capacity != 2 || h.Browser.Capacity != 1 {
		t.Fatalf("memory-gated browser %+v", h.Browser)
	}
}

// A fixed SCARLETT_WEB_CONCURRENCY keeps today's behaviour: no limiter, no
// observer on leases, the configured capacity whatever pages report.
func TestWebFixedLimitKeepsTodaysBehaviour(t *testing.T) {
	worker.ResetRelayHaltForTests()
	t.Cleanup(worker.ResetRelayHaltForTests)
	c := poolFixture(t, "web").config
	c.WebConcurrency = 8
	p := newServicePool(c)
	if p.webLimit != nil || p.capacity() != 8 {
		t.Fatal("fixed pool", p.webLimit, p.capacity())
	}
	leases := []*accountLease{}
	for i := 0; i < 8; i++ {
		lease, ok := p.acquireAccount("web")
		if !ok || lease.config.WebObserver != nil {
			t.Fatal("fixed web lease", i, ok)
		}
		leases = append(leases, lease)
	}
	if p.acquire("web") {
		t.Fatal("web ran past eight")
	}
	for _, lease := range leases {
		p.finishAccount(lease, "expired")
	}
	if h := webWire(t, p); h.Capacity != 8 || h.InFlight != 0 {
		t.Fatalf("fixed web entry %+v", h)
	}
	if s := p.webLimitStatus(); s == nil || *s != (webLimitStatus{Mode: "fixed", Limit: 8}) {
		t.Fatalf("status %+v", s)
	}
	if s := poolFixture(t, "web").webLimitStatus(); s == nil || *s != (webLimitStatus{Mode: "fixed", Limit: 4}) {
		t.Fatalf("default status %+v", s)
	}
	if s := poolFixture(t, "codex").webLimitStatus(); s != nil {
		t.Fatalf("web off: %+v", s)
	}
	// auto without web has no limiter either.
	c = poolFixture(t, "codex").config
	c.WebConcurrencyAuto, c.WebConcurrency = true, config.WebAutoMax
	if p := newServicePool(c); p.webLimit != nil || p.webLimitStatus() != nil {
		t.Fatal("limiter without web")
	}
}

func TestWebLimitStatusRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		status *webLimitStatus
		ok     bool
	}{
		{nil, true},
		{&webLimitStatus{Mode: "fixed", Limit: 4}, true},
		{&webLimitStatus{Mode: "fixed", Limit: 32}, true},
		{&webLimitStatus{Mode: "auto", Limit: 4, Reason: worker.WebLimitStart}, true},
		{&webLimitStatus{Mode: "auto", Limit: 16, Reason: worker.WebLimitHealthy, ChangedAt: &at}, true},
		{&webLimitStatus{Mode: "auto", Limit: 2, Reason: worker.WebLimitMemoryPressure, ChangedAt: &at}, true},
		{&webLimitStatus{Mode: "fixed", Limit: 0}, false},
		{&webLimitStatus{Mode: "fixed", Limit: 33}, false},
		{&webLimitStatus{Mode: "fixed", Limit: 4, Reason: worker.WebLimitHealthy}, false},
		{&webLimitStatus{Mode: "fixed", Limit: 4, ChangedAt: &at}, false},
		{&webLimitStatus{Mode: "auto", Limit: 1, Reason: worker.WebLimitStart}, false},
		{&webLimitStatus{Mode: "auto", Limit: 17, Reason: worker.WebLimitHealthy, ChangedAt: &at}, false},
		{&webLimitStatus{Mode: "auto", Limit: 4, Reason: "faster"}, false},
		{&webLimitStatus{Mode: "auto", Limit: 4, Reason: worker.WebLimitStart, ChangedAt: &at}, false},
		{&webLimitStatus{Mode: "auto", Limit: 4, Reason: worker.WebLimitLatency}, false},
		{&webLimitStatus{Mode: "turbo", Limit: 4}, false},
	} {
		if validWebLimitStatus(tc.status) != tc.ok {
			t.Errorf("%+v: valid %v", tc.status, !tc.ok)
		}
	}
	p, _, _, _ := autoWebPool(t, config.WebAutoStart, "web")
	held, _ := p.acquireAccount("web")
	for i := 0; i < 20; i++ {
		runWebPage(t, p, 1500*time.Millisecond)
	}
	p.finishAccount(held, "")
	status := runtimeStatus{Version: coordinator.Version, State: "running", NodeID: "synthetic-node", Services: p.health(), Release: coordinator.NodeRelease, WebLimit: p.webLimitStatus()}
	if err := saveRuntimeStatus(p.config.StateDir, status); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCARLETT_STATE_DIR", p.config.StateDir)
	var out strings.Builder
	if err := localCommand("status", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"web_limit":{"limit_mode":"auto","limit":5,"limit_reason":"healthy","limit_changed_at":"`) || !strings.Contains(out.String(), `"capacity":5`) {
		t.Fatal("status output", out.String())
	}
	status.WebLimit = &webLimitStatus{Mode: "auto", Limit: 99, Reason: worker.WebLimitHealthy, ChangedAt: &at}
	if err := saveRuntimeStatus(p.config.StateDir, status); err != nil {
		t.Fatal(err)
	}
	if err := localCommand("status", &out); err == nil || !strings.Contains(err.Error(), "web limit") {
		t.Fatal("invalid web limit status read", err)
	}
}

// A node run with SCARLETT_WEB_CONCURRENCY=auto heartbeats its web service
// at the starting limit and keeps the limit's mode and reason in local
// status only.
func TestRunLoopAdvertisesTheAdaptiveWebLimit(t *testing.T) {
	worker.ResetRelayHaltForTests()
	t.Cleanup(worker.ResetRelayHaltForTests)
	heartbeats := make(chan []byte, 16)
	c, stop := startLongPollNodeWith(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/v1/heartbeat" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var raw bytes.Buffer
		if _, err := raw.ReadFrom(r.Body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case heartbeats <- raw.Bytes():
		default:
		}
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
			json.NewEncoder(w).Encode(coordinator.HeartbeatReply{})
		}
	}, func(c *config.Config) {
		helper := fixtureHelperPath(filepath.Dir(c.StateDir))
		if err := installFixtureHelper(helper); err != nil {
			t.Fatal(err)
		}
		c.Executor, c.Services, c.LocalFixture, c.DiagnosticsDisabled = config.ExecutorServices, []string{"web"}, false, true
		c.WebConcurrencyAuto, c.WebConcurrency, c.CodexConcurrency, c.XConcurrency = true, config.WebAutoMax, 1, 1
		c.AccountsFile, c.AccountsRequired, c.Prover, c.MaxInputBytes = filepath.Join(c.StateDir, "accounts.json"), true, helper, 32768
	})
	defer stop()
	var raw []byte
	select {
	case raw = <-heartbeats:
	case <-time.After(10 * time.Second):
		t.Fatal("no heartbeat")
	}
	var h coordinator.Heartbeat
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatal(err)
	}
	if len(h.Services) != 3 || h.Services[2].Kind != "web" || h.Services[2].State != "configured" || h.Services[2].Capacity != 4 || h.Capacity != 4 || h.State != "available" {
		t.Fatalf("auto web heartbeat %s", raw)
	}
	if bytes.Contains(raw, []byte("limit_")) {
		t.Fatalf("heartbeat carries local limit fields: %s", raw)
	}
	statusRaw, err := os.ReadFile(filepath.Join(c.StateDir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	var status runtimeStatus
	if err := json.Unmarshal(statusRaw, &status); err != nil || status.WebLimit == nil || *status.WebLimit != (webLimitStatus{Mode: "auto", Limit: 4, Reason: worker.WebLimitStart}) {
		t.Fatalf("status %s: %v", statusRaw, err)
	}
}
