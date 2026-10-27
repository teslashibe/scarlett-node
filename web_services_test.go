package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

func TestWebServiceReadinessAndCapacity(t *testing.T) {
	worker.ResetRelayHaltForTests()
	t.Cleanup(worker.ResetRelayHaltForTests)
	p := poolFixture(t, "web")
	h := healthKind(t, p, "web")
	if h.State != "configured" || h.Capacity != 4 || h.InFlight != 0 || h.Egress != "direct" || h.MaxInputBytes != 32768 || h.ProofModes != nil || h.Models != nil || h.MaxOutputTokens != 0 || h.ConfiguredCapacity != nil || h.OperationAvailability != nil {
		t.Fatalf("enabled web entry %+v", h)
	}
	for _, kind := range []string{"codex", "x_read"} {
		if other := healthKind(t, p, kind); other.State != "not_added" || other.Capacity != 0 || other.MaxInputBytes != 0 || other.Egress != "" {
			t.Fatalf("unselected %s entry %+v", kind, other)
		}
	}
	if p.capacity() != 4 || len(p.health()) != 3 {
		t.Fatal("web slots not counted", p.capacity())
	}
	for i := 0; i < 4; i++ {
		if !p.acquire("web") {
			t.Fatal("web slot refused", i)
		}
	}
	if p.acquire("web") {
		t.Fatal("web exceeded its concurrency")
	}
	if h = healthKind(t, p, "web"); h.InFlight != 4 || h.Capacity != 4 {
		t.Fatalf("occupied web entry %+v", h)
	}
	// Target-side failures say nothing about this node.
	for _, code := range []string{"web_dns_failed", "web_egress_denied", "web_connect_failed", "web_fetch_failed"} {
		p.finish("web", code)
		if h = healthKind(t, p, "web"); h.State != "configured" || h.LastErrorCode != "" {
			t.Fatalf("%s changed web state: %+v", code, h)
		}
		if !p.acquire("web") {
			t.Fatal("slot not released after", code)
		}
	}
	p.finish("web", "")
	if h = healthKind(t, p, "web"); h.State != "ready" || h.InFlight != 3 {
		t.Fatalf("proven web job: %+v", h)
	}
	p.finish("web", "web_fetch_failed")
	if h = healthKind(t, p, "web"); h.State != "ready" {
		t.Fatalf("target failure undid ready: %+v", h)
	}
	// The node's own proxy failing rests web for a minute.
	p.finish("web", "web_proxy_failed")
	if h = healthKind(t, p, "web"); h.State != "unreachable" || h.LastErrorCode != "web_proxy_failed" || h.Capacity != h.InFlight || p.acquire("web") {
		t.Fatalf("proxy failure did not rest web: %+v", h)
	}
	p.mu.Lock()
	p.entries["web"].restUntil = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if h = healthKind(t, p, "web"); h.State != "configured" || h.LastErrorCode != "" || !p.acquire("web") {
		t.Fatalf("web did not recover from the proxy rest: %+v", h)
	}
	p.finish("web", "")
	p.finish("web", "")
	if h = healthKind(t, p, "web"); h.InFlight != 0 || h.State != "ready" {
		t.Fatalf("slots leaked: %+v", h)
	}
	// A halted relay stops web: it has no MPC mode to fall back to.
	worker.HaltRelay("test")
	if h = healthKind(t, p, "web"); h.State != "unreachable" || h.LastErrorCode != "relay_misuse" || h.Capacity != 0 || p.acquire("web") {
		t.Fatalf("halted relay still offers web: %+v", h)
	}
	worker.ResetRelayHaltForTests()
	if h = healthKind(t, p, "web"); h.State != "configured" || !p.acquire("web") {
		t.Fatalf("web did not resume: %+v", h)
	}
	p.finish("web", "")
	// A missing helper makes web unreachable until it returns.
	if err := os.Remove(p.config.Prover); err != nil {
		t.Fatal(err)
	}
	if h = healthKind(t, p, "web"); h.State != "unreachable" || h.LastErrorCode != "prover_error" || p.acquire("web") {
		t.Fatalf("missing helper: %+v", h)
	}
	if err := installFixtureHelper(p.config.Prover); err != nil {
		t.Fatal(err)
	}
	if h = healthKind(t, p, "web"); h.State != "configured" {
		t.Fatalf("restored helper: %+v", h)
	}
}

// Web needs no account: an account pool that is missing, broken or managed
// never turns it auth_required, and switching into the managed pool keeps its
// occupied slots.
func TestWebServiceIgnoresAccountPool(t *testing.T) {
	worker.ResetRelayHaltForTests()
	p := poolFixture(t, "codex", "x_read", "web")
	p.config.AccountsRequired = true // desktop: no accounts.json yet
	if !p.acquire("web") {
		t.Fatal("web refused without accounts")
	}
	for _, s := range p.health() {
		if s.Kind == "web" && (s.State != "configured" || s.InFlight != 1 || s.Capacity != 4) {
			t.Fatalf("web under a blocked pool: %+v", s)
		}
		if s.Kind != "web" && s.State == "configured" {
			t.Fatalf("%s configured without accounts", s.Kind)
		}
	}
	accounts, _ := json.Marshal(map[string]any{"version": 1, "accounts": []map[string]any{{"id": "work", "service": "codex", "path": filepath.Dir(filepath.Join(p.config.CodexHome, "auth.json")), "concurrency": 1}}})
	if err := writePrivateFixture(p.config.AccountsFile, accounts, 0600); err != nil {
		t.Fatal(err)
	}
	if h := healthKind(t, p, "web"); h.State != "configured" || h.InFlight != 1 {
		t.Fatalf("managed pool reset web: %+v", h)
	}
	for _, a := range p.accountStatus() {
		if a.Service == "web" {
			t.Fatal("web listed as an account")
		}
	}
	p.finish("web", "auth_required") // never a web outcome; must not stick
	if h := healthKind(t, p, "web"); h.State == "auth_required" || h.InFlight != 0 {
		t.Fatalf("account outcome applied to web: %+v", h)
	}
}

func TestWebHeartbeatLimitsAndProxyPrivacy(t *testing.T) {
	worker.ResetRelayHaltForTests()
	p := poolFixture(t, "codex", "x_read", "web")
	proxy, err := config.ParseWebProxy([]byte(`{"provider":"webshare","username":"synthetic0user","password":"synthetic-secret","country":"us","port":3128,"use":"all"}`))
	if err != nil {
		t.Fatal(err)
	}
	p.config.WebEgressProxy = proxy
	p.config.CodexConcurrency, p.config.XConcurrency, p.config.WebConcurrency = 32, 32, 32
	if p.capacity() != 96 {
		t.Fatal("full node capacity", p.capacity())
	}
	raw, _ := json.Marshal(p.health())
	for _, secret := range []string{"synthetic0user", "synthetic-secret", "p.webshare.io", "3128", "webshare"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("heartbeat carries the proxy:", secret)
		}
	}
	if h := healthKind(t, p, "web"); h.Egress != "proxy" {
		t.Fatalf("proxy egress not reported: %+v", h)
	}
	// The exit a page's probe found shows in local status only.
	lease, ok := p.acquireAccount("web")
	if !ok {
		t.Fatal("web slot")
	}
	lease.config.WebEgressObserver(config.WebEgressOutcome{Via: "proxy", Exit: netip.MustParseAddr("93.184.216.34")})
	p.finishAccount(lease, "")
	status := runtimeStatus{Version: coordinator.Version, State: "running", NodeID: "synthetic-node", InFlight: 96, Services: p.health(), WebEgress: p.webEgressStatus(), Release: coordinator.NodeRelease}
	if raw, _ := json.Marshal(p.health()); strings.Contains(string(raw), "93.184.216.34") {
		t.Fatal("heartbeat carries the exit")
	}
	if err := saveRuntimeStatus(p.config.StateDir, status); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCARLETT_STATE_DIR", p.config.StateDir)
	var out strings.Builder
	if err := localCommand("status", &out); err != nil {
		t.Fatal("three-service status refused:", err)
	}
	if strings.Contains(out.String(), "synthetic-secret") || strings.Contains(out.String(), "synthetic0user") || !strings.Contains(out.String(), `"egress":"proxy"`) ||
		!strings.Contains(out.String(), `"web_egress":{"via":"proxy","provider":"webshare","country":"us","last_exit":"93.184.216.34","last_exit_at":`) {
		t.Fatal("status output", out.String())
	}
	for _, code := range []string{"web_egress_denied", "web_dns_failed", "web_connect_failed", "web_proxy_failed", "web_proxy_refused", "web_fetch_failed"} {
		if restsNode(true, code) || restsNode(false, code) {
			t.Fatal("web outcome rests the node:", code)
		}
	}
}

// A failed proxy rests web for as long as its class says, and never sends a
// page from this node's own network instead; a proxy that refused one
// target, or whose exit failed, rests nothing.
func TestWebProxyRests(t *testing.T) {
	worker.ResetRelayHaltForTests()
	t.Cleanup(worker.ResetRelayHaltForTests)
	p := poolFixture(t, "web")
	proxy, err := config.ParseWebProxy([]byte(`{"provider":"webshare","username":"synthetic0user","password":"synthetic-secret","country":"us","port":80,"use":"limited_sites"}`))
	if err != nil {
		t.Fatal(err)
	}
	p.config.WebEgressProxy = proxy
	if h := healthKind(t, p, "web"); h.Egress != "both" {
		t.Fatalf("both egress: %+v", h)
	}
	finish := func(code, class string) {
		t.Helper()
		lease, ok := p.acquireAccount("web")
		if !ok {
			t.Fatal("web slot refused before", code, class)
		}
		lease.config.WebEgressObserver(config.WebEgressOutcome{Via: "proxy", ProxyClass: class})
		p.finishAccount(lease, code)
	}
	recover := func() {
		p.mu.Lock()
		p.entries["web"].restUntil = time.Now().Add(-time.Second)
		p.mu.Unlock()
		if h := healthKind(t, p, "web"); h.State != "configured" || p.webEgressStatus().RestReason != "" {
			t.Fatalf("web did not recover: %+v", h)
		}
	}
	for class, rest := range map[string]time.Duration{"proxy_unreachable": time.Minute, "proxy_busy": time.Minute, "proxy_auth": 10 * time.Minute, "proxy_quota": 30 * time.Minute, "": time.Minute} {
		before := time.Now()
		finish("web_proxy_failed", class)
		h := healthKind(t, p, "web")
		p.mu.Lock()
		until := p.entries["web"].restUntil
		p.mu.Unlock()
		want := class
		if want == "" {
			want = "proxy_unreachable"
		}
		if h.State != "unreachable" || h.LastErrorCode != "web_proxy_failed" || p.acquire("web") || until.Before(before.Add(rest)) || until.After(time.Now().Add(rest)) || p.webEgressStatus().RestReason != want {
			t.Fatalf("%q: %+v until %v reason %q", class, h, until.Sub(before), p.webEgressStatus().RestReason)
		}
		raw, _ := json.Marshal(p.health())
		if strings.Contains(string(raw), want) {
			t.Fatal("heartbeat names the rest reason", string(raw))
		}
		recover()
	}
	// A longer rest is never cut short by a shorter one.
	finish("web_proxy_failed", "proxy_quota")
	p.mu.Lock()
	p.entries["web"].inFlight++
	lease := &accountLease{id: "web", kind: "web", account: p.web, webProxyClass: "proxy_busy"}
	p.mu.Unlock()
	p.finishAccount(lease, "web_proxy_failed")
	if p.webEgressStatus().RestReason != "proxy_quota" {
		t.Fatal("rest shortened", p.webEgressStatus().RestReason)
	}
	recover()
	for _, code := range []string{"web_proxy_refused", "web_connect_failed"} {
		finish(code, "")
		if h := healthKind(t, p, "web"); h.State != "configured" && h.State != "ready" || h.LastErrorCode != "" {
			t.Fatalf("%s rested web: %+v", code, h)
		}
	}
	// Local status reads back, and refuses what this node never writes.
	status := p.webEgressStatus()
	if status.Via != "both" || status.Provider != "webshare" || status.Country != "us" || !validWebEgressStatus(status) {
		t.Fatalf("%+v", status)
	}
	at := time.Now()
	for _, bad := range []webEgressStatus{
		{Via: "home"}, {Via: "direct", Provider: "webshare"}, {Via: "both"}, {Via: "both", Provider: "webshare"},
		{Via: "both", Provider: "http", Country: "us"}, {Via: "proxy", Provider: "webshare", Country: "us", LastExit: "2606:2800:220:1::1", LastExitAt: &at},
		{Via: "proxy", Provider: "webshare", Country: "us", LastExit: "93.184.216.34"}, {Via: "proxy", Provider: "webshare", Country: "us", RestReason: "proxy_exit"},
	} {
		if validWebEgressStatus(&bad) {
			t.Errorf("%+v accepted", bad)
		}
	}
	if !validWebEgressStatus(&webEgressStatus{Via: "direct"}) || !validWebEgressStatus(&webEgressStatus{Via: "proxy", Provider: "http"}) {
		t.Fatal("valid statuses refused")
	}
}
