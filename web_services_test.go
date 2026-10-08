package main

import (
	"encoding/json"
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
	proxy, err := config.ParseWebProxy("http://synthetic-user:synthetic-secret@proxy.synthetic.invalid:3128")
	if err != nil {
		t.Fatal(err)
	}
	p.config.WebEgressProxy = proxy
	p.config.CodexConcurrency, p.config.XConcurrency, p.config.WebConcurrency = 32, 32, 32
	if p.capacity() != 96 {
		t.Fatal("full node capacity", p.capacity())
	}
	raw, _ := json.Marshal(p.health())
	for _, secret := range []string{"synthetic-user", "synthetic-secret", "proxy.synthetic.invalid", "3128"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("heartbeat carries the proxy:", secret)
		}
	}
	if h := healthKind(t, p, "web"); h.Egress != "proxy" {
		t.Fatalf("proxy egress not reported: %+v", h)
	}
	status := runtimeStatus{Version: coordinator.Version, State: "running", NodeID: "synthetic-node", InFlight: 96, Services: p.health(), Release: coordinator.NodeRelease}
	if err := saveRuntimeStatus(p.config.StateDir, status); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCARLETT_STATE_DIR", p.config.StateDir)
	var out strings.Builder
	if err := localCommand("status", &out); err != nil {
		t.Fatal("three-service status refused:", err)
	}
	if strings.Contains(out.String(), "synthetic-secret") || !strings.Contains(out.String(), `"egress":"proxy"`) {
		t.Fatal("status output", out.String())
	}
	for _, code := range []string{"web_egress_denied", "web_dns_failed", "web_connect_failed", "web_proxy_failed", "web_fetch_failed"} {
		if restsNode(true, code) || restsNode(false, code) {
			t.Fatal("web outcome rests the node:", code)
		}
	}
}
