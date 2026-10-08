package main

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	yaml "go.yaml.in/yaml/v2"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

// stubBrowser is a browser tier that reports a fixed status.
type stubBrowser struct {
	mu     sync.Mutex
	status worker.BrowserStatus
}

func (s *stubBrowser) Status() worker.BrowserStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}
func (s *stubBrowser) set(status worker.BrowserStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
}
func (*stubBrowser) Prewarm() {}
func (*stubBrowser) Fetch(context.Context, worker.BrowserFetchRequest) (worker.BrowserFetchResult, error) {
	return worker.BrowserFetchResult{}, worker.ErrBrowserUnavailable
}

func readyBrowser(capacity int) worker.BrowserStatus {
	return worker.BrowserStatus{Ready: true, Capacity: capacity, Version: "155.0.8059.39", Engine: "scrapling/0.4.15", UserAgent: "synthetic"}
}

func browserEntry(t *testing.T, p *servicePool) (coordinator.ServiceHealth, coordinator.BrowserHealth) {
	t.Helper()
	h := healthKind(t, p, "web")
	if h.Browser == nil {
		t.Fatal("enabled web entry without browser")
	}
	return h, *h.Browser
}

func TestWebBrowserReadinessInsideWebCapacity(t *testing.T) {
	worker.ResetRelayHaltForTests()
	t.Cleanup(worker.ResetRelayHaltForTests)
	p := poolFixture(t, "codex", "x_read", "web")
	// Off by configuration: disabled, and the other kinds carry no browser.
	if _, b := browserEntry(t, p); b != (coordinator.BrowserHealth{State: "unavailable", Reason: "disabled"}) {
		t.Fatalf("browser off: %+v", b)
	}
	for _, kind := range []string{"codex", "x_read"} {
		if healthKind(t, p, kind).Browser != nil {
			t.Fatal("browser on", kind)
		}
	}
	p.config.WebBrowser = true
	if _, b := browserEntry(t, p); b.Reason != "runtime_missing" || b.Capacity != 0 {
		t.Fatalf("no runtime: %+v", b)
	}
	tier := &stubBrowser{}
	p.browser = tier
	for _, reason := range []string{"memory_low", "disk_low", "runtime_missing", "runtime_invalid", "browser_downloading", "browser_download_failed", "browser_invalid", "deps_missing", "sandbox_unavailable", "helper_failed"} {
		tier.set(worker.BrowserStatus{Reason: reason})
		if _, b := browserEntry(t, p); b != (coordinator.BrowserHealth{State: "unavailable", Reason: reason}) {
			t.Fatalf("%s: %+v", reason, b)
		}
		if _, ok := p.acquireAccount("web", "browser"); ok {
			t.Fatal("browser slot while", reason)
		}
	}
	// The reason set is closed: a helper's launch_failed marker, or anything
	// else unknown, is reported as helper_failed.
	for _, reason := range []string{"launch_failed", "", "disabled", "web_unavailable", "SECRET"} {
		tier.set(worker.BrowserStatus{Reason: reason})
		if _, b := browserEntry(t, p); b.Reason != "helper_failed" {
			t.Fatalf("%q reported as %+v", reason, b)
		}
	}
	tier.set(readyBrowser(2))
	if h, b := browserEntry(t, p); b != (coordinator.BrowserHealth{State: "ready", Capacity: 2, Version: "155.0.8059.39"}) || h.Capacity != 4 {
		t.Fatalf("ready browser: %+v in %+v", b, h)
	}
	// A browser lease holds a browser slot inside its web slot.
	first, ok := p.acquireAccount("web", "browser")
	second, ok2 := p.acquireAccount("web", "browser")
	if !ok || !ok2 {
		t.Fatal("browser slots refused")
	}
	if _, ok := p.acquireAccount("web", "browser"); ok {
		t.Fatal("browser exceeded its capacity")
	}
	relay, ok := p.acquireAccount("web")
	if !ok {
		t.Fatal("relay web refused while the browser is full")
	}
	if h, b := browserEntry(t, p); h.InFlight != 3 || b.InFlight != 2 || b.Capacity != 2 {
		t.Fatalf("occupied: web %d, browser %+v", h.InFlight, b)
	}
	p.finishAccount(first, "web_browser_failed")
	if h, b := browserEntry(t, p); h.InFlight != 2 || b.InFlight != 1 || h.State != "configured" {
		t.Fatalf("browser failure changed web: %+v %+v", h, b)
	}
	p.finishAccount(second, "")
	p.finishAccount(relay, "")
	if h, b := browserEntry(t, p); h.InFlight != 0 || b.InFlight != 0 || h.State != "ready" {
		t.Fatalf("released: %+v %+v", h, b)
	}
	// Capacity never exceeds web's, nor 4.
	tier.set(readyBrowser(9))
	if _, b := browserEntry(t, p); b.Capacity != 4 {
		t.Fatalf("browser capacity above 4: %+v", b)
	}
	p.config.WebConcurrency = 1
	p.entries["web"].capacity = 1
	if h, b := browserEntry(t, p); b.Capacity != 1 || b.Capacity > h.Capacity {
		t.Fatalf("browser capacity above web's: %+v %+v", b, h)
	}
	tier.set(worker.BrowserStatus{Ready: true, Capacity: 2})
	if _, b := browserEntry(t, p); b.Reason != "helper_failed" {
		t.Fatalf("ready without a version: %+v", b)
	}
	// Web itself unavailable: the browser says so too.
	tier.set(readyBrowser(2))
	worker.HaltRelay("test")
	if h, b := browserEntry(t, p); h.State != "unreachable" || b != (coordinator.BrowserHealth{State: "unavailable", Reason: "web_unavailable"}) {
		t.Fatalf("halted relay: %+v %+v", h, b)
	}
	if _, ok := p.acquireAccount("web", "browser"); ok {
		t.Fatal("browser slot with relay halted")
	}
}

// Every browser entry the node can send satisfies the spec: required on an
// enabled web entry and nowhere else, a closed reason exactly when
// unavailable, capacity within 1-4 and web's capacity, in-flight within it.
func TestWebBrowserHeartbeatMatchesTheSpec(t *testing.T) {
	worker.ResetRelayHaltForTests()
	t.Cleanup(worker.ResetRelayHaltForTests)
	raw, err := os.ReadFile("api/node-v1.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[any]any
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	browserSchema := spec["components"].(map[any]any)["schemas"].(map[any]any)["BrowserHealth"].(map[any]any)
	properties := browserSchema["properties"].(map[any]any)
	reasons := []string{}
	for _, r := range properties["reason"].(map[any]any)["enum"].([]any) {
		reasons = append(reasons, r.(string))
	}
	p := poolFixture(t, "codex", "x_read", "web")
	tier := &stubBrowser{}
	check := func(label string) {
		t.Helper()
		encoded, _ := json.Marshal(p.health())
		var services []map[string]any
		if err := json.Unmarshal(encoded, &services); err != nil {
			t.Fatal(err)
		}
		for _, s := range services {
			b, present := s["browser"].(map[string]any)
			if present != (s["kind"] == "web" && s["state"] != "not_added") {
				t.Fatalf("%s: browser placement on %v", label, s["kind"])
			}
			if !present {
				continue
			}
			for field := range b {
				if properties[field] == nil {
					t.Fatalf("%s: field outside the spec: %s", label, field)
				}
			}
			state, reason := b["state"].(string), b["reason"]
			capacity, inFlight := int(b["capacity"].(float64)), int(b["in_flight"].(float64))
			webCapacity := int(s["capacity"].(float64))
			switch state {
			case "ready":
				if reason != nil || b["version"] == nil || capacity < 1 || capacity > 4 || capacity > webCapacity {
					t.Fatalf("%s: ready entry %v (web capacity %d)", label, b, webCapacity)
				}
			case "unavailable":
				if r, _ := reason.(string); !slices.Contains(reasons, r) || capacity != 0 || b["version"] != nil {
					t.Fatalf("%s: unavailable entry %v", label, b)
				}
			default:
				t.Fatalf("%s: state %q", label, state)
			}
			if inFlight < 0 || inFlight > capacity {
				t.Fatalf("%s: in_flight %d over capacity %d", label, inFlight, capacity)
			}
		}
	}
	check("off")
	p.config.WebBrowser = true
	check("no runtime")
	p.browser = tier
	for _, status := range []worker.BrowserStatus{{Reason: "browser_downloading"}, {Reason: "launch_failed"}, readyBrowser(1), readyBrowser(4)} {
		tier.set(status)
		check("status " + status.Reason)
	}
	held, ok := p.acquireAccount("web", "browser")
	if !ok {
		t.Fatal("browser slot refused")
	}
	tier.set(worker.BrowserStatus{Reason: "helper_failed"})
	check("busy then failed")
	p.finishAccount(held, "web_browser_failed")
	check("released")
	worker.HaltRelay("test")
	check("relay halted")
	// The status file and the local status command carry the entry too.
	worker.ResetRelayHaltForTests()
	tier.set(readyBrowser(2))
	status := runtimeStatus{Version: coordinator.Version, State: "running", NodeID: "synthetic-node", Services: p.health(), Release: coordinator.NodeRelease}
	if err := saveRuntimeStatus(p.config.StateDir, status); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCARLETT_STATE_DIR", p.config.StateDir)
	var out strings.Builder
	if err := localCommand("status", &out); err != nil || !strings.Contains(out.String(), `"browser":{"state":"ready","capacity":2,"in_flight":0,"version":"155.0.8059.39"}`) {
		t.Fatal("status output", err, out.String())
	}
}

func TestWebBrowserOutcomesNeverRestTheNode(t *testing.T) {
	for _, code := range []string{"web_browser_unavailable", "web_browser_failed"} {
		if restsNode(true, code) || restsNode(false, code) {
			t.Fatal("browser outcome rests the node:", code)
		}
	}
}
