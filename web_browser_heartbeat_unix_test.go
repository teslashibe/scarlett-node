//go:build unix

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

// scriptedBrowser is a ready browser tier that renders one fixed page.
type scriptedBrowser struct {
	mu       sync.Mutex
	prewarms int
	fetches  []worker.BrowserFetchRequest
}

const syntheticUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"

func (s *scriptedBrowser) Status() worker.BrowserStatus {
	return worker.BrowserStatus{Ready: true, Capacity: 1, Version: "155.0.8059.39", Engine: "scrapling/0.4.15+scarlett.2", UserAgent: syntheticUA}
}
func (s *scriptedBrowser) Prewarm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prewarms++
}
func (s *scriptedBrowser) Fetch(_ context.Context, req worker.BrowserFetchRequest) (worker.BrowserFetchResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetches = append(s.fetches, req)
	return worker.BrowserFetchResult{Outcome: "ok", FinalURL: "https://example.com/", StatusCode: 200, Headers: [][2]string{{"content-type", "text/html"}}, ContentType: "text/html", HTML: "<p>rendered</p>", Challenge: "solved",
		Cookies: []worker.BrowserCookie{{Name: "cf_clearance", Value: "synthetic-clearance", Domain: ".example.com", Path: "/", Expires: -1}, {Name: "session", Value: "synthetic-session", Domain: ".example.com", Path: "/", Expires: -1}}}, nil
}
func (s *scriptedBrowser) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prewarms, len(s.fetches)
}

func leaseFixture(t *testing.T, name string) coordinator.Lease {
	t.Helper()
	raw, err := os.ReadFile("api/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var l coordinator.Lease
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	l.LeaseDeadline = time.Now().Add(118 * time.Second).UTC().Truncate(time.Second)
	l.SettlementDeadline = l.LeaseDeadline
	return l
}

// A web node with the browser on advertises it inside web, takes a browser
// offer into a browser slot, uploads the rendered copy to /browser-result,
// re-fetches through the relay helper with the browser's User-Agent and
// clearance cookie only, and reports proven. A relay offer carrying the
// pre-warm hint starts the browser.
func TestRunLoopServesWebBrowserLease(t *testing.T) {
	for _, tc := range []struct{ name, fixture string }{{"browser job", "lease-web-browser-offer.json"}, {"pre-warm hint", "lease-web-prewarm-offer.json"}} {
		t.Run(tc.name, func(t *testing.T) {
			worker.ResetRelayHaltForTests()
			dir := privateTestDir(t)
			stdin := filepath.Join(dir, "relay-web-stdin")
			prover := filepath.Join(dir, "synthetic-prover")
			script := "#!/bin/sh\n[ \"$1\" = relay-web ] || exit 3\ncat > '" + stdin + "'\nprintf '{\"status\":\"proof_sent\",\"verifier_sent_bytes\":812,\"verifier_received_bytes\":2048,\"verifier_transport_layer\":\"tcp_payload\",\"hop\":0,\"status_code\":200,\"final\":true}\\n'\n"
			if err := os.WriteFile(prover, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			browser := &scriptedBrowser{}
			previousStart, previousWorker := startBrowserTier, webWorker
			startBrowserTier = func(context.Context, config.Config) (worker.BrowserTier, func()) { return browser, func() {} }
			webWorker = func(c config.Config) worker.Web {
				return worker.Web{Config: c, Egress: worker.NewWebEgressWith(nil, nil), Resolver: func(_ context.Context, host string) ([]netip.Addr, error) {
					if host == "example.com" {
						return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
					}
					return nil, errors.New("synthetic NXDOMAIN")
				}}
			}
			t.Cleanup(func() { startBrowserTier, webWorker = previousStart, previousWorker })
			offer := leaseFixture(t, tc.fixture)
			heartbeats := make(chan coordinator.Heartbeat, 16)
			proven := make(chan []byte, 1)
			uploads := make(chan *http.Request, 1)
			uploaded := make(chan []byte, 1)
			var mu sync.Mutex
			served := false
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/node/v1/heartbeat":
					var h coordinator.Heartbeat
					if json.NewDecoder(r.Body).Decode(&h) != nil {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					heartbeats <- h
					mu.Lock()
					first := !served
					served = true
					mu.Unlock()
					if first {
						json.NewEncoder(w).Encode(coordinator.HeartbeatReply{Lease: &offer})
						return
					}
					select {
					case <-r.Context().Done():
					case <-time.After(200 * time.Millisecond):
						json.NewEncoder(w).Encode(coordinator.HeartbeatReply{})
					}
				case "/api/node/v1/jobs/" + offer.JobID + "/accept":
					accepted := offer
					accepted.VerifierToken = strings.Repeat("ab", 32)
					json.NewEncoder(w).Encode(coordinator.LeaseAcceptance{Version: coordinator.Version, State: "leased", FundingAuthority: "production_receipt", Lease: accepted})
				case "/api/node/v1/jobs/" + offer.JobID + "/browser-result":
					zr, err := gzip.NewReader(r.Body)
					raw, _ := io.ReadAll(zr)
					if err != nil {
						w.WriteHeader(http.StatusUnsupportedMediaType)
						return
					}
					uploads <- r
					uploaded <- raw
					io.WriteString(w, `{"status":"stored"}`)
				case "/api/node/v1/jobs/" + offer.JobID + "/proven":
					body, _ := io.ReadAll(r.Body)
					proven <- body
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Error("unexpected request", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(server.Close)
			c := config.Config{Executor: config.ExecutorServices, Services: []string{"web"}, Profile: "standard", StateDir: filepath.Join(dir, "state"), AccountsFile: filepath.Join(dir, "state", "accounts.json"), AccountsRequired: true, Credential: "synthetic-credential", NodeID: "synthetic-node", CodexConcurrency: 1, XConcurrency: 1, WebConcurrency: 2, WebBrowser: true, Bid: 100, Verifier: "verifier:7047", Prover: prover, JournalLimits: attempts.DefaultLimits(), MaxInputBytes: 32768, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second, DiagnosticsDisabled: true}
			c.Coordinator = server.URL
			c.CoordinatorCA = filepath.Join(privateTestDir(t), "synthetic-coordinator-ca.pem")
			if err := writePrivateFixture(c.CoordinatorCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			reader, writer := io.Pipe()
			done := make(chan error, 1)
			go func() { done <- runWithOwner(c, reader) }()
			defer func() {
				writer.Close()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(10 * time.Second):
					t.Error("synthetic node did not stop")
				}
				reader.Close()
			}()
			first := <-heartbeats
			web := first.Services[2]
			if web.Kind != "web" || web.Browser == nil || !reflect.DeepEqual(*web.Browser, coordinator.BrowserHealth{State: "ready", Capacity: 1, Version: "155.0.8059.39"}) || first.Capacity != 2 {
				t.Fatalf("browser heartbeat %+v %+v", web, web.Browser)
			}
			var body []byte
			select {
			case body = <-proven:
			case <-time.After(10 * time.Second):
				t.Fatal("no proven report")
			}
			want, _ := json.Marshal(coordinator.Proven{Version: coordinator.Version, Attempt: offer.Attempt, Fence: offer.Fence})
			if !bytes.Equal(body, want) {
				t.Fatalf("proven body %s", body)
			}
			raw, err := os.ReadFile(stdin)
			if err != nil {
				t.Fatal(err)
			}
			var in map[string]any
			if err := json.Unmarshal(raw, &in); err != nil || in["ip"] != "93.184.215.14" {
				t.Fatalf("helper input %v", err)
			}
			prewarms, fetches := browser.counts()
			// Prewarm runs beside the acceptance; give it a moment.
			for start := time.Now(); prewarms == 0 && time.Since(start) < 2*time.Second; time.Sleep(10 * time.Millisecond) {
				prewarms, fetches = browser.counts()
			}
			if tc.fixture == "lease-web-prewarm-offer.json" {
				// A relay job: no browser work, no node headers, no upload;
				// the hint started the browser.
				if in["node_headers"] != nil || fetches != 0 || prewarms != 1 || len(uploads) != 0 {
					t.Fatalf("relay job with the hint: headers %v fetches %d prewarms %d", in["node_headers"], fetches, prewarms)
				}
				return
			}
			headers, _ := in["node_headers"].(map[string]any)
			if headers["user_agent"] != syntheticUA || headers["cookie"] != "cf_clearance=synthetic-clearance" || fetches != 1 || prewarms != 1 {
				t.Fatalf("re-fetch headers %v, fetches %d, prewarms %d", headers, fetches, prewarms)
			}
			var request *http.Request
			select {
			case request = <-uploads:
			case <-time.After(time.Second):
				t.Fatal("no browser-result upload")
			}
			if request.Header.Get("Content-Encoding") != "gzip" || request.Header.Get(coordinator.NodeVersionHeader) != coordinator.NodeRelease || request.Header.Get("Authorization") != "Bearer synthetic-credential" {
				t.Fatalf("upload headers %v", request.Header)
			}
			var result coordinator.BrowserResult
			raw = <-uploaded
			if err := json.Unmarshal(raw, &result); err != nil || result.Attempt != offer.Attempt || result.Fence != offer.Fence || result.RequestSHA256 != offer.RequestSHA256 || result.HTML != "<p>rendered</p>" || strings.Contains(string(raw), "synthetic-clearance") || strings.Contains(string(raw), "synthetic-session") {
				t.Fatalf("upload body %s %v", raw, err)
			}
			// The browser slot is released with the job.
			deadline := time.After(10 * time.Second)
			for {
				var h coordinator.Heartbeat
				select {
				case h = <-heartbeats:
				case <-deadline:
					t.Fatal("browser slot not released")
				}
				if web := h.Services[2]; web.InFlight == 0 && web.Browser != nil && web.Browser.InFlight == 0 {
					break
				}
			}
		})
	}
}
