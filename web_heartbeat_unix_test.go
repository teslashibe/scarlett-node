//go:build unix

package main

import (
	"bytes"
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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

func webOfferFixture(t *testing.T) coordinator.Lease {
	t.Helper()
	raw, err := os.ReadFile("api/fixtures/lease-web-offer.json")
	if err != nil {
		t.Fatal(err)
	}
	var offer coordinator.Lease
	if err := json.Unmarshal(raw, &offer); err != nil {
		t.Fatal(err)
	}
	offer.LeaseDeadline = time.Now().Add(118 * time.Second).UTC().Truncate(time.Second)
	offer.SettlementDeadline = offer.LeaseDeadline
	return offer
}

// A web-only node with no accounts heartbeats its web service, accepts a web
// offer, runs the relay-web helper against the checked address and reports
// proven, or reports the hop-0 failure code.
func TestRunLoopServesWebLease(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers map[string][]netip.Addr
		route   string
		code    string
	}{
		{"proven", map[string][]netip.Addr{"example.com": {netip.MustParseAddr("93.184.215.14")}}, "/proven", ""},
		{"dns failure", map[string][]netip.Addr{}, "/fail", "web_dns_failed"},
		{"private target", map[string][]netip.Addr{"example.com": {netip.MustParseAddr("192.168.0.10")}}, "/fail", "web_egress_denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			worker.ResetRelayHaltForTests()
			dir := privateTestDir(t)
			stdin := filepath.Join(dir, "relay-web-stdin")
			prover := filepath.Join(dir, "synthetic-prover")
			// A trusted local test helper: records its input and reports one
			// verified, final hop without contacting anything.
			script := "#!/bin/sh\n[ \"$1\" = relay-web ] || exit 3\ncat > '" + stdin + "'\nprintf '{\"status\":\"proof_sent\",\"verifier_sent_bytes\":812,\"verifier_received_bytes\":2048,\"verifier_transport_layer\":\"tcp_payload\",\"hop\":0,\"status_code\":200,\"final\":true}\\n'\n"
			if err := os.WriteFile(prover, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			previous := webWorker
			webWorker = func(c config.Config) worker.Web {
				return worker.Web{Config: c, Egress: worker.NewWebEgressWith(nil, nil), Resolver: func(_ context.Context, host string) ([]netip.Addr, error) {
					if found, ok := tc.answers[host]; ok {
						return found, nil
					}
					return nil, errors.New("synthetic NXDOMAIN")
				}}
			}
			t.Cleanup(func() { webWorker = previous })
			offer := webOfferFixture(t)
			heartbeats := make(chan coordinator.Heartbeat, 16)
			reports := make(chan []byte, 1)
			var mu sync.Mutex
			served := false
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/api/node/v1/heartbeat":
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
				case r.URL.Path == "/api/node/v1/jobs/"+offer.JobID+"/accept":
					accepted := offer
					accepted.VerifierToken = strings.Repeat("ab", 32)
					json.NewEncoder(w).Encode(coordinator.LeaseAcceptance{Version: coordinator.Version, State: "leased", FundingAuthority: "production_receipt", Lease: accepted})
				case r.URL.Path == "/api/node/v1/jobs/"+offer.JobID+tc.route:
					body, _ := io.ReadAll(r.Body)
					reports <- body
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Error("unexpected request", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(server.Close)
			c := config.Config{Executor: config.ExecutorServices, Services: []string{"web"}, Profile: "standard", StateDir: filepath.Join(dir, "state"), AccountsFile: filepath.Join(dir, "state", "accounts.json"), AccountsRequired: true, Credential: "synthetic-credential", NodeID: "synthetic-node", CodexConcurrency: 1, XConcurrency: 1, WebConcurrency: 2, Bid: 100, Verifier: "verifier:7047", Prover: prover, JournalLimits: attempts.DefaultLimits(), MaxInputBytes: 32768, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second, DiagnosticsDisabled: true}
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
			if len(first.Services) != 3 || first.Services[2].Kind != "web" || first.Services[2].State != "configured" || first.Services[2].Capacity != 2 || first.Services[2].Egress != "direct" || first.Capacity != 2 || first.State != "available" {
				t.Fatalf("web heartbeat %+v", first)
			}
			var body []byte
			select {
			case body = <-reports:
			case <-time.After(10 * time.Second):
				t.Fatal("no report")
			}
			if tc.code == "" {
				want, _ := json.Marshal(coordinator.Proven{Version: coordinator.Version, Attempt: offer.Attempt, Fence: offer.Fence})
				if !bytes.Equal(body, want) {
					t.Fatalf("proven body %s", body)
				}
				var in map[string]any
				raw, err := os.ReadFile(stdin)
				if err != nil || json.Unmarshal(raw, &in) != nil || in["ip"] != "93.184.215.14" || in["url"] != "https://example.com/" || in["token"] != strings.Repeat("ab", 32) || in["verifier"] != "verifier:7047" {
					t.Fatalf("helper input %s %v", raw, err)
				}
			} else {
				var failure coordinator.Failure
				if json.Unmarshal(body, &failure) != nil || failure.Code != tc.code || failure.Attempt != offer.Attempt {
					t.Fatalf("failure body %s", body)
				}
				if _, err := os.Stat(stdin); !os.IsNotExist(err) {
					t.Fatal("helper ran for a refused hop")
				}
			}
			// The finished job frees its slot, and web reports ready only after
			// a proven job; a target failure leaves it configured.
			deadline := time.After(10 * time.Second)
			for {
				var h coordinator.Heartbeat
				select {
				case h = <-heartbeats:
				case <-deadline:
					t.Fatal("web slot not released")
				}
				web := h.Services[2]
				if web.InFlight == 0 && len(web.ActiveLeases) == 0 {
					want := "ready"
					if tc.code != "" {
						want = "configured"
					}
					if web.State != want {
						t.Fatalf("web state %q after %q, want %q", web.State, tc.code, want)
					}
					break
				}
				if web.InFlight != 1 || len(web.ActiveLeases) != 1 || web.ActiveLeases[0].JobID != offer.JobID {
					t.Fatalf("occupied web entry %+v", web)
				}
			}
			journal, err := os.ReadDir(filepath.Join(c.StateDir, "attempts"))
			if err != nil {
				t.Fatal(err)
			}
			records := 0
			for _, entry := range journal {
				if !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				raw, err := os.ReadFile(filepath.Join(c.StateDir, "attempts", entry.Name()))
				var record attempts.Record
				if err != nil || json.Unmarshal(raw, &record) != nil {
					t.Fatal(err)
				}
				records++
				if record.ProviderService != "web" || record.ProviderAccountID != "web" || record.State != "terminal" {
					t.Fatalf("journal record %+v", record)
				}
				if tc.code == "" && (record.ProofTraffic == nil || record.ProofTraffic.MaxSamples != 6 || len(record.ProofTraffic.Samples) != 1 || record.ProofTraffic.Samples[0].State != "complete") {
					t.Fatalf("proof traffic %+v", record.ProofTraffic)
				}
			}
			if records != 1 {
				t.Fatal("journal records", records)
			}
		})
	}
}
