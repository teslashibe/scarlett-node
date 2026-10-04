//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

func communityOffer(t *testing.T) coordinator.Lease {
	t.Helper()
	l := testLease()
	l.SettlementDeadline = l.LeaseDeadline
	l.ServiceType = "codex"
	l.AcceptanceRequired = true
	l.SignedJobID = strings.Repeat("a", 64)
	l.RequestSHA256 = strings.Repeat("b", 64)
	l.CodexPayload = []byte(`{"type":"response.create","model":"gpt-5.6-luna","instructions":"You are a helpful assistant.","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}],"stream":true,"store":false,"reasoning":{"effort":"low"},"text":{"verbosity":"low"}}`)
	return l
}

func TestCommunityAcceptanceBeforeProviderAndLostAcknowledgementRecovery(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "acknowledged", true: "lost-acknowledgement"}[lost], func(t *testing.T) {
			l := communityOffer(t)
			dir := t.TempDir()
			marker := filepath.Join(dir, "synthetic-provider-calls")
			prover := filepath.Join(dir, "synthetic-prover")
			// A trusted local test helper writes proof_sent without contacting a provider.
			script := "#!/bin/sh\nprintf 'called\\n' >> '" + marker + "'\nprintf '{\"status\":\"proof_sent\",\"verifier_sent_bytes\":0,\"verifier_received_bytes\":31,\"verifier_transport_layer\":\"tcp_payload\"}\\n'\n"
			if err := os.WriteFile(prover, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			journal := testJournal(t, filepath.Join(dir, "attempts"))
			var accepted atomic.Bool
			var posts atomic.Int32
			var acceptCalls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic-credential" {
					t.Error("missing credential")
				}
				if strings.HasSuffix(r.URL.Path, "/accept") {
					pending, e := journal.Pending()
					if e != nil || len(pending) != 1 || pending[0].ProviderAccountID != "selected-local-account" || pending[0].ProviderService != "codex" {
						t.Error("account was not pinned before acceptance")
					}
					acceptCalls.Add(1)
					accepted.Store(true)
					if lost {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						conn.Close()
						return
					}
					a := l
					a.VerifierToken = strings.Repeat("c", 64)
					json.NewEncoder(w).Encode(coordinator.LeaseAcceptance{Version: coordinator.Version, State: "leased", FundingAuthority: "production_receipt", Lease: a})
					return
				}
				if !accepted.Load() {
					t.Error("report before funded acceptance")
				}
				if r.Method == "GET" {
					json.NewEncoder(w).Encode(coordinator.AttemptStatus{Version: coordinator.Version, JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, State: "live", ReplaySafe: true})
					return
				}
				posts.Add(1)
				if lost {
					var f coordinator.Failure
					if json.NewDecoder(r.Body).Decode(&f) != nil || f.Code != "execution_uncertain" {
						t.Error("lost acceptance did not preserve execution uncertainty")
					}
				} else if !strings.HasSuffix(r.URL.Path, "/proven") {
					t.Error("wrong proof route")
				} else {
					body, _ := io.ReadAll(r.Body)
					want, _ := json.Marshal(coordinator.Proven{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence})
					pending, err := journal.Pending()
					if err != nil || len(pending) != 1 || !bytes.Equal(body, want) || !bytes.Equal(pending[0].Body, want) || pending[0].SubmissionSHA256 != attempts.Hash(want) {
						t.Error("local counters changed node-v1 body or hash", err)
					} else if traffic := pending[0].ProofTraffic; traffic == nil || !traffic.WorkerFinished || len(traffic.Samples) != 1 || traffic.Samples[0].State != "complete" || *traffic.Samples[0].SentBytes != 0 || *traffic.Samples[0].ReceivedBytes != 31 {
						t.Error("accepted helper evidence not durable before submit")
					}
				}
				w.WriteHeader(204)
			}))
			defer server.Close()
			client := coordinator.New(server.URL, "synthetic-credential")
			client.HTTP = server.Client()
			home := filepath.Join(dir, "codex")
			if err := privateFixtureMkdir(home, 0700); err != nil {
				t.Fatal(err)
			}
			if err := writePrivateFixture(filepath.Join(home, "auth.json"), freshSyntheticCodexAuth(), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := config.Config{CodexHome: home, LocalAccountID: "selected-local-account", Executor: config.ExecutorServices, Services: []string{"codex"}, Profile: l.Profile, Verifier: "locally-configured.invalid:7047", Prover: prover, MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second}
			code, err := submitLease(context.Background(), client, cfg, l, nil, journal)
			if lost {
				if err == nil || code != "" {
					t.Fatal("lost acceptance was treated as execution")
				}
				pending, e := journal.Pending()
				if e != nil || len(pending) != 1 {
					t.Fatal("journal lost uncertainty", e)
				}
				if e = recoverAttempt(context.Background(), client, journal, pending[0]); e != nil {
					t.Fatal(e)
				}
			} else if err != nil || code != "" {
				t.Fatal("valid acceptance failed", code, err)
			}
			raw, e := os.ReadFile(marker)
			if lost {
				if !os.IsNotExist(e) {
					t.Fatal("provider called without acceptance acknowledgement")
				}
			} else if e != nil || string(raw) != "called\n" {
				t.Fatal("synthetic helper was not called once", e)
			}
			cfg.LocalAccountID = "different-local-account"
			if _, err = submitLease(context.Background(), client, cfg, l, nil, journal); err == nil {
				t.Fatal("duplicate accepted lease executed")
			}
			pending, e := journal.Pending()
			if e != nil || len(pending) != 0 || acceptCalls.Load() != 1 || posts.Load() != 1 {
				t.Fatal("duplicate/uncertain execution was replayed", e)
			}
			entries, e := os.ReadDir(filepath.Join(dir, "attempts"))
			if e != nil {
				t.Fatal(e)
			}
			for _, entry := range entries {
				if !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				raw, e := os.ReadFile(filepath.Join(dir, "attempts", entry.Name()))
				if e != nil {
					t.Fatal(e)
				}
				var record attempts.Record
				if json.Unmarshal(raw, &record) != nil || record.State != "terminal" {
					t.Fatal("terminal metadata missing")
				}
				if lost && record.ProofTraffic != nil {
					t.Fatal("unacknowledged offer invented traffic")
				}
				if !lost && (record.ProofTraffic == nil || len(record.ProofTraffic.Samples) != 1 || len(record.Body) != 0) {
					t.Fatal("duplicate/recovery lost terminal evidence")
				}
			}
		})
	}
}
func TestCommunityProviderRejectsLegacyUnfundedLease(t *testing.T) {
	l := testLease()
	j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
	cfg := config.Config{Executor: config.ExecutorServices, Services: []string{"codex"}, Profile: l.Profile}
	if code, err := submitLease(context.Background(), coordinator.New("https://unreachable.invalid", "synthetic"), cfg, l, nil, j); err == nil || code != "invalid_lease" {
		t.Fatal("legacy lease authorized provider work")
	}
	pending, err := j.Pending()
	if err != nil || len(pending) != 0 {
		t.Fatal("legacy lease touched execution journal", err)
	}
}

func TestCodexAdmissionRechecksSelectedProfileBeforeAcceptance(t *testing.T) {
	for _, change := range []string{"deleted", "replaced-expired", "replaced-unknown", "replaced-malformed", "replaced-too-short"} {
		t.Run(change, func(t *testing.T) {
			p := multiPool(t)
			selected, ok := p.acquireAccount("codex")
			if !ok || selected.id != "one" {
				t.Fatal("fresh account was not selected")
			}
			defer p.finishAccount(selected, "auth_required")
			l := communityOffer(t)
			path := filepath.Join(selected.config.CodexHome, "auth.json")
			var err error
			switch change {
			case "deleted":
				err = os.Remove(path)
			case "replaced-expired":
				err = writePrivateFixture(path, syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600)
			case "replaced-unknown":
				err = writePrivateFixture(path, []byte(`{"tokens":{"access_token":"synthetic-opaque","account_id":"synthetic"}}`), 0600)
			case "replaced-malformed":
				err = writePrivateFixture(path, []byte(`{"tokens":`), 0600)
			case "replaced-too-short":
				err = writePrivateFixture(path, syntheticCodexAuth(l.LeaseDeadline.Add(codexAdmissionClockMargin)), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			client := coordinator.New(server.URL, "synthetic-credential")
			client.HTTP = server.Client()
			j := testJournal(t, filepath.Join(privateTestDir(t), "attempts"))
			c := selected.config
			c.Profile = l.Profile
			// An executable that would fail the test if invoked, even without a
			// provider. Insufficient credentials must return before spawning it.
			marker := filepath.Join(privateTestDir(t), "synthetic-provider-called")
			c.Prover = marker + "-helper"
			if err := os.WriteFile(c.Prover, []byte("#!/bin/sh\nprintf called > '"+marker+"'\nexit 1\n"), 0700); err != nil {
				t.Fatal(err)
			}
			code, err := submitLease(context.Background(), client, c, l, nil, j)
			if code != codexLocalAuthExpired || err == nil || calls.Load() != 0 {
				t.Fatal("invalid selected profile funded or submitted an offer")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("provider helper executed without valid selected credentials")
			}
			pending, err := j.Pending()
			if err != nil || len(pending) != 0 {
				t.Fatal("locally unaccepted offer became execution uncertainty")
			}
			// A healthy alternate profile must not substitute for the pinned one.
			other, ok := p.acquireAccount("codex")
			if !ok || other.id != "two" {
				t.Fatal("unrelated profile was blocked")
			}
			other.config.Profile = l.Profile
			if _, err := submitLease(context.Background(), client, other.config, l, nil, j); err == nil || calls.Load() != 0 {
				t.Fatal("local rejection switched accounts or replayed acceptance")
			}
			p.finishAccount(other, "")
		})
	}
}

func TestUnavailableCodexOfferNeverFundsThroughRejection(t *testing.T) {
	p := poolFixture(t, "codex")
	c := p.config
	c.Executor, c.Profile = config.ExecutorServices, "standard"
	c.Credential, c.NodeID = "synthetic-credential", "synthetic-node"
	c.JournalLimits = attempts.DefaultLimits()
	if err := writePrivateFixture(filepath.Join(c.CodexHome, "auth.json"), syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	var heartbeats, providerReports atomic.Int32
	l := communityOffer(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/v1/heartbeat" {
			providerReports.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var heartbeat coordinator.Heartbeat
		if json.NewDecoder(r.Body).Decode(&heartbeat) != nil || heartbeat.Capacity != 0 || heartbeat.State != "exhausted" {
			t.Error("expired account advertised usable capacity")
		}
		if heartbeats.Add(1) == 1 {
			// Even an unsolicited offer delivered to a blocked node cannot
			// trigger the rejection helper's funded acceptance.
			json.NewEncoder(w).Encode(map[string]any{"lease": l})
		} else {
			writer.Close()
			io.WriteString(w, `{"lease":null}`)
		}
	}))
	defer server.Close()
	c.Coordinator = server.URL
	c.CoordinatorCA = filepath.Join(privateTestDir(t), "synthetic-coordinator-ca.pem")
	if err := writePrivateFixture(c.CoordinatorCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- runWithOwner(c, reader) }()
	select {
	case err := <-done:
		if err != nil || providerReports.Load() != 0 || heartbeats.Load() < 2 {
			t.Fatal("blocked offer called acceptance or failure-report HTTP", err)
		}
	case <-time.After(10 * time.Second):
		writer.Close()
		t.Fatal("synthetic node did not stop")
	}
}
