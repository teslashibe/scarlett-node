package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
			script := "#!/bin/sh\nprintf 'called\\n' >> '" + marker + "'\nprintf '{\"status\":\"proof_sent\"}\\n'\n"
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
				}
				w.WriteHeader(204)
			}))
			defer server.Close()
			client := coordinator.New(server.URL, "synthetic-credential")
			client.HTTP = server.Client()
			cfg := config.Config{LocalAccountID: "selected-local-account", Executor: config.ExecutorServices, Services: []string{"codex"}, Profile: l.Profile, Verifier: "locally-configured.invalid:7047", Prover: prover, MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second}
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
