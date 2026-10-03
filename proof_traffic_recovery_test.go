//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

func TestProofTrafficRecoveryOnlyRepostsOriginalReport(t *testing.T) {
	l := communityOffer(t)
	dir := t.TempDir()
	marker, prover := filepath.Join(dir, "calls"), filepath.Join(dir, "synthetic-prover")
	script := "#!/bin/sh\nprintf 'called\\n' >> '" + marker + "'\nprintf '{\"status\":\"proof_sent\",\"verifier_sent_bytes\":19,\"verifier_received_bytes\":31,\"verifier_transport_layer\":\"tcp_payload\"}\\n'\n"
	if err := os.WriteFile(prover, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	j := testJournal(t, filepath.Join(dir, "attempts"))
	var posts atomic.Int32
	var firstBody []byte
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/accept") {
			a := l
			a.VerifierToken = strings.Repeat("c", 64)
			json.NewEncoder(w).Encode(coordinator.LeaseAcceptance{Version: coordinator.Version, State: "leased", FundingAuthority: "production_receipt", Lease: a})
			return
		}
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(coordinator.AttemptStatus{Version: coordinator.Version, JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, State: "live", ReplaySafe: true})
			return
		}
		body, _ := io.ReadAll(r.Body)
		if posts.Add(1) == 1 {
			firstBody = body
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !bytes.Equal(body, firstBody) {
			t.Error("recovery changed exact report")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer s.Close()
	client := coordinator.New(s.URL, "synthetic-credential")
	client.HTTP = s.Client()
	home := filepath.Join(dir, "codex")
	if err := privateFixtureMkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFixture(filepath.Join(home, "auth.json"), freshSyntheticCodexAuth(), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{CodexHome: home, LocalAccountID: "synthetic-account", Executor: config.ExecutorServices, Services: []string{"codex"}, Profile: l.Profile, Verifier: "synthetic.invalid:7047", Prover: prover, MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second}
	if _, err := submitLease(context.Background(), client, cfg, l, nil, j); err == nil {
		t.Fatal("lost report was acknowledged")
	}
	pending, err := j.Pending()
	if err != nil || len(pending) != 1 || pending[0].State != "ready" {
		t.Fatal("ready evidence missing", err)
	}
	before := pending[0].ProofTraffic
	if before == nil || !before.WorkerFinished || pending[0].SubmissionSHA256 != attempts.Hash(firstBody) {
		t.Fatal("ready telemetry/report mismatch")
	}
	if err := recoverAttempt(context.Background(), client, j, pending[0]); err != nil {
		t.Fatal(err)
	}
	calls, err := os.ReadFile(marker)
	if err != nil || string(calls) != "called\n" || posts.Load() != 2 {
		t.Fatal("recovery repeated provider", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "attempts", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var terminal attempts.Record
		if json.Unmarshal(raw, &terminal) != nil || terminal.State != "terminal" || !reflect.DeepEqual(terminal.ProofTraffic, before) || terminal.SubmissionSHA256 != attempts.Hash(firstBody) || len(terminal.Body) != 0 {
			t.Fatal("recovery changed retained telemetry")
		}
	}
}
