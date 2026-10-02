package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

func testJournal(t *testing.T, dir string) *attempts.Journal {
	t.Helper()
	j, e := attempts.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { j.Close() })
	return j
}
func testLease() coordinator.Lease {
	return coordinator.Lease{Version: coordinator.Version, JobID: "synthetic", SignedJobID: "committed", Profile: "standard", ModelID: "gpt-5.6-luna", Prompt: "hello", InputSHA256: worker.SHA("hello"), MaxInputTokens: 100, MaxOutputTokens: 20, Attempt: "1", Fence: "f1", LeaseDeadline: time.Now().Add(time.Minute).UTC(), SettlementDeadline: time.Now().Add(time.Minute).UTC()}
}
func TestLostSubmitAcknowledgementReconcilesWithoutProviderReplay(t *testing.T) {
	var providerCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		io.WriteString(w, `{"model":"gpt-5.6-luna","choices":[{"message":{"content":"synthetic answer"},"finish_reason":"stop"}],"usage_source":"upstream","usage":{"prompt_tokens":8,"completion_tokens":4}}`)
	}))
	defer provider.Close()
	var submissions atomic.Int32
	var committed atomic.Value
	l := testLease()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Error("credential missing")
		}
		if r.Method == http.MethodPost {
			submissions.Add(1)
			raw, _ := io.ReadAll(r.Body)
			committed.Store(attempts.Hash(raw))
			conn, _, e := w.(http.Hijacker).Hijack()
			if e != nil {
				t.Error(e)
				return
			}
			conn.Close()
			return
		}
		if r.URL.Query().Get("attempt") != l.Attempt || r.URL.Query().Get("fence") != l.Fence {
			t.Error("unbound recovery query")
		}
		json.NewEncoder(w).Encode(coordinator.AttemptStatus{Version: coordinator.Version, JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, State: "accepted", ReplaySafe: true, SubmissionSHA256: committed.Load().(string)})
	}))
	defer server.Close()
	client := coordinator.New(server.URL, "synthetic-token")
	dir := filepath.Join(t.TempDir(), "attempts")
	j := testJournal(t, dir)
	cfg := config.Config{Executor: config.ExecutorGateway, Profile: l.Profile, Gateway: provider.URL, MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: time.Second}
	if code, e := submitLease(context.Background(), client, cfg, l, nil, j); e == nil || code != "" {
		t.Fatal("did not preserve lost acknowledgement", code, e)
	}
	if _, e := submitLease(context.Background(), client, cfg, l, nil, j); e == nil {
		t.Fatal("duplicate lease executed")
	}
	j.Close()
	j = testJournal(t, dir)
	pending, e := j.Pending()
	if e != nil || len(pending) != 1 {
		t.Fatal(e)
	}
	if e = recoverAttempt(context.Background(), client, j, pending[0]); e != nil {
		t.Fatal(e)
	}
	pending, e = j.Pending()
	if e != nil || len(pending) != 0 {
		t.Fatal(e)
	}
	if providerCalls.Load() != 1 || submissions.Load() != 1 {
		t.Fatal("provider or accepted report replayed")
	}
}
func TestRecoveryLiveUsesExactBodyAndUncertainCallsNeverRerun(t *testing.T) {
	for _, state := range []string{"started", "ready"} {
		t.Run(state, func(t *testing.T) {
			j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
			l := testLease()
			r, e := attemptRecord(l)
			if e != nil {
				t.Fatal(e)
			}
			if e = j.Begin(r); e != nil {
				t.Fatal(e)
			}
			r.State = "started"
			want := []byte("{\n \"version\":\"node-v1\", \"attempt\":\"1\", \"fence\":\"f1\"\n}")
			if state == "ready" {
				r, e = j.Ready(r, "proven", want)
				if e != nil {
					t.Fatal(e)
				}
			}
			posts := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodGet {
					json.NewEncoder(w).Encode(coordinator.AttemptStatus{Version: coordinator.Version, JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, State: "live", ReplaySafe: true})
					return
				}
				posts++
				raw, _ := io.ReadAll(req.Body)
				if state == "started" {
					var failure coordinator.Failure
					if json.Unmarshal(raw, &failure) != nil || failure.Code != "execution_uncertain" || req.URL.Path != "/api/node/v1/jobs/synthetic/fail" {
						t.Error("uncertainty was not reported")
					}
				} else if string(raw) != string(want) {
					t.Error("report changed")
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			if e = recoverAttempt(context.Background(), coordinator.New(server.URL, "synthetic"), j, r); e != nil {
				t.Fatal(e)
			}
			pending, e := j.Pending()
			if e != nil || len(pending) != 0 || posts != 1 {
				t.Fatal("not resolved", e)
			}
		})
	}
}
func TestRecoveryRejectsWrongIdentityOldContractAndDifferentReceipt(t *testing.T) {
	for _, failure := range []string{"identity", "old-contract", "wrong-receipt", "missing-receipt", "malformed-receipt", "pending", "fenced", "unsupported"} {
		t.Run(failure, func(t *testing.T) {
			j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
			l := testLease()
			r, _ := attemptRecord(l)
			if e := j.Begin(r); e != nil {
				t.Fatal(e)
			}
			r, e := j.Ready(r, "proven", []byte(`{"version":"node-v1"}`))
			if e != nil {
				t.Fatal(e)
			}
			status := coordinator.AttemptStatus{Version: coordinator.Version, JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, State: "accepted", ReplaySafe: true, SubmissionSHA256: r.SubmissionSHA256}
			switch failure {
			case "identity":
				status.Fence = "other"
			case "old-contract":
				status.ReplaySafe = false
			case "wrong-receipt":
				status.SubmissionSHA256 = attempts.Hash([]byte("other"))
			case "missing-receipt":
				status.SubmissionSHA256 = ""
			case "malformed-receipt":
				status.SubmissionSHA256 = "invalid"
			case "pending":
				status.State = "proof_pending"
			case "fenced":
				status.State = "fenced"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet {
					t.Error("unexpected report retry")
				}
				if failure == "unsupported" {
					w.WriteHeader(404)
					return
				}
				json.NewEncoder(w).Encode(status)
			}))
			defer server.Close()
			e = recoverAttempt(context.Background(), coordinator.New(server.URL, "synthetic"), j, r)
			if (e == nil) != (failure == "pending" || failure == "fenced") {
				t.Fatal("wrong recovery outcome", e)
			}
			pending, e := j.Pending()
			if e != nil {
				t.Fatal(e)
			}
			if (len(pending) == 0) != (failure == "fenced") {
				t.Fatal("lost unresolved attempt")
			}
		})
	}
}
func TestInvalidJournalOrJobDoesNotCallProvider(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
	j.Close()
	l := testLease()
	cfg := config.Config{Executor: config.ExecutorGateway, Profile: l.Profile, Gateway: server.URL, MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: time.Second}
	if _, e := submitLease(context.Background(), coordinator.New(server.URL, "synthetic"), cfg, l, nil, j); e == nil {
		t.Fatal("ran with closed journal")
	}
	j = testJournal(t, filepath.Join(t.TempDir(), "attempts"))
	l.JobID = "unsafe/job"
	if _, e := submitLease(context.Background(), coordinator.New(server.URL, "synthetic"), cfg, l, nil, j); e == nil {
		t.Fatal("ran invalid job")
	}
	if calls.Load() != 0 {
		t.Fatal("unsafe lease reached provider")
	}
}

func TestProofIngestionCanStayPendingWithoutRerun(t *testing.T) {
	j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
	l := testLease()
	r, _ := attemptRecord(l)
	if e := j.Begin(r); e != nil {
		t.Fatal(e)
	}
	r, e := j.Ready(r, "proven", []byte(`{"version":"node-v1","attempt":"1","fence":"f1"}`))
	if e != nil {
		t.Fatal(e)
	}
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodPost {
			posts.Add(1)
			w.WriteHeader(202)
			return
		}
		json.NewEncoder(w).Encode(coordinator.AttemptStatus{Version: coordinator.Version, JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, ReplaySafe: true, State: "proof_pending"})
	}))
	defer server.Close()
	client := coordinator.New(server.URL, "synthetic")
	if e := submitRecord(context.Background(), client, j, r); e != nil {
		t.Fatal(e)
	}
	if e := recoverAttempt(context.Background(), client, j, r); e != nil {
		t.Fatal(e)
	}
	pending, e := j.Pending()
	if e != nil || len(pending) != 1 || posts.Load() != 1 {
		t.Fatal("pending proof was discarded or repeated", e)
	}
}
