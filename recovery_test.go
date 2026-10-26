package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// fastReportRetries shortens the in-place report retries for one test.
func fastReportRetries(t *testing.T) {
	t.Helper()
	saved := reportRetryBackoff
	reportRetryBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { reportRetryBackoff = saved })
}

// Every answer to the report is lost: the worker sends the same journal body
// again in place, never the provider call, and then leaves the record to
// recovery, which finds the report accepted and posts nothing more.
func TestLostSubmitAcknowledgementReconcilesWithoutProviderReplay(t *testing.T) {
	fastReportRetries(t)
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
			if old, ok := committed.Load().(string); ok && old != attempts.Hash(raw) {
				t.Error("retried report changed")
			}
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
	if providerCalls.Load() != 1 || submissions.Load() != int32(1+len(reportRetryBackoff)) {
		t.Fatal("provider or accepted report replayed", providerCalls.Load(), submissions.Load())
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
	for _, failure := range []string{"identity", "old-contract", "wrong-receipt", "malformed-receipt", "pending", "fenced", "unsupported"} {
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

// The coordinator completed a relay web job from the verifier's event feed
// (design C2) and the node's report never reached it: the attempt reads
// accepted, or failed for a rejection, with no receipt. Recovery ends the
// record without reposting, rather than retrying it until the journal purges it.
func TestRecoveryEndsAnAttemptTheVerifierDecidedWithoutTheReport(t *testing.T) {
	for _, tc := range []struct{ state, kind string }{{"accepted", "proven"}, {"failed", "fail"}, {"accepted", "fail"}} {
		t.Run(tc.state+"-"+tc.kind, func(t *testing.T) {
			j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
			l := testLease()
			r, _ := attemptRecord(l)
			if e := j.Begin(r); e != nil {
				t.Fatal(e)
			}
			r, e := j.Ready(r, tc.kind, []byte(`{"version":"node-v2","attempt":"1","fence":"f1"}`))
			if e != nil {
				t.Fatal(e)
			}
			var gets, posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method != http.MethodGet {
					posts.Add(1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				gets.Add(1)
				json.NewEncoder(w).Encode(coordinator.AttemptStatus{Version: coordinator.Version, JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, State: tc.state, ReplaySafe: true})
			}))
			defer server.Close()
			client := coordinator.New(server.URL, "synthetic")
			if e = recoverAttempt(context.Background(), client, j, r); e != nil {
				t.Fatal(e)
			}
			pending, e := j.Pending()
			if e != nil || len(pending) != 0 || gets.Load() != 1 || posts.Load() != 0 {
				t.Fatalf("pending %d, gets %d, posts %d, %v", len(pending), gets.Load(), posts.Load(), e)
			}
			// Idle reconciliation finds nothing left to retry.
			if e = (&idleReconciler{}).reconcileIdle(context.Background(), client, j, map[string]bool{}); e != nil || gets.Load() != 1 {
				t.Fatal("record retried", e, gets.Load())
			}
		})
	}
}

// acceptRefusalServer answers every acceptance with the next of replies
// (status, Retry-After, code) and counts rejections and attempt reads.
func acceptRefusalServer(t *testing.T, replies [][3]string) (*coordinator.Client, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var accepts, others atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/accept") {
			others.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		reply := replies[min(int(accepts.Add(1))-1, len(replies)-1)]
		if reply[1] != "" {
			w.Header().Set("Retry-After", reply[1])
		}
		w.Header().Set("Content-Type", "application/json")
		status, _ := strconv.Atoi(reply[0])
		w.WriteHeader(status)
		if reply[2] != "" {
			json.NewEncoder(w).Encode(coordinator.ErrorReply{Error: coordinator.ErrorDetail{Code: reply[2], Message: "synthetic"}})
		}
	}))
	t.Cleanup(server.Close)
	client := coordinator.New(server.URL, "synthetic-credential")
	client.HTTP = server.Client()
	return client, &accepts, &others
}

// An acceptance the coordinator refused in a way that proves it holds no
// lease for this node ends its journal record at once, sends no rejection and
// is logged as an accept failure; one left in doubt stays for reconciliation.
func TestAcceptRefusalEndsTheRecordAtOnce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		replies  [][3]string
		terminal bool
	}{
		{"429 without Retry-After", [][3]string{{"429", "", "rate_limited"}}, true},
		{"429 with a long Retry-After", [][3]string{{"429", "30", "rate_limited"}}, true},
		{"400", [][3]string{{"400", "", "invalid_request"}}, true},
		{"401", [][3]string{{"401", "", "node_unauthorized"}}, true},
		{"404", [][3]string{{"404", "", "attempt_unavailable"}}, true},
		{"409", [][3]string{{"409", "", "attempt_conflict"}}, true},
		{"503", [][3]string{{"503", "", "dispatch_unavailable"}}, false},
		{"502", [][3]string{{"502", "", ""}}, false},
		{"429 after a 503 that may have committed", [][3]string{{"503", "1", "network_unavailable"}, {"429", "", "rate_limited"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := renewalOffer()
			client, accepts, others := acceptRefusalServer(t, tc.replies)
			j := testJournal(t, filepath.Join(privateTestDir(t), "attempts"))
			home := filepath.Join(privateTestDir(t), "codex")
			privateFixtureMkdir(home, 0700)
			if err := writePrivateFixture(filepath.Join(home, "auth.json"), freshSyntheticCodexAuth(), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := config.Config{CodexHome: home, LocalAccountID: "one", Executor: config.ExecutorServices, Services: []string{"codex"}, Profile: l.Profile}
			code, err := submitLease(context.Background(), client, cfg, l, nil, j)
			if err == nil || code != "" || submitStage(err) != "accept" {
				t.Fatal("refused acceptance", code, err)
			}
			pending, perr := j.Pending()
			if perr != nil || (len(pending) == 0) != tc.terminal || accepts.Load() != int32(len(tc.replies)) || others.Load() != 0 {
				t.Fatalf("pending %d, accepts %d, other requests %d, %v", len(pending), accepts.Load(), others.Load(), perr)
			}
		})
	}
}

// The worker retries its own report in place when the coordinator could not
// take it just then, honouring Retry-After, and sends the exact journal body
// each time; a refusal is final.
func TestReportRetriesInPlace(t *testing.T) {
	fastReportRetries(t)
	for _, tc := range []struct {
		name     string
		replies  [][3]string
		posts    int32
		terminal bool
		slow     bool
	}{
		{"rate limited, then stored", [][3]string{{"429", "", "rate_limited"}, {"429", "", "rate_limited"}, {"200", "", ""}}, 3, true, false},
		{"Retry-After honoured", [][3]string{{"429", "1", "rate_limited"}, {"204", "", ""}}, 2, true, true},
		{"network unavailable, then stored", [][3]string{{"503", "", "network_unavailable"}, {"200", "", ""}}, 2, true, false},
		{"rate limited throughout", [][3]string{{"429", "", "rate_limited"}}, 4, false, false},
		{"other 503 is final", [][3]string{{"503", "", "dispatch_unavailable"}, {"200", "", ""}}, 1, false, false},
		{"conflict is final", [][3]string{{"409", "", "attempt_conflict"}, {"200", "", ""}}, 1, false, false},
		{"Retry-After past the budget", [][3]string{{"429", "30", "rate_limited"}, {"200", "", ""}}, 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
			l := testLease()
			r, _ := attemptRecord(l)
			if e := j.Begin(r); e != nil {
				t.Fatal(e)
			}
			body := []byte(`{"version":"node-v2","attempt":"1","fence":"f1"}`)
			r, e := j.Ready(r, "proven", body)
			if e != nil {
				t.Fatal(e)
			}
			var posts atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				raw, _ := io.ReadAll(req.Body)
				if req.Method != http.MethodPost || string(raw) != string(body) {
					t.Error("report changed or not a report")
				}
				reply := tc.replies[min(int(posts.Add(1))-1, len(tc.replies)-1)]
				if reply[1] != "" {
					w.Header().Set("Retry-After", reply[1])
				}
				status, _ := strconv.Atoi(reply[0])
				w.WriteHeader(status)
				if reply[2] != "" {
					json.NewEncoder(w).Encode(coordinator.ErrorReply{Error: coordinator.ErrorDetail{Code: reply[2], Message: "synthetic"}})
				}
			}))
			defer server.Close()
			started := time.Now()
			err := submitReport(context.Background(), coordinator.New(server.URL, "synthetic"), j, r, l.LeaseDeadline)
			pending, perr := j.Pending()
			if (err == nil) != tc.terminal || perr != nil || (len(pending) == 0) != tc.terminal || posts.Load() != tc.posts {
				t.Fatalf("err %v, pending %d, posts %d", err, len(pending), posts.Load())
			}
			if took := time.Since(started); tc.slow != (took >= time.Second) {
				t.Fatal("waited", took)
			}
		})
	}
	// No retry waits past the deadline it is given.
	j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
	l := testLease()
	r, _ := attemptRecord(l)
	if e := j.Begin(r); e != nil {
		t.Fatal(e)
	}
	r, _ = j.Ready(r, "fail", []byte(`{"version":"node-v2"}`))
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		posts.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()
	if err := submitReport(context.Background(), coordinator.New(server.URL, "synthetic"), j, r, time.Now()); err == nil || posts.Load() != 1 {
		t.Fatal("retried past the deadline", err, posts.Load())
	}
}

// pendingRecords writes n started records for distinct jobs.
func pendingRecords(t *testing.T, j *attempts.Journal, n int) {
	t.Helper()
	for i := range n {
		l := testLease()
		l.JobID = fmt.Sprintf("synthetic-%02d", i)
		r, err := attemptRecord(l)
		if err != nil {
			t.Fatal(err)
		}
		if err = j.Begin(r); err != nil {
			t.Fatal(err)
		}
	}
}

// One idle pass reads at most reconcilePassRecords records, and the next
// starts where it stopped, so every record is read in turn.
func TestReconcileIdleCapsAndRotates(t *testing.T) {
	j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
	pendingRecords(t, j, 12)
	var mu sync.Mutex
	read := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		read = append(read, strings.Split(req.URL.Path, "/")[5])
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"error":{"code":"attempt_conflict","message":"x"}}`)
	}))
	defer server.Close()
	client := coordinator.New(server.URL, "synthetic")
	var idle idleReconciler
	for range 3 {
		if err := idle.reconcileIdle(context.Background(), client, j, map[string]bool{}); err != nil {
			t.Fatal(err)
		}
	}
	pending, _ := j.Pending()
	order := []string{}
	for _, r := range pending {
		order = append(order, r.JobID)
	}
	// Three passes of eight over twelve records read each one twice, in order.
	want := append(append([]string{}, order...), order...)
	if len(pending) != 12 || strings.Join(read, ",") != strings.Join(want, ",") {
		t.Fatalf("read %v, want %v", read, want)
	}
	if !idle.due(time.Now().Add(reconcileInterval)) || idle.due(time.Now().Add(reconcileInterval-time.Second)) {
		t.Fatal("next pass not paced by the interval")
	}
}

// A pass stops at the first 429, 5xx or transport failure, and the next one
// waits the longer of the interval and the coordinator's Retry-After.
func TestReconcileIdleStopsWhenTheCoordinatorCannotTakeMore(t *testing.T) {
	for _, tc := range []struct {
		status     int
		retryAfter string
		wait       time.Duration
	}{
		{http.StatusTooManyRequests, "45", 45 * time.Second},
		{http.StatusTooManyRequests, "", reconcileInterval},
		{http.StatusTooManyRequests, "5", reconcileInterval},
		{http.StatusServiceUnavailable, "", reconcileInterval},
		{http.StatusBadGateway, "", reconcileInterval},
		{0, "", reconcileInterval},
	} {
		j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
		pendingRecords(t, j, 3)
		var gets atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			gets.Add(1)
			if tc.status == 0 {
				conn, _, _ := w.(http.Hijacker).Hijack()
				conn.Close()
				return
			}
			if tc.retryAfter != "" {
				w.Header().Set("Retry-After", tc.retryAfter)
			}
			w.WriteHeader(tc.status)
		}))
		var idle idleReconciler
		started := time.Now()
		err := idle.reconcileIdle(context.Background(), coordinator.New(server.URL, "synthetic"), j, map[string]bool{})
		server.Close()
		if err != nil || gets.Load() != 1 {
			t.Fatalf("%d: %d reads, %v", tc.status, gets.Load(), err)
		}
		if idle.due(started.Add(tc.wait-time.Second)) || !idle.due(time.Now().Add(tc.wait*3/2)) {
			t.Fatalf("%d %q: next pass at %v", tc.status, tc.retryAfter, idle.next.Sub(started))
		}
		// The record the pass stopped at is the next pass's first.
		if idle.after != "" {
			t.Fatal("stopped record counted as read")
		}
	}
}

// A pass ends within reconcilePassBudget however slowly the coordinator
// answers, and the record it was reading is read first next time.
func TestReconcileIdleKeepsToItsBudget(t *testing.T) {
	j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
	pendingRecords(t, j, reconcilePassRecords)
	var gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gets.Add(1)
		time.Sleep(800 * time.Millisecond)
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	var idle idleReconciler
	started := time.Now()
	if err := idle.reconcileIdle(context.Background(), coordinator.New(server.URL, "synthetic"), j, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(started); took > reconcilePassBudget+500*time.Millisecond || gets.Load() != 3 {
		t.Fatalf("pass took %v for %d reads", took, gets.Load())
	}
	pending, _ := j.Pending()
	if idle.after != pending[1].Key() {
		t.Fatal("the cut record was counted as read")
	}
}

// A record a pass handled and left pending (the verifier is still ingesting
// its proof) is read again only after a wait that doubles, and a worker's own
// records, ready ones included, are left to it.
func TestReconcileIdleBacksOffAPendingProof(t *testing.T) {
	j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
	l := testLease()
	r, _ := attemptRecord(l)
	if e := j.Begin(r); e != nil {
		t.Fatal(e)
	}
	r, e := j.Ready(r, "proven", []byte(`{"version":"node-v2","attempt":"1","fence":"f1"}`))
	if e != nil {
		t.Fatal(e)
	}
	var gets atomic.Int32
	state := atomic.Value{}
	state.Store("proof_pending")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			t.Error("pending proof reposted")
		}
		gets.Add(1)
		json.NewEncoder(w).Encode(coordinator.AttemptStatus{Version: coordinator.Version, JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, ReplaySafe: true, State: state.Load().(string), SubmissionSHA256: r.SubmissionSHA256})
	}))
	defer server.Close()
	client := coordinator.New(server.URL, "synthetic")
	var idle idleReconciler
	if err := idle.reconcileIdle(context.Background(), client, j, map[string]bool{r.Key(): true}); err != nil || gets.Load() != 0 {
		t.Fatal("a running worker's ready record was reconciled", err)
	}
	pass := func() {
		t.Helper()
		if err := idle.reconcileIdle(context.Background(), client, j, map[string]bool{}); err != nil {
			t.Fatal(err)
		}
	}
	pass()
	pass()
	if gets.Load() != 1 || idle.waits[r.Key()].wait != reconcileProofWait {
		t.Fatalf("%d reads, wait %v", gets.Load(), idle.waits[r.Key()].wait)
	}
	for _, want := range []time.Duration{2 * reconcileProofWait, 4 * reconcileProofWait, 8 * reconcileProofWait, reconcileProofWaitCap, reconcileProofWaitCap} {
		w := idle.waits[r.Key()]
		w.at = time.Now().Add(-time.Second)
		idle.waits[r.Key()] = w
		pass()
		if idle.waits[r.Key()].wait != want {
			t.Fatalf("wait %v, want %v", idle.waits[r.Key()].wait, want)
		}
	}
	// Once accepted, the record ends and its wait is dropped.
	state.Store("accepted")
	w := idle.waits[r.Key()]
	w.at = time.Now().Add(-time.Second)
	idle.waits[r.Key()] = w
	pass()
	pass()
	if pending, _ := j.Pending(); len(pending) != 0 || len(idle.waits) != 0 {
		t.Fatal("accepted proof still pending", len(pending), idle.waits)
	}
}
