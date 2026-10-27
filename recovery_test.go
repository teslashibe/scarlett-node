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

// pendingRecords writes n started records for distinct jobs, the i-th due
// (n-i) seconds after deadline, so that their lease deadlines run against
// the order of their job IDs.
func pendingRecords(t *testing.T, j *attempts.Journal, n int, deadline time.Time) []attempts.Record {
	t.Helper()
	records := []attempts.Record{}
	for i := range n {
		l := testLease()
		l.JobID = fmt.Sprintf("synthetic-%02d", i)
		l.LeaseDeadline = deadline.Add(time.Duration(n-i) * time.Second)
		r, err := attemptRecord(l)
		if err != nil {
			t.Fatal(err)
		}
		if err = j.Begin(r); err != nil {
			t.Fatal(err)
		}
		records = append(records, r)
	}
	return records
}

// attemptJob is the job ID of an attempt read or report.
func attemptJob(req *http.Request) string { return strings.Split(req.URL.Path, "/")[5] }

// expireWaits makes every record's wait run out.
func expireWaits(idle *idleReconciler) {
	for key, w := range idle.waits {
		w.at = time.Now().Add(-time.Second)
		idle.waits[key] = w
	}
}

// One idle pass reads at most reconcilePassRecords records, earliest lease
// deadline first and any past it last; the next follows soon while records
// are left unread, and a record read and left pending waits for later ones.
func TestReconcileIdleCapsAndOrders(t *testing.T) {
	j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
	records := pendingRecords(t, j, 11, time.Now().Add(time.Minute))
	// One more record is past its deadline: it can only be closed.
	l := testLease()
	l.JobID, l.LeaseDeadline = "synthetic-past", time.Now().Add(-time.Minute)
	past, _ := attemptRecord(l)
	if err := j.Begin(past); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	read := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		read = append(read, attemptJob(req))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, `{"error":{"code":"attempt_conflict","message":"x"}}`)
	}))
	defer server.Close()
	client := coordinator.New(server.URL, "synthetic")
	want := []string{}
	for i := len(records) - 1; i >= 0; i-- {
		want = append(want, records[i].JobID)
	}
	want = append(want, past.JobID)
	var idle idleReconciler
	pass := func(reads []string, next time.Duration) {
		t.Helper()
		mu.Lock()
		read = read[:0]
		mu.Unlock()
		if err := idle.reconcileIdle(context.Background(), client, j, map[string]bool{}); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if strings.Join(read, ",") != strings.Join(reads, ",") {
			t.Fatalf("read %v, want %v", read, reads)
		}
		if now := time.Now(); idle.due(now.Add(next-time.Second)) || !idle.due(now.Add(next)) {
			t.Fatalf("next pass in %v, want %v", idle.next.Sub(now), next)
		}
	}
	pass(want[:reconcilePassRecords], reconcileBacklogInterval)
	pass(want[reconcilePassRecords:], reconcileInterval)
	// Every record now waits; once the waits run out the order is the same.
	pass(nil, reconcileInterval)
	expireWaits(&idle)
	pass(want[:reconcilePassRecords], reconcileBacklogInterval)
	if pending, _ := j.Pending(); len(pending) != len(want) {
		t.Fatal("records settled on a conflict", len(pending))
	}
}

// A pass stops at the first 429, 502, 503, 504 or transport failure, and the
// next one waits the longer of the interval and the coordinator's
// Retry-After. A 429 limits the node, so the record it answered is first
// again; any other stop puts the record off like a failure.
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
		{http.StatusGatewayTimeout, "", reconcileInterval},
		{0, "", reconcileInterval},
	} {
		j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
		records := pendingRecords(t, j, 3, time.Now().Add(time.Minute))
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
		_, waits := idle.waits[records[2].Key()]
		if waits != (tc.status != http.StatusTooManyRequests) || len(idle.waits) > 1 {
			t.Fatalf("%d: waits %v", tc.status, idle.waits)
		}
	}
}

// A record the coordinator keeps failing on, with a 500, a 503 or no answer
// in reconcileRecordTimeout, never holds the others back: a 500 concerns the
// record alone and the pass goes on, and a record that stopped a pass waits
// before it is read again.
func TestReconcileIdleOneFailingRecordHoldsNoneBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply func(w http.ResponseWriter, req *http.Request)
		first int32 // reads in the first pass
	}{
		{"500", func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, 4},
		{"503", func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }, 1},
		{"no answer", func(w http.ResponseWriter, req *http.Request) { <-req.Context().Done() }, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
			records := pendingRecords(t, j, 4, time.Now().Add(time.Minute))
			bad := records[3].JobID // the earliest deadline
			var mu sync.Mutex
			read := map[string]int{}
			var gets atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				gets.Add(1)
				mu.Lock()
				read[attemptJob(req)]++
				mu.Unlock()
				if attemptJob(req) == bad {
					tc.reply(w, req)
					return
				}
				w.WriteHeader(http.StatusConflict)
			}))
			defer server.Close()
			client := coordinator.New(server.URL, "synthetic")
			var idle idleReconciler
			started := time.Now()
			if err := idle.reconcileIdle(context.Background(), client, j, map[string]bool{}); err != nil || gets.Load() != tc.first {
				t.Fatalf("first pass: %d reads, %v", gets.Load(), err)
			}
			if tc.name == "no answer" {
				if took := time.Since(started); took < reconcileRecordTimeout || took > reconcileRecordTimeout+time.Second {
					t.Fatalf("record cut after %v", took)
				}
			}
			if err := idle.reconcileIdle(context.Background(), client, j, map[string]bool{}); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			for _, r := range records {
				if read[r.JobID] != 1 {
					t.Fatalf("reads %v", read)
				}
			}
		})
	}
}

// The pass budget only decides whether another record starts: a record whose
// read takes longer is answered, not cut, and the records after it are read
// by the next pass, which follows after reconcileBacklogInterval.
func TestReconcileIdleKeepsToItsBudget(t *testing.T) {
	j := testJournal(t, filepath.Join(t.TempDir(), "attempts"))
	records := pendingRecords(t, j, 3, time.Now().Add(time.Minute))
	slow := records[2].JobID // the earliest deadline
	var gets atomic.Int32
	var cut atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gets.Add(1)
		if attemptJob(req) == slow {
			select {
			case <-time.After(reconcilePassBudget + 500*time.Millisecond):
			case <-req.Context().Done():
				cut.Store(true)
				return
			}
		}
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	client := coordinator.New(server.URL, "synthetic")
	var idle idleReconciler
	started := time.Now()
	if err := idle.reconcileIdle(context.Background(), client, j, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(started); took < reconcilePassBudget || took > reconcilePassBudget+1500*time.Millisecond || gets.Load() != 1 || cut.Load() {
		t.Fatalf("pass took %v for %d reads, cut %v", took, gets.Load(), cut.Load())
	}
	if _, ok := idle.waits[records[2].Key()]; !ok || idle.due(time.Now().Add(reconcileBacklogInterval-time.Second)) || !idle.due(time.Now().Add(reconcileBacklogInterval)) {
		t.Fatal("slow record not counted as read, or the backlog not picked up soon", idle.waits, idle.next.Sub(time.Now()))
	}
	if err := idle.reconcileIdle(context.Background(), client, j, map[string]bool{}); err != nil || gets.Load() != 3 {
		t.Fatal("the rest were not read next", gets.Load(), err)
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
	if gets.Load() != 1 || idle.waits[r.Key()].wait != reconcileRetryWait {
		t.Fatalf("%d reads, wait %v", gets.Load(), idle.waits[r.Key()].wait)
	}
	for _, want := range []time.Duration{2 * reconcileRetryWait, 4 * reconcileRetryWait, 8 * reconcileRetryWait, reconcileRetryWaitCap, reconcileRetryWaitCap} {
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
