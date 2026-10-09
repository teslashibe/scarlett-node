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
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
)

func TestDiagnosticMetadataExcludesPrivateLeaseContent(t *testing.T) {
	store := diagnostics.New(privateTestDir(t))
	l := testLease()
	l.ServiceType = "x_read"
	l.XRequest = &coordinator.XRequest{Operation: "search", Query: "PRIVATE_QUERY", Username: "PRIVATE_HANDLE", Pages: 3}
	l.XPayload = []byte(`{"proof_mode":"relay","private":"PRIVATE_PLAN"}`)
	l.VerifierToken = "PRIVATE_TOKEN"
	a := beginLeaseDiagnostics(store, l)
	a.Finish("x_request_failed")
	raw, err := json.Marshal(store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{l.Prompt, "PRIVATE_QUERY", "PRIVATE_HANDLE", "PRIVATE_PLAN", "PRIVATE_TOKEN", `"fence"`, `"job_id"`} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private lease data entered diagnostics")
		}
	}
	records := store.Snapshot().Attempts
	if len(records) != 1 || records[0].Operation != "search" || records[0].Pages != 3 || records[0].ProofMode != "relay" || records[0].Outcome != "x_request_failed" {
		t.Fatal("finite workload labels or failure outcome lost")
	}
	var disabled *diagnostics.Store
	if beginLeaseDiagnostics(disabled, l).Context(context.Background()) == nil {
		t.Fatal("disabled context unavailable")
	}
}

// A search is labelled with its page count, one to ten, so a ten-page search
// gets its own row; a count past the bound is clamped and never refused.
func TestDiagnosticSearchPagesUpToTen(t *testing.T) {
	for _, tc := range []struct{ pages, want int }{{1, 1}, {3, 3}, {4, 4}, {10, 10}, {11, 10}} {
		store := diagnostics.New(privateTestDir(t))
		l := testLease()
		l.ServiceType = "x_read"
		l.XRequest = &coordinator.XRequest{Operation: "search", Query: "synthetic", Count: 20, Pages: tc.pages}
		beginLeaseDiagnostics(store, l).Finish("success")
		records := store.Snapshot().Attempts
		if len(records) != 1 || records[0].Operation != "search" || records[0].Pages != tc.want {
			t.Fatalf("%d pages recorded as %+v", tc.pages, records)
		}
	}
}

func TestDiagnosticsPreserveReportsWhenStorageFails(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusPartialContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			dir := privateTestDir(t)
			// A directory where the optional history file belongs rejects publication.
			if err := os.Mkdir(filepath.Join(dir, "diagnostics-v1.json"), 0700); err != nil {
				t.Fatal(err)
			}
			store := diagnostics.New(dir)
			journal := testJournal(t, filepath.Join(privateTestDir(t), "attempts"))
			l := testLease()
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(8 * time.Millisecond)
				io.WriteString(w, `{"model":"gpt-5.6-luna","choices":[{"message":{"content":"synthetic answer"},"finish_reason":"stop"}],"usage_source":"upstream","usage":{"prompt_tokens":8,"completion_tokens":4}}`)
			}))
			defer provider.Close()
			var report []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				report, _ = io.ReadAll(r.Body)
				pending, err := journal.Pending()
				if err != nil || len(pending) != 1 || !bytes.Equal(pending[0].Body, report) || pending[0].SubmissionSHA256 != attempts.Hash(report) {
					t.Error("observations changed the exact durable submission")
				}
				time.Sleep(8 * time.Millisecond)
				w.WriteHeader(status)
			}))
			defer server.Close()
			client := coordinator.New(server.URL, "synthetic-token")
			cfg := config.Config{Executor: config.ExecutorGateway, Profile: l.Profile, Gateway: provider.URL, MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: time.Second}
			a := beginLeaseDiagnostics(store, l)
			ctx := a.Context(context.Background())
			code, err := submitLease(ctx, client, cfg, l, nil, journal)
			a.Finish(diagnosticOutcome(ctx, code, err))
			if code != "" || (err == nil) != (status == http.StatusNoContent) {
				t.Fatal("optional diagnostics changed job outcome", code, err)
			}
			store.Close()
			snapshot := store.Snapshot()
			if snapshot.LoadError != "write_error" || len(snapshot.Attempts) != 1 {
				t.Fatal("optional storage failure not visible")
			}
			timeline := snapshot.Attempts[0]
			var workerMS, reportMS float64
			for _, span := range timeline.Spans {
				if span.Phase == "worker" {
					workerMS = span.DurationMS
				}
				if span.Phase == "report_http" {
					reportMS = span.DurationMS
					want := "success"
					if status != http.StatusNoContent {
						want = "report_error"
					}
					if span.Outcome != want {
						t.Fatal("report response classified incorrectly", span)
					}
				}
			}
			if workerMS < 7 || reportMS < 7 {
				t.Fatal("fixture delays missing from phases", workerMS, reportMS)
			}
			for _, field := range []string{`"spans"`, `"diagnostics"`, `"unclassified_ms"`} {
				if bytes.Contains(report, []byte(field)) {
					t.Fatal("local diagnostics entered report wire")
				}
			}
			pending, e := journal.Pending()
			if e != nil || len(pending) != map[bool]int{true: 0, false: 1}[err == nil] {
				t.Fatal("diagnostics changed recovery disposition", e)
			}
		})
	}
}

func TestDiagnosticsCommandMissingHistoryIsSafe(t *testing.T) {
	t.Setenv("SCARLETT_STATE_DIR", privateTestDir(t))
	var output bytes.Buffer
	if err := localCommand("diagnostics", &output); err != nil {
		t.Fatal(err)
	}
	var snapshot diagnostics.Snapshot
	if err := json.Unmarshal(output.Bytes(), &snapshot); err != nil || snapshot.Version != 1 || len(snapshot.Attempts) != 0 || len(snapshot.Summaries) != 0 {
		t.Fatal("missing history did not return an empty local snapshot", err)
	}
}

// A browser web job is recorded as scrape in browser mode, with its browser
// phase and upload as node spans and nothing from the page or its URL.
func TestDiagnosticsRecordBrowserWebJobs(t *testing.T) {
	store := diagnostics.New(privateTestDir(t))
	raw, err := os.ReadFile("api/fixtures/lease-web-browser.json")
	if err != nil {
		t.Fatal(err)
	}
	var l coordinator.Lease
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	a := beginLeaseDiagnostics(store, l)
	ctx := a.Context(context.Background())
	diagnostics.Start(ctx, "browser_fetch", 0)("success")
	diagnostics.Start(ctx, "browser_upload", 0)("web_browser_failed")
	a.Finish("web_browser_failed")
	records := store.Snapshot().Attempts
	if len(records) != 1 || records[0].Operation != "scrape" || records[0].ProofMode != "browser" || records[0].Pages != 1 || records[0].Outcome != "web_browser_failed" || len(records[0].Spans) != 2 || records[0].Spans[0].Phase != "browser_fetch" || records[0].Spans[1].Outcome != "web_browser_failed" {
		t.Fatalf("browser diagnostics %+v", records)
	}
	encoded, _ := json.Marshal(store.Snapshot())
	if bytes.Contains(encoded, []byte("example.com")) {
		t.Fatal("page URL entered diagnostics")
	}
	l.WebRequest = &coordinator.WebRequest{Operation: "scrape", URL: "https://example.com/"}
	l.Attempt = "44444444-4444-4444-8444-444444444444"
	relay := beginLeaseDiagnostics(store, l)
	relay.Finish("")
	if records = store.Snapshot().Attempts; len(records) != 2 || records[1].ProofMode != "relay" && records[0].ProofMode != "relay" {
		t.Fatal("relay web job mode", records)
	}
}
