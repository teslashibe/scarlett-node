package worker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
)

func workerDiagnosticAttempt(operation string, pages int) (*diagnostics.Store, *diagnostics.Attempt, context.Context) {
	store := diagnostics.New("")
	attempt := store.Begin(diagnostics.Metadata{ID: "synthetic-diagnostic-attempt", Operation: operation, Pages: pages, ProofMode: "mpc"})
	return store, attempt, attempt.Context(context.Background())
}

func diagnosticSpan(t *testing.T, record diagnostics.Record, phase, source string, exchange int) diagnostics.Span {
	t.Helper()
	for _, span := range record.Spans {
		if span.Phase == phase && span.Source == source && span.Exchange == exchange {
			return span
		}
	}
	t.Fatalf("missing %s/%s/%d in %+v", source, phase, exchange, record.Spans)
	return diagnostics.Span{}
}

func TestXHelperDiagnosticsCannotChangeResponseOrProofTraffic(t *testing.T) {
	var baseline attempts.ProofSample
	for _, mode := range []string{"xdiag", "xdiaglegacy", "xdiagbad", "xdiagnull", "xdiaglegacynull"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("SCARLETT_FAKE_PROVER", mode)
			store, attempt, ctx := workerDiagnosticAttempt("post", 1)
			var samples []attempts.ProofSample
			ctx = WithProofObserver(ctx, func() (func(attempts.ProofSample) error, error) {
				return func(sample attempts.ProofSample) error { samples = append(samples, sample); return nil }, nil
			})
			request := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/TweetResultByRestId?variables=%7B%7D").WithContext(ctx)
			transport := XTransport{Prover: os.Args[0], Verifier: "verifier:7047", Token: strings.Repeat("ab", 32)}
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != `{"echo":"GET /i/api/graphql/q/TweetResultByRestId?variables=%7B%7D HTTP/1.1"}` || len(samples) != 1 || samples[0].State != "complete" {
				t.Fatal("optional diagnostics changed proof response or traffic", string(body), err, samples)
			}
			if baseline.State == "" {
				baseline = samples[0]
			} else if !reflect.DeepEqual(baseline, samples[0]) {
				t.Fatal("optional diagnostics changed the proof traffic sample", baseline, samples[0])
			}
			attempt.Finish("")
			record := store.Snapshot().Attempts[0]
			wall := diagnosticSpan(t, record, "helper_wall", "node", 1)
			if wall.DurationMS < 20 || wall.Outcome != "success" {
				t.Fatal("helper parent runtime omitted the fixture delay", wall)
			}
			diagnosticSpan(t, record, "helper_stdout_decode", "node", 1)
			diagnosticSpan(t, record, "proof_journal_begin", "node", 1)
			diagnosticSpan(t, record, "proof_journal_complete", "node", 1)
			if mode == "xdiag" || mode == "xdiaglegacy" {
				total := diagnosticSpan(t, record, "helper_total", "helper", 1)
				if total.DurationMS != 20 || total.StartMS != 0 || total.Outcome != "success" {
					t.Fatal("helper origin/duration changed", total)
				}
			} else {
				for _, span := range record.Spans {
					if span.Source == "helper" {
						t.Fatal("malformed optional helper measurements were trusted", span)
					}
				}
			}
			raw, _ := json.Marshal(store.Snapshot())
			for _, forbidden := range []string{"SECRET_PRIVATE_DIAGNOSTIC", "variables", "verifier:7047", strings.Repeat("ab", 32), "TweetResultByRestId?"} {
				if strings.Contains(string(raw), forbidden) {
					t.Fatal("private request data escaped into diagnostics", forbidden)
				}
			}
		})
	}
}

func TestFailedHelperRetainsMeasuredPrefixAndOriginalError(t *testing.T) {
	t.Setenv("SCARLETT_FAKE_PROVER", "xdiagfail")
	store, attempt, ctx := workerDiagnosticAttempt("post", 1)
	request := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/TweetResultByRestId?variables=%7B%7D").WithContext(ctx)
	transport := XTransport{Prover: os.Args[0], Verifier: "verifier:7047", Token: strings.Repeat("ab", 32)}
	if _, err := transport.RoundTrip(request); err == nil || !strings.Contains(err.Error(), "synthetic helper failure") || strings.Contains(err.Error(), "SCARLETT_DIAGNOSTICS=") {
		t.Fatal("optional diagnostic line changed the existing helper error", err)
	}
	attempt.Finish("prover_error")
	record := store.Snapshot().Attempts[0]
	if span := diagnosticSpan(t, record, "helper_wall", "node", 1); span.Outcome != "error" || span.DurationMS <= 0 {
		t.Fatal("failed helper parent runtime was fabricated", span)
	}
	if span := diagnosticSpan(t, record, "x_tcp_connect", "helper", 1); span.Outcome != "error" || span.DurationMS != 4 {
		t.Fatal("failed helper's measured prefix was lost", span)
	}
	if span := diagnosticSpan(t, record, "helper_total", "helper", 1); span.Outcome != "error" {
		t.Fatal("failed helper fabricated a successful total", span)
	}
	for _, span := range record.Spans {
		if span.Phase == "helper_stdout_decode" {
			t.Fatal("failed helper fabricated a completed stdout decode")
		}
	}
}

type slowDiagnosticBody struct {
	io.ReadCloser
	delayed bool
}

func (b *slowDiagnosticBody) Read(p []byte) (int, error) {
	if !b.delayed {
		b.delayed = true
		time.Sleep(20 * time.Millisecond)
	}
	return b.ReadCloser.Read(p)
}

func TestWarmPageDiagnosticsMeasureWaitAndDecodeSeparately(t *testing.T) {
	c, lease, clients, fake := xWarmFixture(t, "fixture")
	clients.minGap = 40 * time.Millisecond
	if code := xRun(c, lease, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal("synthetic warm-up failed", code)
	}
	store, attempt, ctx := workerDiagnosticAttempt("profile", 1)
	proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := xBootstrap(r)
		response.Body = &slowDiagnosticBody{ReadCloser: response.Body}
		return response, err
	})
	if code := (X{Config: c, Base: fake, Proof: proof, Clients: clients}).Run(ctx, lease); code != "" {
		t.Fatal("instrumentation changed the page result", code)
	}
	attempt.Finish("")
	record := store.Snapshot().Attempts[0]
	if span := diagnosticSpan(t, record, "client_acquire", "node", 0); span.Outcome != "cache_hit" {
		t.Fatal("warm cache hit was not identified", span)
	}
	if span := diagnosticSpan(t, record, "pacing_wait", "node", 1); span.DurationMS < 20 || span.Outcome != "success" {
		t.Fatal("actual pacing delay was not measured", span)
	}
	decode := diagnosticSpan(t, record, "response_decode", "node", 1)
	page := diagnosticSpan(t, record, "page_wall", "node", 1)
	if decode.DurationMS < 15 || page.DurationMS < decode.DurationMS || decode.StartMS < page.StartMS || decode.StartMS+decode.DurationMS > page.StartMS+page.DurationMS+1 {
		t.Fatal("overlapping page/decode timing boundaries changed", decode, page)
	}
}

func TestCancelledPacingRetainsMeasuredPrefixWithoutSendingProof(t *testing.T) {
	c, lease, clients, fake := xWarmFixture(t, "fixture")
	clients.minGap = 200 * time.Millisecond
	if code := xRun(c, lease, clients, fake, &xProfileProof{}); code != "" {
		t.Fatal("synthetic warm-up failed", code)
	}
	store, attempt, ctx := workerDiagnosticAttempt("profile", 1)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	defer cancel()
	proof := &xProfileProof{}
	if code := (X{Config: c, Base: fake, Proof: proof, Clients: clients}).Run(ctx, lease); code != "expired" || proof.proofs.Load() != 0 {
		t.Fatal("cancelled pacing changed the result or spent proof", code, proof.proofs.Load())
	}
	attempt.Finish("cancelled")
	record := store.Snapshot().Attempts[0]
	if span := diagnosticSpan(t, record, "pacing_wait", "node", 1); span.Outcome != "cancelled" || span.DurationMS < 15 || span.DurationMS > 150 {
		t.Fatal("cancelled wait prefix was inferred rather than measured", span)
	}
	for _, span := range record.Spans {
		if span.Phase == "binding_check" || span.Phase == "helper_wall" {
			t.Fatal("cancelled pre-proof wait fabricated an exchange", span)
		}
	}
}

func TestResponseDecodeDiagnosticsReportMalformedGraphQL(t *testing.T) {
	c, lease, clients, fake := xWarmFixture(t, "fixture")
	store, attempt, ctx := workerDiagnosticAttempt("profile", 1)
	proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return xResponse(r, http.StatusOK, `{"data":`), nil
	})
	if code := (X{Config: c, Base: fake, Proof: proof, Clients: clients}).Run(ctx, lease); code != "x_request_failed" {
		t.Fatal("instrumentation changed malformed GraphQL failure", code)
	}
	attempt.Finish("x_request_failed")
	record := store.Snapshot().Attempts[0]
	if span := diagnosticSpan(t, record, "response_decode", "node", 1); span.Outcome != "error" {
		t.Fatal("malformed GraphQL falsely reported successful decoding", span)
	}
}

func TestCancelledHelperKeepsParentRuntimeAndEmittedPrefix(t *testing.T) {
	t.Setenv("SCARLETT_FAKE_PROVER", "xdiagcancel")
	marker := filepath.Join(t.TempDir(), "diagnostic-ready")
	t.Setenv("SCARLETT_FAKE_DIAG_READY", marker)
	store, attempt, ctx := workerDiagnosticAttempt("post", 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	request := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/TweetResultByRestId?variables=%7B%7D").WithContext(ctx)
	transport := XTransport{Prover: os.Args[0], Verifier: "verifier:7047", Token: strings.Repeat("ab", 32)}
	result := make(chan error, 1)
	go func() { _, err := transport.RoundTrip(request); result <- err }()
	deadline := time.Now().Add(3 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			ready = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-result; !ready || err == nil {
		t.Fatal("helper cancellation fixture failed", ready, err)
	}
	attempt.Finish("cancelled")
	record := store.Snapshot().Attempts[0]
	if span := diagnosticSpan(t, record, "helper_wall", "node", 1); span.Outcome != "cancelled" || span.DurationMS <= 0 {
		t.Fatal("helper cancellation omitted parent elapsed time", span)
	}
	diagnosticSpan(t, record, "x_tcp_connect", "helper", 1)
	for _, span := range record.Spans {
		if span.Phase == "helper_stdout_decode" {
			t.Fatal("cancelled helper fabricated output decoding")
		}
	}
}

func TestThreeExchangesKeepSeparateMeasurementsAndProofSamples(t *testing.T) {
	store, attempt, ctx := workerDiagnosticAttempt("search", 3)
	var samples []attempts.ProofSample
	ctx = WithProofObserver(ctx, func() (func(attempts.ProofSample) error, error) {
		return func(sample attempts.ProofSample) error { samples = append(samples, sample); return nil }, nil
	})
	transport := XTransport{Prover: os.Args[0], Verifier: "verifier:7047", Token: strings.Repeat("ab", 32)}
	for index, mode := range []string{"xdiag", "xdiagbad", "xdiaglegacy"} {
		t.Setenv("SCARLETT_FAKE_PROVER", mode)
		request := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/SearchTimeline?variables=%7B%7D").WithContext(withXExchange(ctx, index+1))
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal("optional per-page diagnostics changed an exchange", index, err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	if len(samples) != 3 || !reflect.DeepEqual(samples[0], samples[1]) || !reflect.DeepEqual(samples[0], samples[2]) {
		t.Fatal("optional per-page measurements altered proof traffic", samples)
	}
	attempt.Finish("")
	record := store.Snapshot().Attempts[0]
	for index := 1; index <= 3; index++ {
		diagnosticSpan(t, record, "helper_wall", "node", index)
		diagnosticSpan(t, record, "proof_journal_complete", "node", index)
	}
	diagnosticSpan(t, record, "helper_total", "helper", 1)
	diagnosticSpan(t, record, "helper_total", "helper", 3)
	for _, span := range record.Spans {
		if span.Source == "helper" && span.Exchange == 2 {
			t.Fatal("malformed second page invented a helper measurement", span)
		}
	}
}
