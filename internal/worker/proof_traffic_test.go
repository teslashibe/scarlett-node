package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

func TestProofSamplePresenceAndAllowlist(t *testing.T) {
	good := `{"status":"proof_sent","verifier_sent_bytes":0,"verifier_received_bytes":23,"verifier_transport_layer":"tcp_payload"}`
	for _, tc := range []struct {
		name, raw, reason string
		ok                bool
	}{
		{"zero", good, "", true},
		{"failure", good, "helper_failed", false},
		{"missing", `{"status":"proof_sent","sent_bytes":999,"received_bytes":888}`, "missing", true},
		{"garbage", `not json`, "invalid", true},
		{"duplicate", strings.Replace(good, `"verifier_sent_bytes":0`, `"verifier_sent_bytes":0,"verifier_sent_bytes":8`, 1), "invalid", true},
		{"negative", strings.Replace(good, `bytes":0`, `bytes":-1`, 1), "invalid", true},
		{"fraction", strings.Replace(good, `bytes":0`, `bytes":0.5`, 1), "invalid", true},
		{"string", strings.Replace(good, `bytes":0`, `bytes":"0"`, 1), "invalid", true},
		{"null", strings.Replace(good, `bytes":0`, `bytes":null`, 1), "invalid", true},
		{"above bound", strings.Replace(good, `bytes":0`, fmt.Sprintf(`bytes":%d`, attempts.MaxProofBytes+1), 1), "invalid", true},
		{"wrong layer", strings.Replace(good, "tcp_payload", "plaintext", 1), "invalid", true},
		{"wrong saturation", strings.Replace(good, `"status":`, `"verifier_bytes_saturated":"false","status":`, 1), "invalid", true},
		{"saturated", strings.Replace(good, `"status":`, `"verifier_bytes_saturated":true,"status":`, 1), "saturated", true},
		{"false saturation", strings.Replace(good, `"status":`, `"verifier_bytes_saturated":false,"status":`, 1), "", true},
		{"private fields ignored", strings.Replace(good, `"status":`, `"response":"synthetic private content","account":"synthetic private label","status":`, 1), "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := proofSample([]byte(tc.raw), tc.ok)
			if s.Reason != tc.reason {
				t.Fatalf("reason %s want %s", s.Reason, tc.reason)
			}
			if tc.reason == "" || tc.reason == "saturated" {
				if s.SentBytes == nil || *s.SentBytes != 0 || s.ReceivedBytes == nil || *s.ReceivedBytes != 23 {
					t.Fatal("zero/presence lost")
				}
			} else if s.SentBytes != nil || s.ReceivedBytes != nil {
				t.Fatal("unknown counters became numbers")
			}
		})
	}
}

func TestProofObserverOnceAndPersistenceFault(t *testing.T) {
	var callbacks atomic.Int32
	ctx := WithProofObserver(context.Background(), func() (func(attempts.ProofSample) error, error) {
		return func(s attempts.ProofSample) error { callbacks.Add(1); return errors.New("synthetic write failure") }, nil
	})
	observe, err := beginProofObservation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); observe(nil, false) }()
	}
	wg.Wait()
	if callbacks.Load() != 1 {
		t.Fatal("duplicate delivery", callbacks.Load())
	}
	ctx = WithProofObserver(context.Background(), func() (func(attempts.ProofSample) error, error) {
		return nil, errors.New("synthetic reservation failure")
	})
	if _, err := beginProofObservation(ctx); err == nil {
		t.Fatal("reservation failure ignored")
	}
}

func trafficProverFixture() (config.Config, coordinator.Lease) {
	c := config.Config{Executor: config.ExecutorCodexTLSN, Verifier: "verifier:7047", Prover: os.Args[0], Profile: "standard", MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 5 * time.Second}
	l := coordinator.Lease{Version: coordinator.Version, JobID: "synthetic-job", SignedJobID: "synthetic-job", Profile: c.Profile, ModelID: "gpt-5.6-luna", Prompt: "hello", MaxInputTokens: 100, MaxOutputTokens: 20, InputSHA256: SHA("hello"), Attempt: "1", Fence: "f", LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute), CodexPayload: []byte(`{"type":"response.create","model":"gpt-5.6-luna","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hello"}]}]}`), VerifierToken: strings.Repeat("ab", 32)}
	return c, l
}

func TestActualHelperTrafficAndPreSpawnFailure(t *testing.T) {
	for _, tc := range []struct{ mode, reason string }{{"traffic", ""}, {"ok", "missing"}, {"fail", "helper_failed"}, {"garbage", "invalid"}} {
		t.Run(tc.mode, func(t *testing.T) {
			t.Setenv("SCARLETT_FAKE_PROVER", tc.mode)
			var observed []attempts.ProofSample
			ctx := WithProofObserver(context.Background(), func() (func(attempts.ProofSample) error, error) {
				return func(s attempts.ProofSample) error { observed = append(observed, s); return nil }, nil
			})
			c, l := trafficProverFixture()
			Prover{Config: c}.Run(ctx, l)
			if len(observed) != 1 || observed[0].Reason != tc.reason {
				t.Fatalf("helper observation %+v", observed)
			}
		})
	}
	t.Setenv("SCARLETT_FAKE_PROVER", "traffic")
	marker := filepath.Join(t.TempDir(), "helper-started")
	t.Setenv("SCARLETT_FAKE_PROVER_MARKER", marker)
	ctx := WithProofObserver(context.Background(), func() (func(attempts.ProofSample) error, error) {
		return nil, errors.New("private journal persistence failed")
	})
	c, l := trafficProverFixture()
	if code, _ := (Prover{Config: c}).Run(ctx, l); code != "prover_error" {
		t.Fatal(code)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("helper ran before durable reservation", err)
	}
	transport := XTransport{Prover: os.Args[0], Verifier: "verifier:7047", Token: strings.Repeat("ab", 32)}
	r := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/TweetResultByRestId?variables=%7B%7D").WithContext(ctx)
	if _, err := transport.RoundTrip(r); err == nil {
		t.Fatal("X reserve failure ignored")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("X helper ran before durable reservation", err)
	}
}

// Every page of a signed search, up to MaxXSearchPages, reserves one durable
// sample; the journal's bound must hold a ten-page plan, or its first page
// would fail its reservation and the job would never run.
func TestXHelperPaginationBoundAndBootstrapExcluded(t *testing.T) {
	if attempts.MaxProofSamples < coordinator.MaxXSearchPages {
		t.Fatal("the journal cannot reserve every page of the longest search")
	}
	for _, pages := range []int{3, coordinator.MaxXSearchPages} {
		t.Run(fmt.Sprint(pages), func(t *testing.T) {
			c, l, _ := xFixture(t, coordinator.XRequest{Operation: "search", Query: "synthetic", Count: 20, Pages: pages})
			if got := ProofSampleLimit(c, l); got != pages {
				t.Fatal("signed page bound", got)
			}
			// The existing X client pins one total helper attempt per page, so a
			// transport retry or an extra page must fail closed at the durable
			// boundary.
			j, err := attempts.Open(filepath.Join(t.TempDir(), "attempts"))
			if err != nil {
				t.Fatal(err)
			}
			defer j.Close()
			r := attempts.Record{JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, Fingerprint: attempts.Hash([]byte("synthetic lease")), Deadline: l.LeaseDeadline}
			if err := j.Begin(r); err != nil {
				t.Fatal(err)
			}
			ctx := WithProofObserver(context.Background(), func() (func(attempts.ProofSample) error, error) {
				ordinal, err := j.BeginProof(r, ProofSampleLimit(c, l))
				if err != nil {
					return nil, err
				}
				return func(s attempts.ProofSample) error { s.Ordinal = ordinal; return j.CompleteProof(r, s) }, nil
			})
			t.Setenv("SCARLETT_FAKE_PROVER", "xtraffic")
			var bootstrapCalls int
			transport := XTransport{Prover: os.Args[0], Verifier: "verifier:7047", Token: strings.Repeat("ab", 32), Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				bootstrapCalls++
				return &http.Response{StatusCode: 204, Body: http.NoBody, Request: req}, nil
			})}
			bootstrap := mustRequest(t, http.MethodGet, "https://abs.twimg.com/synthetic.js").WithContext(ctx)
			if _, err := transport.RoundTrip(bootstrap); err != nil {
				t.Fatal(err)
			}
			for range pages {
				req := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/SearchTimeline?variables=%7B%7D").WithContext(ctx)
				resp, err := transport.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			retry := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/SearchTimeline?variables=%7B%7D").WithContext(ctx)
			if _, err := transport.RoundTrip(retry); err == nil {
				t.Fatal("extra helper escaped signed bound")
			}
			if err := j.FinishProofTraffic(r); err != nil {
				t.Fatal(err)
			}
			pending, err := j.Pending()
			if err != nil || len(pending) != 1 {
				t.Fatal(err)
			}
			tm := pending[0].ProofTraffic
			if bootstrapCalls != 1 || tm == nil || len(tm.Samples) != pages || !tm.WorkerFinished {
				t.Fatal("wrong coverage")
			}
			for i, s := range tm.Samples {
				if s.Ordinal != i+1 || s.State != "complete" || s.SentBytes == nil || *s.SentBytes != 41 || *s.ReceivedBytes != 71 {
					t.Fatal("missing actual helper bytes", s)
				}
			}
		})
	}
}

// A keyed relay read reserves its sample under the same signed bound as
// MPC-TLS, and relay-x carries the same verifier counters as prove-x. A relay
// plan the node may not serve reserves nothing; validation refuses it first.
func TestRelayHelperTrafficIsBoundedAndJournaledLikeMPC(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	c, l, plan := xFixture(t, coordinator.XRequest{Operation: "post", PostID: "20"})
	plan.ProofMode, plan.ProofPolicy = "relay", xRelayPolicy
	l.XPayload, _ = json.Marshal(plan)
	if got := ProofSampleLimit(c, l); got != 0 {
		t.Fatal("relay lease without opt-in reserved samples", got)
	}
	c.XRelay = true
	if got := ProofSampleLimit(c, l); got != 1 {
		t.Fatal("relay lease sample bound", got)
	}
	HaltRelay("synthetic misuse")
	if got := ProofSampleLimit(c, l); got != 0 {
		t.Fatal("halted relay lease reserved samples", got)
	}
	ResetRelayHaltForTests()
	var observed []attempts.ProofSample
	ctx := WithProofObserver(context.Background(), func() (func(attempts.ProofSample) error, error) {
		return func(s attempts.ProofSample) error { observed = append(observed, s); return nil }, nil
	})
	c.Prover, c.Verifier = os.Args[0], "verifier:7047"
	transport := xTransport(c, plan, l.VerifierToken)
	if !transport.Relay {
		t.Fatal("opted-in relay plan built an MPC-TLS transport")
	}
	t.Setenv("SCARLETT_FAKE_PROVER", "xrelaytraffic")
	resp, err := transport.RoundTrip(mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/TweetResultByRestId?variables=%7B%7D").WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if len(observed) != 1 || observed[0].State != "complete" || observed[0].SentBytes == nil || *observed[0].SentBytes != 41 || observed[0].ReceivedBytes == nil || *observed[0].ReceivedBytes != 71 {
		t.Fatalf("relay helper observation %+v", observed)
	}
}
