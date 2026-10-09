package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFundedAcceptanceExactTermsAndAuthority(t *testing.T) {
	offer := Lease{Version: Version, ServiceType: "codex", JobID: "synthetic-funded", SignedJobID: strings.Repeat("a", 64), RequestSHA256: strings.Repeat("b", 64), Attempt: "attempt", Fence: "fence", Profile: "p", Prompt: "synthetic", AcceptanceRequired: true, LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute), CodexPayload: json.RawMessage(`{"type":"response.create"}`)}
	offer.SettlementDeadline = offer.LeaseDeadline
	for _, name := range []string{"valid", "prototype", "state", "fence", "request", "terms", "payload", "deadline", "token", "missing-required", "refused"} {
		t.Run(name, func(t *testing.T) {
			accepted := offer
			accepted.VerifierToken = strings.Repeat("c", 64)
			reply := LeaseAcceptance{Version: Version, State: "leased", FundingAuthority: "production_receipt", Lease: accepted}
			switch name {
			case "prototype":
				reply.FundingAuthority = "prototype"
			case "state":
				reply.State = "pending"
			case "fence":
				reply.Lease.Fence = "other"
			case "request":
				reply.Lease.RequestSHA256 = strings.Repeat("d", 64)
			case "terms":
				reply.Lease.SignedJobID = strings.Repeat("d", 64)
			case "payload":
				reply.Lease.CodexPayload = json.RawMessage(`{"type":"other"}`)
			case "deadline":
				reply.Lease.LeaseDeadline = time.Now().Add(-time.Second)
			case "token":
				reply.Lease.VerifierToken = strings.Repeat("C", 64)
			case "missing-required":
				reply.Lease.AcceptanceRequired = false
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/node/v1/jobs/synthetic-funded/accept" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer synthetic-credential" {
					t.Error("unscoped acceptance")
				}
				var in map[string]string
				if json.NewDecoder(r.Body).Decode(&in) != nil || len(in) != 5 || in["version"] != Version || in["attempt"] != offer.Attempt || in["fence"] != offer.Fence || in["request_sha256"] != offer.RequestSHA256 || in["terms_sha256"] != offer.SignedJobID {
					t.Error("request did not bind exact quote/request")
				}
				if name == "refused" {
					w.WriteHeader(409)
					return
				}
				json.NewEncoder(w).Encode(reply)
			}))
			defer server.Close()
			client := New(server.URL, "synthetic-credential")
			client.HTTP = server.Client()
			got, err := client.Accept(context.Background(), offer)
			if name == "valid" {
				if err != nil || got.VerifierToken != accepted.VerifierToken {
					t.Fatal("valid synthetic acceptance denied", err)
				}
			} else if err == nil {
				t.Fatal("untrusted acceptance authorized work")
			}
		})
	}
	for _, origin := range []string{"http://127.0.0.1:1", "https://example.invalid/path", "https://example.invalid?q=1"} {
		client := New(origin, "synthetic")
		if _, err := client.Accept(context.Background(), offer); err == nil {
			t.Fatal("untrusted coordinator origin allowed")
		}
	}
}

func TestAcceptanceFitsMaximalBoundedCodexPayloadAndRejectsOversize(t *testing.T) {
	var offer Lease
	raw, err := os.ReadFile("../../api/fixtures/lease-offer.json")
	if err != nil || json.Unmarshal(raw, &offer) != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	offer.LeaseDeadline = time.Now().Add(time.Minute)
	offer.SettlementDeadline = offer.LeaseDeadline
	if json.Unmarshal(offer.CodexPayload, &payload) != nil {
		t.Fatal("invalid fixture")
	}
	for n := 10_000; n < 11_000; n++ {
		prompt := strings.Repeat("\x01", n)
		payload["input"] = []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": prompt}}}}
		encoded, _ := json.Marshal(payload)
		if len(encoded) > 65536 {
			break
		}
		offer.Prompt = prompt
		offer.CodexPayload = encoded
	}
	accepted := offer
	accepted.VerifierToken = strings.Repeat("c", 64)
	reply, _ := json.Marshal(LeaseAcceptance{Version: Version, State: "leased", FundingAuthority: "production_receipt", Lease: accepted})
	if len(reply) <= 131072 || len(reply) > maxReplyBytes {
		t.Fatal("fixture does not exercise duplicated prompt envelope", len(reply))
	}
	for _, oversized := range []bool{false, true} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if oversized {
				io.WriteString(w, strings.Repeat("x", maxReplyBytes+1))
				return
			}
			w.Write(reply)
		}))
		client := New(server.URL, "synthetic")
		client.HTTP = server.Client()
		_, err = client.Accept(context.Background(), offer)
		server.Close()
		if (err != nil) != oversized {
			t.Fatal("wrong bounded acceptance response", err)
		}
	}
}

func TestUnboundedOrPrefilledCommunityOfferDoesNotCallCoordinator(t *testing.T) {
	offer := Lease{Version: Version, ServiceType: "codex", JobID: "synthetic", Attempt: "attempt", Fence: "fence", AcceptanceRequired: true, SignedJobID: strings.Repeat("a", 64), RequestSHA256: strings.Repeat("b", 64), LeaseDeadline: time.Now().Add(time.Minute)}
	offer.SettlementDeadline = offer.LeaseDeadline
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(503) }))
	defer server.Close()
	client := New(server.URL, "synthetic")
	client.HTTP = server.Client()
	for _, edit := range []func(*Lease){func(l *Lease) { l.AcceptanceRequired = false }, func(l *Lease) { l.VerifierToken = strings.Repeat("c", 64) }, func(l *Lease) { l.RequestSHA256 = "invalid" }, func(l *Lease) {
		l.LeaseDeadline = time.Now().Add(MaxCodexOfferLifetime + OfferClockSkew + time.Second)
		l.SettlementDeadline = l.LeaseDeadline
	}, func(l *Lease) { l.SettlementDeadline = l.LeaseDeadline.Add(time.Second) }} {
		changed := offer
		edit(&changed)
		if _, err := client.Accept(context.Background(), changed); err == nil {
			t.Fatal("unsafe offer accepted")
		}
	}
	if calls != 0 {
		t.Fatal("unsafe offer contacted coordinator")
	}
}

// The node receives the coordinator's stored terms digest, not its private
// buyer quote. This test checks commitment preservation across denominations;
// monetary validity and funding evidence belong to the coordinator tests.
func TestFundedAcceptanceBindsMicroUSDQuoteCommitment(t *testing.T) {
	termsDigest := func(asset string, atoms int64) string {
		identity := fmt.Sprintf(`{"terms":{"nodeId":"synthetic-node","service":"codex","policyReference":"synthetic-v1","model":"gpt-5.6-luna","operation":"","maxInput":100,"maxOutput":20,"exchanges":1,"quote":{"asset":%q,"amountAtoms":%d,"pricingReference":"synthetic-price-v1"}},"requestHash":%q}`, asset, atoms, strings.Repeat("b", 64))
		sum := sha256.Sum256([]byte(identity))
		return hex.EncodeToString(sum[:])
	}
	for _, denomination := range []string{"usd", "usdc", "usd_micros"} {
		t.Run(denomination, func(t *testing.T) {
			offer := Lease{Version: Version, ServiceType: "codex", JobID: "synthetic-quote", SignedJobID: termsDigest(denomination, 100), RequestSHA256: strings.Repeat("b", 64), Attempt: "attempt", Fence: "fence", Profile: "p", AcceptanceRequired: true, LeaseDeadline: time.Now().Add(time.Minute)}
			offer.SettlementDeadline = offer.LeaseDeadline
			otherDenomination := "usd_micros"
			if denomination == otherDenomination {
				otherDenomination = "usd"
			}
			for _, responseDigest := range []string{offer.SignedJobID, termsDigest(otherDenomination, 100), termsDigest(denomination, 101)} {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var request map[string]string
					if json.NewDecoder(r.Body).Decode(&request) != nil || request["terms_sha256"] != offer.SignedJobID {
						t.Error("funded acceptance changed the offered quote commitment")
					}
					accepted := offer
					accepted.SignedJobID = responseDigest
					accepted.VerifierToken = strings.Repeat("c", 64)
					json.NewEncoder(w).Encode(LeaseAcceptance{Version: Version, State: "leased", FundingAuthority: "production_receipt", Lease: accepted})
				}))
				client := New(server.URL, "synthetic-credential")
				client.HTTP = server.Client()
				got, err := client.Accept(context.Background(), offer)
				server.Close()
				if responseDigest == offer.SignedJobID {
					if err != nil || got.SignedJobID != offer.SignedJobID {
						t.Fatal("exact denomination commitment rejected", err)
					}
				} else if err == nil {
					t.Fatal("changed quote denomination or amount authorized execution")
				}
			}
		})
	}
}

// acceptRetryServer answers acceptance requests from replies in order, then
// accepts the exact offer. Each reply is a status, a Retry-After and a code.
type acceptReply struct {
	status     int
	retryAfter string
	code       string
}

func acceptRetryServer(t *testing.T, offer Lease, replies []acceptReply) (*Client, *atomic.Int32, func() []time.Time) {
	t.Helper()
	var calls atomic.Int32
	var mu sync.Mutex
	arrivals := []time.Time{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		if r.URL.Path != "/api/node/v1/jobs/"+offer.JobID+"/accept" || json.NewDecoder(r.Body).Decode(&in) != nil || in["attempt"] != offer.Attempt || in["fence"] != offer.Fence || in["terms_sha256"] != offer.SignedJobID {
			t.Error("retry changed the acceptance request")
		}
		n := int(calls.Add(1)) - 1
		mu.Lock()
		arrivals = append(arrivals, time.Now())
		mu.Unlock()
		if n < len(replies) {
			if replies[n].retryAfter != "" {
				w.Header().Set("Retry-After", replies[n].retryAfter)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(replies[n].status)
			if replies[n].code != "" {
				json.NewEncoder(w).Encode(ErrorReply{Error: ErrorDetail{Code: replies[n].code, Message: "synthetic"}})
			}
			return
		}
		accepted := offer
		accepted.VerifierToken = strings.Repeat("c", 64)
		json.NewEncoder(w).Encode(LeaseAcceptance{Version: Version, State: "leased", FundingAuthority: "production_receipt", Lease: accepted})
	}))
	t.Cleanup(server.Close)
	client := New(server.URL, "synthetic-credential")
	client.HTTP = server.Client()
	return client, &calls, func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Time(nil), arrivals...)
	}
}

func retryOffer(deadline time.Duration) Lease {
	offer := Lease{Version: Version, ServiceType: "codex", JobID: "synthetic-retry", SignedJobID: strings.Repeat("a", 64), RequestSHA256: strings.Repeat("b", 64), Attempt: "attempt", Fence: "fence", Profile: "p", AcceptanceRequired: true, LeaseDeadline: time.Now().Add(deadline)}
	offer.SettlementDeadline = offer.LeaseDeadline
	return offer
}

// A busy or temporarily unavailable coordinator is asked again inside the same
// acceptance, after each Retry-After (one second when absent, clamped to a
// minute), with the identical request.
func TestAcceptRetriesBusyAndUnavailableHonouringRetryAfter(t *testing.T) {
	offer := retryOffer(time.Minute)
	client, calls, _ := acceptRetryServer(t, offer, []acceptReply{{503, "2", "dispatch_busy"}, {503, "", "network_unavailable"}, {503, "600", "dispatch_busy"}})
	var waits []time.Duration
	client.retryWait = func(after time.Duration) time.Duration {
		waits = append(waits, after)
		return time.Millisecond
	}
	got, err := client.Accept(context.Background(), offer)
	if err != nil || got.VerifierToken != strings.Repeat("c", 64) {
		t.Fatal("retried acceptance failed", err)
	}
	if calls.Load() != 4 || !reflect.DeepEqual(waits, []time.Duration{2 * time.Second, time.Second, MaxRetryAfter}) {
		t.Fatalf("calls %d, Retry-After waits %v", calls.Load(), waits)
	}
}

// At most three retries; the last busy answer is returned as the error.
func TestAcceptRetryLimit(t *testing.T) {
	offer := retryOffer(time.Minute)
	busy := acceptReply{503, "1", "dispatch_busy"}
	client, calls, _ := acceptRetryServer(t, offer, []acceptReply{busy, busy, busy, busy, busy})
	retries := 0
	client.retryWait = func(time.Duration) time.Duration { retries++; return time.Millisecond }
	_, err := client.Accept(context.Background(), offer)
	var status *StatusError
	if !errors.As(err, &status) || status.Status != 503 || status.Code != "dispatch_busy" {
		t.Fatal("exhausted retries reported as", err)
	}
	if calls.Load() != 1+acceptRetries || retries != acceptRetries {
		t.Fatalf("calls %d, retries %d", calls.Load(), retries)
	}
}

// A caller that accepts only to report a rejection at once sends the
// acceptance once, busy or not, as before acceptance retried.
func TestAcceptWithoutRetrySendsOnce(t *testing.T) {
	offer := retryOffer(time.Minute)
	busy := acceptReply{503, "1", "dispatch_busy"}
	client, calls, _ := acceptRetryServer(t, offer, []acceptReply{busy, busy})
	client.retryWait = func(time.Duration) time.Duration { t.Error("rejection acceptance retried"); return time.Millisecond }
	_, err := client.Accept(WithoutAcceptRetry(context.Background()), offer)
	var status *StatusError
	if !errors.As(err, &status) || status.Code != "dispatch_busy" || calls.Load() != 1 {
		t.Fatalf("calls %d, error %v", calls.Load(), err)
	}
	// An answered acceptance is unaffected.
	client, calls, _ = acceptRetryServer(t, offer, nil)
	if got, err := client.Accept(WithoutAcceptRetry(context.Background()), offer); err != nil || got.VerifierToken != strings.Repeat("c", 64) || calls.Load() != 1 {
		t.Fatalf("calls %d, error %v", calls.Load(), err)
	}
}

// Refusals, rate limits and other unavailability are final: one request each.
func TestAcceptNeverRetriesRefusals(t *testing.T) {
	for _, reply := range []acceptReply{{401, "1", "node_unauthorized"}, {404, "1", "attempt_unavailable"}, {409, "1", "attempt_conflict"}, {429, "1", "rate_limited"}, {400, "", "invalid_request"}, {503, "1", "dispatch_unavailable"}, {503, "1", ""}, {500, "1", "network_unavailable"}} {
		offer := retryOffer(time.Minute)
		client, calls, _ := acceptRetryServer(t, offer, []acceptReply{reply, reply})
		client.retryWait = func(time.Duration) time.Duration { t.Error("refusal retried", reply); return time.Millisecond }
		if _, err := client.Accept(context.Background(), offer); err == nil {
			t.Fatal("refused acceptance authorized work", reply)
		}
		if calls.Load() != 1 {
			t.Fatalf("%+v: %d requests", reply, calls.Load())
		}
	}
}

// No retry starts later than 30 seconds before the lease deadline: the rest of
// the lease belongs to provider work.
func TestAcceptRetryStopsBeforeLeaseDeadline(t *testing.T) {
	busy := acceptReply{503, "15", "dispatch_busy"}
	offer := retryOffer(40 * time.Second)
	client, calls, _ := acceptRetryServer(t, offer, []acceptReply{busy, busy})
	started := time.Now()
	if _, err := client.Accept(context.Background(), offer); err == nil {
		t.Fatal("busy acceptance authorized work")
	}
	// A retry would first wait out the 15-second Retry-After; five seconds
	// leaves a slow runner's first TLS request room without hiding one.
	if calls.Load() != 1 || time.Since(started) > 5*time.Second {
		t.Fatalf("retried into the last 30 seconds: %d requests in %v", calls.Load(), time.Since(started))
	}
	// One-second waits fit twice before the margin, not three times.
	unavailable := acceptReply{503, "", "network_unavailable"}
	offer = retryOffer(acceptRetryMargin + 2500*time.Millisecond)
	client, calls, _ = acceptRetryServer(t, offer, []acceptReply{unavailable, unavailable, unavailable, unavailable})
	client.retryWait = func(after time.Duration) time.Duration { return after }
	if _, err := client.Accept(context.Background(), offer); err == nil {
		t.Fatal("unavailable acceptance authorized work")
	}
	if calls.Load() != 3 {
		t.Fatalf("%d requests before the deadline margin, want 3", calls.Load())
	}
}

// The real wait honours Retry-After plus jitter, and cancellation ends it.
func TestAcceptRetryWaitsRetryAfterAndStopsOnCancel(t *testing.T) {
	offer := retryOffer(time.Minute)
	client, calls, arrivals := acceptRetryServer(t, offer, []acceptReply{{503, "1", "dispatch_busy"}})
	if _, err := client.Accept(context.Background(), offer); err != nil {
		t.Fatal(err)
	}
	at := arrivals()
	if gap := at[1].Sub(at[0]); calls.Load() != 2 || gap < time.Second || gap > 2500*time.Millisecond {
		t.Fatalf("retry after %v, %d requests", gap, calls.Load())
	}
	client, calls, _ = acceptRetryServer(t, offer, []acceptReply{{503, "1", "dispatch_busy"}})
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel only once the retry wait has begun: a fixed timer from the start
	// could fire before a slow runner finishes the first TLS request.
	var waiting time.Time
	client.retryWait = func(time.Duration) time.Duration {
		waiting = time.Now()
		time.AfterFunc(50*time.Millisecond, cancel)
		return 10 * time.Second
	}
	if _, err := client.Accept(ctx, offer); err == nil {
		t.Fatal("cancelled acceptance authorized work")
	}
	if calls.Load() != 1 || waiting.IsZero() || time.Since(waiting) > time.Second {
		t.Fatalf("cancel did not end the retry wait: %d requests, waited %v", calls.Load(), time.Since(waiting))
	}
}

// The coordinator stamps a deadline up to its service's OfferLifetime ahead of
// its own clock and delivers it within milliseconds. A node whose clock runs
// slightly behind must still accept it; only a deadline beyond the skew margin
// is unsafe.
func TestValidOfferToleratesSlowLocalClock(t *testing.T) {
	now := time.Now()
	for _, service := range []string{"codex", "x_read", "web"} {
		offer := Lease{Version: Version, ServiceType: service, JobID: "synthetic", Attempt: "attempt", Fence: "fence", AcceptanceRequired: true, SignedJobID: strings.Repeat("a", 64), RequestSHA256: strings.Repeat("b", 64)}
		lifetime := OfferLifetime(service)
		for _, tc := range []struct {
			ahead time.Duration
			ok    bool
		}{{lifetime, true}, {lifetime + 900*time.Millisecond, true}, {lifetime + OfferClockSkew, true}, {lifetime + OfferClockSkew + time.Second, false}, {0, false}, {-time.Second, false}} {
			offer.LeaseDeadline = now.Add(tc.ahead)
			offer.SettlementDeadline = offer.LeaseDeadline
			if err := ValidOffer(offer, now); (err == nil) != tc.ok {
				t.Fatalf("%s deadline %v ahead: err %v, want ok=%v", service, tc.ahead, err, tc.ok)
			}
		}
	}
}

// A web offer may run 300 s (its job deadline is creation + 298 s), so a
// large page fits a slow uplink. An x_read offer may too: a search of four to
// ten pages runs up to 298 s, and the offer need not say how many pages it
// has. Codex keeps 120 s. The clock skew margin applies to all three.
func TestValidOfferLifetimePerService(t *testing.T) {
	now := time.Now()
	web := readLeaseFixture(t, "lease-web-offer.json")
	xRead := readLeaseFixture(t, "lease-x-pages10.json")
	xRead.VerifierToken = "" // the offer form of the accepted fixture
	bare := Lease{Version: Version, ServiceType: "x_read", JobID: "synthetic", Attempt: "attempt", Fence: "fence", AcceptanceRequired: true, SignedJobID: strings.Repeat("a", 64), RequestSHA256: strings.Repeat("b", 64)}
	codex := bare
	codex.ServiceType = "codex"
	if OfferLifetime("web") != 300*time.Second || OfferLifetime("x_read") != 300*time.Second || OfferLifetime("codex") != 120*time.Second {
		t.Fatal("lifetimes")
	}
	for _, tc := range []struct {
		offer Lease
		ahead time.Duration
		ok    bool
	}{
		{web, 298 * time.Second, true},
		{web, 300*time.Second + OfferClockSkew, true},
		{web, 300*time.Second + OfferClockSkew + time.Second, false},
		{xRead, 118 * time.Second, true},
		{xRead, 298 * time.Second, true},
		{xRead, 300*time.Second + OfferClockSkew, true},
		{xRead, 300*time.Second + OfferClockSkew + time.Second, false},
		{bare, 121 * time.Second, true},
		{bare, 298 * time.Second, true},
		{bare, 306 * time.Second, false},
		{codex, 121 * time.Second, true},
		{codex, 130 * time.Second, false},
		{codex, 298 * time.Second, false},
	} {
		tc.offer.LeaseDeadline = now.Add(tc.ahead)
		tc.offer.SettlementDeadline = tc.offer.LeaseDeadline
		if err := ValidOffer(tc.offer, now); (err == nil) != tc.ok {
			t.Fatalf("%s %v ahead: err %v, want ok=%v", tc.offer.ServiceType, tc.ahead, err, tc.ok)
		}
	}
}
