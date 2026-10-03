package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	x "github.com/teslashibe/x-go"
)

// All transports below are synthetic and never connect to X or a provider.
func xResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}
}
func xBootstrap(r *http.Request) (*http.Response, error) {
	body := `{"data":{"user":{"result":{"__typename":"User","rest_id":"12","legacy":{"screen_name":"fixture"}}}}}`
	if strings.HasSuffix(r.URL.Path, "/Viewer") {
		body = `{"data":{"viewer":{"user_results":{"result":{"rest_id":"12"}}}}}`
	}
	if !strings.Contains(r.URL.Path, "/i/api/graphql/") {
		return xResponse(r, 404, ""), nil
	}
	return xResponse(r, 200, body), nil
}
func xFixture(t *testing.T, request coordinator.XRequest) (config.Config, coordinator.Lease, xPlan) {
	t.Helper()
	ctx := context.Background()
	session := x.Session{AuthToken: "synthetic-auth", CT0: "synthetic-csrf"}
	var spec xSpec
	capture := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/UserByScreenName") || strings.HasSuffix(r.URL.Path, "/SearchTimeline") || strings.HasSuffix(r.URL.Path, "/TweetResultByRestId") || strings.HasSuffix(r.URL.Path, "/TweetDetail") {
			parts := strings.Split(r.URL.Path, "/")
			spec.Operation = parts[len(parts)-1]
			spec.QueryID = parts[len(parts)-2]
			v, e := uniqueJSON([]byte(r.URL.Query().Get("variables")))
			if e != nil {
				t.Fatal(e)
			}
			spec.Variables = v.(map[string]any)
			v, e = uniqueJSON([]byte(r.URL.Query().Get("features")))
			if e != nil {
				t.Fatal(e)
			}
			spec.Features = v.(map[string]any)
			return nil, errors.New("captured synthetic request, no network")
		}
		return xBootstrap(r)
	})
	client, e := session.NewClient(ctx, x.WithHTTPClient(&http.Client{Transport: capture}), x.WithRetry(1, time.Millisecond), x.WithMinRequestGap(0))
	if e != nil {
		t.Fatal(e)
	}
	switch request.Operation {
	case "profile":
		client.GetProfile(ctx, request.Username)
	case "post":
		client.GetTweet(ctx, request.PostID)
	case "thread":
		client.GetTweetDetail(ctx, request.PostID)
	case "search":
		client.SearchTweetsPage(ctx, request.Query, request.Count, "", x.WithSearchType(x.SearchLatest))
	}
	if spec.Operation == "" {
		t.Fatal("no operation captured")
	}
	_, pages, ok := xRequestPolicy(&request)
	if !ok {
		t.Fatal("invalid synthetic request")
	}
	plan := xPlan{Type: "x.read", MaxAttempts: pages}
	for i := range pages {
		s := spec
		if i > 0 {
			source := i - 1
			s.CursorFrom = &source
		}
		plan.Exchanges = append(plan.Exchanges, s)
	}
	payload, _ := json.Marshal(plan)
	raw, _ := json.Marshal(request)
	dir := filepath.Join(t.TempDir(), "private")
	if e := localfs.EnsureDir(dir); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "session.json")
	sessionJSON, _ := json.Marshal(session)
	if e = localfs.WriteAtomic(path, sessionJSON, true); e != nil {
		t.Fatal(e)
	}
	c := config.Config{Profile: "standard", XSession: path, MaxInputBytes: 1024, InferenceTimeout: 10 * time.Second}
	l := coordinator.Lease{Version: coordinator.Version, ServiceType: "x_read", JobID: "synthetic-x", SignedJobID: "synthetic-commitment", Profile: c.Profile, InputSHA256: SHA(string(raw)), Attempt: "1", Fence: "f1", LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute), VerifierToken: strings.Repeat("ab", 32), XRequest: &request, XPayload: payload}
	return c, l, plan
}
func TestXPublicOperationsAndExactPagination(t *testing.T) {
	for _, request := range []coordinator.XRequest{{Operation: "profile", Username: "fixture"}, {Operation: "post", PostID: "20"}, {Operation: "thread", PostID: "20"}, {Operation: "search", Query: "bitcoin", Count: 20, Pages: 3}} {
		t.Run(request.Operation, func(t *testing.T) {
			c, l, plan := xFixture(t, request)
			proofs := 0
			proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Host != "x.com" || r.Method != "GET" {
					t.Error("wrong destination")
				}
				if !strings.Contains(r.Header.Get("Cookie"), "synthetic-auth") {
					t.Error("local session missing")
				}
				proofs++
				if request.Operation == "search" {
					cursor := r.URL.Query().Get("variables")
					if proofs > 1 && !strings.Contains(cursor, "cursor-") {
						t.Error("page did not follow proven response cursor")
					}
					body := `{"data":{"search_by_raw_query":{"search_timeline":{"timeline":{"instructions":[{"type":"TimelineAddEntries","entries":[{"entryId":"cursor-bottom-1","content":{"entryType":"TimelineTimelineCursor","cursorType":"Bottom","value":"cursor-` + string(rune('0'+proofs)) + `"}}]}]}}}}}`
					return xResponse(r, 200, body), nil
				}
				if request.Operation == "post" {
					return xResponse(r, 200, `{"data":{"tweetResult":{"result":{"__typename":"Tweet","rest_id":"20","legacy":{"id_str":"20","full_text":"synthetic post","user_id_str":"12"}}}}}`), nil
				}
				if request.Operation == "thread" {
					return xResponse(r, 200, `{"data":{"threaded_conversation_with_injections_v2":{"instructions":[{"type":"TimelineAddEntries","entries":[{"entryId":"tweet-20","content":{"itemContent":{"tweet_results":{"result":{"__typename":"Tweet","rest_id":"20","legacy":{"id_str":"20","full_text":"synthetic thread","user_id_str":"12"}}}}}}]}]}}}`), nil
				}
				return xBootstrap(r)
			})
			if code := (X{Config: c, Base: roundTripFunc(xBootstrap), Proof: proof}).Run(context.Background(), l); code != "" {
				t.Fatal("synthetic X job failed", code)
			}
			if proofs != len(plan.Exchanges) {
				t.Fatal("missing or repeated exchange")
			}
		})
	}
}
func TestXRejectedPoliciesNeverReachAnyTransport(t *testing.T) {
	c, original, _ := xFixture(t, coordinator.XRequest{Operation: "search", Query: "bitcoin", Count: 20, Pages: 2})
	cases := map[string]func(*coordinator.Lease){
		"hash":    func(l *coordinator.Lease) { l.InputSHA256 = SHA("other") },
		"service": func(l *coordinator.Lease) { l.ServiceType = "codex" },
		"wrong policy": func(l *coordinator.Lease) {
			l.XPayload = json.RawMessage(`{"type":"x.read","exchanges":[],"max_attempts":2}`)
		},
		"duplicated JSON": func(l *coordinator.Lease) { l.XPayload = json.RawMessage(`{"type":"x.read","type":"x.read"}`) },
		"Codex mixed in":  func(l *coordinator.Lease) { l.Prompt = "arbitrary" },
		"expired":         func(l *coordinator.Lease) { l.LeaseDeadline = time.Now().Add(-time.Second) },
		"unbounded pages": func(l *coordinator.Lease) { r := *l.XRequest; r.Pages = 4; l.XRequest = &r },
		"unrequested target": func(l *coordinator.Lease) {
			var p xPlan
			json.Unmarshal(l.XPayload, &p)
			p.Exchanges[0].Variables["rawQuery"] = "other"
			l.XPayload, _ = json.Marshal(p)
		},
		"future cursor": func(l *coordinator.Lease) {
			var p xPlan
			json.Unmarshal(l.XPayload, &p)
			n := 2
			p.Exchanges[1].CursorFrom = &n
			l.XPayload, _ = json.Marshal(p)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			l := original
			edit(&l)
			var calls atomic.Int32
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) { calls.Add(1); return nil, errors.New("must not call") })
			code := (X{Config: c, Base: transport, Proof: transport}).Run(context.Background(), l)
			if code == "" || calls.Load() != 0 {
				t.Fatal("invalid work reached provider")
			}
		})
	}
}
func TestXExactRequestFenceAndNoRetries(t *testing.T) {
	c, l, plan := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "fixture"})
	var proofs atomic.Int32
	proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		proofs.Add(1)
		return xResponse(r, 429, `{"errors":[{"code":88,"message":"synthetic rate limit"}]}`), nil
	})
	if code := (X{Config: c, Base: roundTripFunc(xBootstrap), Proof: proof}).Run(context.Background(), l); code != "x_rate_limited" || proofs.Load() != 1 {
		t.Fatal("rate limited job retried or misclassified", code, proofs.Load())
	}
	transport := &xBoundTransport{base: roundTripFunc(xBootstrap), proof: proof, specs: plan.Exchanges}
	s := plan.Exchanges[0]
	v, _ := json.Marshal(s.Variables)
	f, _ := json.Marshal(s.Features)
	query := url.Values{"variables": {string(v)}, "features": {string(f)}}
	path := "https://x.com/i/api/graphql/" + s.QueryID + "/" + s.Operation
	for _, bad := range []string{"https://other.example/i/api/graphql/q/UserByScreenName", path + "?" + query.Encode() + "&variables=%7B%7D", path + "?variables=%7B%22screen_name%22%3A%22other%22%7D&features=" + url.QueryEscape(string(f))} {
		r, _ := http.NewRequest("GET", bad, nil)
		if _, e := transport.RoundTrip(r); e == nil {
			t.Fatal("accepted changed request")
		}
	}
	if proofs.Load() != 1 {
		t.Fatal("fenced request consumed another proof")
	}
}
func TestXCredentialsAndEmptyPaginationAreFailClosed(t *testing.T) {
	c, l, _ := xFixture(t, coordinator.XRequest{Operation: "search", Query: "bitcoin", Count: 20, Pages: 2})
	proofs := 0
	proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		proofs++
		return xResponse(r, 200, `{"data":{"search_by_raw_query":{"search_timeline":{"timeline":{"instructions":[]}}}}}`), nil
	})
	if code := (X{Config: c, Base: roundTripFunc(xBootstrap), Proof: proof}).Run(context.Background(), l); code != "x_incomplete" || proofs != 1 {
		t.Fatal("empty cursor claimed complete pagination", code, proofs)
	}
	if e := makeSessionPublic(c.XSession); e != nil {
		t.Fatal(e)
	}
	if code := (X{Config: c, Base: roundTripFunc(xBootstrap), Proof: proof}).Run(context.Background(), l); code != "auth_required" || proofs != 1 {
		t.Fatal("unsafe session used", code)
	}
	for _, secret := range []string{"secret\r\nInjected: header", "secret;other=cookie", strings.Repeat("x", 161)} {
		s := x.Session{AuthToken: "synthetic", CT0: secret}
		raw, _ := json.Marshal(s)
		makeSessionPrivate(c.XSession)
		localfs.WriteAtomic(c.XSession, raw, true)
		if XConfigured(c.XSession) {
			t.Fatal("accepted unsafe secret")
		}
	}
}

func TestXWireFixtureMatchesPinnedClientRequest(t *testing.T) {
	raw, e := os.ReadFile("../../api/fixtures/lease-x.json")
	if e != nil {
		t.Fatal(e)
	}
	var l coordinator.Lease
	if e = json.Unmarshal(raw, &l); e != nil {
		t.Fatal(e)
	}
	c, _, plan := xFixture(t, *l.XRequest)
	if _, _, code := validateXLease(c, l); code != "" {
		t.Fatal("invalid pinned fixture", code)
	}
	expected, _ := json.Marshal(plan)
	a, e := uniqueJSON(l.XPayload)
	if e != nil {
		t.Fatal(e)
	}
	b, e := uniqueJSON(expected)
	if e != nil || !reflect.DeepEqual(a, b) {
		t.Fatal("X wire policy no longer matches pinned x-go")
	}
}

// A relay lease is served only when the operator opted in, and only under the
// one policy name this node knows. Nothing about the mode is implied.
func TestXRelayLeaseNeedsOperatorOptInAndTheExactPolicy(t *testing.T) {
	raw, e := os.ReadFile("../../api/fixtures/lease-x.json")
	if e != nil {
		t.Fatal(e)
	}
	lease := func(mode, policy string) coordinator.Lease {
		var l coordinator.Lease
		if e := json.Unmarshal(raw, &l); e != nil {
			t.Fatal(e)
		}
		var payload map[string]any
		if e := json.Unmarshal(l.XPayload, &payload); e != nil {
			t.Fatal(e)
		}
		if mode != "" {
			payload["proof_mode"] = mode
		}
		if policy != "" {
			payload["proof_policy"] = policy
		}
		l.XPayload, _ = json.Marshal(payload)
		return l
	}
	base := lease("", "")
	c, _, _ := xFixture(t, *base.XRequest)
	for _, tc := range []struct {
		mode, policy string
		optIn, relay bool
		code         string
	}{
		{"", "", false, false, ""},
		{"mpc", "", false, false, ""},
		{"mpc", "", true, false, ""},
		{"relay", xRelayPolicy, true, true, ""},
		{"relay", xRelayPolicy, false, false, "invalid_lease"},
		{"relay", "", true, false, "invalid_lease"},
		{"relay", "x-relay-v2", true, false, "invalid_lease"},
		{"", xRelayPolicy, true, false, "invalid_lease"},
		{"mpc", xRelayPolicy, true, false, "invalid_lease"},
		{"proxy", "", true, false, "invalid_lease"},
	} {
		c.XRelay = tc.optIn
		plan, _, code := validateXLease(c, lease(tc.mode, tc.policy))
		if code != tc.code {
			t.Fatalf("mode %q policy %q opt-in %v: code %q, want %q", tc.mode, tc.policy, tc.optIn, code, tc.code)
		}
		if relay, _ := plan.relay(c); code == "" && relay != tc.relay {
			t.Fatalf("mode %q policy %q: relay %v, want %v", tc.mode, tc.policy, relay, tc.relay)
		}
	}
}

// The transport a lease gets and the pre-acceptance check both follow the
// validated plan and the operator's opt-in, never the plan alone.
func TestXTransportAndOfferCheckFollowPlanAndOptIn(t *testing.T) {
	c := config.Config{Prover: "p", Verifier: "v:1", VerifierCA: "/ca"}
	relay := xPlan{ProofMode: "relay", ProofPolicy: xRelayPolicy}
	if got := xTransport(c, relay, "t"); got.Relay || got.Prover != "p" || got.Verifier != "v:1" || got.VerifierCA != "/ca" || got.Token != "t" {
		t.Fatalf("relay plan without opt-in built %+v", got)
	}
	c.XRelay = true
	if !xTransport(c, relay, "t").Relay || xTransport(c, xPlan{}, "t").Relay || xTransport(c, xPlan{ProofMode: "relay", ProofPolicy: "other"}, "t").Relay {
		t.Fatal("transport relay flag does not follow the plan")
	}
	for _, tc := range []struct {
		payload string
		optIn   bool
		ok      bool
	}{
		{``, false, true},
		{`{"type":"x.read"}`, false, true},
		{`{"proof_mode":"mpc"}`, false, true},
		{`{"proof_mode":"relay","proof_policy":"x-relay-v1"}`, false, false},
		{`{"proof_mode":"relay","proof_policy":"x-relay-v1"}`, true, true},
		{`{"proof_mode":"relay"}`, true, false},
		{`{"proof_mode":"relay","proof_policy":"x-relay-v2"}`, true, false},
		{`{"proof_policy":"x-relay-v1"}`, true, false},
		{`not json`, true, false},
	} {
		c.XRelay = tc.optIn
		if got := XOfferServable(c, json.RawMessage(tc.payload)); got != tc.ok {
			t.Fatalf("offer %q opt-in %v: servable %v, want %v", tc.payload, tc.optIn, got, tc.ok)
		}
	}
}

// A caught verifier misuse is a node-wide trust break, not an account fault:
// it is classified on its own, halts relay for the whole process, and from
// then on relay offers are declined while MPC-TLS keeps being served.
func TestCaughtVerifierMisuseHaltsRelayNodeWide(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	ctx := context.Background()
	c := config.Config{Prover: "p", Verifier: "v:1", XRelay: true}
	relayOffer := json.RawMessage(`{"proof_mode":"relay","proof_policy":"x-relay-v1"}`)
	mpcOffer := json.RawMessage(`{"proof_mode":"mpc"}`)
	relayPlan := xPlan{ProofMode: "relay", ProofPolicy: xRelayPolicy}

	// An ordinary helper failure neither halts nor is mistaken for misuse.
	if code := xFailure(ctx, errors.New("prover: exit status 1: Error: verifier closed the connection")); code != "x_request_failed" || RelayHalted() {
		t.Fatalf("ordinary failure: code %q halted %v", code, RelayHalted())
	}
	if !XOfferServable(c, relayOffer) || !xTransport(c, relayPlan, "t").Relay {
		t.Fatal("relay not served before any misuse")
	}

	// The marker arrives the way xproof wraps the helper's stderr.
	wrapped := errors.New("prover: exit status 1: Error: " + relayMisuseMarker + ": the record it sealed was not this node's request")
	if code := xFailure(ctx, wrapped); code != "relay_misuse" {
		t.Fatalf("misuse classified as %q", code)
	}
	if !RelayHalted() {
		t.Fatal("misuse did not halt relay")
	}
	// From here on: relay offers declined, MPC still accepted, an in-flight
	// relay plan falls back to the stronger mode rather than running relay.
	if XOfferServable(c, relayOffer) {
		t.Fatal("relay offer accepted after a halt")
	}
	if !XOfferServable(c, mpcOffer) || !XOfferServable(c, nil) {
		t.Fatal("MPC offers declined after a relay halt")
	}
	if xTransport(c, relayPlan, "t").Relay {
		t.Fatal("transport still ran relay after a halt")
	}
	// Sticky and idempotent: a second report changes nothing and a later
	// ordinary failure does not clear it.
	HaltRelay("again")
	if code := xFailure(ctx, errors.New("prover: timeout")); code != "x_request_failed" || !RelayHalted() {
		t.Fatalf("after second report: code %q halted %v", code, RelayHalted())
	}
	// A context that is already cancelled still reports expiry first.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if code := xFailure(cancelled, wrapped); code != "expired" {
		t.Fatalf("expired context classified as %q", code)
	}
}

func TestTypedXQuotaCarriesOnlyCooldownIntoLocalScheduler(t *testing.T) {
	observed := time.Duration(0)
	w := X{Config: config.Config{AccountCooldown: func(wait time.Duration) { observed = wait }}}
	if code := w.failure(context.Background(), &x.RateLimitError{Wait: 2 * time.Hour}); code != "x_rate_limited" || observed != 2*time.Hour {
		t.Fatal("authoritative quota duration lost", code, observed)
	}
	observed = 0
	if code := w.failure(context.Background(), errors.New("private error with rate limit words")); code != "x_request_failed" || observed != 0 {
		t.Fatal("raw error drove account scheduler")
	}
}
