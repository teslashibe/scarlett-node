package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPollChallenge(t *testing.T) {
	for _, tc := range []struct {
		name, nonce                     string
		expired, httpOnly, noCredential bool
		echoStatus                      int
		wantEcho, wantErr               bool
	}{
		{name: "authenticated", nonce: strings.Repeat("a", 64), echoStatus: 204, wantEcho: true},
		{name: "expired", nonce: strings.Repeat("a", 64), expired: true, wantErr: true},
		{name: "malformed", nonce: "short", wantErr: true},
		{name: "loopback HTTP", nonce: strings.Repeat("a", 64), httpOnly: true, echoStatus: 204, wantEcho: true},
		{name: "unauthenticated", nonce: strings.Repeat("a", 64), noCredential: true, wantErr: true},
		{name: "rejected replay", nonce: strings.Repeat("a", 64), echoStatus: 409, wantEcho: true, wantErr: true},
		{name: "ambiguous response", nonce: strings.Repeat("a", 64), echoStatus: 500, wantEcho: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			echoes := 0
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !tc.noCredential && r.Header.Get("Authorization") != "Bearer test-credential" {
					t.Error("missing authentication")
				}
				switch r.URL.Path {
				case "/api/node/v1/heartbeat":
					expiry := time.Now().Add(time.Minute)
					if tc.expired {
						expiry = time.Now().Add(-time.Minute)
					}
					json.NewEncoder(w).Encode(HeartbeatReply{Lease: &Lease{JobID: "job"}, Challenge: &Challenge{Version: Version, Nonce: tc.nonce, ExpiresAt: expiry}})
				case "/api/node/v1/challenge/echo":
					echoes++
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if len(body) != 3 || body["version"] != Version || body["node_id"] != "node" || body["nonce"] != tc.nonce {
						t.Errorf("unexpected echo: %v", body)
					}
					w.WriteHeader(tc.echoStatus)
				default:
					t.Error("unexpected request")
				}
			})
			var server *httptest.Server
			if tc.httpOnly {
				server = httptest.NewServer(handler)
			} else {
				server = httptest.NewTLSServer(handler)
			}
			defer server.Close()
			c := New(server.URL, "test-credential")
			c.HTTP = server.Client()
			if tc.noCredential {
				c.Credential = ""
			}
			reply, err := c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v", err)
			}
			if !tc.wantErr && (reply.Lease == nil || reply.Lease.JobID != "job") {
				t.Fatal("lost lease")
			}
			if tc.wantErr && reply.Lease != nil {
				t.Fatal("returned lease despite failed challenge")
			}
			want := 0
			if tc.wantEcho {
				want = 1
			}
			if echoes != want {
				t.Fatalf("echo calls = %d, want %d (no retry)", echoes, want)
			}
		})
	}
}

func TestWireFixtures(t *testing.T) {
	for _, tc := range []struct {
		file  string
		value any
	}{
		{"lease.json", &Lease{}},
		{"lease-proven.json", &Lease{}},
		{"lease-offer.json", &Lease{}},
		{"lease-acceptance.json", &LeaseAcceptance{}},
		{"lease-x.json", &Lease{}},
		{"lease-web-offer.json", &Lease{}},
		{"lease-web.json", &Lease{}},
		{"heartbeat-web.json", &Heartbeat{}},
		{"failure-web.json", &Failure{}},
		{"lease-web-browser-offer.json", &Lease{}},
		{"lease-web-browser.json", &Lease{}},
		{"lease-web-prewarm-offer.json", &Lease{}},
		{"heartbeat-web-browser.json", &Heartbeat{}},
		{"browser-result.json", &BrowserResult{}},
		{"failure-web-browser.json", &Failure{}},
		{"heartbeat-services.json", &Heartbeat{}},
		{"heartbeat-active-leases.json", &Heartbeat{}},
		{"heartbeat-quota-readiness.json", &Heartbeat{}},
		{"proven.json", &Proven{}},
		{"attempt-status.json", &AttemptStatus{}},
		{"result.json", &Result{}},
		{"failure.json", &Failure{}},
		{"heartbeat-challenge.json", &HeartbeatReply{}},
		{"challenge-echo.json", &ChallengeEcho{}},
		{"error-dispatch-busy.json", &ErrorReply{}},
		{"error-heartbeat-too-large.json", &ErrorReply{}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile("../../api/fixtures/" + tc.file)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, tc.value); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			var original, roundtrip any
			if err := json.Unmarshal(data, &original); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &roundtrip); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(original, roundtrip) {
				t.Fatalf("fixture and Go wire fields differ: %s", tc.file)
			}
		})
	}
}

func TestEchoPolicy(t *testing.T) {
	remote := New("http://host.docker.internal:8091", "cred")
	origin, err := url.Parse(remote.Origin)
	if err != nil || remote.allowEcho(origin) {
		t.Fatal("shared-key HTTP outside loopback must not echo")
	}
	remote.EchoUnqualifiedHTTP = true
	if !remote.allowEcho(origin) {
		t.Fatal("explicit fixture mode should echo")
	}
	loopback := New("http://127.0.0.1:8080", "cred")
	origin, _ = url.Parse(loopback.Origin)
	if !loopback.allowEcho(origin) {
		t.Fatal("loopback HTTP with a credential should echo")
	}
	if New("https://coordinator.example", "").allowEcho(mustOrigin(t, "https://coordinator.example")) {
		t.Fatal("https without a credential")
	}
	if !New("https://coordinator.example", "cred").allowEcho(mustOrigin(t, "https://coordinator.example")) {
		t.Fatal("authenticated https")
	}
}

func mustOrigin(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// A heartbeat the coordinator rejects as invalid (400) or too large (413) is
// one distinct error carrying the status and code. Poll sends it once and
// never resends a reduced shape: the caller logs it and backs off.
func TestPollReportsRejectionWithoutRetry(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		code   string
	}{
		{http.StatusBadRequest, `{"error":{"code":"node_invalid","message":"That node report is invalid."}}`, "node_invalid"},
		{http.StatusRequestEntityTooLarge, `{"error":{"code":"heartbeat_too_large","message":"The heartbeat is too large."}}`, "heartbeat_too_large"},
		{http.StatusBadRequest, `not json`, ""},
	} {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			var h Heartbeat
			if json.NewDecoder(r.Body).Decode(&h) != nil || len(h.Services) != 2 || h.Services[1].ProofModes == nil || len(h.Services[1].ActiveLeases) != 1 {
				t.Error("heartbeat sent without its extensions")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			io.WriteString(w, tc.body)
		}))
		lease := ActiveLease{JobID: "11111111-1111-4111-8111-111111111111", Attempt: "22222222-2222-4222-8222-222222222222", Fence: "33333333-3333-4333-8333-333333333333"}
		services := []ServiceHealth{{Kind: "codex", State: "ready", Capacity: 1}, {Kind: "x_read", State: "ready", Capacity: 2, InFlight: 1, ProofModes: []string{"mpc", "relay"}, ActiveLeases: []ActiveLease{lease}}}
		_, err := New(server.URL, "demo").Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node", Services: services})
		server.Close()
		var status *StatusError
		if !errors.Is(err, ErrHeartbeatRejected) || !errors.As(err, &status) || status.Status != tc.status || status.Code != tc.code {
			t.Fatalf("HTTP %d reported as %v", tc.status, err)
		}
		if calls.Load() != 1 {
			t.Fatalf("HTTP %d: %d heartbeats sent, want 1", tc.status, calls.Load())
		}
	}
}

// Retry-After is read in seconds or as an HTTP date and clamped to [1, 60]
// seconds; an absent or unreadable header is zero.
func TestRetryAfterParsingAndClamp(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	for value, want := range map[string]time.Duration{
		"":                              0,
		"soon":                          0,
		"-5":                            0,
		"1.5":                           0,
		"0":                             MinRetryAfter,
		"1":                             time.Second,
		" 7 ":                           7 * time.Second,
		"60":                            MaxRetryAfter,
		"61":                            MaxRetryAfter,
		"3600":                          MaxRetryAfter,
		"99999999999999999999999":       MaxRetryAfter,
		"Tue, 06 Oct 2026 12:00:20 GMT": 20 * time.Second,
		"Tue, 06 Oct 2026 11:59:00 GMT": MinRetryAfter,
		"Tue, 06 Oct 2026 13:00:00 GMT": MaxRetryAfter,
	} {
		header := http.Header{}
		if value != "" {
			header.Set("Retry-After", value)
		}
		if got := retryAfter(header, now); got != want {
			t.Errorf("Retry-After %q = %v, want %v", value, got, want)
		}
	}
}

// The wait on a Retry-After is the value plus up to half of it again, so a
// fleet told the same wait spreads out instead of returning together.
func TestRetryAfterWaitJitterBounds(t *testing.T) {
	if RetryAfterWait(0) != 0 {
		t.Fatal("no Retry-After must add no wait")
	}
	for _, after := range []time.Duration{MinRetryAfter, 5 * time.Second, MaxRetryAfter} {
		seen := map[time.Duration]bool{}
		for range 1000 {
			wait := RetryAfterWait(after)
			if wait < after || wait > after+after/2 {
				t.Fatalf("Retry-After %v waited %v", after, wait)
			}
			seen[wait] = true
		}
		if len(seen) < 100 {
			t.Fatalf("Retry-After %v: only %d distinct waits", after, len(seen))
		}
	}
}

// A 200 with a null lease reports its Retry-After to the caller; a 429 or 503
// reports it, with the status and code, on the error. Other bodies and codes
// that are not short machine codes are not trusted into logs.
func TestPollReportsRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		status           int
		retryAfter, body string
		wantAfter        time.Duration
		wantCode         string
	}{
		{http.StatusOK, "3", `{"lease":null}`, 3 * time.Second, ""},
		{http.StatusOK, "", `{"lease":null}`, 0, ""},
		{http.StatusTooManyRequests, "120", `{"error":{"code":"rate_limited","message":"Too many node requests."}}`, MaxRetryAfter, "rate_limited"},
		{http.StatusServiceUnavailable, "0", `{"error":{"code":"network_unavailable","message":"x"}}`, MinRetryAfter, "network_unavailable"},
		{http.StatusServiceUnavailable, "", `{"error":{"code":"Bad Code\n","message":"x"}}`, 0, ""},
		{http.StatusServiceUnavailable, "2", strings.Repeat(" ", maxErrorBytes) + `{"error":{"code":"network_unavailable"}}`, 2 * time.Second, ""},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.retryAfter != "" {
				w.Header().Set("Retry-After", tc.retryAfter)
			}
			w.WriteHeader(tc.status)
			io.WriteString(w, tc.body)
		}))
		reply, err := New(server.URL, "demo").Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"})
		server.Close()
		if tc.status == http.StatusOK {
			if err != nil || reply.Lease != nil || reply.RetryAfter != tc.wantAfter {
				t.Fatalf("200 Retry-After %q: reply %+v, err %v", tc.retryAfter, reply, err)
			}
			continue
		}
		var status *StatusError
		if !errors.As(err, &status) || errors.Is(err, ErrHeartbeatRejected) || status.Status != tc.status || status.RetryAfter != tc.wantAfter || status.Code != tc.wantCode {
			t.Fatalf("HTTP %d Retry-After %q: %#v", tc.status, tc.retryAfter, err)
		}
	}
}

func TestPollWithoutChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/v1/heartbeat" {
			t.Fatal("unexpected echo")
		}
		json.NewEncoder(w).Encode(HeartbeatReply{Lease: &Lease{JobID: "demo"}})
	}))
	defer server.Close()
	reply, err := New(server.URL, "demo").Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"})
	if err != nil || reply.Lease == nil {
		t.Fatalf("legacy/demo poll: %v", err)
	}
}

// The heartbeat is a long poll. It carries the hold it asks for, runs under its
// own deadline of that hold plus the grace rather than the client's 10-second
// timeout, and ctx cancellation ends it at once.
func TestPollLongPollDeadlineIsWaitPlusGrace(t *testing.T) {
	c := New("https://coordinator.example", "cred")
	for wait, want := range map[int]time.Duration{0: 10 * time.Second, 20: 30 * time.Second, -3: 10 * time.Second} {
		if got := c.heartbeatTimeout(wait); got != want {
			t.Fatalf("wait %d: deadline %v, want %v", wait, got, want)
		}
	}
	var firstHold atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var h Heartbeat
		if json.NewDecoder(r.Body).Decode(&h) != nil {
			t.Error("bad heartbeat body")
		}
		firstHold.CompareAndSwap(0, int32(h.WaitSeconds))
		// Hold the request for most of the asked wait, then answer idle.
		select {
		case <-time.After(300 * time.Millisecond):
			io.WriteString(w, `{"lease":null}`)
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	c = New(server.URL, "cred")
	c.HTTP.Timeout = 50 * time.Millisecond // Far shorter than the hold.
	c.heartbeatGrace = 200 * time.Millisecond
	started := time.Now()
	if _, err := c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node", WaitSeconds: 1}); err != nil {
		t.Fatalf("held heartbeat failed under the client timeout: %v", err)
	}
	if time.Since(started) < 300*time.Millisecond {
		t.Fatal("heartbeat did not wait for the hold")
	}
	if firstHold.Load() != 1 {
		t.Fatalf("wait_seconds on the wire: %d", firstHold.Load())
	}
	// The client timeout still bounds every other call.
	if _, err := c.Post(context.Background(), "/api/node/v1/heartbeat", Heartbeat{Version: Version, WaitSeconds: 1}, nil); err == nil {
		t.Fatal("an ordinary post outlived the client timeout")
	}
	// A hold the coordinator does not honour ends at wait plus grace.
	started = time.Now()
	if _, err := c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node", WaitSeconds: 0}); err == nil {
		t.Fatal("heartbeat outlived wait plus grace")
	}
	if elapsed := time.Since(started); elapsed < 200*time.Millisecond || elapsed > 290*time.Millisecond {
		t.Fatalf("heartbeat deadline fired after %v, want about 200ms", elapsed)
	}
	// Cancellation aborts a held heartbeat promptly.
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	started = time.Now()
	if _, err := c.Poll(ctx, Heartbeat{Version: Version, NodeID: "node", WaitSeconds: 20}); err == nil {
		t.Fatal("cancelled heartbeat returned a reply")
	}
	if time.Since(started) > 250*time.Millisecond {
		t.Fatal("cancellation did not abort the held heartbeat", time.Since(started))
	}
}

func TestActiveLeaseReferencesAreCanonical(t *testing.T) {
	valid := ActiveLease{JobID: "11111111-1111-4111-8111-111111111111", Attempt: "22222222-2222-4222-8222-222222222222", Fence: "33333333-3333-4333-8333-333333333333"}
	if !valid.Valid() {
		t.Fatal("canonical owned reference rejected")
	}
	for _, change := range []func(*ActiveLease){
		func(l *ActiveLease) { l.JobID = "00000000-0000-0000-0000-000000000000" },
		func(l *ActiveLease) { l.Attempt = "1" },
		func(l *ActiveLease) { l.Fence = "{33333333-3333-4333-8333-333333333333}" },
		func(l *ActiveLease) { l.JobID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" },
	} {
		invalid := valid
		change(&invalid)
		if invalid.Valid() {
			t.Fatal("noncanonical or nil reference accepted")
		}
	}
}
