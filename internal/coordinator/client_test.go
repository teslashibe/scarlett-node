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
		{"heartbeat-services.json", &Heartbeat{}},
		{"heartbeat-active-leases.json", &Heartbeat{}},
		{"heartbeat-quota-readiness.json", &Heartbeat{}},
		{"proven.json", &Proven{}},
		{"attempt-status.json", &AttemptStatus{}},
		{"result.json", &Result{}},
		{"failure.json", &Failure{}},
		{"heartbeat-challenge.json", &HeartbeatReply{}},
		{"challenge-echo.json", &ChallengeEcho{}},
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

// A coordinator older than proof_modes rejects the whole heartbeat; the
// client reports that as a distinct error and the node can send the older
// shape, which drops only proof_modes.
func TestPollReportsRejectionAndProofModesCanBeStripped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var h Heartbeat
		if json.NewDecoder(r.Body).Decode(&h) != nil {
			t.Fatal("bad heartbeat body")
		}
		for _, s := range h.Services {
			if s.ProofModes != nil {
				http.Error(w, `{"error":"invalid heartbeat"}`, http.StatusBadRequest)
				return
			}
		}
		json.NewEncoder(w).Encode(HeartbeatReply{})
	}))
	defer server.Close()
	services := []ServiceHealth{{Kind: "codex", State: "ready", Capacity: 1}, {Kind: "x_read", State: "ready", Capacity: 1, ProofModes: []string{"mpc", "relay"}}}
	h := Heartbeat{Version: Version, NodeID: "node", Services: services}
	if _, err := New(server.URL, "demo").Poll(context.Background(), h); !errors.Is(err, ErrHeartbeatRejected) {
		t.Fatalf("400 reported as %v", err)
	}
	stripped, removed := WithoutProofModes(services)
	if !removed || stripped[1].ProofModes != nil || stripped[0].Kind != "codex" || stripped[1].Capacity != 1 || services[1].ProofModes == nil {
		t.Fatalf("strip: removed %v, result %+v, original mutated %v", removed, stripped, services[1].ProofModes == nil)
	}
	h.Services = stripped
	if _, err := New(server.URL, "demo").Poll(context.Background(), h); err != nil {
		t.Fatalf("legacy heartbeat rejected: %v", err)
	}
	if _, removed := WithoutProofModes(stripped); removed {
		t.Fatal("nothing left to strip but removed reported")
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

func TestActiveLeaseReferencesAreCanonicalAndCompatibilityIsConservative(t *testing.T) {
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
	original := []ServiceHealth{{Kind: "x_read", State: "ready", Capacity: 2, InFlight: 1, ActiveLeases: []ActiveLease{valid}}}
	stripped, removed := WithoutExtensions(original)
	if !removed || stripped[0].ActiveLeases != nil || stripped[0].Capacity != 2 || stripped[0].InFlight != 1 || len(original[0].ActiveLeases) != 1 {
		t.Fatal("compatibility fallback changed occupancy or original")
	}
	if _, removed = WithoutExtensions(stripped); removed {
		t.Fatal("compatibility fallback was not stable")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var h Heartbeat
		if err := json.NewDecoder(r.Body).Decode(&h); err != nil {
			t.Fatal(err)
		}
		if len(h.Services[0].ActiveLeases) > 0 {
			http.Error(w, "invalid heartbeat", 400)
			return
		}
		json.NewEncoder(w).Encode(HeartbeatReply{})
	}))
	defer server.Close()
	h := Heartbeat{Version: Version, NodeID: "synthetic-node", Services: original}
	client := New(server.URL, "synthetic-credential")
	if _, err := client.Poll(context.Background(), h); !errors.Is(err, ErrHeartbeatRejected) {
		t.Fatal("old coordinator rejection not classified")
	}
	h.Services = stripped
	if _, err := client.Poll(context.Background(), h); err != nil {
		t.Fatal("old shape not accepted", err)
	}
}
