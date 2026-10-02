package coordinator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
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
