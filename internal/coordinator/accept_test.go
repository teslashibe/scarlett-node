package coordinator

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
		l.LeaseDeadline = time.Now().Add(121 * time.Second)
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
