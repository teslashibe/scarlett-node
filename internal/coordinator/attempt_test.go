package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A committed report's receipt must be a well-formed hash; an accepted or
// failed attempt without one was decided from the verifier's own record
// before the node's report arrived (C2), and is valid.
func TestAttemptStatusChecksTheReportReceipt(t *testing.T) {
	for _, tc := range []struct {
		state, hash string
		valid       bool
	}{
		{"accepted", "", true}, {"failed", "", true}, {"accepted", "abcd", false}, {"failed", strings.Repeat("A", 64), false}, {"accepted", strings.Repeat("a", 64), true}, {"failed", strings.Repeat("b", 64), true}, {"proof_pending", strings.Repeat("c", 64), true}, {"live", "", true},
	} {
		t.Run(tc.state+tc.hash, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic" || r.Method != "GET" || r.URL.Query().Get("attempt") != "1" || r.URL.Query().Get("fence") != "f1" {
					t.Error("unbound recovery request")
				}
				json.NewEncoder(w).Encode(AttemptStatus{Version: Version, JobID: "synthetic", Attempt: "1", Fence: "f1", State: tc.state, ReplaySafe: true, SubmissionSHA256: tc.hash})
			}))
			defer server.Close()
			client := New(server.URL, "synthetic")
			client.HTTP = server.Client()
			_, err := client.AttemptStatus(context.Background(), "synthetic", "1", "f1")
			if (err == nil) != tc.valid {
				t.Fatal("incorrect committed report authority", err)
			}
		})
	}
}

// Any answer but 200 is a *StatusError with its code and Retry-After, so
// reconciliation can tell a rate limit or an unavailable coordinator from a
// refusal of the attempt; no answer at all is a *TransportError.
func TestAttemptStatusErrorsAreTyped(t *testing.T) {
	for _, tc := range []struct {
		status     int
		code       string
		retryAfter string
		wait       time.Duration
	}{
		{429, "rate_limited", "7", 7 * time.Second}, {503, "network_unavailable", "", 0}, {401, "node_unauthorized", "", 0}, {404, "attempt_unavailable", "", 0}, {409, "attempt_conflict", "", 0}, {502, "", "", 0},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tc.retryAfter != "" {
				w.Header().Set("Retry-After", tc.retryAfter)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			if tc.code != "" {
				json.NewEncoder(w).Encode(ErrorReply{Error: ErrorDetail{Code: tc.code, Message: "synthetic"}})
			}
		}))
		client := New(server.URL, "synthetic")
		client.HTTP = server.Client()
		_, err := client.AttemptStatus(context.Background(), "synthetic", "1", "f1")
		server.Close()
		var status *StatusError
		if !errors.As(err, &status) || status.Status != tc.status || status.Code != tc.code || status.RetryAfter != tc.wait || errors.Is(err, ErrUnavailable) {
			t.Fatalf("%d %s: %#v", tc.status, tc.code, err)
		}
	}
	client := New("https://127.0.0.1:1", "synthetic")
	_, err := client.AttemptStatus(context.Background(), "synthetic", "1", "f1")
	var transport *TransportError
	if !errors.As(err, &transport) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no answer: %#v", err)
	}
}
