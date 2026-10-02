package coordinator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAttemptStatusRequiresCommittedReportReceipt(t *testing.T) {
	for _, tc := range []struct {
		state, hash string
		valid       bool
	}{
		{"accepted", "", false}, {"failed", "", false}, {"accepted", "abcd", false}, {"failed", strings.Repeat("A", 64), false}, {"accepted", strings.Repeat("a", 64), true}, {"failed", strings.Repeat("b", 64), true}, {"proof_pending", strings.Repeat("c", 64), true}, {"live", "", true},
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
