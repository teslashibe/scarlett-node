package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

func TestGatewayUsageAndModel(t *testing.T) {
	c := config.Config{Model: "model-a", Profile: "standard", MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: time.Second}
	lease := coordinator.Lease{Version: coordinator.Version, JobID: "committed", SignedJobID: "signed-committed", Profile: c.Profile, ModelID: c.Model, Prompt: "hello", MaxInputTokens: 100, MaxOutputTokens: 20, InputSHA256: SHA("hello"), Attempt: "1", Fence: "f", LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute)}
	cases := []struct{ name, body, code string }{
		{"good", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":4}}`, ""},
		{"no usage", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}]}`, "usage_unavailable"},
		{"missing completion", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8}}`, "usage_unavailable"},
		{"wrong model", `{"model":"model-b","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":4}}`, "invalid_gateway_response"},
		{"over budget", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":21}}`, "usage_out_of_bounds"},
		{"truncated", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"length"}],"usage":{"prompt_tokens":8,"completion_tokens":4}}`, "invalid_gateway_response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/chat/completions" {
					t.Errorf("path %s", r.URL.Path)
				}
				var req struct {
					Model     string `json:"model"`
					MaxTokens int    `json:"max_tokens"`
				}
				json.NewDecoder(r.Body).Decode(&req)
				if req.Model != "model-a" || req.MaxTokens != 20 {
					t.Errorf("request %+v", req)
				}
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c.Gateway = srv.URL
			got, code := New(c).Run(context.Background(), lease)
			if code != tc.code {
				t.Fatalf("code %q want %q", code, tc.code)
			}
			if code == "" {
				if !got.UsageAvailable || got.InputTokens != 8 || got.OutputTokens != 4 || got.OutputSHA256 != SHA("world") {
					t.Fatalf("result %+v", got)
				}
			} else if got.UsageAvailable || got.Output != "" {
				t.Fatalf("rewardable failure %+v", got)
			}
		})
	}
}
func TestRejectLeaseBeforeGateway(t *testing.T) {
	c := config.Config{Gateway: "http://127.0.0.1:1", Model: "a", Profile: "p", MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: time.Second}
	l := coordinator.Lease{Version: coordinator.Version, JobID: "j", SignedJobID: "signed-j", Profile: "p", ModelID: "b", Prompt: "x", InputSHA256: SHA("x"), MaxInputTokens: 10, MaxOutputTokens: 10, Attempt: "1", Fence: "f", LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute)}
	_, code := New(c).Run(context.Background(), l)
	if code != "invalid_lease" {
		t.Fatal(code)
	}
}
