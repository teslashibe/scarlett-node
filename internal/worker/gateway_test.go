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
		{"good", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage_source":"upstream","usage":{"prompt_tokens":8,"completion_tokens":4}}`, ""},
		{"missing source", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":4}}`, "usage_untrusted"},
		{"unknown source", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage_source":"unknown","usage":{"prompt_tokens":8,"completion_tokens":4}}`, "usage_untrusted"},
		{"estimated source", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage_source":"estimated","usage":{"prompt_tokens":8,"completion_tokens":4}}`, "usage_untrusted"},
		{"no usage", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}]}`, "usage_unavailable"},
		{"missing completion", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage_source":"upstream","usage":{"prompt_tokens":8}}`, "usage_unavailable"},
		{"wrong model", `{"model":"model-b","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage_source":"upstream","usage":{"prompt_tokens":8,"completion_tokens":4}}`, "invalid_gateway_response"},
		{"over budget", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"stop"}],"usage_source":"upstream","usage":{"prompt_tokens":8,"completion_tokens":21}}`, "usage_out_of_bounds"},
		{"truncated", `{"model":"model-a","choices":[{"message":{"content":"world"},"finish_reason":"length"}],"usage_source":"upstream","usage":{"prompt_tokens":8,"completion_tokens":4}}`, "invalid_gateway_response"},
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
				if !got.UsageAvailable || got.UsageSource != "upstream" || got.ExecutionMode != "paid" || got.InputTokens != 8 || got.OutputTokens != 4 || got.OutputSHA256 != SHA("world") {
					t.Fatalf("result %+v", got)
				}
			} else if got.UsageAvailable || got.Output != "" {
				t.Fatalf("rewardable failure %+v", got)
			}
		})
	}
}
func TestUnpaidDemoUsage(t *testing.T) {
	for _, source := range []string{"", "unknown", "estimated", "upstream"} {
		t.Run(source, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"model": "model-a", "choices": []any{map[string]any{"message": map[string]string{"content": "world"}, "finish_reason": "stop"}}, "usage_source": source, "usage": map[string]int{"prompt_tokens": 8, "completion_tokens": 4}})
			}))
			defer s.Close()
			g := New(config.Config{Gateway: s.URL, Model: "model-a", Profile: "standard", LocalFixture: true, MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: time.Second})
			got, code := g.Run(context.Background(), coordinator.Lease{Version: coordinator.Version, JobID: "job", SignedJobID: "signed", Attempt: "1", Fence: "f", Profile: "standard", ModelID: "model-a", Prompt: "hello", InputSHA256: SHA("hello"), MaxInputTokens: 100, MaxOutputTokens: 20, LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute)})
			if code != "" || !got.UsageAvailable || got.ExecutionMode != "unpaid_local_demo" {
				t.Fatalf("demo result: %+v, %s", got, code)
			}
			want := "unknown"
			if source == "upstream" {
				want = source
			}
			if got.UsageSource != want {
				t.Fatalf("source = %q", got.UsageSource)
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
