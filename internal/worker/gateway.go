package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

type Gateway struct {
	Config config.Config
	HTTP   *http.Client
}

func New(c config.Config) *Gateway {
	return &Gateway{Config: c, HTTP: &http.Client{Timeout: c.InferenceTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}
func SHA(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// checkLease validates untrusted lease fields and returns the inference deadline or a failure code.
func checkLease(c config.Config, l coordinator.Lease) (time.Time, string) {
	if (l.ServiceType != "" && l.ServiceType != "codex") || l.XRequest != nil || len(l.XPayload) > 0 {
		return time.Time{}, "invalid_lease"
	}
	if l.Version != coordinator.Version || l.JobID == "" || l.SignedJobID == "" || l.Attempt == "" || l.Fence == "" || l.InputSHA256 == "" || l.Profile != c.Profile || l.MaxInputTokens < 1 || l.MaxOutputTokens < 1 || l.MaxOutputTokens > c.MaxOutputTokens || !utf8.ValidString(l.Prompt) || len(l.Prompt) > c.MaxInputBytes || SHA(l.Prompt) != l.InputSHA256 {
		return time.Time{}, "invalid_lease"
	}
	if _, ok := config.Serves(l.ModelID); !ok {
		return time.Time{}, "invalid_lease"
	}
	// The local gateway ignores max_tokens: the local fixture is for
	// observing usage, not for enforcing a pre-execution supplier cost cap.
	if c.LocalFixture && (len(l.Prompt) > 32 || l.MaxInputTokens > 32000) {
		return time.Time{}, "invalid_lease"
	}
	// A byte cap is not a tokenizer: require the coordinator's explicit token cap,
	// and reject oversized bytes. Exact input tokens must come from upstream.
	now := time.Now()
	if !l.LeaseDeadline.After(now) || !l.SettlementDeadline.After(now) {
		return time.Time{}, "expired"
	}
	deadline := l.LeaseDeadline
	if l.SettlementDeadline.Before(deadline) {
		deadline = l.SettlementDeadline
	}
	if c.InferenceTimeout < time.Until(deadline) {
		deadline = now.Add(c.InferenceTimeout)
	}
	return deadline, ""
}
func newResult(c config.Config, l coordinator.Lease) coordinator.Result {
	r := coordinator.Result{Version: coordinator.Version, JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, InputSHA256: l.InputSHA256, UsageSource: "unknown", ExecutionMode: "paid"}
	if c.LocalFixture {
		r.ExecutionMode = "unpaid_local_demo"
	}
	return r
}

// finish validates an untrusted completion against the lease and records it on r.
func finish(ctx context.Context, r coordinator.Result, l coordinator.Lease, start time.Time, model, text string, in, out int, cached *int, upstream bool) (coordinator.Result, string) {
	// An effort/fast alias resolves to its base model upstream.
	base, _ := config.Serves(l.ModelID)
	if model != l.ModelID && model != base || text == "" || !utf8.ValidString(text) {
		return r, "invalid_gateway_response"
	}
	if in < 1 || out < 1 || in > l.MaxInputTokens || out > l.MaxOutputTokens {
		return r, "usage_out_of_bounds"
	}
	if cached != nil {
		if *cached < 0 || *cached > in {
			return r, "usage_out_of_bounds"
		}
		r.CachedInputTokens = cached
	}
	if ctx.Err() != nil || !time.Now().Before(l.LeaseDeadline) || !time.Now().Before(l.SettlementDeadline) {
		return r, "expired"
	}
	r.Output = text
	r.OutputSHA256 = SHA(text)
	r.ResolvedModelID = model
	r.InputTokens = in
	r.OutputTokens = out
	r.DurationMS = time.Since(start).Milliseconds()
	r.UsageAvailable = true
	if upstream {
		r.UsageSource = "upstream"
	}
	return r, ""
}

func (g *Gateway) Run(ctx context.Context, l coordinator.Lease) (coordinator.Result, string) {
	r := newResult(g.Config, l)
	fail := func(code string) (coordinator.Result, string) { return r, code }
	c := g.Config
	deadline, code := checkLease(c, l)
	if code != "" {
		return fail(code)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	payload, _ := json.Marshal(struct {
		Model    string `json:"model"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
		MaxTokens int  `json:"max_tokens"`
		Stream    bool `json:"stream"`
	}{Model: l.ModelID, Messages: []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}{{Role: "user", Content: l.Prompt}}, MaxTokens: l.MaxOutputTokens})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Gateway+"/v1/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return fail("gateway_error")
	}
	req.Header.Set("Content-Type", "application/json")
	if c.GatewayKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.GatewayKey)
	}
	start := time.Now()
	resp, err := g.HTTP.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return fail("gateway_error")
		}
		return fail("capacity_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		return fail("capacity_unavailable")
	}
	if resp.StatusCode != http.StatusOK {
		return fail("gateway_error")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 131073))
	if err != nil || len(data) > 131072 {
		return fail("gateway_error")
	}
	var answer struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		UsageSource string `json:"usage_source"`
		Usage       *struct {
			PromptTokens     *int `json:"prompt_tokens"`
			CompletionTokens *int `json:"completion_tokens"`
			PromptDetails    *struct {
				CachedTokens *int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
		} `json:"usage"`
	}
	if json.Unmarshal(data, &answer) != nil || len(answer.Choices) != 1 || answer.Choices[0].FinishReason != "stop" {
		return fail("invalid_gateway_response")
	}
	if answer.Usage == nil || answer.Usage.PromptTokens == nil || answer.Usage.CompletionTokens == nil {
		return fail("usage_unavailable")
	}
	if answer.UsageSource != "upstream" && !c.LocalFixture {
		return fail("usage_untrusted")
	}
	var cached *int
	if d := answer.Usage.PromptDetails; d != nil {
		cached = d.CachedTokens
	}
	return finish(ctx, r, l, start, answer.Model, answer.Choices[0].Message.Content, *answer.Usage.PromptTokens, *answer.Usage.CompletionTokens, cached, answer.UsageSource == "upstream")
}
