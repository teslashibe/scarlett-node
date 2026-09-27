package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/teslashibe/open-agent-api/pkg/codex"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

type fakeCodex struct {
	model, prompt string
	res           codex.Result
	err           error
}

func (f *fakeCodex) Complete(_ context.Context, model, prompt string) (codex.Result, error) {
	f.model, f.prompt = model, prompt
	return f.res, f.err
}

func TestCodexExecutor(t *testing.T) {
	c := config.Config{Profile: "standard", MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: time.Second}
	lease := coordinator.Lease{Version: coordinator.Version, JobID: "j", SignedJobID: "s", Profile: c.Profile, ModelID: "gpt-5.6-terra-fast-low", Prompt: "hello", MaxInputTokens: 100, MaxOutputTokens: 20, InputSHA256: SHA("hello"), Attempt: "1", Fence: "f", LeaseDeadline: time.Now().Add(time.Minute), SettlementDeadline: time.Now().Add(time.Minute)}
	good := codex.Result{Text: "world", Model: "gpt-5.6-terra", Usage: true, InputTokens: 8, OutputTokens: 4}
	for _, tc := range []struct {
		name string
		res  codex.Result
		err  error
		code string
	}{
		{"base resolved", good, nil, ""},
		{"no usage", codex.Result{Text: "world", Model: "gpt-5.6-terra"}, nil, "usage_unavailable"},
		{"other model", codex.Result{Text: "world", Model: "gpt-5.6-luna", Usage: true, InputTokens: 8, OutputTokens: 4}, nil, "invalid_gateway_response"},
		{"over budget", codex.Result{Text: "world", Model: "gpt-5.6-terra", Usage: true, InputTokens: 8, OutputTokens: 21}, nil, "usage_out_of_bounds"},
		{"empty", codex.Result{Model: "gpt-5.6-terra", Usage: true, InputTokens: 8, OutputTokens: 4}, nil, "invalid_gateway_response"},
		{"upstream error", codex.Result{}, errors.New("boom"), "gateway_error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeCodex{res: tc.res, err: tc.err}
			r, code := Codex{Config: c, Client: f}.Run(context.Background(), lease)
			if code != tc.code {
				t.Fatalf("code %q want %q", code, tc.code)
			}
			if f.model != lease.ModelID || f.prompt != "hello" {
				t.Fatalf("sent %q %q", f.model, f.prompt)
			}
			if code == "" && (r.ResolvedModelID != "gpt-5.6-terra" || r.InputTokens != 8 || r.OutputTokens != 4 || !r.UsageAvailable || r.UsageSource != "upstream" || r.OutputSHA256 != SHA("world") || r.ExecutionMode != "paid") {
				t.Fatalf("result %+v", r)
			}
		})
	}
	if _, code := (Codex{Config: c, Client: &fakeCodex{}}).Run(context.Background(), coordinator.Lease{}); code != "invalid_lease" {
		t.Fatalf("unchecked lease: %q", code)
	}
}
