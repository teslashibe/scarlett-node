package worker

import (
	"context"
	"time"

	"github.com/teslashibe/open-agent-api/pkg/codex"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// Completer is the in-process Codex client; *codex.Client satisfies it.
type Completer interface {
	Complete(ctx context.Context, model, prompt string) (codex.Result, error)
}

// Codex runs leases in-process with this node's own Codex login instead of an HTTP gateway.
type Codex struct {
	Config config.Config
	Client Completer
}

func NewCodex(c config.Config) (*codex.Client, error) {
	return codex.New(codex.Config{
		Accounts:     []codex.Account{{Label: "node", AuthPath: c.CodexHome + "/auth.json", CodexHome: c.CodexHome}},
		ProfilePath:  c.CodexProfile,
		ScaffoldPath: c.CodexScaffold,
		MaxInflight:  max(c.Concurrency, 1),
		Timeout:      c.InferenceTimeout,
	})
}

func (x Codex) Run(ctx context.Context, l coordinator.Lease) (coordinator.Result, string) {
	r := newResult(x.Config, l)
	deadline, code := checkLease(x.Config, l)
	if code != "" {
		return r, code
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	start := time.Now()
	res, err := x.Client.Complete(ctx, l.ModelID, l.Prompt)
	if err != nil {
		if codex.IsCapacity(err) {
			return r, "capacity_unavailable"
		}
		return r, "gateway_error"
	}
	if !res.Usage {
		return r, "usage_unavailable"
	}
	return finish(ctx, r, l, start, res.Model, res.Text, res.InputTokens, res.OutputTokens, nil, true)
}
