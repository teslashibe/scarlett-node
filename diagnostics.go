package main

import (
	"context"
	"encoding/json"
	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
)

// Only finite workload labels and a private attempt-binding hash are observed.
// Prompts, queries, handles, raw job IDs, fences and tokens never enter history.
func beginLeaseDiagnostics(store *diagnostics.Store, l coordinator.Lease) *diagnostics.Attempt {
	meta := diagnostics.Metadata{
		ID:        (attempts.Record{JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence}).Key(),
		Operation: "other", ProofMode: "none",
	}
	if l.ServiceType == "codex" || l.ServiceType == "" {
		meta.Operation = "codex"
	}
	if l.ServiceType == "web" {
		// Hops are exchanges; the page is one unit of work. A browser job's
		// browser phase and upload are exchange 0, its re-fetch hops 1-6.
		meta.Operation, meta.Pages, meta.ProofMode = "scrape", 1, "relay"
		if l.WebRequest != nil && l.WebRequest.Mode == "browser" {
			meta.ProofMode = "browser"
		}
	}
	if l.ServiceType == "x_read" && l.XRequest != nil {
		switch l.XRequest.Operation {
		case "search":
			meta.Operation, meta.Pages = "search", max(0, min(3, l.XRequest.Pages))
		case "profile", "post", "thread":
			meta.Operation, meta.Pages = l.XRequest.Operation, 1
		}
		if len(l.XPayload) <= 65536 {
			var mode struct {
				ProofMode string `json:"proof_mode"`
			}
			if json.Unmarshal(l.XPayload, &mode) == nil {
				switch mode.ProofMode {
				case "relay":
					meta.ProofMode = "relay"
				case "", "mpc":
					meta.ProofMode = "mpc"
				}
			}
		}
	}
	return store.Begin(meta)
}

func diagnosticOutcome(ctx context.Context, code string, err error) string {
	if ctx.Err() != nil {
		return "cancelled"
	}
	if err != nil {
		return "error"
	}
	if code != "" {
		return code
	}
	return "success"
}
