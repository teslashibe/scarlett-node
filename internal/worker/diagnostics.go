package worker

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/teslashibe/scarlett-node/internal/diagnostics"
	x "github.com/teslashibe/x-go"
)

type xExchangeKey struct{}

func withXExchange(ctx context.Context, exchange int) context.Context {
	if !diagnostics.Enabled(ctx) {
		return ctx
	}
	ctx = context.WithValue(ctx, xExchangeKey{}, exchange)
	ctx = x.WithWaitObserver(ctx, func(reason string) func(bool) {
		phase := "pacing_wait"
		fine := "fixed_gap_wait"
		switch reason {
		case "jitter":
			fine = "jitter_wait"
		case "spread":
			fine = "quota_spread_wait"
		case "reset":
			fine = "quota_reset_wait"
		}
		if reason == "quota" || reason == "spread" || reason == "reset" {
			phase = "quota_wait"
		}
		end := diagnostics.Start(ctx, phase, exchange)
		endFine := diagnostics.Start(ctx, fine, exchange)
		return func(cancelled bool) {
			if cancelled {
				end("cancelled")
				endFine("cancelled")
			} else {
				end("success")
				endFine("success")
			}
		}
	})
	ctx = x.WithQuotaObserver(ctx, func(q x.QuotaObservation) {
		operation := ""
		switch q.Operation {
		case "SearchTimeline":
			operation = "search"
		case "UserByScreenName":
			operation = "profile"
		case "TweetResultByRestId":
			operation = "post"
		case "TweetDetail":
			operation = "thread"
		}
		diagnostics.ObserveQuota(ctx, diagnostics.QuotaSnapshot{ObservedAt: q.ObservedAt.UTC(), CapturedAt: q.CapturedAt.UTC(), NextEligibleAt: q.NextEligibleAt.UTC(), Exchange: exchange, Operation: operation, Mode: q.Mode, Limit: q.Limit, Remaining: q.Remaining, Reset: q.Reset.UTC(), Complete: q.Complete, Authoritative: q.Authoritative})
	})
	return x.WithDecodeObserver(ctx, func() func(bool) {
		end := diagnostics.Start(ctx, "response_decode", exchange)
		return func(failed bool) {
			if failed {
				if ctx.Err() != nil {
					end("cancelled")
				} else {
					end("error")
				}
			} else {
				end("success")
			}
		}
	})
}

func xExchange(ctx context.Context) int {
	exchange, _ := ctx.Value(xExchangeKey{}).(int)
	return exchange
}

func diagnosticOutcome(ctx context.Context, err error) string {
	if err == nil {
		return "success"
	}
	if ctx != nil && ctx.Err() != nil {
		return "cancelled"
	}
	return "error"
}

// helperDiagnostics is deliberately independent of the proof summary parser.
// Optional operational measurements cannot determine proof success or failure.
func helperDiagnostics(ctx context.Context, exchange int, raw []byte) {
	if !diagnostics.Enabled(ctx) {
		return
	}
	var summary struct {
		Status      string          `json:"status"`
		Diagnostics json.RawMessage `json:"diagnostics"`
		Duration    json.RawMessage `json:"duration_ms"`
	}
	if json.Unmarshal(raw, &summary) != nil {
		return
	}
	if len(summary.Diagnostics) > 0 {
		diagnostics.AddHelper(ctx, exchange, summary.Diagnostics)
		return
	}
	// Older helpers already supplied a coarse duration without nested spans.
	if len(summary.Duration) > 0 && summary.Status == "proof_sent" {
		value, err := json.Marshal(struct {
			Version  int             `json:"version"`
			Duration json.RawMessage `json:"duration_ms"`
			Spans    []any           `json:"spans"`
			Outcome  string          `json:"outcome"`
		}{1, summary.Duration, []any{}, "success"})
		if err == nil {
			diagnostics.AddHelper(ctx, exchange, value)
		}
	}
}

// Failed helpers emit one bounded diagnostic line. Remove only those lines
// before applying the existing stderr classification and local error handling.
func helperStderr(ctx context.Context, exchange int, stderr string) string {
	const prefix = "SCARLETT_DIAGNOSTICS="
	lines := strings.Split(stderr, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			diagnostics.AddHelper(ctx, exchange, json.RawMessage(strings.TrimPrefix(line, prefix)))
		} else {
			kept = append(kept, line)
		}
	}
	detail := strings.Join(kept, "\n")
	// The extra stderr capacity belongs only to optional diagnostics. Existing
	// error text keeps its original 4 KiB bound after the marker is removed.
	if len(detail) > 4096 {
		detail = detail[:4096]
	}
	return strings.TrimSpace(detail)
}
