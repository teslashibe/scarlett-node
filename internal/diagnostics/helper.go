package diagnostics

import (
	"context"
	"encoding/json"
)

type helperSpan struct {
	Phase      string   `json:"phase"`
	StartMS    *float64 `json:"start_ms"`
	DurationMS *float64 `json:"duration_ms"`
	Outcome    string   `json:"outcome"`
}

type helperDiagnostics struct {
	Version    int          `json:"version"`
	Outcome    string       `json:"outcome,omitempty"`
	DurationMS *float64     `json:"duration_ms"`
	Spans      []helperSpan `json:"spans"`
}

// AddHelper accepts only optional operational fields from a helper. Offsets
// retain their helper-local origin and are never aligned to the node clock.
func AddHelper(ctx context.Context, exchange int, raw json.RawMessage) {
	a := fromContext(ctx)
	if a == nil || exchange < 1 || exchange > MaxExchanges || len(raw) == 0 || len(raw) > MaxHelperBytes {
		return
	}
	var parsed helperDiagnostics
	if strictJSON(raw, &parsed) != nil || parsed.Version != Version || parsed.DurationMS == nil || !finiteMS(*parsed.DurationMS) || parsed.Spans == nil || len(parsed.Spans) > 32 {
		return
	}
	if parsed.Outcome != "" && parsed.Outcome != "success" && parsed.Outcome != "error" && parsed.Outcome != "cancelled" && parsed.Outcome != "interrupted" {
		return
	}
	totalOutcome := parsed.Outcome
	if totalOutcome == "" {
		totalOutcome = "interrupted"
	}
	spans := make([]Span, 0, len(parsed.Spans)+1)
	spans = append(spans, Span{Phase: "helper_total", Source: "helper", Exchange: exchange, DurationMS: *parsed.DurationMS, Outcome: totalOutcome})
	for _, item := range parsed.Spans {
		if item.StartMS == nil || item.DurationMS == nil {
			return
		}
		span := Span{Phase: item.Phase, Source: "helper", Exchange: exchange, StartMS: *item.StartMS, DurationMS: *item.DurationMS, Outcome: item.Outcome}
		if !validSpan(span) || item.Phase == "helper_total" || *item.StartMS+*item.DurationMS > *parsed.DurationMS {
			return
		}
		spans = append(spans, span)
	}
	s := a.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.finished || !a.retained {
		return
	}
	for _, prior := range a.record.Spans {
		if prior.Source == "helper" && prior.Exchange == exchange {
			return
		}
	}
	for _, span := range spans {
		index := a.spanSlotLocked(span.Phase, span.Source)
		if index < 0 {
			continue
		}
		a.record.Spans[index] = span
		a.spanStarts[index] = a.started
		a.spanGenerations[index]++
	}
	s.changedLocked()
}
