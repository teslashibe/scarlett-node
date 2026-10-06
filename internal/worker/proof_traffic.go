package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
)

// ProofObserver belongs to one already accepted lease. Begin must persist before
// the helper starts; completion receives only finite labels and byte counters.
type ProofObserver func() (func(attempts.ProofSample) error, error)
type proofObserverKey struct{}

func WithProofObserver(ctx context.Context, observer ProofObserver) context.Context {
	return context.WithValue(ctx, proofObserverKey{}, observer)
}

// ProofSampleLimit uses the current production policy, never experimental batch
// settings. x-go WithRetry(1) means one total attempt for each pinned exchange.
func ProofSampleLimit(c config.Config, l coordinator.Lease) int {
	if l.ServiceType == "x_read" {
		plan, _, code := validateXLease(c, l)
		if code != "" {
			return 0
		}
		return plan.MaxAttempts
	}
	return 1
}

func beginProofObservation(ctx context.Context) (func([]byte, bool), error) {
	observer, _ := ctx.Value(proofObserverKey{}).(ProofObserver)
	if observer == nil {
		return func([]byte, bool) {}, nil
	}
	exchange := xExchange(ctx)
	if exchange == 0 {
		exchange = 1
	}
	endBegin := diagnostics.Start(ctx, "proof_journal_begin", exchange)
	complete, err := observer()
	endBegin(diagnosticOutcome(ctx, err))
	if err != nil {
		return nil, err
	}
	var once sync.Once
	return func(raw []byte, helperOK bool) {
		once.Do(func() {
			// A failed completion write leaves the durable started sample unknown.
			// It cannot become complete merely because the worker later finishes.
			endComplete := diagnostics.Start(ctx, "proof_journal_complete", exchange)
			err := complete(proofSample(raw, helperOK))
			endComplete(diagnosticOutcome(ctx, err))
		})
	}, nil
}

func proofSample(raw []byte, helperOK bool) attempts.ProofSample {
	incomplete := func(reason string) attempts.ProofSample {
		return attempts.ProofSample{State: "incomplete", Reason: reason}
	}
	if !helperOK {
		return incomplete("helper_failed")
	}
	v, err := proofSummaryJSON(raw)
	if err != nil || v["status"] != "proof_sent" {
		return incomplete("invalid")
	}
	for _, field := range []string{"verifier_sent_bytes", "verifier_received_bytes", "verifier_transport_layer"} {
		if _, exists := v[field]; !exists {
			return incomplete("missing")
		}
	}
	if v["verifier_transport_layer"] != "tcp_payload" {
		return incomplete("invalid")
	}
	number := func(value any) (*uint64, bool) {
		n, ok := value.(json.Number)
		if !ok {
			return nil, false
		}
		count, err := strconv.ParseUint(string(n), 10, 64)
		return &count, err == nil && count <= attempts.MaxProofBytes
	}
	sent, sentOK := number(v["verifier_sent_bytes"])
	received, receivedOK := number(v["verifier_received_bytes"])
	if !sentOK || !receivedOK {
		return incomplete("invalid")
	}
	saturated := false
	if value, exists := v["verifier_bytes_saturated"]; exists {
		var ok bool
		saturated, ok = value.(bool)
		if !ok {
			return incomplete("invalid")
		}
	}
	sample := attempts.ProofSample{State: "complete", SentBytes: sent, ReceivedBytes: received}
	if saturated {
		sample.State, sample.Reason, sample.Saturated = "incomplete", "saturated", true
	}
	return sample
}

// Operational fields are optional and cannot invalidate the independent byte
// sample. All remaining fields retain unique-key and integer-JSON validation.
func proofSummaryJSON(raw []byte) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid proof summary")
	}
	value := map[string]any{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, errors.New("invalid proof summary key")
		}
		var field json.RawMessage
		if d.Decode(&field) != nil {
			return nil, errors.New("invalid proof summary field")
		}
		if key == "diagnostics" || key == "duration_ms" {
			continue
		}
		if _, exists := value[key]; exists {
			return nil, errors.New("duplicate proof summary key")
		}
		fieldValue, err := uniqueJSON(field)
		if err != nil {
			return nil, err
		}
		value[key] = fieldValue
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("invalid proof summary end")
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing proof summary")
	}
	return value, nil
}
