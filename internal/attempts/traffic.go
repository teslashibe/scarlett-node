package attempts

import (
	"context"
	"path/filepath"
	"reflect"
	"time"
)

const MaxProofBytes uint64 = 1 << 40

// ProofTraffic is private operational telemetry, never proof or billing evidence.
// The enclosing immutable journal identity binds it to one accepted node attempt.
type ProofTraffic struct {
	Schema           int           `json:"schema"`
	LeaseFingerprint string        `json:"lease_fingerprint"`
	Layer            string        `json:"layer"`
	MaxSamples       int           `json:"max_samples"`
	WorkerFinished   bool          `json:"worker_finished"`
	Samples          []ProofSample `json:"samples"`
}

type ProofSample struct {
	Ordinal       int     `json:"ordinal"`
	State         string  `json:"state"`
	SentBytes     *uint64 `json:"sent_bytes,omitempty"`
	ReceivedBytes *uint64 `json:"received_bytes,omitempty"`
	Saturated     bool    `json:"saturated,omitempty"`
	Reason        string  `json:"reason,omitempty"`
}

func (s ProofSample) valid() bool {
	if s.Ordinal < 1 || s.Ordinal > 3 {
		return false
	}
	numbers := s.SentBytes != nil && s.ReceivedBytes != nil && *s.SentBytes <= MaxProofBytes && *s.ReceivedBytes <= MaxProofBytes
	empty := s.SentBytes == nil && s.ReceivedBytes == nil
	switch s.State {
	case "started":
		return empty && !s.Saturated && s.Reason == ""
	case "complete":
		return numbers && !s.Saturated && s.Reason == ""
	case "incomplete":
		switch s.Reason {
		case "helper_failed", "missing", "invalid":
			return empty && !s.Saturated
		case "saturated":
			return numbers && s.Saturated
		}
	}
	return false
}

func (t ProofTraffic) valid(fingerprint string) bool {
	if t.Schema != 1 || t.LeaseFingerprint != fingerprint || t.Layer != "tcp_payload" || t.MaxSamples < 1 || t.MaxSamples > 3 || len(t.Samples) < 1 || len(t.Samples) > t.MaxSamples {
		return false
	}
	for i, sample := range t.Samples {
		if sample.Ordinal != i+1 || !sample.valid() {
			return false
		}
	}
	return true
}

func boundRecord(old, r Record) bool {
	return old.JobID == r.JobID && old.Attempt == r.Attempt && old.Fence == r.Fence && old.Fingerprint == r.Fingerprint && old.Deadline.Equal(r.Deadline) && old.ProviderAccountID == r.ProviderAccountID && old.ProviderService == r.ProviderService
}

// BeginProof reserves evidence before spawning a helper. A crash leaves a started
// sample with no byte values; recovery never calls this method or repeats work.
func (j *Journal) BeginProof(r Record, maxSamples int) (int, error) {
	return j.BeginProofContext(context.Background(), r, maxSamples)
}

// BeginProofContext records local timings for the existing durable reservation.
func (j *Journal) BeginProofContext(ctx context.Context, r Record, maxSamples int) (int, error) {
	j.lockContext(ctx)
	defer j.mu.Unlock()
	old, err := j.read(filepath.Join(j.dir, key(r)+".json"))
	if err != nil {
		return 0, err
	}
	if !boundRecord(old, r) || old.State != "started" || maxSamples < 1 || maxSamples > 3 {
		return 0, ErrConflict
	}
	if old.ProofTraffic == nil {
		old.ProofTraffic = &ProofTraffic{Schema: 1, LeaseFingerprint: old.Fingerprint, Layer: "tcp_payload", MaxSamples: maxSamples}
	}
	t := old.ProofTraffic
	if t.MaxSamples != maxSamples || t.WorkerFinished || len(t.Samples) >= maxSamples {
		return 0, ErrConflict
	}
	ordinal := len(t.Samples) + 1
	t.Samples = append(t.Samples, ProofSample{Ordinal: ordinal, State: "started"})
	old.UpdatedAt = time.Now().UTC()
	if err := j.writeContext(ctx, old); err != nil {
		return 0, err
	}
	return ordinal, nil
}

// CompleteProof accepts a single allowlisted observation for the reserved call.
// An identical delivery is idempotent while started; after Ready no edits occur.
func (j *Journal) CompleteProof(r Record, sample ProofSample) error {
	return j.CompleteProofContext(context.Background(), r, sample)
}

// CompleteProofContext records local timings for the existing proof observation.
func (j *Journal) CompleteProofContext(ctx context.Context, r Record, sample ProofSample) error {
	j.lockContext(ctx)
	defer j.mu.Unlock()
	old, err := j.read(filepath.Join(j.dir, key(r)+".json"))
	if err != nil {
		return err
	}
	if !boundRecord(old, r) || old.State != "started" || old.ProofTraffic == nil || old.ProofTraffic.WorkerFinished || !sample.valid() || sample.State == "started" || sample.Ordinal > len(old.ProofTraffic.Samples) {
		return ErrConflict
	}
	previous := old.ProofTraffic.Samples[sample.Ordinal-1]
	if previous.State != "started" {
		if reflect.DeepEqual(previous, sample) {
			return nil
		}
		return ErrConflict
	}
	old.ProofTraffic.Samples[sample.Ordinal-1] = sample
	old.UpdatedAt = time.Now().UTC()
	return j.writeContext(ctx, old)
}

func (j *Journal) FinishProofTraffic(r Record) error {
	return j.FinishProofTrafficContext(context.Background(), r)
}

// FinishProofTrafficContext records local timings for the existing worker marker.
func (j *Journal) FinishProofTrafficContext(ctx context.Context, r Record) error {
	j.lockContext(ctx)
	defer j.mu.Unlock()
	old, err := j.read(filepath.Join(j.dir, key(r)+".json"))
	if err != nil {
		return err
	}
	if !boundRecord(old, r) || old.State != "started" {
		return ErrConflict
	}
	if old.ProofTraffic == nil || old.ProofTraffic.WorkerFinished {
		return nil
	}
	old.ProofTraffic.WorkerFinished = true
	old.UpdatedAt = time.Now().UTC()
	return j.writeContext(ctx, old)
}
