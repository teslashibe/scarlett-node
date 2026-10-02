package coordinator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
)

// AttemptStatus is the authenticated coordinator's durable attempt outcome.
// ReplaySafe explicitly promises idempotent exact-body reports for this fence.
// A missing/older endpoint cannot authorize a report retry or provider replay.
type AttemptStatus struct {
	Version          string `json:"version"`
	JobID            string `json:"job_id"`
	Attempt          string `json:"attempt"`
	Fence            string `json:"fence"`
	State            string `json:"state"`
	ReplaySafe       bool   `json:"replay_safe"`
	SubmissionSHA256 string `json:"submission_sha256,omitempty"`
}

func (c *Client) AttemptStatus(ctx context.Context, job, attempt, fence string) (AttemptStatus, error) {
	var result AttemptStatus
	path, err := JobPath(job, "attempt")
	if err != nil {
		return result, err
	}
	path += "?" + url.Values{"attempt": {attempt}, "fence": {fence}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Origin+path, nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Credential)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return result, errors.New("attempt reconciliation unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result, errors.New("attempt reconciliation not supported or unauthorized")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil || len(raw) > 8192 || json.Unmarshal(raw, &result) != nil {
		return result, errors.New("invalid attempt reconciliation")
	}
	if result.Version != Version || result.JobID != job || result.Attempt != attempt || result.Fence != fence || !result.ReplaySafe {
		return result, errors.New("attempt reconciliation identity or replay contract mismatch")
	}
	if result.SubmissionSHA256 != "" {
		hash, e := hex.DecodeString(result.SubmissionSHA256)
		if e != nil || len(hash) != 32 || hex.EncodeToString(hash) != result.SubmissionSHA256 {
			return result, errors.New("invalid attempt report receipt")
		}
	}
	if (result.State == "accepted" || result.State == "failed") && result.SubmissionSHA256 == "" {
		return result, errors.New("committed attempt report receipt is missing")
	}
	switch result.State {
	case "live", "proof_pending", "accepted", "failed", "expired", "fenced":
	default:
		return result, errors.New("invalid attempt reconciliation state")
	}
	return result, nil
}
