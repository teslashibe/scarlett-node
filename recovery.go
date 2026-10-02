package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

func attemptRecord(l coordinator.Lease) (attempts.Record, error) {
	raw, err := json.Marshal(l)
	if err != nil {
		return attempts.Record{}, err
	}
	return attempts.Record{JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, Fingerprint: attempts.Hash(raw), Deadline: l.LeaseDeadline}, nil
}

// Recovery does no provider work. A started record means execution might have
// happened before a crash; only the coordinator may resolve that uncertainty.
func recoverAttempt(ctx context.Context, client *coordinator.Client, journal *attempts.Journal, r attempts.Record) error {
	if r.State != "started" && r.State != "ready" {
		return errors.New("invalid pending attempt state")
	}
	status, err := client.AttemptStatus(ctx, r.JobID, r.Attempt, r.Fence)
	if err != nil {
		return err
	}
	switch status.State {
	case "accepted", "failed":
		if r.SubmissionSHA256 != "" && status.SubmissionSHA256 != r.SubmissionSHA256 {
			return errors.New("coordinator accepted a different attempt report")
		}
		return journal.Terminal(r)
	case "expired", "fenced":
		return journal.Terminal(r)
	case "proof_pending":
		return nil // verifier owns proof ingestion; don't rerun the provider
	case "live":
		if r.State == "started" {
			body, err := json.Marshal(coordinator.Failure{Version: coordinator.Version, Attempt: r.Attempt, Fence: r.Fence, Code: "execution_uncertain"})
			if err != nil {
				return err
			}
			r, err = journal.Ready(r, "fail", body)
			if err != nil {
				return err
			}
		}
		return submitRecord(ctx, client, journal, r)
	}
	return errors.New("unknown reconciliation state")
}
func submitRecord(ctx context.Context, client *coordinator.Client, journal *attempts.Journal, r attempts.Record) error {
	path, err := coordinator.JobPath(r.JobID, r.Kind)
	if err != nil {
		return err
	}
	status, err := client.Post(ctx, path, json.RawMessage(r.Body), nil)
	if err != nil {
		return err
	} // durable ready record remains for reconciliation
	if status == http.StatusAccepted && r.Kind == "proven" {
		return nil
	}
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusNoContent {
		return errors.New("unexpected attempt report status")
	}
	return journal.Terminal(r)
}
