package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
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
	endReport := diagnostics.Start(ctx, "report_http", 0)
	status, err := client.Post(ctx, path, json.RawMessage(r.Body), nil)
	if err != nil {
		endReport(diagnosticOutcome(ctx, "", err))
		return err
	} // durable ready record remains for reconciliation
	if status == http.StatusAccepted && r.Kind == "proven" {
		endReport("success")
		return nil
	}
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusNoContent {
		endReport("report_error")
		return errors.New("unexpected attempt report status")
	}
	endReport("success")
	return journal.TerminalContext(ctx, r)
}

func rejectLease(ctx context.Context, client *coordinator.Client, journal *attempts.Journal, l coordinator.Lease, code string) error {
	if _, err := coordinator.JobPath(l.JobID, "fail"); err != nil {
		return err
	}
	r, err := attemptRecord(l)
	if err != nil {
		return err
	}
	// A rejection never runs a provider. Say so explicitly, so its pending
	// record is not mistaken for unbound provider work on some profile.
	r.NoProvider = true
	if err = journal.BeginContext(ctx, r); err != nil {
		return err
	}
	if l.AcceptanceRequired {
		if err = coordinator.ValidOffer(l, time.Now()); err != nil {
			// No acceptance HTTP was sent; the offer expires remotely.
			if terminalErr := journal.TerminalContext(ctx, r); terminalErr != nil {
				return terminalErr
			}
			return err
		}
		endAccept := diagnostics.Start(ctx, "accept_http", 0)
		_, err = client.Accept(ctx, l)
		endAccept(diagnosticOutcome(ctx, "", err))
		if err != nil {
			return err
		}
	}
	raw, err := json.Marshal(coordinator.Failure{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence, Code: code})
	if err != nil {
		return err
	}
	r, err = journal.ReadyContext(ctx, r, "fail", raw)
	if err != nil {
		return err
	}
	return submitRecord(ctx, client, journal, r)
}

// activeAttempts counts attempt keys whose worker goroutine has not returned.
type activeAttempts struct {
	mu   sync.Mutex
	keys map[string]int
}

func (a *activeAttempts) add(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.keys == nil {
		a.keys = map[string]int{}
	}
	a.keys[key]++
}
func (a *activeAttempts) done(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.keys[key]--; a.keys[key] <= 0 {
		delete(a.keys, key)
	}
}
func (a *activeAttempts) snapshot() map[string]bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]bool, len(a.keys))
	for key := range a.keys {
		out[key] = true
	}
	return out
}

// reconcileIdle retries ready reports and resolves started records that no
// running worker owns, such as one left by a lost acceptance acknowledgement
// or a failed report write. That is the same uncertainty a restart reconciles,
// through the same recovery: no provider call is ever repeated. active must be
// taken before the journal is read, by the only goroutine that adds keys.
func reconcileIdle(ctx context.Context, client *coordinator.Client, journal *attempts.Journal, active map[string]bool) error {
	records, err := journal.Pending()
	if err != nil {
		return err
	}
	for _, record := range records {
		if record.State == "ready" || record.State == "started" && !active[record.Key()] {
			if err := recoverAttempt(ctx, client, journal, record); err != nil {
				fmt.Fprintln(os.Stderr, "reconcile:", err)
			}
		}
	}
	return nil
}
