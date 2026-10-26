package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
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
		// Without a receipt the coordinator decided the attempt from the
		// verifier's own record before this node's report reached it: the
		// outcome is final, and the report has nothing left to change.
		if r.SubmissionSHA256 != "" && status.SubmissionSHA256 != "" && status.SubmissionSHA256 != r.SubmissionSHA256 {
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

// submitRecord sends a ready record's exact report once. Anything but an
// answer that settles it leaves the durable record for reconciliation.
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

// reportRetryBudget bounds the in-place retries of a worker's own report,
// waits included: past it, or past the lease deadline less the service's
// report margin, the durable record is left to reconciliation.
const reportRetryBudget = 10 * time.Second

// reportRetryBackoff is the wait before each in-place retry of a report when
// the coordinator sent no Retry-After, plus up to a quarter of it again.
var reportRetryBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// submitReport is submitRecord for the report of the attempt this worker just
// ran. A coordinator that could not take it just then, with a 429, a 503
// network_unavailable or no answer at all, is asked again in place after its
// Retry-After or reportRetryBackoff, within reportRetryBudget and never later
// than deadline. The coordinator records the exact journal body once and
// answers a repeat of it as it answered the first, so a retry after a lost
// answer cannot record a second report. Reconciliation sends a report once per
// pass instead, because its passes share the coordinator's budget for this node
// with every acceptance.
func submitReport(ctx context.Context, client *coordinator.Client, journal *attempts.Journal, r attempts.Record, deadline time.Time) error {
	started := time.Now()
	for retry := 0; ; retry++ {
		err := submitRecord(ctx, client, journal, r)
		wait, again := reportRetryAfter(err, retry)
		if !again || ctx.Err() != nil || time.Since(started)+wait > reportRetryBudget || time.Now().Add(wait).After(deadline) {
			return err
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
	}
}

// reportRetryAfter reports whether a failed report may be sent again in place,
// and the wait first: the coordinator's Retry-After with its jitter, else the
// retry-th step of reportRetryBackoff with a quarter of it as jitter.
func reportRetryAfter(err error, retry int) (time.Duration, bool) {
	var status *coordinator.StatusError
	switch {
	case err == nil:
		return 0, false
	case errors.As(err, &status):
		if status.Status != http.StatusTooManyRequests && (status.Status != http.StatusServiceUnavailable || status.Code != "network_unavailable") {
			return 0, false
		}
		if status.RetryAfter > 0 {
			return coordinator.RetryAfterWait(status.RetryAfter), true
		}
	case !errors.Is(err, coordinator.ErrUnavailable):
		return 0, false
	}
	if retry >= len(reportRetryBackoff) {
		return 0, false
	}
	step := reportRetryBackoff[retry]
	return step + rand.N(step/4+1), true
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

// declineOffer rejects a funded offer this node will not accept after all, so
// that the coordinator moves the job at once instead of waiting for a timer
// or the deadline. It is only for offers no acceptance was sent for, and is
// best effort: a failure is logged and the coordinator's timers cover it.
func declineOffer(ctx context.Context, client *coordinator.Client, l coordinator.Lease, reason string) {
	if client == nil || !l.AcceptanceRequired {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rejectTimeout)
	defer cancel()
	fmt.Fprintln(os.Stderr, "offer: rejected ("+reason+")")
	if err := client.Reject(ctx, l.OfferAttempt(), reason); err != nil {
		fmt.Fprintln(os.Stderr, "offer: rejection not delivered:", err)
	}
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

// Idle reconciliation runs in the heartbeat loop between two polls, and the
// coordinator counts every attempt read and report against the same per-node
// budget as acceptances, so each pass is bounded.
const (
	// reconcileInterval is the least time from one pass to the next.
	reconcileInterval = 30 * time.Second
	// reconcilePassRecords is the most records one pass reads; the rest wait
	// for later passes, which start where this one stopped.
	reconcilePassRecords = 8
	// reconcilePassBudget bounds one pass, its requests included, so the next
	// poll starts well inside the coordinator's three-second liveness window.
	reconcilePassBudget = 2 * time.Second
	// A record that a pass handled and left pending (a proven report the
	// verifier is still ingesting, read proof_pending or answered 202) is read
	// again after reconcileProofWait, doubling to reconcileProofWaitCap.
	reconcileProofWait    = 30 * time.Second
	reconcileProofWaitCap = 5 * time.Minute
)

// idleReconciler paces reconcileIdle. Only the heartbeat loop uses it.
type idleReconciler struct {
	// next is when the next pass is due.
	next time.Time
	// after is the key of the last record a pass handled; the next pass
	// starts after it in key order and wraps around, so no record waits
	// behind others for ever.
	after string
	// waits holds the records a pass handled and left pending: when each is
	// read again and the wait before that.
	waits map[string]reconcileWait
}

type reconcileWait struct {
	at   time.Time
	wait time.Duration
}

// due reports whether a pass may start at now.
func (r *idleReconciler) due(now time.Time) bool { return !now.Before(r.next) }

// reconcileIdle retries ready reports and resolves started records that no
// running worker owns, such as one left by a lost acceptance acknowledgement
// or a failed report write. That is the same uncertainty a restart reconciles,
// through the same recovery: no provider call is ever repeated. active must be
// taken before the journal is read, by the only goroutine that adds keys; a
// worker that is still running keeps its records, ready ones included, until
// it returns. One pass reads at most reconcilePassRecords records within
// reconcilePassBudget, and stops at the first 429, 5xx or transport failure:
// the next pass is then due after reconcileInterval or the coordinator's
// Retry-After, whichever is longer.
func (r *idleReconciler) reconcileIdle(ctx context.Context, client *coordinator.Client, journal *attempts.Journal, active map[string]bool) error {
	now := time.Now()
	r.next = now.Add(reconcileInterval)
	records, err := journal.Pending()
	if err != nil {
		return err
	}
	pending := make(map[string]bool, len(records))
	for _, record := range records {
		pending[record.Key()] = true
	}
	for key := range r.waits {
		if !pending[key] {
			delete(r.waits, key)
		}
	}
	passCtx, cancel := context.WithTimeout(ctx, reconcilePassBudget)
	defer cancel()
	// Pending lists records in key order.
	first := sort.Search(len(records), func(i int) bool { return records[i].Key() > r.after })
	read := 0
	for i := range records {
		record := records[(first+i)%len(records)]
		key := record.Key()
		if active[key] || record.State != "ready" && record.State != "started" || now.Before(r.waits[key].at) {
			continue
		}
		if read == reconcilePassRecords || passCtx.Err() != nil {
			break
		}
		read++
		err := recoverAttempt(passCtx, client, journal, record)
		if err != nil && passCtx.Err() != nil && ctx.Err() == nil {
			// The pass ran out of time; this record is the next one's first.
			break
		}
		if pause, stop := reconcileStop(err); stop {
			fmt.Fprintln(os.Stderr, "reconcile:", err)
			r.next = time.Now().Add(max(reconcileInterval, pause))
			break
		}
		r.after = key
		if err != nil {
			fmt.Fprintln(os.Stderr, "reconcile:", err)
			continue
		}
		// Handled without error: a record that settled leaves the journal and
		// its wait is dropped next pass; one still pending waits longer.
		if r.waits == nil {
			r.waits = map[string]reconcileWait{}
		}
		wait := reconcileProofWait
		if last, ok := r.waits[key]; ok {
			wait = min(2*last.wait, reconcileProofWaitCap)
		}
		r.waits[key] = reconcileWait{at: time.Now().Add(wait), wait: wait}
	}
	return nil
}

// reconcileStop reports whether a recovery error ends the pass, and the
// coordinator's Retry-After, if any: a 429 or 5xx answer, or no answer at all,
// means the coordinator could not take more of this node's requests now.
func reconcileStop(err error) (time.Duration, bool) {
	var status *coordinator.StatusError
	switch {
	case errors.As(err, &status):
		if status.Status == http.StatusTooManyRequests || status.Status >= 500 {
			return coordinator.RetryAfterWait(status.RetryAfter), true
		}
	case errors.Is(err, coordinator.ErrUnavailable):
		return 0, true
	}
	return 0, false
}
