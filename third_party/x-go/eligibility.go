package x

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Eligibility is a private, request-free scheduling snapshot. It contains no
// credentials, query strings, identity or operation-specific quota claims.
type Eligibility struct {
	At            time.Time
	Reason        string
	Quota         RateLimitState
	Authoritative bool
	Complete      bool
}

type QuotaObservation struct {
	ObservedAt, CapturedAt, NextEligibleAt time.Time
	Operation                              string
	Limit, Remaining                       int
	Reset                                  time.Time
	Complete, Authoritative                bool
	Mode                                   string
}

type quotaObserverKey struct{}

// WithQuotaObserver exposes a bounded numerical snapshot only. Observational
// callbacks cannot alter scheduling or turn their failure into provider work.
func WithQuotaObserver(ctx context.Context, callback func(QuotaObservation)) context.Context {
	return context.WithValue(ctx, quotaObserverKey{}, callback)
}

func observeQuota(ctx context.Context, snapshot QuotaObservation) {
	callback, _ := ctx.Value(quotaObserverKey{}).(func(QuotaObservation))
	if callback != nil {
		defer func() { _ = recover() }()
		callback(snapshot)
	}
}

func (c *Client) dispatch(req *http.Request, operation ...string) (*http.Response, error) {
	op := boundedPacingOperation(operation)
	p := c.pacing
	for {
		if err := req.Context().Err(); err != nil {
			return nil, errors.Join(errWriteNotAttempted, err)
		}
		p.gapMu.Lock()
		p.rlMu.Lock()
		now, rs := time.Now(), p.rlState
		matched := p.rlKnown && p.rlOperation == op && op != ""
		gap, reason := quotaGap(rs, matched, p.burst, c.minGap, now)
		next := maxTime(now, p.lastSentAt.Add(gap))
		if reason == "spread" {
			slots := time.Duration(max(int64(float64(rs.Remaining)*0.9), 1))
			next = maxTime(now, maxTime(p.lastSentAt.Add(c.minGap), p.lastSentAt.Add(rs.Reset.Sub(p.lastSentAt)/(slots+1))))
		}
		mode := "conservative"
		if p.burst {
			mode = "quota_budget"
		}
		snapshot := QuotaObservation{ObservedAt: p.observedAt, CapturedAt: now, Operation: op, Limit: rs.Limit, Remaining: rs.Remaining, Reset: rs.Reset, Complete: matched && now.Before(rs.Reset), Authoritative: p.resetKnown && now.Before(rs.Reset), Mode: mode}
		if now.Before(rs.Reset) && rs.Remaining == 0 {
			reset := time.Time{}
			if p.resetKnown {
				reset = rs.Reset
			}
			p.rlMu.Unlock()
			p.gapMu.Unlock()
			observeQuota(req.Context(), snapshot)
			return nil, errors.Join(errWriteNotAttempted, &RateLimitError{Wait: rs.Reset.Add(50 * time.Millisecond).Sub(now), Reset: reset})
		}
		if next.After(now) {
			p.rlMu.Unlock()
			p.gapMu.Unlock()
			if err := waitUntil(req.Context(), next, reason); err != nil {
				return nil, errors.Join(errWriteNotAttempted, err)
			}
			continue
		}
		if now.Before(rs.Reset) && rs.Remaining > 0 {
			p.rlState.Remaining--
		}
		if !now.Before(rs.Reset) {
			p.rlState.RetryAfter = 0
			p.rlKnown, p.resetKnown = false, false
		}
		p.lastSentAt = now
		snapshot.NextEligibleAt = p.eligibilityLocked(c.minGap, now, op).At
		p.rlMu.Unlock()
		p.gapMu.Unlock()
		observeQuota(req.Context(), snapshot)
		return c.httpClient.Do(req)
	}
}

// Eligibility returns the earliest next slot without reserving it. Dispatch
// rechecks this snapshot under the pacing lock before consuming provider quota.
func (p *RequestPacing) Eligibility(minGap time.Duration, now time.Time, operation ...string) Eligibility {
	p.gapMu.Lock()
	defer p.gapMu.Unlock()
	p.rlMu.Lock()
	defer p.rlMu.Unlock()
	return p.eligibilityLocked(minGap, now, boundedPacingOperation(operation))
}

func (p *RequestPacing) eligibilityLocked(minGap time.Duration, now time.Time, operation string) Eligibility {
	rs := p.rlState
	matched := operation != "" && p.rlOperation == operation && p.rlKnown
	gap, reason := quotaGap(rs, matched, p.burst, minGap, now)
	last := maxTime(p.lastReqAt, p.lastSentAt)
	at := last.Add(gap)
	if reason == "spread" {
		// Solve now >= last + (reset-now)/slots. The readiness deadline is
		// stable while headers and reservations are unchanged.
		slots := time.Duration(max(int64(float64(rs.Remaining)*0.9), 1))
		at = last.Add(rs.Reset.Sub(last) / (slots + 1))
		at = maxTime(at, last.Add(minGap))
	}
	if at.Before(now) {
		at = now
	}
	// Exhaustion is an absolute provider floor. It must not be measured only
	// from the previous request, which would admit work before reset.
	if rs.Remaining == 0 && now.Before(rs.Reset) {
		at = maxTime(at, rs.Reset.Add(50*time.Millisecond))
	}
	return Eligibility{At: at, Reason: reason, Quota: rs, Authoritative: p.resetKnown, Complete: matched}
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// WithQuotaBurst permits the configured minimum gap only while complete
// provider headers show headroom above a twenty-percent reserve (at least two
// requests). It is opt-in; incomplete observations retain window spreading.
func WithQuotaBurst(enabled bool) Option {
	return func(c *Client) { c.pacing.burst = enabled }
}

func quotaGap(rs RateLimitState, known, burst bool, minGap time.Duration, now time.Time) (time.Duration, string) {
	if d := rs.Reset.Sub(now); d > 0 {
		if rs.Remaining == 0 {
			return minGap, "reset"
		}
		reserve := max(2, (rs.Limit+4)/5)
		if burst && known && rs.Limit > 0 && rs.Remaining > reserve {
			return minGap, "gap"
		}
		if rs.Remaining > 0 {
			spread := d / time.Duration(max(int64(float64(rs.Remaining)*0.9), 1))
			if spread > minGap {
				return spread, "spread"
			}
		}
	}
	return minGap, "gap"
}

// NextEligibility shares the exact domain policy used for admission and reads.
func (c *Client) NextEligibility(now time.Time, operation ...string) Eligibility {
	return c.pacing.Eligibility(c.minGap, now, operation...)
}

func boundedPacingOperation(operation []string) string {
	if len(operation) == 1 {
		switch operation[0] {
		case "SearchTimeline", "UserByScreenName", "TweetResultByRestId", "TweetDetail":
			return operation[0]
		}
	}
	return ""
}

type requestReservation struct {
	baseAt, at time.Time
	reason     string
}

func requestSlot(last, now time.Time, gap, jitter time.Duration, floor time.Time) (base, at time.Time) {
	base = maxTime(maxTime(last.Add(gap), now), floor)
	return base, base.Add(max(0, jitter))
}

func (p *RequestPacing) reserve(minGap, jitter time.Duration, now time.Time, operation string) requestReservation {
	p.gapMu.Lock()
	defer p.gapMu.Unlock()
	p.rlMu.Lock()
	defer p.rlMu.Unlock()
	matched := operation != "" && operation == p.rlOperation && p.rlKnown
	gap, reason := quotaGap(p.rlState, matched, p.burst, minGap, now)
	floor := time.Time{}
	if p.rlState.Remaining == 0 && now.Before(p.rlState.Reset) {
		floor = p.rlState.Reset.Add(50 * time.Millisecond)
	}
	base, at := requestSlot(p.lastReqAt, now, gap, jitter, floor)
	p.lastReqAt = at
	return requestReservation{baseAt: base, at: at, reason: reason}
}

// Missing/malformed headers keep the unknown-denial fallback distinct from
// authoritative provider timing, including HTTP200 GraphQL rate-limit bodies.
func providerReset(h http.Header) (time.Duration, time.Time) {
	wait := max(parseRetryAfter(rlHeader(h, "Reset"), 0), parseRetryAfter(h.Get("Retry-After"), 0))
	if wait > 0 {
		return wait, time.Now().Add(wait)
	}
	return 60 * time.Second, time.Time{}
}
