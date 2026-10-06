package x

import (
	"sync"
	"time"
)

// RequestPacing holds only request slots and provider quota observations.
// Separate authenticated sessions of one verified user can share it without
// sharing cookies, clients, transports or profile validation.
type RequestPacing struct {
	gapMu                                  sync.Mutex
	lastReqAt                              time.Time
	rlMu                                   sync.Mutex
	rlState                                RateLimitState
	rlKnown                                bool // complete, mutually consistent provider quota headers
	rlHasLimit, rlHasRemaining, rlHasReset bool
	rlOperation                            string
	resetKnown                             bool
	lastSentAt                             time.Time
	observedAt                             time.Time
	burst                                  bool
}

// RateLimit returns the domain's conservative quota snapshot.
func (p *RequestPacing) RateLimit() RateLimitState {
	p.rlMu.Lock()
	defer p.rlMu.Unlock()
	return p.rlState
}

// LastRequestAt returns the most recently reserved request slot.
func (p *RequestPacing) LastRequestAt() time.Time {
	p.gapMu.Lock()
	defer p.gapMu.Unlock()
	return p.lastReqAt
}

// RetainUntil bounds how long a removed identity's observations still affect
// admission. A caller must also keep domains used by clients or active jobs.
func (p *RequestPacing) RetainUntil(minGap time.Duration) time.Time {
	p.gapMu.Lock()
	defer p.gapMu.Unlock()
	p.rlMu.Lock()
	defer p.rlMu.Unlock()
	return maxTime(maxTime(p.lastReqAt, p.lastSentAt).Add(minGap), p.rlState.Reset)
}

// merge carries the validation client's observations into the stable user
// domain. It runs before the new client can be used concurrently.
func (p *RequestPacing) merge(local *RequestPacing) {
	local.rlMu.Lock()
	rs, burst, known, resetKnown, operation, observedAt := local.rlState, local.burst, local.rlKnown, local.resetKnown, local.rlOperation, local.observedAt
	hasLimit, hasRemaining, hasReset := local.rlHasLimit, local.rlHasRemaining, local.rlHasReset
	local.rlMu.Unlock()
	p.observe(rs, hasLimit, hasRemaining, hasReset, operation)
	p.rlMu.Lock()
	p.burst = p.burst || burst
	// Merging validation observations is not a new provider observation.
	if !observedAt.IsZero() && (p.observedAt.IsZero() || observedAt.Before(p.observedAt)) {
		p.observedAt = observedAt
	}
	if !known {
		// A validation client with incomplete headers cannot authorize bursts.
		p.rlKnown = false
	}
	if !resetKnown {
		p.resetKnown = false
	}
	p.rlMu.Unlock()
	local.gapMu.Lock()
	last, sent := local.lastReqAt, local.lastSentAt
	local.gapMu.Unlock()
	p.gapMu.Lock()
	if last.After(p.lastReqAt) {
		p.lastReqAt = last
	}
	if sent.After(p.lastSentAt) {
		p.lastSentAt = sent
	}
	p.gapMu.Unlock()
}

// observe never relaxes an unexpired observation when concurrent requests or
// another operation return older quota headers. Policy remains one shared
// provider window; operation-specific pacing is a separate optimization.
func (p *RequestPacing) observe(observed RateLimitState, hasLimit, hasRemaining, hasReset bool, operation ...string) {
	p.rlMu.Lock()
	defer p.rlMu.Unlock()
	prior := p.rlState
	active := time.Now().Before(prior.Reset)
	if active && hasReset && observed.Reset.Before(prior.Reset) {
		return
	}
	if !prior.Reset.IsZero() && !active {
		p.rlHasLimit, p.rlHasRemaining, p.rlHasReset = false, false, false
	}
	p.rlHasLimit = p.rlHasLimit || hasLimit
	p.rlHasRemaining = p.rlHasRemaining || hasRemaining
	p.rlHasReset = p.rlHasReset || hasReset
	if hasLimit && (!active || prior.Limit <= 0 || observed.Limit < prior.Limit) {
		p.rlState.Limit = observed.Limit
	}
	if hasRemaining && (!active || observed.Remaining < prior.Remaining) {
		p.rlState.Remaining = observed.Remaining
	}
	if hasReset && (!active || observed.Reset.After(prior.Reset)) {
		p.rlState.Reset = observed.Reset
	}
	if !active {
		p.rlState.RetryAfter = observed.RetryAfter
		p.rlKnown = false
		p.rlOperation = ""
		p.resetKnown = false
	}
	if hasReset {
		p.resetKnown = true
	}
	complete := hasLimit && hasRemaining && hasReset && observed.Limit > 0 && observed.Limit <= 1000000000 && observed.Remaining >= 0 && observed.Remaining <= observed.Limit && p.rlState.Limit > 0 && p.rlState.Remaining >= 0 && p.rlState.Remaining <= p.rlState.Limit
	if !complete && p.rlState != prior {
		// A partial response can tighten a shared floor, but its mixed state is
		// not a new complete provider triplet authorizing operation bursts.
		p.rlKnown = false
		p.rlOperation = ""
	}
	if complete {
		p.rlKnown = true
		p.rlOperation = boundedPacingOperation(operation)
		p.observedAt = time.Now()
	}
}
