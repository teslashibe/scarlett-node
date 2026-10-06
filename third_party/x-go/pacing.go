package x

import (
	"sync"
	"time"
)

// RequestPacing holds only request slots and provider quota observations.
// Separate authenticated sessions of one verified user can share it without
// sharing cookies, clients, transports or profile validation.
type RequestPacing struct {
	gapMu     sync.Mutex
	lastReqAt time.Time
	rlMu      sync.Mutex
	rlState   RateLimitState
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
	rs := p.RateLimit()
	until := p.LastRequestAt().Add(minGap)
	if rs.Reset.After(until) {
		until = rs.Reset
	}
	return until
}

// merge carries the validation client's observations into the stable user
// domain. It runs before the new client can be used concurrently.
func (p *RequestPacing) merge(local *RequestPacing) {
	rs := local.RateLimit()
	p.observe(rs, rs.Limit > 0, !rs.Reset.IsZero(), !rs.Reset.IsZero())
	last := local.LastRequestAt()
	p.gapMu.Lock()
	if last.After(p.lastReqAt) {
		p.lastReqAt = last
	}
	p.gapMu.Unlock()
}

// observe never relaxes an unexpired observation when concurrent requests or
// another operation return older quota headers. Policy remains one shared
// provider window; operation-specific pacing is a separate optimization.
func (p *RequestPacing) observe(observed RateLimitState, hasLimit, hasRemaining, hasReset bool) {
	p.rlMu.Lock()
	defer p.rlMu.Unlock()
	prior := p.rlState
	active := time.Now().Before(prior.Reset)
	if active && hasReset && observed.Reset.Before(prior.Reset) {
		return
	}
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
	}
}
