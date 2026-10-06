package main

import (
	"github.com/teslashibe/scarlett-node/internal/worker"
	"time"
)

// xReadyAt combines retained identity quota with the current credential-local
// rest. Caller holds p.mu; the cache callback never takes the pool mutex.
func (p *servicePool) xReadyAt(a *pooledAccount, now time.Time, operation ...string) time.Time {
	at := now
	if a.entry.restUntil.After(at) {
		at = a.entry.restUntil
	}
	if p.xEligibility != nil && a.identity.ID != "" {
		op := ""
		if len(operation) == 1 {
			op = operation[0]
		}
		if observed := p.xEligibility(a.identity.ID, op, now); observed.After(at) {
			at = observed
		}
	}
	return at
}

func (p *servicePool) notifyAvailability() {
	if p.availabilityChanges != nil {
		select {
		case p.availabilityChanges <- struct{}{}:
		default:
		}
	}
}

func (p *servicePool) accountReady(lease *accountLease) func(string) bool {
	return func(operation string) bool {
		if lease.kind != "x_read" {
			return true
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		now := time.Now()
		p.refresh(now)
		a := lease.account
		return !p.healthError && !p.accountsError && !p.xIdentityError && !p.xRecoveryHolds(a) &&
			!a.removed && a.entry.inFlight > 0 && (a.entry.state == "configured" || a.entry.state == "ready") &&
			worker.XSessionStamp(lease.config.XSession) == lease.xStamp && (lease.xIdentity == "" || a.identity.ID == lease.xIdentity) &&
			!p.xReadyAt(a, now, operation).After(now)
	}
}

// quotaReset is separate from the duration-only fallback: only authoritative
// provider headers may shorten the default fifteen-minute unknown-quota rest.
func (p *servicePool) quotaReset(lease *accountLease) func(time.Time) {
	return func(reset time.Time) {
		now := time.Now()
		if reset.IsZero() || !reset.After(now) {
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		defer p.notifyAvailability()
		a, identity := lease.account, lease.xIdentity
		if lease.kind != "x_read" || identity == "" && (lease.xStamp == "" || a.spec.Path != lease.config.XSession || worker.XSessionStamp(a.spec.Path) != lease.xStamp) {
			return
		}
		if reset.After(now.Add(30 * 24 * time.Hour)) {
			if identity != "" {
				p.recordXCooldown(identity, time.Time{}, true)
			} else {
				a.entry.state, a.entry.lastError = "auth_required", "auth_required"
			}
			p.saveHealth()
			return
		}
		until := reset.Add(50 * time.Millisecond)
		if until.After(lease.quotaUntil) {
			lease.quotaUntil = until
		}
		if identity != "" {
			p.recordXCooldown(identity, until, false)
		} else if until.After(a.entry.restUntil) {
			a.entry.restUntil = until
			a.entry.state, a.entry.lastError = "exhausted", "x_rate_limited"
		}
		p.saveHealth()
	}
}

type xAvailability struct {
	configured, active, ready, cooling int
	available                          int
	next                               time.Time
}

// xAvailability counts canonical usable registrations. Busy identities count
// as active; removed registrations only retain their accepted occupancy.
func (p *servicePool) xAvailability(now time.Time, operation ...string) xAvailability {
	result := xAvailability{configured: p.entries["x_read"].inFlight}
	for _, a := range p.accounts {
		if a.spec.Service != "x_read" || a.removed || a.duplicate || a.identity.ID == "" || p.xIdentityError || p.healthError || p.accountsError || p.renewalHolds(a) {
			continue
		}
		if a.entry.state != "configured" && a.entry.state != "ready" && a.entry.state != "exhausted" {
			continue
		}
		result.active++
		available := p.xGroupAvailable(a)
		result.configured += available
		if available == 0 || p.xRecoveryHolds(a) {
			continue
		}
		at := p.xReadyAt(a, now, operation...)
		if !at.After(now) && (a.entry.state == "configured" || a.entry.state == "ready") {
			result.available += available
		}
		if len(operation) == 0 {
			// Account telemetry describes whether any supported operation can
			// run. Generic capacity remains conservative across all operations.
			for _, op := range []string{"search", "profile", "post", "thread"} {
				candidate := p.xReadyAt(a, now, op)
				if candidate.Before(at) {
					at = candidate
				}
			}
		}
		if at.After(now) {
			result.cooling++
			if result.next.IsZero() || at.Before(result.next) {
				result.next = at
			}
		} else if a.entry.state == "configured" || a.entry.state == "ready" {
			result.ready++
		}
	}
	result.configured = min(p.config.XConcurrency, result.configured)
	result.available = min(result.available, max(0, result.configured-p.entries["x_read"].inFlight))
	return result
}
