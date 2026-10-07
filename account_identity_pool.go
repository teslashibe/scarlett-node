package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/teslashibe/scarlett-node/internal/worker"
)

type xIdentityCooldown struct {
	Until   time.Time `json:"until,omitempty"`
	Blocked bool      `json:"blocked,omitempty"`
}

func validStatusUsername(name string) bool {
	if len(name) > 15 {
		return false
	}
	for _, c := range name {
		if c != '_' && !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// Identity cooldowns outlive a local nickname or session. They contain no
// credentials and are independent of account-health's credential-local errors.
func (p *servicePool) loadXCooldowns(now time.Time) {
	if p.xCooldowns != nil {
		return
	}
	p.xCooldowns = map[string]xIdentityCooldown{}
	if p.config.StateDir == "" {
		return
	}
	raw, err := readLocalFile(filepath.Join(p.config.StateDir, "x-cooldowns.json"), 16384)
	if os.IsNotExist(err) {
		return
	}
	if err != nil || json.Unmarshal(raw, &p.xCooldowns) != nil || p.xCooldowns == nil || len(p.xCooldowns) > 64 {
		p.xIdentityHealthError = true
		return
	}
	for id, rest := range p.xCooldowns {
		if !validCooldownIdentity(id) || !rest.Blocked && (rest.Until.IsZero() || rest.Until.After(now.Add(30*24*time.Hour))) || rest.Blocked && !rest.Until.IsZero() {
			p.xIdentityHealthError = true
			return
		}
	}
}

func validCooldownIdentity(id string) bool {
	if len(id) < 1 || len(id) > 32 {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (p *servicePool) recordXCooldown(id string, until time.Time, blocked bool) {
	if id == "" || !validCooldownIdentity(id) {
		return
	}
	now := time.Now()
	p.loadXCooldowns(now)
	prior := p.xCooldowns[id]
	if p.xIdentityHealthError || prior.Blocked || !blocked && !until.After(prior.Until) {
		return
	}
	for key, rest := range p.xCooldowns {
		if !rest.Blocked && !rest.Until.After(now) {
			delete(p.xCooldowns, key)
		}
	}
	if _, exists := p.xCooldowns[id]; !exists && len(p.xCooldowns) >= 64 {
		p.xIdentityHealthError = true
		return
	}
	p.xCooldowns[id] = xIdentityCooldown{Until: until, Blocked: blocked}
	p.xCooldownsDirty = true
	p.flushLocalState(now)
	for _, a := range p.accounts {
		if a.spec.Service == "x_read" && a.identity.ID == id && blocked {
			a.entry.xRestIdentity = id
			a.entry.state, a.entry.lastError = "auth_required", "auth_required"
			a.entry.localAuthInvalid = false
		} else if a.spec.Service == "x_read" && a.identity.ID == id && until.After(a.entry.restUntil) {
			a.entry.xRestIdentity = id
			a.entry.restUntil = until
			if a.entry.state != "auth_required" {
				a.entry.state, a.entry.lastError = "exhausted", "x_rate_limited"
			}
		}
	}
}

// refreshXIdentities binds each current session to authenticated, stamp-bound
// metadata. Unknown or malformed identity cannot add an independent X slot.
// Caller holds p.mu and has refreshed credential-local health first.
func (p *servicePool) refreshXIdentities(now time.Time) {
	p.loadXCooldowns(now)
	p.xIdentityError = p.xIdentityHealthError
	if _, err := loadXIdentities(p.config.StateDir); err != nil && !os.IsNotExist(err) {
		p.xIdentityError = true
	}
	keys := make([]string, 0, len(p.accounts))
	for key, a := range p.accounts {
		if a.spec.Service != "x_read" {
			continue
		}
		a.duplicate = false
		if a.removed {
			continue // Already selected attempts retain their authenticated identity.
		}
		identity, err := verifiedXIdentity(p.config.StateDir, a.spec.Path)
		if err != nil || worker.XSessionStamp(a.spec.Path) != identity.Stamp {
			a.identity = worker.VerifiedXIdentity{}
			continue
		}
		p.applyXIdentity(a, identity, now)
		keys = append(keys, key)
	}
	// Prefer a currently usable session, then a stable local nickname. Aliases
	// remain visible, but only one can provide the identity's admission lane.
	sort.Slice(keys, func(i, j int) bool {
		a, b := p.accounts[keys[i]], p.accounts[keys[j]]
		usable := func(a *pooledAccount) bool { return a.entry.state == "ready" || a.entry.state == "configured" }
		if usable(a) != usable(b) {
			return usable(a)
		}
		return keys[i] < keys[j]
	})
	seen := map[string]bool{}
	for _, key := range keys {
		a := p.accounts[key]
		a.duplicate = seen[a.identity.ID]
		seen[a.identity.ID] = true
	}
}

// Caller holds p.mu. A newly authenticated legacy session can bind attempts
// admitted before the keeper knew its user, but only for their exact snapshot.
func (p *servicePool) bindXLeases(a *pooledAccount, path string, identity worker.VerifiedXIdentity) {
	for lease := range a.xLeases {
		if lease.xIdentity == "" && lease.config.XSession == path && lease.xStamp == identity.Stamp {
			lease.xIdentity = identity.ID
			if p.xInFlight == nil {
				p.xInFlight = map[string]int{}
			}
			p.xInFlight[identity.ID]++
		}
	}
}

func (p *servicePool) trackXLease(lease *accountLease) {
	if lease.kind != "x_read" {
		return
	}
	if lease.account.xLeases == nil {
		lease.account.xLeases = map[*accountLease]struct{}{}
	}
	lease.account.xLeases[lease] = struct{}{}
	if lease.xIdentity != "" {
		if p.xInFlight == nil {
			p.xInFlight = map[string]int{}
		}
		p.xInFlight[lease.xIdentity]++
	}
}

func (p *servicePool) applyXIdentity(a *pooledAccount, identity worker.VerifiedXIdentity, now time.Time) {
	if a.entry.xRestIdentity != "" && a.entry.xRestIdentity != identity.ID {
		// A different authenticated user must not inherit the old user's rest.
		if a.entry.lastError == "x_rate_limited" || a.entry.lastError == "capacity_unavailable" {
			a.entry.restUntil = time.Time{}
			a.entry.xRestIdentity = ""
			a.entry.state, a.entry.lastError = "configured", ""
		}
	}
	a.identity = identity
	rest := p.xCooldowns[identity.ID]
	if rest.Blocked {
		a.entry.xRestIdentity = identity.ID
		a.entry.state, a.entry.lastError = "auth_required", "auth_required"
		a.entry.localAuthInvalid = false
	} else if until := rest.Until; now.Before(until) {
		a.entry.xRestIdentity = identity.ID
		if until.After(a.entry.restUntil) {
			a.entry.restUntil = until
		}
		if a.entry.state != "auth_required" {
			a.entry.state, a.entry.lastError = "exhausted", "x_rate_limited"
		}
	}
}

func (p *servicePool) xGroupAvailable(a *pooledAccount) int {
	if p.xIdentityError || a.removed || a.duplicate || a.identity.ID == "" || p.xRecoveryHolds(a) {
		return 0
	}
	limit, occupied := p.xGroupLimit(a), p.xInFlight[a.identity.ID]
	for _, other := range p.accounts {
		if other.spec.Service == "x_read" && other.removed && other.identity.ID == "" && other.entry.inFlight > 0 {
			// A legacy attempt admitted before identity binding must drain before
			// a managed registration can safely claim an independent identity lane.
			return 0
		}
	}
	return max(0, limit-occupied)
}

func (p *servicePool) xGroupLimit(a *pooledAccount) int {
	limit := a.entry.capacity
	if p.config.XAccountConcurrency > 0 {
		limit = min(limit, p.config.XAccountConcurrency)
	}
	for _, other := range p.accounts {
		if other.spec.Service == "x_read" && !other.removed && other.identity.ID == a.identity.ID {
			limit = min(limit, other.entry.capacity)
		}
	}
	return limit
}

func (p *servicePool) xIdentityValidated(path string, identity worker.VerifiedXIdentity) {
	p.mu.Lock()
	defer p.mu.Unlock()
	defer p.notifyAvailability()
	if identity.ID == "" || identity.Stamp == "" || worker.XSessionStamp(path) != identity.Stamp {
		return
	}
	p.refresh(time.Now())
	for _, a := range p.accounts {
		if a.spec.Service != "x_read" || a.spec.Path != path {
			continue
		}
		p.bindXLeases(a, path, identity)
		if a.removed {
			continue // Bind accepted work without restoring a retired registration.
		}
		if p.config.StateDir == "" || !p.accountMode {
			p.loadXCooldowns(time.Now())
			p.applyXIdentity(a, identity, time.Now())
			return
		}
		if a.identity == identity {
			// Keeper checks of unchanged warm clients do not add a synced write
			// under the admission mutex for each account on every tick.
			return
		}
		if err := saveXIdentity(p.config.StateDir, path, identity); err != nil {
			// The worker cannot turn a memory-only validation into advertised supply.
			p.xIdentityError = true
			return
		}
		p.refresh(time.Now())
		return
	}
}
