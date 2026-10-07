package main

import (
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

type serviceEntry struct {
	enabled                 bool
	capacity, inFlight      int
	state, lastError, stamp string
	restUntil               time.Time
	helperMissing           bool
	localAuthInvalid        bool
	xRestIdentity           string
}
type servicePool struct {
	mu                                      sync.Mutex
	renewal                                 *codexRenewal
	config                                  config.Config
	entries                                 map[string]*serviceEntry
	accounts                                map[string]*pooledAccount
	saved                                   map[string]savedAccountHealth
	next                                    map[string]int
	accountMode, accountsError, healthError bool
	xCooldowns                              map[string]xIdentityCooldown
	xInFlight                               map[string]int
	activeCoordinatorLeases                 map[*accountLease]coordinator.ActiveLease
	xIdentityError, xIdentityHealthError    bool
	xEligibility                            func(string, string, time.Time) time.Time
	availabilityChanges                     chan<- struct{}
	xRecovery                               func() ([]attempts.Record, error)
	xRecoveryIdentities                     map[string]bool
	xRecoveryUnknown                        bool
	// web is the account-free web service's slot holder. Its entry is
	// entries["web"], which only the web paths below ever change.
	web *pooledAccount
}

func newServicePool(c config.Config) *servicePool {
	p := &servicePool{next: map[string]int{}, config: c, entries: map[string]*serviceEntry{"codex": {capacity: c.CodexConcurrency}, "x_read": {capacity: c.XConcurrency}, "web": {capacity: c.WebConcurrency}}}
	if c.XAccountConcurrency > 0 {
		p.entries["x_read"].capacity = min(c.XConcurrency, c.XAccountConcurrency)
	}
	for _, kind := range c.Services {
		p.entries[kind].enabled = true
	}
	p.web = &pooledAccount{spec: providerAccount{"web", "web", "", c.WebConcurrency}, entry: p.entries["web"]}
	return p
}
func (p *servicePool) refresh(now time.Time) {
	p.refreshWeb(now)
	if p.refreshAccounts(now) {
		return
	}
	_, helperError := exec.LookPath(p.config.Prover)
	for kind, s := range p.entries {
		if kind == "web" {
			continue
		}
		if !s.enabled {
			s.state = "not_added"
			continue
		}
		refreshAccount(p.accounts[kind+":legacy"], now, helperError != nil)
	}
	p.refreshXRecovery()
}

func blockOperationAvailability(services []coordinator.ServiceHealth) {
	for i := range services {
		for j := range services[i].OperationAvailability {
			services[i].OperationAvailability[j].RunnableCapacity = 0
		}
	}
}

func (p *servicePool) health() []coordinator.ServiceHealth {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.refresh(now)
	out := []coordinator.ServiceHealth{}
	for _, kind := range []string{"codex", "x_read", "web"} {
		s := p.entries[kind]
		capacity := 0
		if s.enabled {
			capacity = s.capacity
			if s.state != "configured" && s.state != "ready" {
				capacity = s.inFlight
			}
		}
		if kind == "x_read" && s.enabled && !p.accountMode {
			if a := p.accounts["x_read:legacy"]; a != nil && (p.xReadyAt(a, now).After(now) || p.xRecoveryHolds(a)) {
				capacity = s.inFlight
			}
		}
		h := coordinator.ServiceHealth{Kind: kind, State: s.state, Capacity: capacity, InFlight: s.inFlight, LastErrorCode: s.lastError}
		if capacity == 0 && (h.State == "ready" || h.State == "configured") {
			h.State = "exhausted"
		}
		if kind == "x_read" && s.enabled && p.accountMode {
			a := p.xAvailability(now)
			h.ConfiguredCapacity, h.ActiveAccounts, h.ReadyAccounts, h.CoolingAccounts = &a.configured, &a.active, &a.ready, &a.cooling
			runnable := max(0, capacity-s.inFlight)
			h.RunnableCapacity = &runnable
			for _, operation := range []string{"search", "profile", "post", "thread"} {
				a := p.xAvailability(now, operation)
				hint := coordinator.OperationAvailability{Operation: operation, RunnableCapacity: min(a.available, max(0, a.configured-s.inFlight))}
				if a.cooling > 0 && !a.next.IsZero() && !a.next.After(now.Add(30*24*time.Hour)) {
					next := a.next.UTC()
					hint.NextReadyAt = &next
				}
				h.OperationAvailability = append(h.OperationAvailability, hint)
				if hint.RunnableCapacity > 0 && h.State == "exhausted" && h.LastErrorCode == "" {
					h.State = "configured"
				}
			}
			if !a.next.IsZero() && !a.next.After(now.Add(30*24*time.Hour)) {
				next := a.next.UTC()
				h.NextReadyAt = &next
			}
		}
		for account, lease := range p.activeCoordinatorLeases {
			if account.kind == kind {
				h.ActiveLeases = append(h.ActiveLeases, lease)
			}
		}
		sort.Slice(h.ActiveLeases, func(i, j int) bool { return h.ActiveLeases[i].JobID < h.ActiveLeases[j].JobID })
		// An unreadable local pool must never assert more identities than work.
		if len(h.ActiveLeases) > min(32, h.InFlight) {
			h.ActiveLeases = nil
		}
		if s.enabled {
			h.MaxInputBytes = p.config.MaxInputBytes
			if kind == "codex" {
				h.MaxOutputTokens = p.config.MaxOutputTokens
				h.Models = config.AvailableModelsAt(time.Now())
			}
			if kind == "web" {
				h.Egress = p.config.WebEgress()
			}
			// Only an opted-in node says so, and a node that has not opted
			// in sends exactly the heartbeat it sent before the field existed.
			// A node that has halted relay after catching its verifier keeps
			// advertising MPC so the coordinator keeps sending it that work.
			if kind == "x_read" && p.config.XRelay {
				if worker.RelayHalted() {
					h.ProofModes = []string{"mpc"}
				} else {
					h.ProofModes = []string{"mpc", "relay"}
				}
			}
		}
		out = append(out, h)
	}
	return out
}

// xAccounts lists the X accounts whose session files are usable right now,
// for keeping their clients warm. An account that is resting or that X
// refused is left out, so the background does not ask X about it either.
func (p *servicePool) xAccounts() []worker.XAccount {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh(time.Now())
	out := []worker.XAccount{}
	if p.accountsError || p.healthError {
		return out
	}
	keys := []string{}
	for key, a := range p.accounts {
		if a.spec.Service == "x_read" && !a.removed && !p.xRecoveryHolds(a) && (a.entry.state == "configured" || a.entry.state == "ready") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		a := p.accounts[key]
		out = append(out, worker.XAccount{ID: a.spec.ID, Path: a.spec.Path})
	}
	return out
}

// xRefreshAllowed applies the keeper's same availability rules to the cache's
// autonomous timer, which otherwise retains clients while accounts rest.
func (p *servicePool) xRefreshAllowed(path string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.refresh(now)
	for _, a := range p.accounts {
		if a.spec.Service == "x_read" && a.spec.Path == path && !a.removed && !p.healthError && !p.accountsError && (a.entry.state == "configured" || a.entry.state == "ready") {
			return !p.xRecoveryHolds(a) && !p.xReadyAt(a, now).After(now)
		}
	}
	return false
}

func (p *servicePool) acquire(kind string) bool { _, ok := p.acquireAccount(kind); return ok }
func (p *servicePool) finish(kind, code string) {
	if kind == "web" {
		p.finishAccount(&accountLease{id: "web", kind: "web", config: p.config, account: p.web}, code)
		return
	}
	p.mu.Lock()
	p.initAccounts()
	a := p.accounts[kind+":legacy"]
	lease := &accountLease{kind: kind, account: a, config: p.config}
	if a != nil && kind == "x_read" {
		lease.xStamp = worker.XSessionStamp(a.spec.Path)
		lease.xIdentity = a.identity.ID
		for admitted := range a.xLeases {
			lease = admitted
			break
		}
	}
	p.mu.Unlock()
	if a != nil {
		p.finishAccount(lease, code)
	}
}

// capacity is the static configured slot ceiling. It reads only immutable
// configuration, never the advertised capacity that refresh and renewal adjust.
func (p *servicePool) capacity() int {
	total := 0
	for kind, ceiling := range map[string]int{"codex": p.config.CodexConcurrency, "x_read": p.config.XConcurrency, "web": p.config.WebConcurrency} {
		if p.config.Enabled(kind) {
			total += ceiling
		}
	}
	return total
}

// webProxyRest is how long the web service reports unreachable after its
// egress proxy failed, before it is offered work again.
const webProxyRest = 60 * time.Second

// refreshWeb derives the web state. Web has no accounts: it is configured
// once enabled with the proof helper present, and only the helper, a relay
// halt or a failed egress proxy make it unreachable. Caller holds p.mu.
func (p *servicePool) refreshWeb(now time.Time) {
	s := p.entries["web"]
	if !s.enabled {
		s.state, s.lastError = "not_added", ""
		return
	}
	_, helperErr := exec.LookPath(p.config.Prover)
	switch {
	case helperErr != nil:
		s.state, s.lastError = "unreachable", "prover_error"
	case worker.RelayHalted():
		// Web is keyed relay only, through the one verifier that misbehaved.
		s.state, s.lastError = "unreachable", "relay_misuse"
	case now.Before(s.restUntil):
		s.state, s.lastError = "unreachable", "web_proxy_failed"
	case s.state != "ready":
		s.state, s.lastError, s.restUntil = "configured", "", time.Time{}
	}
}

// acquireWebLocked takes a web slot. Account files, their health and their
// errors never apply: a web-only node may have no accounts at all.
func (p *servicePool) acquireWebLocked() (*accountLease, bool) {
	s := p.entries["web"]
	if !s.enabled || s.state != "configured" && s.state != "ready" || s.inFlight >= s.capacity {
		return nil, false
	}
	s.inFlight++
	c := p.config
	c.LocalAccountID = "web"
	return &accountLease{id: "web", kind: "web", config: c, account: p.web}, true
}

// settleWeb applies one finished web job. Only the node's own egress proxy
// failing rests the service; a target that fails, refuses or does not resolve
// says nothing about this node. Caller holds p.mu.
func (p *servicePool) settleWeb(code string) {
	s := p.entries["web"]
	switch code {
	case "":
		s.state, s.lastError = "ready", ""
	case "web_proxy_failed":
		s.state, s.lastError, s.restUntil = "unreachable", code, time.Now().Add(webProxyRest)
	}
}
