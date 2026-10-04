package main

import (
	"os/exec"
	"sync"
	"time"

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
}
type servicePool struct {
	mu                                      sync.Mutex
	config                                  config.Config
	entries                                 map[string]*serviceEntry
	accounts                                map[string]*pooledAccount
	saved                                   map[string]savedAccountHealth
	next                                    map[string]int
	accountMode, accountsError, healthError bool
}

func newServicePool(c config.Config) *servicePool {
	p := &servicePool{next: map[string]int{}, config: c, entries: map[string]*serviceEntry{"codex": {capacity: c.CodexConcurrency}, "x_read": {capacity: c.XConcurrency}}}
	for _, kind := range c.Services {
		p.entries[kind].enabled = true
	}
	return p
}
func (p *servicePool) refresh(now time.Time) {
	if p.refreshAccounts(now) {
		return
	}
	_, helperError := exec.LookPath(p.config.Prover)
	for kind, s := range p.entries {
		if !s.enabled {
			s.state = "not_added"
			continue
		}
		refreshAccount(p.accounts[kind+":legacy"], now, helperError != nil)
	}
}
func (p *servicePool) health() []coordinator.ServiceHealth {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh(time.Now())
	out := []coordinator.ServiceHealth{}
	for _, kind := range []string{"codex", "x_read"} {
		s := p.entries[kind]
		capacity := 0
		if s.enabled {
			capacity = s.capacity
		}
		h := coordinator.ServiceHealth{Kind: kind, State: s.state, Capacity: capacity, InFlight: s.inFlight, LastErrorCode: s.lastError}
		if s.enabled {
			h.MaxInputBytes = p.config.MaxInputBytes
			if kind == "codex" {
				h.MaxOutputTokens = p.config.MaxOutputTokens
				h.Models = config.AvailableModelsAt(time.Now())
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
func (p *servicePool) acquire(kind string) bool { _, ok := p.acquireAccount(kind); return ok }
func (p *servicePool) finish(kind, code string) {
	p.mu.Lock()
	p.initAccounts()
	a := p.accounts[kind+":legacy"]
	p.mu.Unlock()
	if a != nil {
		p.finishAccount(&accountLease{kind: kind, account: a}, code)
	}
}
func (p *servicePool) capacity() int {
	total := 0
	for _, s := range p.entries {
		if s.enabled {
			total += s.capacity
		}
	}
	return total
}
