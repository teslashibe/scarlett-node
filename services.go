package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	mu      sync.Mutex
	config  config.Config
	entries map[string]*serviceEntry
}

func newServicePool(c config.Config) *servicePool {
	p := &servicePool{config: c, entries: map[string]*serviceEntry{"codex": {capacity: c.CodexConcurrency}, "x_read": {capacity: c.XConcurrency}}}
	for _, kind := range c.Services {
		p.entries[kind].enabled = true
	}
	return p
}
func (p *servicePool) refresh(now time.Time) {
	_, helperError := exec.LookPath(p.config.Prover)
	for kind, s := range p.entries {
		if !s.enabled {
			s.state = "not_added"
			continue
		}
		path := p.config.XSession
		if kind == "codex" {
			path = filepath.Join(p.config.CodexHome, "auth.json")
		}
		info, e := os.Lstat(path)
		stamp := "unavailable"
		configured := false
		if e == nil && info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 && info.Size() > 0 && info.Size() <= 65536 {
			stamp = fmt.Sprintf("%d:%d:%d", info.ModTime().UnixNano(), info.Size(), info.Mode().Perm())
			configured = true
		}
		configured = configured && (kind != "x_read" || worker.XConfigured(path))
		if stamp != s.stamp || s.state == "" {
			s.stamp = stamp
			s.lastError = ""
			s.restUntil = time.Time{}
			s.state = "configured"
			if !configured {
				s.state = "auth_required"
			}
		}
		if !s.restUntil.IsZero() && !now.Before(s.restUntil) {
			s.restUntil = time.Time{}
			s.state = "configured"
		}
		if configured && helperError != nil {
			s.helperMissing = true
			s.state, s.lastError = "unreachable", "prover_error"
		} else if configured && s.helperMissing {
			s.helperMissing = false
			s.state, s.lastError = "configured", ""
			s.restUntil = time.Time{}
		}
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
				h.Models = append([]string(nil), config.Models...)
			}
		}
		out = append(out, h)
	}
	return out
}
func (p *servicePool) acquire(kind string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh(time.Now())
	s := p.entries[kind]
	if s == nil || !s.enabled || s.inFlight >= s.capacity || s.state != "configured" && s.state != "ready" {
		return false
	}
	s.inFlight++
	return true
}
func (p *servicePool) finish(kind, code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.entries[kind]
	if s == nil {
		return
	}
	s.inFlight--
	s.lastError = code
	switch code {
	case "":
		s.state = "ready"
	case "auth_required":
		s.state = "auth_required"
	case "x_rate_limited", "capacity_unavailable":
		s.state = "exhausted"
		s.restUntil = time.Now().Add(capacityRest)
	case "prover_error", "x_request_failed":
		s.state = "unreachable"
		s.restUntil = time.Now().Add(capacityRest)
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
