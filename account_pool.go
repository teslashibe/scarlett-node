package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

type pooledAccount struct {
	spec       providerAccount
	entry      *serviceEntry
	removed    bool
	renewing   *renewalAttempt
	renewAfter time.Time
	identity   worker.VerifiedXIdentity
	duplicate  bool
}
type accountLease struct {
	id, kind  string
	config    config.Config
	account   *pooledAccount
	xStamp    string
	xIdentity string
}
type accountStatus struct {
	ID        string    `json:"id"`
	Service   string    `json:"service"`
	State     string    `json:"state"`
	Capacity  int       `json:"capacity"`
	InFlight  int       `json:"in_flight"`
	LastError string    `json:"last_error_code,omitempty"`
	RestUntil time.Time `json:"rest_until,omitempty"`
	Username  string    `json:"username,omitempty"`
}
type savedAccountHealth struct {
	// Older readers ignore this optional marker and conservatively quarantine.
	LocalAuthInvalid bool      `json:"local_auth_invalid,omitempty"`
	State            string    `json:"state"`
	Error            string    `json:"error,omitempty"`
	Stamp            string    `json:"stamp,omitempty"`
	RestUntil        time.Time `json:"rest_until,omitempty"`
	XIdentity        string    `json:"x_identity,omitempty"`
}

func validAccountStatuses(status []accountStatus) bool {
	if len(status) > maxProviderAccounts*4 {
		return false
	}
	for _, s := range status {
		localXState := s.Service == "x_read" && (s.State == "identity_unverified" || s.State == "duplicate_account") && s.LastError == "" && s.Capacity == 0
		if (!validAccountID(s.ID) && s.ID != "legacy") || s.Service != "codex" && s.Service != "x_read" || s.Capacity < 0 || s.Capacity > 32 || s.InFlight < 0 || s.InFlight > 32 || !validHealth(s.State, s.LastError) && !localXState || !validStatusUsername(s.Username) {
			return false
		}
	}
	return true
}
func validHealth(state, code string) bool {
	switch state {
	case "configured", "ready", "auth_required", "exhausted", "unreachable", "draining":
	default:
		return false
	}
	switch code {
	case "", "auth_required", "capacity_unavailable", "x_rate_limited", "prover_error", "x_request_failed", "report_pending", "expired", "invalid_lease", "service_unavailable", "x_incomplete", "execution_uncertain", "relay_misuse":
		return true
	}
	return false
}
func (p *servicePool) initAccounts() {
	if p.accounts != nil {
		return
	}
	p.accounts = map[string]*pooledAccount{}
	for _, kind := range []string{"codex", "x_read"} {
		path := p.config.CodexHome
		if kind == "x_read" {
			path = p.config.XSession
		}
		p.accounts[kind+":legacy"] = &pooledAccount{spec: providerAccount{"legacy", kind, path, p.entries[kind].capacity}, entry: p.entries[kind]}
	}
	p.saved = map[string]savedAccountHealth{}
	if p.config.StateDir == "" {
		return
	}
	mode, err := readLocalFile(filepath.Join(p.config.StateDir, "accounts-mode"), 8)
	if err == nil {
		if string(mode) != "managed\n" {
			p.healthError = true
			return
		}
		p.accountMode = true
		p.accounts = map[string]*pooledAccount{}
	} else if !os.IsNotExist(err) {
		p.healthError = true
		return
	}
	raw, e := readLocalFile(filepath.Join(p.config.StateDir, "account-health.json"), 32768)
	if os.IsNotExist(e) {
		return
	}
	if e != nil || json.Unmarshal(raw, &p.saved) != nil || p.saved == nil || len(p.saved) > 64 {
		p.healthError = true
		return
	}
	for key, h := range p.saved {
		if !validSavedKey(key) || !validHealth(h.State, h.Error) || len(h.Stamp) > 96 || h.RestUntil.After(time.Now().Add(30*24*time.Hour)) || h.XIdentity != "" && !validCooldownIdentity(h.XIdentity) {
			p.healthError = true
			return
		}
		// The marker only qualifies a local auth_required state. Drop it from any
		// other state rather than reject the file: without it the account is
		// quarantined conservatively, as an older reader would do.
		if h.LocalAuthInvalid && (h.State != "auth_required" || h.Error != "auth_required") {
			h.LocalAuthInvalid = false
			p.saved[key] = h
		}
	}
	for key, a := range p.accounts {
		if h, ok := p.saved[key]; ok {
			a.entry.state, a.entry.lastError, a.entry.stamp, a.entry.restUntil = h.State, h.Error, h.Stamp, h.RestUntil
			a.entry.localAuthInvalid = h.LocalAuthInvalid
			a.entry.xRestIdentity = h.XIdentity
		}
	}
}
func validSavedKey(key string) bool {
	for _, kind := range []string{"codex", "x_read"} {
		prefix := kind + ":"
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			return validAccountID(key[len(prefix):]) || key[len(prefix):] == "legacy"
		}
	}
	return false
}
func (p *servicePool) saveHealth() {
	if p.config.StateDir == "" {
		return
	}
	for key, a := range p.accounts {
		e := a.entry
		if e.state == "exhausted" || e.state == "auth_required" || e.state == "unreachable" {
			local := e.localAuthInvalid && e.state == "auth_required" && e.lastError == "auth_required"
			p.saved[key] = savedAccountHealth{State: e.state, Error: e.lastError, Stamp: e.stamp, RestUntil: e.restUntil, LocalAuthInvalid: local, XIdentity: e.xRestIdentity}
		} else {
			delete(p.saved, key)
		}
	}
	if len(p.saved) > 64 {
		p.healthError = true
		return
	}
	raw, e := json.Marshal(p.saved)
	if e != nil || writeLocalFile(p.config.StateDir, "account-health.json", raw) != nil {
		p.healthError = true
	}
}

// refreshAccounts returns false only while using the legacy single-account
// configuration. Once a private account file is observed, missing or invalid
// replacements fail closed rather than silently re-enabling legacy accounts.
func (p *servicePool) refreshAccounts(now time.Time) bool {
	p.initAccounts()
	if p.healthError {
		p.blockAccounts()
		return true
	}
	f, e := loadAccounts(p.config.AccountsFile)
	if os.IsNotExist(e) && !p.accountMode && !p.config.AccountsRequired {
		return false
	}
	if !p.accountMode {
		if p.config.StateDir != "" && writeLocalFile(p.config.StateDir, "accounts-mode", []byte("managed\n")) != nil {
			p.healthError = true
			p.blockAccounts()
			return true
		}
		p.accountMode = true
		for kind, old := range p.entries {
			p.entries[kind] = &serviceEntry{enabled: old.enabled, capacity: old.capacity}
		}
	}
	if e != nil || p.healthError {
		p.blockAccounts()
		return true
	}
	p.accountsError = false
	for _, a := range p.accounts {
		a.removed = true
	}
	for _, spec := range f.Accounts {
		key := spec.Service + ":" + spec.ID
		a := p.accounts[key]
		if a == nil {
			if len(p.accounts) >= 32 {
				p.blockAccounts()
				return true
			}
			a = &pooledAccount{spec: spec, entry: &serviceEntry{capacity: spec.Concurrency}}
			if h, ok := p.saved[key]; ok {
				a.entry.state, a.entry.lastError, a.entry.stamp, a.entry.restUntil = h.State, h.Error, h.Stamp, h.RestUntil
				a.entry.localAuthInvalid = h.LocalAuthInvalid
				a.entry.xRestIdentity = h.XIdentity
			}
			p.accounts[key] = a
		} else if a.spec.Path != spec.Path {
			// A changed credential location drains the selected snapshot. Admission
			// waits for its outstanding work, retaining cooldown under this local ID.
			if a.entry.inFlight > 0 || a.renewing != nil {
				if a.renewing != nil {
					a.renewing.cancel()
				}
				continue
			}
			a.spec.Path = spec.Path
			a.entry.stamp = ""
		}
		a.spec.Concurrency = spec.Concurrency
		a.entry.capacity = spec.Concurrency
		a.removed = false
	}
	_, helperErr := exec.LookPath(p.config.Prover)
	for key, a := range p.accounts {
		if a.removed {
			if a.renewing != nil {
				a.renewing.cancel()
			}
			if a.entry.inFlight == 0 && a.renewing == nil {
				delete(p.accounts, key)
			}
			continue
		}
		if a.renewing == nil {
			refreshAccount(a, now, helperErr != nil)
		}
	}
	p.refreshXIdentities(now)
	for kind, s := range p.entries {
		s.inFlight = 0
		available := 0
		s.state = "auth_required"
		s.lastError = "auth_required"
		ready, configured, exhausted, unreachable := false, false, false, false
		for _, a := range p.accounts {
			if a.spec.Service != kind {
				continue
			}
			s.inFlight += a.entry.inFlight
			held := p.renewalHolds(a)
			identityUnavailable := kind == "x_read" && (p.xIdentityError || a.identity.ID == "" || a.duplicate)
			if !a.removed && !held && (a.entry.state == "ready" || a.entry.state == "configured") {
				if kind == "x_read" {
					available += p.xGroupAvailable(a)
				} else {
					available += max(0, a.entry.capacity-a.entry.inFlight)
				}
			}
			if a.removed || held || identityUnavailable {
				if held {
					unreachable = true
				}
				continue
			}
			switch a.entry.state {
			case "ready":
				ready = true
			case "configured":
				configured = true
			case "exhausted":
				exhausted = true
			case "unreachable":
				unreachable = true
			}
		}
		ceiling := p.config.CodexConcurrency
		if kind == "x_read" {
			ceiling = p.config.XConcurrency
		}
		s.capacity = min(ceiling, s.inFlight+available)
		switch {
		case !s.enabled:
			s.state, s.lastError = "not_added", ""
		case ready:
			s.state, s.lastError = "ready", ""
		case configured:
			s.state, s.lastError = "configured", ""
		case exhausted:
			s.state, s.lastError = "exhausted", "capacity_unavailable"
		case unreachable:
			s.state, s.lastError = "unreachable", "prover_error"
		}
	}
	return true
}
func refreshAccount(a *pooledAccount, now time.Time, helperMissing bool) {
	s := a.entry
	path, open := a.spec.Path, localfs.OpenPrivate
	if a.spec.Service == "codex" {
		// codex-cli and open-agent-api write auth.json with an inherited Windows
		// DACL; X sessions are written by the node itself.
		path, open = filepath.Join(path, "auth.json"), localfs.OpenPrivateInherited
	}
	f, e := open(path)
	var info os.FileInfo
	if e == nil {
		info, e = f.Stat()
		f.Close()
	}
	stamp := "unavailable"
	configured := false
	if e == nil && info.Size() > 0 && info.Size() <= 65536 {
		stamp = fmt.Sprintf("%d:%d:%d", info.ModTime().UnixNano(), info.Size(), info.Mode().Perm())
		configured = true
	}
	configured = configured && (a.spec.Service != "x_read" || worker.XConfigured(path))
	if a.spec.Service == "codex" {
		configured = configured && codexAdmissionValid(a.spec.Path, codexAdmissionWindow(now))
	}
	wasLocalInvalid := s.localAuthInvalid
	stampChanged := stamp != s.stamp
	if s.state == "" || stampChanged {
		s.stamp = stamp
		s.localAuthInvalid = false
		// Credential changes can repair authentication, but do not erase a known
		// quota cooldown (including one restored after a process restart).
		if s.restUntil.IsZero() || !now.Before(s.restUntil) {
			s.lastError = ""
			s.state = "configured"
		} else if s.state == "auth_required" && wasLocalInvalid {
			s.state, s.lastError = "exhausted", "capacity_unavailable"
		}
	}
	if !configured {
		// Preserve real provider denial even as its unchanged credential ages.
		if stampChanged || s.state != "auth_required" || s.localAuthInvalid {
			s.localAuthInvalid = a.spec.Service == "codex"
		}
		s.state, s.lastError = "auth_required", "auth_required"
		return
	}
	if s.state == "auth_required" && s.localAuthInvalid {
		// Only local evaluation sets this marker, and it no longer holds.
		s.localAuthInvalid = false
		if s.restUntil.IsZero() || !now.Before(s.restUntil) {
			s.state, s.lastError = "configured", ""
		} else {
			s.state, s.lastError = "exhausted", "capacity_unavailable"
		}
	}
	if !s.restUntil.IsZero() && !now.Before(s.restUntil) {
		s.restUntil = time.Time{}
		// A quota timer cannot repair an independent authentication failure.
		if s.state != "auth_required" {
			s.state, s.lastError = "configured", ""
		}
	}
	if helperMissing {
		s.helperMissing = true
		if s.state != "auth_required" && s.state != "exhausted" {
			s.state, s.lastError = "unreachable", "prover_error"
		}
	} else if s.helperMissing {
		s.helperMissing = false
		if s.state == "unreachable" && s.lastError == "prover_error" && s.restUntil.IsZero() {
			s.state, s.lastError = "configured", ""
		}
	}
}
func (p *servicePool) acquireAccount(kind string) (*accountLease, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh(time.Now())
	s := p.entries[kind]
	if s == nil || !s.enabled || s.inFlight >= s.capacity || p.healthError || p.accountsError {
		return nil, false
	}
	if !p.accountMode {
		if s.state != "configured" && s.state != "ready" {
			return nil, false
		}
		a := p.accounts[kind+":legacy"]
		stamp := ""
		if kind == "x_read" {
			stamp = worker.XSessionStamp(a.spec.Path)
			if stamp == "" {
				return nil, false
			}
		}
		s.inFlight++
		c := p.config
		c.LocalAccountID = "legacy"
		if kind == "x_read" {
			c.ExpectedXStamp = stamp
			c.ExpectedXIdentity = a.identity.ID
			if a.identity.ID != "" {
				if p.xInFlight == nil {
					p.xInFlight = map[string]int{}
				}
				p.xInFlight[a.identity.ID]++
			}
		}
		c.AccountCooldown = p.cooldown(a)
		return &accountLease{id: "legacy", kind: kind, config: c, account: a, xStamp: stamp, xIdentity: a.identity.ID}, true
	}
	keys := []string{}
	for key, a := range p.accounts {
		if a.spec.Service == kind && !a.removed {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return nil, false
	}
	for offset := 0; offset < len(keys); offset++ {
		idx := (p.next[kind] + offset) % len(keys)
		a := p.accounts[keys[idx]]
		e := a.entry
		if p.renewalHolds(a) || e.inFlight >= e.capacity || e.state != "configured" && e.state != "ready" {
			continue
		}
		stamp := ""
		if kind == "x_read" {
			stamp = worker.XSessionStamp(a.spec.Path)
			if stamp == "" || stamp != a.identity.Stamp || p.xGroupAvailable(a) == 0 {
				continue
			}
			if p.xInFlight == nil {
				p.xInFlight = map[string]int{}
			}
			p.xInFlight[a.identity.ID]++
		}
		e.inFlight++
		s.inFlight++
		p.next[kind] = (idx + 1) % len(keys)
		c := p.config
		c.LocalAccountID = a.spec.ID
		c.AccountCooldown = p.cooldown(a)
		if kind == "codex" {
			c.CodexHome = a.spec.Path
		} else {
			c.XSession = a.spec.Path
			c.ExpectedXStamp, c.ExpectedXIdentity = stamp, a.identity.ID
		}
		return &accountLease{id: a.spec.ID, kind: kind, config: c, account: a, xStamp: stamp, xIdentity: a.identity.ID}, true
	}
	return nil, false
}
func (p *servicePool) finishAccount(l *accountLease, code string) {
	if l == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	s := l.account.entry
	if s.inFlight > 0 {
		s.inFlight--
	}
	if l.xIdentity != "" && p.xInFlight[l.xIdentity] > 0 {
		p.xInFlight[l.xIdentity]--
		if p.xInFlight[l.xIdentity] == 0 {
			delete(p.xInFlight, l.xIdentity)
		}
	}
	if l.kind == "x_read" && l.xIdentity != "" && (code == "x_rate_limited" || code == "capacity_unavailable") {
		p.recordXCooldown(l.xIdentity, time.Now().Add(15*time.Minute), false)
		p.refresh(time.Now())
		if l.account.identity.ID != l.xIdentity {
			return
		}
	}
	if l.kind == "x_read" && code == "auth_required" {
		// Login can replace credentials while an admitted job finishes. Drain
		// its slot, then refresh before deciding whether its refusal still
		// describes this account's current path and exact valid contents.
		p.refresh(time.Now())
		if l.xStamp == "" || l.account.spec.Path != l.config.XSession || worker.XSessionStamp(l.account.spec.Path) != l.xStamp {
			return
		}
	}
	// Rate limits apply to the account across credential replacement; only
	// authentication refusals are fenced by the admitted credential snapshot.
	p.settle(l.account, code, false)
}

// xValidated applies the outcome of an X client build that asked X to
// validate the session at path: "" when the client was installed, otherwise
// the failure code. A failure moves the account exactly as a failed job
// would, so a session the node already knows is refused or unreachable is not
// advertised until a funded job finds out again.
func (p *servicePool) xValidated(path, stamp, code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh(time.Now())
	// A login may replace this path while the observer waits for p.mu. Apply
	// the old result only to the exact content that produced it.
	if stamp == "" || worker.XSessionStamp(path) != stamp {
		return
	}
	if p.healthError || p.accountsError || !p.entries["x_read"].enabled {
		return
	}
	for _, a := range p.accounts {
		if a.spec.Service == "x_read" && !a.removed && a.spec.Path == path {
			p.settle(a, code, true)
			return
		}
	}
}

// xSessionPaths is every X session path the pool still holds, including
// accounts that are removed but still draining, so a client is only evicted
// once no job can be using it.
func (p *servicePool) xSessionPaths() map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh(time.Now())
	keep := map[string]bool{}
	for _, a := range p.accounts {
		if a.spec.Service == "x_read" {
			keep[a.spec.Path] = true
		}
	}
	return keep
}

// settle moves an account's state for one outcome: a finished job's result
// code or, with validation set, an X client build's. Caller holds p.mu.
func (p *servicePool) settle(a *pooledAccount, code string, validation bool) {
	s := a.entry
	if validation && code == "" {
		// A validated session is ready for work. It repairs nothing a job
		// reported: an authentication failure waits for a changed session file
		// and a rest runs its time. The keeper repeats this on every check, so
		// only a change is written.
		if s.state == "configured" && s.restUntil.IsZero() {
			s.state = "ready"
			p.saveHealth()
		}
		return
	}
	if code == codexLocalAuthExpired {
		// Local evidence only, so renewal may repair it. It never overrides a
		// provider denial already recorded for this credential.
		if s.state != "auth_required" {
			s.state, s.lastError, s.localAuthInvalid = "auth_required", "auth_required", a.spec.Service == "codex"
		}
		p.saveHealth()
		return
	}
	// An older concurrent result cannot repair an authoritative auth failure.
	if s.state == "auth_required" && code != "auth_required" {
		p.saveHealth()
		return
	}
	// An older transient result cannot shorten an authoritative quota reset or
	// replace its exhausted state, including when another attempt finishes later.
	if (code == "prover_error" || code == "x_request_failed") && s.state == "exhausted" && time.Now().Before(s.restUntil) {
		p.saveHealth()
		return
	}
	s.lastError = code
	switch code {
	case "":
		if s.state != "auth_required" && s.restUntil.IsZero() {
			s.state = "ready"
		}
	case "relay_misuse":
		// The verifier misbehaved, not this account. Keep the account ready
		// for MPC-TLS work; the node-wide halt (worker.HaltRelay) is what
		// stops relay, and the code stays in lastError so status shows why.
		if s.state != "auth_required" && s.restUntil.IsZero() {
			s.state = "ready"
		}
	case "auth_required":
		s.state = "auth_required"
		s.localAuthInvalid = false
	case "x_rate_limited", "capacity_unavailable":
		s.state = "exhausted"
		if until := time.Now().Add(15 * time.Minute); until.After(s.restUntil) {
			s.restUntil = until
		}
		if a.spec.Service == "x_read" {
			p.recordXCooldown(a.identity.ID, s.restUntil, false)
		}
	case "prover_error", "x_request_failed":
		s.state = "unreachable"
		if until := time.Now().Add(capacityRest); until.After(s.restUntil) {
			s.restUntil = until
		}
	}
	p.saveHealth()
}
func (p *servicePool) accountStatus() []accountStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh(time.Now())
	out := []accountStatus{}
	keys := []string{}
	for key := range p.accounts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		a := p.accounts[key]
		if !p.entries[a.spec.Service].enabled {
			continue
		}
		state := a.entry.state
		capacity := a.entry.capacity
		lastError := a.entry.lastError
		if a.spec.Service == "x_read" && p.accountMode {
			capacity = p.xGroupLimit(a)
			if a.identity.ID == "" {
				capacity = 0
			}
			switch {
			case p.xIdentityError:
				state, capacity, lastError = "unreachable", 0, "prover_error"
			case a.identity.ID == "" && (state == "configured" || state == "ready"):
				state, capacity, lastError = "identity_unverified", 0, ""
			case a.duplicate:
				state, capacity, lastError = "duplicate_account", 0, ""
			}
		}
		if p.accountsError {
			state, capacity, lastError = "unreachable", 0, "prover_error"
		}
		if p.renewalHolds(a) {
			state, capacity, lastError = "unreachable", 0, ""
		}
		if a.removed {
			state = "draining"
			capacity = 0
		}
		out = append(out, accountStatus{ID: a.spec.ID, Service: a.spec.Service, State: state, Capacity: capacity, InFlight: a.entry.inFlight, LastError: lastError, RestUntil: a.entry.restUntil, Username: a.identity.Username})
	}
	return out
}

func (p *servicePool) cooldown(a *pooledAccount) func(time.Duration) {
	identity := a.identity.ID
	return func(wait time.Duration) {
		p.mu.Lock()
		defer p.mu.Unlock()
		if wait < 15*time.Minute {
			wait = 15 * time.Minute
		}
		// Outside the bounded scheduling window, require operator attention rather
		// than resuming earlier than an authoritative provider reset.
		if wait > 30*24*time.Hour {
			if a.spec.Service == "x_read" && identity != "" {
				p.recordXCooldown(identity, time.Time{}, true)
				p.saveHealth()
				return
			}
			a.entry.state, a.entry.lastError = "auth_required", "auth_required"
			a.entry.localAuthInvalid = false
			p.saveHealth()
			return
		}
		until := time.Now().Add(wait)
		if a.spec.Service == "x_read" && identity != "" {
			p.recordXCooldown(identity, until, false)
			p.saveHealth()
			return
		}
		if until.After(a.entry.restUntil) {
			a.entry.restUntil = until
		}
		if a.entry.state != "auth_required" {
			a.entry.state, a.entry.lastError = "exhausted", "x_rate_limited"
		}
		p.saveHealth()
	}
}

func (p *servicePool) blockAccounts() {
	p.accountsError = true
	for kind, s := range p.entries {
		inFlight := 0
		for _, a := range p.accounts {
			if a.spec.Service == kind {
				inFlight += a.entry.inFlight
			}
		}
		s.inFlight, s.capacity = inFlight, inFlight
		// A legacy account shares this entry; the forced state is not local expiry.
		s.localAuthInvalid = false
		if s.enabled {
			s.state, s.lastError = "unreachable", "prover_error"
		} else {
			s.state, s.lastError = "not_added", ""
		}
	}
}
