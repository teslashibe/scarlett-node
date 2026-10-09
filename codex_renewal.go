package main

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/teslashibe/open-agent-api/pkg/codex"
	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// Bound privately managed renewal independently of any accepted job. There is
// never inference, result replay, or a change to a selected attempt's account.
const (
	codexRenewalWatch   = time.Second
	codexRenewalCadence = time.Minute
	codexRenewalBackoff = 5 * time.Minute
	codexRenewalTimeout = 15 * time.Second
	// Renewal starts this far before expiry, so a failed attempt is retried
	// several times (backoff) before funded admission drops the profile at
	// MaxCodexOfferLifetime plus the clock margin before expiry.
	codexRenewalHorizon = 30 * time.Minute
)

type managedAuthentication interface {
	EnsureValidUntil(context.Context, time.Time) error
}
type authenticationFactory func(string) (managedAuthentication, error)

// Renewal goes through the gateway's public authentication-only package. It
// runs only for profiles under an explicit SCARLETT_CODEX_MANAGED_ROOT.
var managedAuthenticationFactory authenticationFactory = newCodexAuthentication

// newCodexAuthentication selects one absolute auth.json without reading it.
// Any failure, including a nil value, refuses renewal for that profile.
func newCodexAuthentication(authPath string) (managedAuthentication, error) {
	auth, err := codex.NewAuthentication(authPath)
	if err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, codex.ErrAuthenticationUnavailable
	}
	return auth, nil
}

// inheritedPending limits renewal's journal view to attempts that were still
// pending when this process started. Only those can mean provider work outside
// this process's in-flight accounting, for example a helper left running by a
// crashed node. This process's own attempts hold their account in flight until
// the worker returns, and a finished worker never runs the provider again.
// A resolved inherited record never becomes pending again, so once none remain
// the journal is no longer read on every renewal tick.
func inheritedPending(pending func() ([]attempts.Record, error), inherited map[string]bool) func() ([]attempts.Record, error) {
	var mu sync.Mutex
	remaining := maps.Clone(inherited)
	return func() ([]attempts.Record, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(remaining) == 0 {
			return nil, nil
		}
		records, err := pending()
		if err != nil {
			return nil, err
		}
		out := []attempts.Record{}
		still := map[string]bool{}
		for _, record := range records {
			if remaining[record.Key()] {
				out = append(out, record)
				still[record.Key()] = true
			}
		}
		remaining = still
		return out, nil
	}
}

type renewalAttempt struct {
	cancel     context.CancelFunc
	done       chan struct{}
	root, home os.FileInfo
	path       string
}
type codexRenewal struct {
	factory  authenticationFactory
	pending  func() ([]attempts.Record, error)
	cancel   context.CancelFunc
	done     chan struct{}
	active   *pooledAccount
	next     int
	stopOnce sync.Once
}

func (p *servicePool) startCodexRenewal(ctx context.Context, factory authenticationFactory, pending func() ([]attempts.Record, error)) func() {
	if factory == nil || p.config.CodexManagedRoot == "" || pending == nil {
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &codexRenewal{factory: factory, pending: pending, cancel: cancel, done: make(chan struct{})}
	p.mu.Lock()
	if p.renewal != nil {
		p.mu.Unlock()
		cancel()
		return func() {}
	}
	p.renewal = r
	p.mu.Unlock()
	go func() {
		defer close(r.done)
		ticker := time.NewTicker(codexRenewalWatch)
		defer ticker.Stop()
		for {
			p.renewCodexStep(ctx, time.Now())
			select {
			case <-ctx.Done():
				p.mu.Lock()
				var done chan struct{}
				if r.active != nil && r.active.renewing != nil {
					r.active.renewing.cancel()
					done = r.active.renewing.done
				}
				p.mu.Unlock()
				if done != nil {
					<-done
				}
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { r.stopOnce.Do(func() { cancel(); <-r.done }) }
}

func (p *servicePool) renewCodexStep(ctx context.Context, now time.Time) <-chan struct{} {
	p.mu.Lock()
	r := p.renewal
	p.mu.Unlock()
	if r == nil {
		return nil
	}
	records, err := r.pending() // Journal I/O never runs under the account mutex.
	blocked := map[string]bool{}
	unknown := err != nil
	for _, record := range records {
		switch {
		case record.NoProvider && record.ProviderAccountID == "":
			// A rejection never runs provider work on any profile.
		case record.ProviderService == "codex" && validAccountID(record.ProviderAccountID):
			blocked[record.ProviderAccountID] = true
		case record.ProviderService == "x_read" && validAccountID(record.ProviderAccountID):
		case record.ProviderService == "web" && record.ProviderAccountID == "web":
			// Web runs no provider credential.
		default:
			unknown = true
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refresh(now)
	if r.active != nil {
		a := r.active
		// The reservation already excludes new work on this profile, so no
		// journal observation can newly mean provider execution on it, and an
		// already-sent token exchange must not be abandoned for one. Cancel only
		// if the reserved profile goes away or changes; the timeout bounds the rest.
		if a.renewing != nil && (ctx.Err() != nil || a.removed || !p.sameRenewalProfile(a)) {
			a.renewing.cancel()
		}
		return nil
	}
	// A record names its account, not its directory. Once that ID is no longer
	// registered, the directory its helper may still use is unknown (it may now
	// be registered under another ID), so no profile is renewed.
	for id := range blocked {
		if p.accounts["codex:"+id] == nil {
			unknown = true
		}
	}
	if ctx.Err() != nil || unknown || !p.accountMode || p.accountsError || p.healthError || !p.entries["codex"].enabled {
		return nil
	}
	keys := []string{}
	for key, a := range p.accounts {
		if a.spec.Service == "codex" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for offset := 0; offset < len(keys); offset++ {
		idx := (r.next + offset) % len(keys)
		a := p.accounts[keys[idx]]
		s := a.entry
		if a.removed || s.inFlight != 0 || a.renewing != nil || blocked[a.spec.ID] || now.Before(a.renewAfter) || s.state == "auth_required" && !s.localAuthInvalid {
			continue
		}
		root, home, ok := managedProfile(p.config.CodexManagedRoot, a.spec.Path)
		if !ok {
			a.renewAfter = now.Add(codexRenewalCadence)
			continue
		}
		// Reserve only a profile that may need a refresh. One that is valid past
		// the horizon stays selectable and is checked again next cadence.
		if codexAdmissionValid(a.spec.Path, now.Add(codexRenewalHorizon)) {
			a.renewAfter = now.Add(codexRenewalCadence)
			continue
		}
		// Idleness belongs to the profile, not the ID: a draining, renewing or
		// journal-blocked account may use the same directory under another ID.
		if p.codexProfileBusy(a, home, blocked) {
			continue
		}
		jobCtx, cancel := context.WithTimeout(ctx, codexRenewalTimeout)
		run := &renewalAttempt{cancel: cancel, done: make(chan struct{}), root: root, home: home, path: a.spec.Path}
		a.renewing = run
		r.active = a
		r.next = (idx + 1) % len(keys)
		// Recompute offered slots immediately while retaining health/quota evidence.
		p.refresh(now)
		go p.executeCodexRenewal(jobCtx, a, run, now.Add(codexRenewalHorizon))
		return run.done
	}
	return nil
}

func managedProfile(root, path string) (os.FileInfo, os.FileInfo, bool) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Clean(path) != path || filepath.Dir(path) != root || path == root {
		return nil, nil, false
	}
	// Reject aliases/reparse ancestors rather than following a different profile.
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != root {
		return nil, nil, false
	}
	if localfs.CheckOwnedDir(root) != nil || localfs.CheckOwnedDir(path) != nil {
		return nil, nil, false
	}
	// The credential itself must already pass the node's Codex credential check,
	// the same one account refresh and funded admission use: on Windows a
	// codex-cli login may inherit its ACL from the protected private profile
	// checked above. Renewal keeps that descriptor; it never repairs one, so a
	// profile that fails here is left for reconnection.
	f, err := localfs.OpenPrivateInherited(filepath.Join(path, "auth.json"))
	if err != nil {
		return nil, nil, false
	}
	f.Close()
	r, err := os.Lstat(root)
	if err != nil {
		return nil, nil, false
	}
	h, err := os.Lstat(path)
	if err != nil {
		return nil, nil, false
	}
	// Windows resolves FileInfo IDs lazily; freeze them before any operation.
	if !os.SameFile(r, r) || !os.SameFile(h, h) {
		return nil, nil, false
	}
	return r, h, true
}

// codexProfileBusy reports whether another Codex account, including a removed
// one still draining, has selected work, a renewal, or a pending attempt from an
// earlier process on a's directory. Attempts are pinned by ID, so a blocked ID
// covers the directory that ID is registered on now.
func (p *servicePool) codexProfileBusy(a *pooledAccount, home os.FileInfo, blocked map[string]bool) bool {
	for _, other := range p.accounts {
		if other == a || other.spec.Service != "codex" || other.entry.inFlight == 0 && other.renewing == nil && !blocked[other.spec.ID] {
			continue
		}
		if filepath.Clean(other.spec.Path) == a.spec.Path {
			return true
		}
		if info, err := os.Lstat(other.spec.Path); err == nil && os.SameFile(info, home) {
			return true
		}
	}
	return false
}

// renewalHolds reports whether a's profile is reserved by the running renewal:
// a is the reserved account, or another ID now registered on the directory
// being renewed. A cancelled renewal holds its directory until it returns.
func (p *servicePool) renewalHolds(a *pooledAccount) bool {
	if a.renewing != nil {
		return true
	}
	if a.spec.Service != "codex" || p.renewal == nil || p.renewal.active == nil || p.renewal.active.renewing == nil {
		return false
	}
	run := p.renewal.active.renewing
	if filepath.Clean(a.spec.Path) == run.path {
		return true
	}
	info, err := os.Lstat(a.spec.Path)
	return err == nil && os.SameFile(info, run.home)
}

func (p *servicePool) sameRenewalProfile(a *pooledAccount) bool {
	run := a.renewing
	if run == nil || a.spec.Path != run.path {
		return false
	}
	root, home, ok := managedProfile(p.config.CodexManagedRoot, run.path)
	return ok && os.SameFile(root, run.root) && os.SameFile(home, run.home)
}
func (p *servicePool) executeCodexRenewal(ctx context.Context, a *pooledAccount, run *renewalAttempt, deadline time.Time) {
	defer close(run.done)
	defer run.cancel()
	// Check cancellation before the constructor, which is specified to perform no
	// credential reads or network work. The bounded operation alone can renew.
	err := ctx.Err()
	if err == nil {
		var auth managedAuthentication
		auth, err = p.renewal.factory(filepath.Join(run.path, "auth.json"))
		if err == nil && auth != nil {
			err = auth.EnsureValidUntil(ctx, deadline.Add(codexAdmissionClockMargin))
		} else if err == nil {
			err = context.Canceled
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	same := !a.removed && p.sameRenewalProfile(a)
	a.renewing = nil
	p.renewal.active = nil
	now := time.Now()
	a.renewAfter = now.Add(codexRenewalBackoff)
	if same {
		// A cancellation may follow a durably saved rotation. Reread the unchanged
		// home, but never clear genuine provider rejection absent a new file stamp.
		refreshAccount(a, now, false)
		if err == nil && ctx.Err() == nil && codexAdmissionValid(run.path, deadline) {
			a.renewAfter = now.Add(codexRenewalCadence)
		}
	}
	p.refresh(now)
	p.saveHealth()
}
