package worker

import (
	"context"
	"errors"
	"time"

	x "github.com/teslashibe/x-go"
)

// VerifiedXIdentity is the user returned by authenticated Viewer validation.
// Stamp binds a warm client's identity to exact private session file content;
// direct in-memory verification leaves it empty. Never log the Stamp.
type VerifiedXIdentity struct {
	ID       string `json:"id"`
	Username string `json:"username,omitempty"`
	Stamp    string `json:"stamp,omitempty"`
}

// VerifyXSession validates this session's own credentials with Viewer. It
// never substitutes another session's cached client or cookie-supplied user ID.
func VerifyXSession(ctx context.Context, session x.Session, opts ...x.Option) (VerifiedXIdentity, error) {
	opts = append(opts, x.WithRetry(1, time.Second))
	client, err := session.NewClient(ctx, opts...)
	if err != nil {
		return VerifiedXIdentity{}, err
	}
	return verifiedXClient(ctx, client)
}

func verifiedXClient(ctx context.Context, client *x.Client) (VerifiedXIdentity, error) {
	u, err := client.Me(ctx)
	if err != nil || u == nil || !validXUserID(u.ID) || !validXUsername(u.ScreenName) {
		return VerifiedXIdentity{}, errors.New("authenticated X identity unavailable")
	}
	return VerifiedXIdentity{ID: u.ID, Username: u.ScreenName}, nil
}

func validXUserID(id string) bool {
	if len(id) == 0 || len(id) > 32 {
		return false
	}
	for _, ch := range id {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// A partial profile may omit a handle; the authenticated stable ID is enough
// for grouping. Any displayed handle must be an X handle rather than prose.
func validXUsername(name string) bool {
	if len(name) > 15 {
		return false
	}
	for _, ch := range name {
		if ch != '_' && !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') && !(ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

// ObserveIdentity receives a session-fenced identity before its successful
// build is reported by Observe. The callback runs without cache locks and
// must compare Stamp again while persisting or applying its result.
func (c *XClients) ObserveIdentity(f func(path string, identity VerifiedXIdentity)) {
	c.mu.Lock()
	c.observeIdentity = f
	c.mu.Unlock()
}

// VerifiedIdentity returns an installed authenticated identity only while
// the session file still contains the exact content used to build the client.
func (c *XClients) VerifiedIdentity(path string) (VerifiedXIdentity, bool) {
	c.mu.Lock()
	a := c.accounts[path]
	c.mu.Unlock()
	if a == nil {
		return VerifiedXIdentity{}, false
	}
	a.mu.Lock()
	cur := a.current
	if cur == nil || a.stopped {
		a.mu.Unlock()
		return VerifiedXIdentity{}, false
	}
	identity := cur.identity
	a.mu.Unlock()
	if identity.Stamp == "" || XSessionStamp(path) != identity.Stamp {
		return VerifiedXIdentity{}, false
	}
	return identity, true
}

func (c *XClients) reportIdentity(path string, identity VerifiedXIdentity) {
	c.mu.Lock()
	observe := c.observeIdentity
	c.mu.Unlock()
	if observe != nil && identity.Stamp != "" && XSessionStamp(path) == identity.Stamp {
		observe(path, identity)
	}
}

const maxXIdentityDomains = 64

type xIdentityDomain struct {
	pacing   *x.RequestPacing
	accounts map[*xAccount]bool
	jobs     int
}

// pacingFor binds only the pacing state of authenticated identities. Retired
// domains stay until their quota and reserved slots expire; capacity is bounded
// and a full cache refuses new identities rather than resetting active limits.
func (a *xAccount) pacingFor(id string) (*x.RequestPacing, error) {
	if !validXUserID(id) {
		return nil, errors.New("invalid authenticated X identity")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped {
		return nil, errXDropped
	}
	c := a.clients
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.identities == nil {
		c.identities = make(map[string]*xIdentityDomain)
	}
	domain := c.identities[id]
	if domain == nil {
		now := time.Now()
		for key, old := range c.identities {
			if len(old.accounts) == 0 && old.jobs == 0 && !now.Before(old.pacing.RetainUntil(c.gap())) {
				delete(c.identities, key)
			}
		}
		if len(c.identities) >= maxXIdentityDomains {
			return nil, errors.New("retained X identity capacity reached")
		}
		domain = &xIdentityDomain{pacing: &x.RequestPacing{}, accounts: make(map[*xAccount]bool)}
		c.identities[id] = domain
	}
	domain.accounts[a] = true
	return domain.pacing, nil
}

func (c *XClients) holdIdentity(id string) func() {
	c.mu.Lock()
	domain := c.identities[id]
	if domain != nil {
		domain.jobs++
	}
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		if domain != nil {
			domain.jobs--
		}
		c.mu.Unlock()
	}
}

// acquireJob reserves its domain before removal can detach this account's
// final client reference. Plain warm-up acquisition need not keep a job pin.
func (a *xAccount) acquireJob(ctx context.Context, ids map[string]string, strict bool) (*xWarm, func(), error) {
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return nil, func() {}, errXDropped
	}
	a.acquiring++
	a.mu.Unlock()
	warm, err := a.acquire(ctx, ids, strict)
	a.mu.Lock()
	if err == nil && a.stopped {
		err = errXDropped
	}
	release := func() {}
	if err == nil {
		release = a.clients.holdIdentity(warm.identity.ID)
	}
	a.acquiring--
	if a.stopped && a.acquiring == 0 {
		a.detachIdentityDomains()
	}
	a.mu.Unlock()
	return warm, release, err
}

// Caller holds a.mu. Jobs retain their own references while removal drains.
func (a *xAccount) detachIdentityDomains() {
	c := a.clients
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, domain := range c.identities {
		delete(domain.accounts, a)
	}
}

// A completed construction no longer pins another identity's domain. Jobs
// hold independent references and expired observations can then be reclaimed.
// Caller holds a.mu and no construction remains in progress.
func (a *xAccount) syncIdentityDomains() {
	c := a.clients
	c.mu.Lock()
	defer c.mu.Unlock()
	if a.stopped && a.acquiring > 0 {
		return
	}
	for id, domain := range c.identities {
		if a.current == nil || a.current.identity.ID != id {
			delete(domain.accounts, a)
		}
	}
}
