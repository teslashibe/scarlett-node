package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
	x "github.com/teslashibe/x-go"
)

func TestVerifyXSessionUsesAuthenticatedViewer(t *testing.T) {
	fake := &xFakeX{}
	session := x.Session{AuthToken: "synthetic-auth", CT0: "synthetic-csrf"}
	opts := []x.Option{x.WithHTTPClient(&http.Client{Transport: fake}), x.WithMinRequestGap(0)}
	identity, err := VerifyXSession(context.Background(), session, opts...)
	if err != nil || identity.ID != "12" || identity.Username != "fixture" || identity.Stamp != "" {
		t.Fatal("unexpected authenticated identity", identity, err)
	}
	// A cookie hint cannot override the identity returned by Viewer.
	session.Twid = "u=999"
	if _, err := VerifyXSession(context.Background(), session, opts...); err == nil {
		t.Fatal("accepted a cookie identity that contradicted Viewer")
	}
	session.Twid = ""
	wrongProfile := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/UserByRestId") {
			return xResponse(r, 200, `{"data":{"user":{"result":{"__typename":"User","rest_id":"999","legacy":{"screen_name":"other"}}}}}`), nil
		}
		return fake.RoundTrip(r)
	})
	if _, err := VerifyXSession(context.Background(), session, x.WithHTTPClient(&http.Client{Transport: wrongProfile}), x.WithMinRequestGap(0)); err == nil {
		t.Fatal("accepted a profile identity that contradicted Viewer")
	}
}

func TestSeparateXSessionClientsShareIdentityPacingAndKeepOwnCookies(t *testing.T) {
	c, l, clients, fake := xWarmFixture(t, "fixture")
	other := c
	other.LocalAccountID = "other-alias"
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	other.XSession = filepath.Join(dir, "session.json")
	raw, _ := json.Marshal(x.Session{AuthToken: "other-auth", CT0: "other-csrf"})
	if err := localfs.WriteAtomic(other.XSession, raw, true); err != nil {
		t.Fatal(err)
	}
	first, second := &xProfileProof{}, &xProfileProof{}
	if code := xRun(c, l, clients, fake, first); code != "" {
		t.Fatal(code)
	}
	if code := xRun(other, l, clients, fake, second); code != "" {
		t.Fatal(code)
	}
	if v, _ := fake.counts(); v != 4 {
		t.Fatal("the second session skipped its own validation", v)
	}
	a := clients.account(c, c.LocalAccountID, c.XSession, nil).current
	b := clients.account(other, other.LocalAccountID, other.XSession, nil).current
	if a.client == b.client || a.identity.ID != b.identity.ID || a.stamp == b.stamp {
		t.Fatal("sessions were not independently authenticated")
	}
	if !strings.Contains(first.cookies[0], "synthetic-auth") || !strings.Contains(second.cookies[0], "other-auth") || strings.Contains(second.cookies[0], "synthetic-auth") {
		t.Fatal("a client borrowed the other session's cookies")
	}
	// A cooldown on one client is visible on the other; generous later headers
	// from the second session cannot relax it while that window is active.
	limited := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response := xResponse(r, 429, "")
		response.Header.Set("Retry-After", "60")
		return response, nil
	})
	if code := xRun(c, l, clients, fake, limited); code != "x_rate_limited" {
		t.Fatal(code)
	}
	if quota := b.client.RateLimit(); quota.Remaining != 0 || quota.ResetIn() < 59*time.Second {
		t.Fatal("same user's separate session missed its cooldown", quota)
	}
	if a.client.LastRequestAt() != b.client.LastRequestAt() {
		t.Fatal("same user's clients did not share request slots")
	}
	identity := a.identity.ID
	prior := clients.identities[identity]
	clients.Retain(map[string]bool{})
	if clients.identities[identity] != prior || prior.pacing.RateLimit().ResetIn() < 59*time.Second {
		t.Fatal("removing aliases discarded a live provider cooldown")
	}
	// Re-adding the same credential path must attach to the retained domain.
	readded := clients.account(c, "new-alias", c.XSession, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := readded.acquire(ctx, nil, false); err == nil {
		t.Fatal("re-added alias bypassed the shared cooldown")
	}
	if clients.identities[identity] != prior || prior.pacing.RateLimit().ResetIn() < 58*time.Second {
		t.Fatal("re-added alias reset quota state")
	}
}

func TestXIdentityObserverAndAcquireFenceSessionRotation(t *testing.T) {
	c, _, clients, fake := xWarmFixture(t, "fixture")
	var once sync.Once
	entered, release := make(chan struct{}), make(chan struct{})
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/Viewer") {
			once.Do(func() {
				close(entered)
				<-release
			})
		}
		return fake.RoundTrip(r)
	})
	var observed atomic.Int32
	var observedStamp atomic.Value
	clients.ObserveIdentity(func(path string, identity VerifiedXIdentity) {
		observed.Add(1)
		observedStamp.Store(identity.Stamp)
	})
	account := clients.account(c, "main", c.XSession, base)
	result := make(chan *xWarm, 1)
	errors := make(chan error, 1)
	go func() {
		warm, err := account.acquire(context.Background(), nil, false)
		result <- warm
		errors <- err
	}()
	<-entered
	raw, _ := json.Marshal(x.Session{AuthToken: "rotated-auth", CT0: "rotated-csrf"})
	if err := localfs.WriteAtomic(c.XSession, raw, true); err != nil {
		t.Fatal(err)
	}
	currentStamp := XSessionStamp(c.XSession)
	close(release)
	warm, err := <-result, <-errors
	if err != nil || warm.stamp != currentStamp || observed.Load() != 1 || observedStamp.Load() != currentStamp {
		t.Fatal("stale validation escaped its content fence", err, observed.Load())
	}
	if identity, ok := clients.VerifiedIdentity(c.XSession); !ok || identity.Stamp != currentStamp {
		t.Fatal("current identity was not exposed")
	}
	raw, _ = json.Marshal(x.Session{AuthToken: "another-auth", CT0: "another-csrf"})
	if err := localfs.WriteAtomic(c.XSession, raw, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := clients.VerifiedIdentity(c.XSession); ok {
		t.Fatal("exposed identity after credentials changed")
	}
}

func TestXIdentityDomainsBoundedWithoutEvictingActiveReferences(t *testing.T) {
	clients := NewXClients()
	clients.log = nil
	t.Cleanup(clients.Stop)
	a := &xAccount{clients: clients}
	for i := 1; i <= maxXIdentityDomains; i++ {
		id := strconv.Itoa(i)
		if _, err := a.pacingFor(id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.pacingFor("999"); err == nil || len(clients.identities) != maxXIdentityDomains {
		t.Fatal("identity cache exceeded its bound or evicted active domains")
	}
	first := clients.identities["1"]
	release := clients.holdIdentity("1")
	a.mu.Lock()
	a.detachIdentityDomains()
	a.mu.Unlock()
	if _, err := a.pacingFor("999"); err != nil || len(clients.identities) != 2 || clients.identities["1"] != first {
		t.Fatal("expired unused domains were not reclaimed", err, len(clients.identities))
	}
	release()
	if _, err := a.pacingFor("777"); err != nil || len(clients.identities) != 2 || clients.identities["1"] != nil {
		t.Fatal("completed job still pinned its expired identity domain", err)
	}
}

func TestXAcceptedIdentityFenceStopsCredentialRotationBeforeProof(t *testing.T) {
	for _, scenario := range []string{"changed stamp same user", "wrong provider identity", "matching identity"} {
		t.Run(scenario, func(t *testing.T) {
			c, l, clients, fake := xWarmFixture(t, "fixture")
			c.ExpectedXStamp = XSessionStamp(c.XSession)
			c.ExpectedXIdentity = "12"
			switch scenario {
			case "changed stamp same user":
				// The new credentials still authenticate the same provider user.
				// Accepted work remains bound to the exact admitted session.
				raw, _ := json.Marshal(x.Session{AuthToken: "rotated-auth", CT0: "rotated-csrf"})
				if err := localfs.WriteAtomic(c.XSession, raw, true); err != nil {
					t.Fatal(err)
				}
			case "wrong provider identity":
				c.ExpectedXIdentity = "999"
			}
			proof := &xProfileProof{}
			code := xRun(c, l, clients, fake, proof)
			if scenario == "matching identity" {
				if code != "" || proof.proofs.Load() != 1 {
					t.Fatal("matching accepted identity could not serve", code)
				}
			} else if code != "auth_required" || proof.proofs.Load() != 0 {
				t.Fatal("stale accepted credentials spent a proof", code, proof.proofs.Load())
			}
		})
	}
}
