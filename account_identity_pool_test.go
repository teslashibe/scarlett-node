package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

func xOnlyRegistry(t *testing.T, p *servicePool) accountFile {
	t.Helper()
	f, err := loadAccounts(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	kept := make([]providerAccount, 0, 2)
	for _, a := range f.Accounts {
		if a.Service == "x_read" {
			kept = append(kept, a)
		}
	}
	f.Accounts = kept
	return f
}

func TestVerifiedXAliasesShareOneAdmissionLane(t *testing.T) {
	p := multiPool(t)
	f := xOnlyRegistry(t, p)
	// Different valid credentials and different local names describe one
	// authenticated user. A more permissive alias cannot enlarge its lane.
	f.Accounts[0].Concurrency = 2
	saveAccountFixture(t, p, f)
	if err := localfs.WriteAtomic(f.Accounts[1].Path, []byte(`{"auth_token":"same-user-second-session","ct0":"same-user-second-csrf"}`), true); err != nil {
		t.Fatal(err)
	}
	saveVerifiedXFixture(t, p, f.Accounts[1].Path, "123", "fixture_one")
	statuses := p.accountStatus()
	if len(statuses) != 2 || statuses[0].Capacity != 1 || statuses[1].State != "duplicate_account" || statuses[1].Capacity != 0 {
		t.Fatalf("duplicate alias status: %+v", statuses)
	}
	if !validAccountStatuses(statuses) {
		t.Fatal("bounded local duplicate status was rejected")
	}
	h := healthKind(t, p, "x_read")
	if h.Capacity != 1 || h.InFlight != 0 {
		t.Fatalf("same user advertised more than one lane: %+v", h)
	}
	leases := make(chan *accountLease, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if lease, ok := p.acquireAccount("x_read"); ok {
				leases <- lease
			}
		}()
	}
	wg.Wait()
	close(leases)
	if len(leases) != 1 {
		t.Fatalf("same-user concurrent admissions=%d, want 1", len(leases))
	}
	for lease := range leases {
		if lease.xIdentity != "123" || lease.config.XSession != f.Accounts[0].Path {
			t.Fatal("lease was not pinned to canonical authenticated session")
		}
		p.finishAccount(lease, "")
	}
	// Private aliases/verified handles stay out of the service heartbeat.
	raw, err := json.Marshal(p.health())
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"123", "fixture_one", f.Accounts[0].Path, "duplicate_account"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("identity metadata leaked into service heartbeat")
		}
	}
}

func TestRemovedXAliasStillOccupiesIdentityWhileDraining(t *testing.T) {
	p := multiPool(t)
	f := xOnlyRegistry(t, p)
	saveAccountFixture(t, p, f)
	if err := localfs.WriteAtomic(f.Accounts[1].Path, []byte(`{"auth_token":"same-user-second-session","ct0":"same-user-second-csrf"}`), true); err != nil {
		t.Fatal(err)
	}
	saveVerifiedXFixture(t, p, f.Accounts[1].Path, "123", "fixture_one")
	lease, ok := p.acquireAccount("x_read")
	if !ok || lease.id != "one" {
		t.Fatal("canonical session unavailable")
	}
	f.Accounts = f.Accounts[1:]
	saveAccountFixture(t, p, f)
	if _, ok := p.acquireAccount("x_read"); ok {
		t.Fatal("alternate alias bypassed removed account's accepted lane")
	}
	statuses := p.accountStatus()
	if len(statuses) != 2 || statuses[0].State != "draining" || statuses[0].InFlight != 1 || statuses[0].Capacity != 0 {
		t.Fatalf("accepted removed session was not visible as draining: %+v", statuses)
	}
	if _, err := os.Stat(lease.config.XSession); err != nil {
		t.Fatal("removal destroyed selected session snapshot:", err)
	}
	p.finishAccount(lease, "")
	fresh, ok := p.acquireAccount("x_read")
	if !ok || fresh.id != "two" || fresh.xIdentity != "123" {
		t.Fatal("retained alias unavailable after accepted work drained")
	}
	p.finishAccount(fresh, "")
}

func TestManagedXRequiresCurrentVerifiedIdentity(t *testing.T) {
	for _, mutation := range []string{"missing", "stale", "corrupt", "public"} {
		t.Run(mutation, func(t *testing.T) {
			p := multiPool(t)
			f := xOnlyRegistry(t, p)
			switch mutation {
			case "missing":
				if err := os.Remove(xIdentitiesPath(p.config.StateDir)); err != nil {
					t.Fatal(err)
				}
			case "stale":
				for _, a := range f.Accounts {
					if err := localfs.WriteAtomic(a.Path, []byte(`{"auth_token":"rotated-synthetic-auth","ct0":"rotated-synthetic-csrf"}`), true); err != nil {
						t.Fatal(err)
					}
				}
			case "corrupt":
				if err := writeLocalFile(p.config.StateDir, "x-identities.json", []byte(`null`)); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := makeFixturePublic(xIdentitiesPath(p.config.StateDir)); err != nil {
					t.Fatal(err)
				}
			}
			if _, ok := p.acquireAccount("x_read"); ok {
				t.Fatal("unverified identity admitted X work")
			}
			if h := healthKind(t, p, "x_read"); h.Capacity != 0 || h.InFlight != 0 {
				t.Fatalf("unverified identity advertised X supply: %+v", h)
			}
			codex, ok := p.acquireAccount("codex")
			if !ok {
				t.Fatal("X metadata failure disabled an independent Codex account")
			}
			p.finishAccount(codex, "")
			for _, s := range p.accountStatus() {
				if s.Service == "x_read" && s.Capacity != 0 {
					t.Fatalf("unverified local status retained capacity: %+v", s)
				}
			}
		})
	}
}

func TestOldXAttemptCannotPoisonReplacementUser(t *testing.T) {
	for _, outcome := range []string{"auth_required", "x_rate_limited"} {
		for _, restBeforeReplacement := range []bool{false, true} {
			name := outcome + "/" + map[bool]string{false: "late-reset", true: "known-reset"}[restBeforeReplacement]
			t.Run(name, func(t *testing.T) {
				p := xLeasePool(t, true)
				old, ok := p.acquireAccount("x_read")
				if !ok {
					t.Fatal("original session unavailable")
				}
				if restBeforeReplacement {
					old.config.AccountCooldown(2 * time.Hour)
				}
				if err := localfs.WriteAtomic(old.config.XSession, []byte(`{"auth_token":"different-user-synthetic-auth","ct0":"different-user-synthetic-csrf"}`), true); err != nil {
					t.Fatal(err)
				}
				saveVerifiedXFixture(t, p, old.config.XSession, "789", "new_fixture")
				// Exercise the replacement while the original identity is still
				// pinned by a job, before its delayed result reaches the pool.
				_ = p.accountStatus()
				if !restBeforeReplacement {
					old.config.AccountCooldown(2 * time.Hour)
				}
				p.finishAccount(old, outcome)
				fresh, ok := p.acquireAccount("x_read")
				if !ok || fresh.xIdentity != "789" || fresh.xStamp == old.xStamp {
					t.Fatalf("old identity result poisoned new authenticated user: %+v", p.accountStatus())
				}
				p.finishAccount(fresh, "")
				restarted := newServicePool(p.config)
				fresh, ok = restarted.acquireAccount("x_read")
				if !ok || fresh.xIdentity != "789" {
					t.Fatalf("restart inherited another user's cooldown: %+v", restarted.accountStatus())
				}
				restarted.finishAccount(fresh, "")
			})
		}
	}
}

func TestIdentityCooldownSurvivesRemovalNewAliasAndRestart(t *testing.T) {
	p := xLeasePool(t, true)
	old, ok := p.acquireAccount("x_read")
	if !ok {
		t.Fatal("original session unavailable")
	}
	old.config.AccountCooldown(2 * time.Hour)
	p.finishAccount(old, "x_rate_limited")
	reset := old.account.entry.restUntil
	f := xOnlyRegistry(t, p)
	f.Accounts = nil
	saveAccountFixture(t, p, f)
	_ = p.accountStatus()
	path := filepath.Join(p.config.StateDir, "replacement-session.json")
	if err := writeLocalFile(p.config.StateDir, filepath.Base(path), []byte(`{"auth_token":"reauthenticated-synthetic-auth","ct0":"reauthenticated-synthetic-csrf"}`)); err != nil {
		t.Fatal(err)
	}
	f.Accounts = []providerAccount{{ID: "replacement", Service: "x_read", Path: path, Concurrency: 1}}
	saveAccountFixture(t, p, f)
	saveVerifiedXFixture(t, p, path, old.xIdentity, "fixture_one")
	for _, pool := range []*servicePool{p, newServicePool(p.config)} {
		if _, ok := pool.acquireAccount("x_read"); ok {
			t.Fatal("same authenticated user bypassed cooldown under a new local nickname")
		}
		statuses := pool.accountStatus()
		if len(statuses) != 1 || statuses[0].State != "exhausted" || !statuses[0].RestUntil.Equal(reset) {
			t.Fatalf("identity cooldown was lost or shortened: %+v, expected %v", statuses, reset)
		}
	}
}

func TestDelayedIdentityValidationCannotResurrectRemovedAccount(t *testing.T) {
	p := xLeasePool(t, true)
	f := xOnlyRegistry(t, p)
	path := f.Accounts[0].Path
	identity := worker.VerifiedXIdentity{ID: "123", Username: "fixture_one", Stamp: worker.XSessionStamp(path)}
	f.Accounts = nil
	saveAccountFixture(t, p, f)
	if err := os.Remove(xIdentitiesPath(p.config.StateDir)); err != nil {
		t.Fatal(err)
	}
	p.xIdentityValidated(path, identity)
	if _, err := os.Stat(xIdentitiesPath(p.config.StateDir)); !os.IsNotExist(err) {
		t.Fatal("late warm result persisted removed account identity")
	}
	if statuses := p.accountStatus(); len(statuses) != 0 {
		t.Fatalf("late warm result resurrected removed account: %+v", statuses)
	}
}

func TestUnknownLegacyXAttemptDrainsBeforeManagedIdentityAdmission(t *testing.T) {
	p := poolFixture(t, "x_read")
	p.config.XConcurrency = 2
	p.entries["x_read"].capacity = 2
	old, ok := p.acquireAccount("x_read")
	if !ok || old.xIdentity != "" {
		t.Fatal("fixture must start with an accepted, unverified legacy session")
	}
	path := filepath.Join(p.config.StateDir, "managed-session.json")
	if err := writeLocalFile(p.config.StateDir, filepath.Base(path), []byte(`{"auth_token":"managed-synthetic-auth","ct0":"managed-synthetic-csrf"}`)); err != nil {
		t.Fatal(err)
	}
	saveAccountFixture(t, p, accountFile{Version: 1, Accounts: []providerAccount{{ID: "managed", Service: "x_read", Path: path, Concurrency: 1}}})
	saveVerifiedXFixture(t, p, path, "123", "fixture_one")
	if _, ok := p.acquireAccount("x_read"); ok {
		t.Fatal("unknown legacy identity allowed a potentially duplicate managed lane")
	}
	p.finishAccount(old, "")
	managed, ok := p.acquireAccount("x_read")
	if !ok || managed.xIdentity != "123" {
		t.Fatal("verified managed account did not become usable after legacy drain")
	}
	p.finishAccount(managed, "")
}

func TestUnchangedIdentityObservationDoesNotRewriteMetadata(t *testing.T) {
	p := xLeasePool(t, true)
	f := xOnlyRegistry(t, p)
	identity, err := verifiedXIdentity(p.config.StateDir, f.Accounts[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	path := xIdentitiesPath(p.config.StateDir)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(path, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	p.xIdentityValidated(f.Accounts[0].Path, identity)
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || !stat.ModTime().Equal(fixed) {
		t.Fatal("unchanged keeper identity observation rewrote private metadata")
	}
}
