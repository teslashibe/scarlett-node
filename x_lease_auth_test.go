package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

func xLeasePool(t *testing.T, managed bool) *servicePool {
	t.Helper()
	if !managed {
		p := poolFixture(t, "x_read")
		p.config.XConcurrency = 2
		p.entries["x_read"].capacity = 2
		return p
	}
	p := multiPool(t)
	f, err := loadAccounts(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range f.Accounts {
		if a.Service == "x_read" {
			a.Concurrency = 2
			f.Accounts = []providerAccount{a}
			break
		}
	}
	saveAccountFixture(t, p, f)
	return p
}

func assertXLeaseState(t *testing.T, p *servicePool, l *accountLease, state string, inFlight int) {
	t.Helper()
	healthKind(t, p, "x_read") // Refresh aggregate and credential metadata.
	p.mu.Lock()
	defer p.mu.Unlock()
	if l.account.entry.state != state || l.account.entry.inFlight != inFlight || p.entries["x_read"].inFlight != inFlight {
		t.Fatalf("account state=%s inFlight=%d aggregate=%d; want %s/%d", l.account.entry.state, l.account.entry.inFlight, p.entries["x_read"].inFlight, state, inFlight)
	}
}

func TestXLeaseAuthenticationUsesAdmittedCredentialStamp(t *testing.T) {
	for _, managed := range []bool{false, true} {
		mode := map[bool]string{false: "legacy", true: "managed"}[managed]
		for _, scenario := range []string{"replacement", "replacement-before-health-refresh", "unchanged", "identical-rewrite", "invalid-replacement"} {
			t.Run(mode+"/"+scenario, func(t *testing.T) {
				p := xLeasePool(t, managed)
				l, ok := p.acquireAccount("x_read")
				if !ok || l.xStamp == "" {
					t.Fatal("valid credential was not captured at admission")
				}
				if l.xStamp != worker.XSessionStamp(l.config.XSession) {
					t.Fatal("lease stamp does not describe admitted credentials")
				}
				want := "auth_required"
				var raw []byte
				switch scenario {
				case "replacement", "replacement-before-health-refresh":
					raw = []byte(`{"auth_token":"new-verified-synthetic-session","ct0":"new-synthetic-csrf"}`)
					want = "configured"
				case "identical-rewrite":
					var err error
					raw, err = os.ReadFile(l.config.XSession)
					if err != nil {
						t.Fatal(err)
					}
				case "invalid-replacement":
					raw = []byte(`{"auth_token":"missing-csrf"}`)
				}
				if raw != nil {
					if err := localfs.WriteAtomic(l.config.XSession, raw, true); err != nil {
						t.Fatal(err)
					}
					if managed && want == "configured" {
						saveVerifiedXFixture(t, p, l.config.XSession, l.xIdentity, "fixture_one")
					}
				}
				if scenario != "replacement-before-health-refresh" {
					healthKind(t, p, "x_read")
				}
				p.finishAccount(l, "auth_required")
				assertXLeaseState(t, p, l, want, 0)
				if want == "configured" {
					fresh, ok := p.acquireAccount("x_read")
					if !ok || fresh.xStamp == l.xStamp {
						t.Fatal("fresh credential was not admitted with its own stamp")
					}
					p.finishAccount(fresh, "auth_required")
					assertXLeaseState(t, p, fresh, "auth_required", 0)
				} else if _, ok := p.acquireAccount("x_read"); ok {
					t.Fatal("refused or locally invalid credentials admitted work")
				}
			})
		}
	}
}

func TestXLeaseAuthenticationCannotSettleRelocatedManagedAccount(t *testing.T) {
	p := xLeasePool(t, true)
	l, ok := p.acquireAccount("x_read")
	if !ok {
		t.Fatal("missing old lease")
	}
	raw, err := os.ReadFile(l.config.XSession)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(l.config.XSession), "relocated-session.json")
	if err := localfs.WriteAtomic(path, raw, false); err != nil {
		t.Fatal(err)
	}
	f, err := loadAccounts(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	f.Accounts[0].Path = path
	saveAccountFixture(t, p, f)
	saveVerifiedXFixture(t, p, path, l.xIdentity, "fixture_one")
	healthKind(t, p, "x_read")
	if _, ok := p.acquireAccount("x_read"); ok {
		t.Fatal("relocated account admitted before old work drained")
	}
	p.finishAccount(l, "auth_required")
	assertXLeaseState(t, p, l, "configured", 0)
	fresh, ok := p.acquireAccount("x_read")
	if !ok || fresh.config.XSession != path || fresh.xStamp != l.xStamp {
		t.Fatal("new path with identical bytes was not independently admitted")
	}
	p.finishAccount(fresh, "auth_required")
	assertXLeaseState(t, p, fresh, "auth_required", 0)
}

func TestXLeaseReplacementRetainsAccountWideQuota(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, beforeReplacement := range []bool{false, true} {
			name := map[bool]string{false: "legacy", true: "managed"}[managed] + "/" + map[bool]string{false: "quota-after-replacement", true: "quota-before-replacement"}[beforeReplacement]
			t.Run(name, func(t *testing.T) {
				p := xLeasePool(t, managed)
				older, ok := p.acquireAccount("x_read")
				if !ok {
					t.Fatal("old lease unavailable")
				}
				limited, ok := p.acquireAccount("x_read")
				if !ok {
					t.Fatal("second lease unavailable")
				}
				var reset time.Time
				quota := func() {
					limited.config.AccountCooldown(2 * time.Hour)
					p.finishAccount(limited, "x_rate_limited")
					p.mu.Lock()
					reset = limited.account.entry.restUntil
					p.mu.Unlock()
				}
				if beforeReplacement {
					quota()
				}
				if err := localfs.WriteAtomic(older.config.XSession, []byte(`{"auth_token":"replacement-synthetic-auth","ct0":"replacement-synthetic-csrf"}`), true); err != nil {
					t.Fatal(err)
				}
				if managed {
					saveVerifiedXFixture(t, p, older.config.XSession, older.xIdentity, "fixture_one")
				}
				healthKind(t, p, "x_read")
				if !beforeReplacement {
					quota()
				}
				// A later short reset cannot shorten the authoritative account cooldown.
				older.config.AccountCooldown(time.Minute)
				p.finishAccount(older, "auth_required")
				assertXLeaseState(t, p, older, "exhausted", 0)
				p.mu.Lock()
				entry := *older.account.entry
				p.mu.Unlock()
				if entry.lastError != "x_rate_limited" || !entry.restUntil.Equal(reset) {
					t.Fatal("stale authentication result lost quota state or maximum reset")
				}
				if _, ok := p.acquireAccount("x_read"); ok {
					t.Fatal("replacement bypassed account-wide quota")
				}
				restarted := newServicePool(p.config)
				for _, a := range restarted.accountStatus() {
					if a.Service == "x_read" && (a.State != "exhausted" || !a.RestUntil.Equal(reset)) {
						t.Fatal("restart lost account-wide quota")
					}
				}
			})
		}
	}
}
