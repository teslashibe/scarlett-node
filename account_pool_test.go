package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func multiPool(t *testing.T) *servicePool {
	t.Helper()
	p := poolFixture(t, "codex", "x_read")
	dir := t.TempDir()
	p.config.StateDir = dir
	p.config.AccountsFile = filepath.Join(dir, "accounts.json")
	p.config.CodexConcurrency = 2
	p.config.XConcurrency = 2
	p.entries["x_read"].capacity = 2
	f := accountFile{Version: 1, Accounts: []providerAccount{}}
	for _, kind := range []string{"codex", "x_read"} {
		for _, id := range []string{"one", "two"} {
			path := filepath.Join(dir, kind+"-"+id)
			if kind == "codex" {
				os.Mkdir(path, 0700)
				os.WriteFile(filepath.Join(path, "auth.json"), []byte(`{"synthetic_fixture":true}`), 0600)
			} else {
				os.WriteFile(path, []byte(`{"auth_token":"synthetic-private-auth","ct0":"synthetic-private-csrf"}`), 0600)
			}
			f.Accounts = append(f.Accounts, providerAccount{id, kind, path, 1})
		}
	}
	saveAccountFixture(t, p, f)
	return p
}
func saveAccountFixture(t *testing.T, p *servicePool, f accountFile) {
	t.Helper()
	raw, e := json.Marshal(f)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeLocalFile(filepath.Dir(p.config.AccountsFile), filepath.Base(p.config.AccountsFile), raw); e != nil {
		t.Fatal(e)
	}
}
func TestBothProviderPoolsSelectOnceAndBoundAggregateCapacity(t *testing.T) {
	p := multiPool(t)
	for _, kind := range []string{"codex", "x_read"} {
		one, ok := p.acquireAccount(kind)
		if !ok {
			t.Fatal("first account unavailable")
		}
		two, ok := p.acquireAccount(kind)
		if !ok || one.id == two.id {
			t.Fatal("distinct accounts not selected")
		}
		if _, ok := p.acquireAccount(kind); ok {
			t.Fatal("aggregate/per-account concurrency exceeded")
		}
		if one.config.LocalAccountID != one.id || two.config.LocalAccountID != two.id {
			t.Fatal("private identity not pinned")
		}
		if kind == "codex" && one.config.CodexHome == two.config.CodexHome || kind == "x_read" && one.config.XSession == two.config.XSession {
			t.Fatal("credential paths shared")
		}
		p.finishAccount(one, "")
		p.finishAccount(two, "")
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	leases := make(chan *accountLease, 30)
	for range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l, ok := p.acquireAccount("codex"); ok {
				wins.Add(1)
				leases <- l
			}
		}()
	}
	wg.Wait()
	close(leases)
	if wins.Load() != 2 {
		t.Fatalf("concurrent claims=%d", wins.Load())
	}
	for l := range leases {
		p.finishAccount(l, "")
	}
	// A service-wide ceiling still applies even when the account limits sum higher.
	p.config.CodexConcurrency = 1
	l, ok := p.acquireAccount("codex")
	if !ok {
		t.Fatal("missing slot")
	}
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("service ceiling exceeded")
	}
	p.finishAccount(l, "")
}
func TestQuotaAndAuthenticationAreAccountLocalPersistedAndDoNotReplay(t *testing.T) {
	p := multiPool(t)
	l, ok := p.acquireAccount("x_read")
	if !ok {
		t.Fatal("missing account")
	}
	original := l.config.XSession
	l.config.AccountCooldown(2 * time.Hour)
	p.finishAccount(l, "x_rate_limited")
	fresh, ok := p.acquireAccount("x_read")
	if !ok || fresh.id == l.id {
		t.Fatal("new job did not use healthy account")
	}
	if l.config.XSession != original {
		t.Fatal("failed job was reassigned")
	}
	p.finishAccount(fresh, "")
	// Restarting or replacing the account file cannot erase a provider reset.
	restarted := newServicePool(p.config)
	r, ok := restarted.acquireAccount("x_read")
	if !ok || r.id == l.id {
		t.Fatal("restart erased quota cooldown")
	}
	restarted.finishAccount(r, "auth_required")
	if _, ok := restarted.acquireAccount("x_read"); ok {
		t.Fatal("auth-required account served work")
	}
	if _, ok := restarted.acquireAccount("codex"); !ok {
		t.Fatal("X failure disabled Codex")
	}
	if e := os.WriteFile(original, []byte(`{"auth_token":"replacement","ct0":"synthetic-csrf"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, ok := restarted.acquireAccount("x_read"); ok {
		t.Fatal("credential replacement erased quota cooldown")
	}
}
func TestRemovalDrainsSelectedSnapshotAndMissingFileFailsClosed(t *testing.T) {
	p := multiPool(t)
	l, ok := p.acquireAccount("codex")
	if !ok {
		t.Fatal("missing account")
	}
	f, e := loadAccounts(p.config.AccountsFile)
	if e != nil {
		t.Fatal(e)
	}
	out := []providerAccount{}
	for _, a := range f.Accounts {
		if a.Service != "codex" || a.ID != l.id {
			out = append(out, a)
		}
	}
	f.Accounts = out
	saveAccountFixture(t, p, f)
	status := p.accountStatus()
	found := false
	for _, s := range status {
		if s.ID == l.id && s.Service == "codex" {
			found = s.State == "draining" && s.InFlight == 1 && s.Capacity == 0
		}
	}
	if !found {
		t.Fatal("removed in-flight account not draining")
	}
	if _, e := os.Stat(filepath.Join(l.config.CodexHome, "auth.json")); e != nil {
		t.Fatal("drain deleted selected credentials")
	}
	other, ok := p.acquireAccount("codex")
	if !ok || other.id == l.id {
		t.Fatal("removed account reselected")
	}
	p.finishAccount(other, "")
	p.finishAccount(l, "")
	for _, s := range p.accountStatus() {
		if s.ID == l.id && s.Service == "codex" {
			t.Fatal("finished removal still active")
		}
	}
	if e := os.Remove(p.config.AccountsFile); e != nil {
		t.Fatal(e)
	}
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("missing explicit configuration resurrected legacy account")
	}
	saveAccountFixture(t, p, f)
	if _, ok := p.acquireAccount("codex"); !ok {
		t.Fatal("valid file did not restore admission")
	}
}
func TestAccountConfigurationPrivacyAndStatusRedaction(t *testing.T) {
	p := multiPool(t)
	raw, e := json.Marshal(p.accountStatus())
	if e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"synthetic-private-auth", "synthetic-private-csrf", p.config.StateDir, "auth.json"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("local status leaked private material")
		}
	}
	heartbeat, _ := json.Marshal(p.health())
	if bytes.Contains(heartbeat, []byte(`"id"`)) || bytes.Contains(heartbeat, []byte("rest_until")) {
		t.Fatal("account identities leaked to coordinator")
	}
	if e := os.Chmod(p.config.AccountsFile, 0644); e != nil {
		t.Fatal(e)
	}
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("public account configuration accepted")
	}
	if e := os.Chmod(p.config.AccountsFile, 0600); e != nil {
		t.Fatal(e)
	}
	if _, ok := p.acquireAccount("codex"); !ok {
		t.Fatal("private configuration did not recover")
	}
	if e := os.WriteFile(p.config.AccountsFile, []byte(`{"version":1,"accounts":[],"secret":"never"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, ok := p.acquireAccount("x_read"); ok {
		t.Fatal("unknown configuration fields accepted")
	}
}
func TestConcurrentSuccessCannotClearSameAccountQuota(t *testing.T) {
	p := multiPool(t)
	f, _ := loadAccounts(p.config.AccountsFile)
	f.Accounts = []providerAccount{f.Accounts[0]}
	f.Accounts[0].Concurrency = 2
	saveAccountFixture(t, p, f)
	one, ok := p.acquireAccount("codex")
	if !ok {
		t.Fatal("missing account")
	}
	two, ok := p.acquireAccount("codex")
	if !ok || one.id != two.id {
		t.Fatal("per-account capacity unavailable")
	}
	p.finishAccount(one, "capacity_unavailable")
	p.finishAccount(two, "")
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("older success cleared quota")
	}
}
func TestCorruptAccountHealthFailsClosed(t *testing.T) {
	p := multiPool(t)
	if e := writeLocalFile(p.config.StateDir, "account-health.json", []byte(`null`)); e != nil {
		t.Fatal(e)
	}
	r := newServicePool(p.config)
	if _, ok := r.acquireAccount("codex"); ok {
		t.Fatal("invalid health state was ignored")
	}
}

func TestExplicitMissingFileAndDuplicateCredentialAliasesFailClosed(t *testing.T) {
	p := multiPool(t)
	p.config.AccountsRequired = true
	os.Remove(p.config.AccountsFile)
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("explicit missing file enabled legacy fallback")
	}
	p = multiPool(t)
	f, e := loadAccounts(p.config.AccountsFile)
	if e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(t.TempDir(), "home-alias")
	if e = os.Symlink(f.Accounts[0].Path, alias); e != nil {
		t.Fatal(e)
	}
	f.Accounts[1].Path = alias
	raw, _ := json.Marshal(f)
	os.WriteFile(p.config.AccountsFile, raw, 0600)
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("duplicate credential inode accepted under another local name")
	}
}

func TestConcurrentResultAndHelperRepairCannotClearAuthentication(t *testing.T) {
	p := multiPool(t)
	f, _ := loadAccounts(p.config.AccountsFile)
	f.Accounts = []providerAccount{f.Accounts[0]}
	f.Accounts[0].Concurrency = 2
	saveAccountFixture(t, p, f)
	one, _ := p.acquireAccount("codex")
	two, _ := p.acquireAccount("codex")
	p.finishAccount(one, "auth_required")
	p.finishAccount(two, "")
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("older success repaired failed authentication")
	}
	os.Chmod(p.config.Prover, 0600)
	p.health()
	os.Chmod(p.config.Prover, 0700)
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("helper installation repaired failed authentication")
	}
}
func TestUnboundedProviderResetRequiresOperatorAttention(t *testing.T) {
	p := multiPool(t)
	l, ok := p.acquireAccount("x_read")
	if !ok {
		t.Fatal("account unavailable")
	}
	l.config.AccountCooldown(31 * 24 * time.Hour)
	p.finishAccount(l, "x_rate_limited")
	for _, s := range p.accountStatus() {
		if s.ID == l.id && s.Service == "x_read" && s.State != "auth_required" {
			t.Fatal("out-of-policy reset resumed after an earlier cooldown")
		}
	}
}

func TestManagedAdmissionNeverResurrectsLegacyAfterRestart(t *testing.T) {
	p := multiPool(t)
	p.health()
	if e := os.Remove(p.config.AccountsFile); e != nil {
		t.Fatal(e)
	}
	restarted := newServicePool(p.config)
	if _, ok := restarted.acquireAccount("codex"); ok {
		t.Fatal("restart resurrected legacy Codex home after managed file removal")
	}
	if _, ok := restarted.acquireAccount("x_read"); ok {
		t.Fatal("restart resurrected legacy X session")
	}
}

// These are the coordinator's typed report invariants, independent of account
// selection or private account-status capacity (which is zero while draining).
func assertTypedHeartbeatInFlight(t *testing.T, p *servicePool, kind, state string, wantFlight int) {
	t.Helper()
	total := 0
	allBlocked := true
	found := false
	for _, h := range p.health() {
		if h.InFlight > h.Capacity || h.InFlight < 0 || h.Capacity < 0 {
			t.Fatal("invalid typed in-flight capacity", h)
		}
		switch h.State {
		case "configured", "ready":
			allBlocked = false
			if h.Capacity == 0 {
				t.Fatal("healthy typed service has zero capacity", h)
			}
		case "not_added", "auth_required", "exhausted", "unreachable":
		default:
			t.Fatal("unknown typed service state", h)
		}
		if h.State == "not_added" && (h.Capacity != 0 || h.InFlight != 0) {
			t.Fatal("disabled service retains work", h)
		}
		if h.Kind == kind {
			found = true
			if h.State != state || h.InFlight != wantFlight || h.Capacity != wantFlight {
				t.Fatal("blocked/draining work lost typed capacity", h)
			}
		}
		total += h.Capacity
	}
	if !found || total == 0 && !allBlocked {
		t.Fatal("invalid aggregate zero capacity")
	}
}
func TestTypedCooldownAndAuthenticationRetainAnotherAcceptedSlot(t *testing.T) {
	for _, code := range []string{"auth_required", "capacity_unavailable", "x_rate_limited"} {
		t.Run(code, func(t *testing.T) {
			p := multiPool(t)
			kind := "codex"
			if code == "x_rate_limited" {
				kind = "x_read"
			}
			f, _ := loadAccounts(p.config.AccountsFile)
			for _, a := range f.Accounts {
				if a.Service == kind && a.ID == "one" {
					a.Concurrency = 2
					f.Accounts = []providerAccount{a}
					break
				}
			}
			saveAccountFixture(t, p, f)
			one, ok := p.acquireAccount(kind)
			if !ok {
				t.Fatal("missing first accepted slot")
			}
			two, ok := p.acquireAccount(kind)
			if !ok {
				t.Fatal("missing second accepted slot")
			}
			p.finishAccount(one, code)
			state := "exhausted"
			if code == "auth_required" {
				state = "auth_required"
			}
			assertTypedHeartbeatInFlight(t, p, kind, state, 1)
			if _, ok := p.acquireAccount(kind); ok {
				t.Fatal("blocked account accepted fresh work")
			}
			p.finishAccount(two, "")
			assertTypedHeartbeatInFlight(t, p, kind, state, 0)
		})
	}
}
func TestTypedSoleAccountRemovalAndInvalidFileRetainAcceptedSlots(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed", true: "invalid-file"}[invalid], func(t *testing.T) {
			p := multiPool(t)
			f, _ := loadAccounts(p.config.AccountsFile)
			f.Accounts = []providerAccount{f.Accounts[0]}
			f.Accounts[0].Concurrency = 2
			saveAccountFixture(t, p, f)
			one, ok := p.acquireAccount("codex")
			if !ok {
				t.Fatal("missing first slot")
			}
			two, ok := p.acquireAccount("codex")
			if !ok {
				t.Fatal("missing second slot")
			}
			state := "auth_required"
			if invalid {
				os.WriteFile(p.config.AccountsFile, []byte(`{"invalid":true}`), 0600)
				state = "unreachable"
			} else {
				f.Accounts = []providerAccount{}
				saveAccountFixture(t, p, f)
			}
			assertTypedHeartbeatInFlight(t, p, "codex", state, 2)
			if _, ok := p.acquireAccount("codex"); ok {
				t.Fatal("removed/invalid account accepted fresh work")
			}
			p.finishAccount(one, "")
			assertTypedHeartbeatInFlight(t, p, "codex", state, 1)
			p.finishAccount(two, "")
			assertTypedHeartbeatInFlight(t, p, "codex", state, 0)
		})
	}
}
func TestTypedLegacyToManagedTransitionRetainsSelectedLegacySlot(t *testing.T) {
	p := poolFixture(t, "codex")
	p.config.StateDir = t.TempDir()
	p.config.AccountsFile = filepath.Join(p.config.StateDir, "accounts.json")
	selected, ok := p.acquireAccount("codex")
	if !ok {
		t.Fatal("missing legacy slot")
	}
	saveAccountFixture(t, p, accountFile{Version: 1, Accounts: []providerAccount{}})
	assertTypedHeartbeatInFlight(t, p, "codex", "auth_required", 1)
	if selected.id != "legacy" {
		t.Fatal("selected legacy identity changed")
	}
	p.finishAccount(selected, "")
	assertTypedHeartbeatInFlight(t, p, "codex", "auth_required", 0)
}
