package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

func eligibilityCount(t *testing.T, value *int) int {
	t.Helper()
	if value == nil {
		t.Fatal("missing aggregate readiness count")
	}
	return *value
}

func eligibilityOperation(t *testing.T, h coordinator.ServiceHealth, operation string) coordinator.OperationAvailability {
	t.Helper()
	for _, hint := range h.OperationAvailability {
		if hint.Operation == operation {
			return hint
		}
	}
	t.Fatalf("missing %s readiness hint", operation)
	return coordinator.OperationAvailability{}
}

func eligibilityOffer() coordinator.Lease {
	l := testLease()
	l.ServiceType, l.AcceptanceRequired = "x_read", true
	l.JobID = "00000000-0000-4000-8000-000000000001"
	l.Attempt = "00000000-0000-4000-8000-000000000002"
	l.Fence = "00000000-0000-4000-8000-000000000003"
	l.SettlementDeadline = l.LeaseDeadline
	l.SignedJobID, l.RequestSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
	l.ModelID, l.Prompt, l.MaxInputTokens, l.MaxOutputTokens = "", "", 0, 0
	l.XRequest = &coordinator.XRequest{Operation: "search", Query: "synthetic", Count: 1, Pages: 1}
	return l
}

func TestAccountEligibilitySelectsDistinctReadyIdentity(t *testing.T) {
	p := multiPool(t)
	saveAccountFixture(t, p, xOnlyRegistry(t, p))
	next := time.Now().Add(time.Minute)
	p.xEligibility = func(id, operation string, now time.Time) time.Time {
		if id == "123" {
			return next
		}
		return now
	}
	h := healthKind(t, p, "x_read")
	if h.Capacity != 1 || eligibilityCount(t, h.RunnableCapacity) != 1 || eligibilityCount(t, h.ActiveAccounts) != 2 || eligibilityCount(t, h.ReadyAccounts) != 1 || eligibilityCount(t, h.CoolingAccounts) != 1 || h.NextReadyAt == nil || !h.NextReadyAt.Equal(next) {
		t.Fatalf("distinct-identity readiness: %+v", h)
	}
	lease, ok := p.acquireAccount("x_read", "search")
	if !ok || lease.xIdentity != "456" || lease.id != "two" {
		t.Fatal("exact-operation admission selected the cooling identity")
	}
	defer p.finishAccount(lease, "")
	if _, ok := p.acquireAccount("x_read", "search"); ok {
		t.Fatal("a busy ready account or cooling account supplied another slot")
	}
	h = healthKind(t, p, "x_read")
	if h.InFlight != 1 || h.Capacity != 1 || eligibilityCount(t, h.RunnableCapacity) != 0 || eligibilityCount(t, h.ActiveAccounts) != 2 {
		t.Fatalf("busy usable identity disappeared from active supply: %+v", h)
	}
}

func TestAccountEligibilityOperationHintsOverlapWithoutGenericGrant(t *testing.T) {
	t.Run("search-only", func(t *testing.T) {
		p := multiPool(t)
		f := xOnlyRegistry(t, p)
		f.Accounts = f.Accounts[:1]
		saveAccountFixture(t, p, f)
		next := time.Now().Add(time.Minute)
		p.xEligibility = func(id, operation string, now time.Time) time.Time {
			if operation == "search" {
				return now
			}
			return next
		}
		h := healthKind(t, p, "x_read")
		if h.Capacity != 0 || eligibilityCount(t, h.RunnableCapacity) != 0 || eligibilityCount(t, h.ReadyAccounts) != 1 || eligibilityOperation(t, h, "search").RunnableCapacity != 1 || eligibilityOperation(t, h, "profile").RunnableCapacity != 0 {
			t.Fatalf("search-only readiness granted another operation or generic capacity: %+v", h)
		}
		if _, ok := p.acquireAccount("x_read"); ok {
			t.Fatal("search-only readiness granted unspecified work")
		}
		lease, ok := p.acquireAccount("x_read", "search")
		if !ok {
			t.Fatal("search-only account declined its eligible operation")
		}
		p.finishAccount(lease, "")
	})

	p := multiPool(t)
	f := xOnlyRegistry(t, p)
	f.Accounts = f.Accounts[:1]
	saveAccountFixture(t, p, f)
	p.config.XConcurrency = 1
	next := time.Now().Add(time.Minute)
	p.xEligibility = func(id, operation string, now time.Time) time.Time {
		if operation == "search" || operation == "profile" {
			return now
		}
		return next
	}
	h := healthKind(t, p, "x_read")
	if h.Capacity != 0 || eligibilityCount(t, h.RunnableCapacity) != 0 || eligibilityCount(t, h.ConfiguredCapacity) != 1 || eligibilityCount(t, h.ReadyAccounts) != 1 || eligibilityCount(t, h.CoolingAccounts) != 0 {
		t.Fatalf("any-operation telemetry granted generic capacity: %+v", h)
	}
	for _, operation := range []string{"search", "profile"} {
		if eligibilityOperation(t, h, operation).RunnableCapacity != 1 {
			t.Fatalf("eligible %s lane was not advertised", operation)
		}
	}
	for _, operation := range []string{"post", "thread"} {
		if eligibilityOperation(t, h, operation).RunnableCapacity != 0 {
			t.Fatalf("cooling %s lane was advertised runnable", operation)
		}
	}
	if _, ok := p.acquireAccount("x_read"); ok {
		t.Fatal("operation-specific readiness granted an unspecified operation")
	}
	if _, ok := p.acquireAccount("x_read", "post"); ok {
		t.Fatal("search/profile readiness granted a cooling post operation")
	}
	lease, ok := p.acquireAccount("x_read", "search")
	if !ok || lease.xIdentity != "123" {
		t.Fatal("eligible exact search operation was not acquired")
	}
	defer p.finishAccount(lease, "")
	if _, ok := p.acquireAccount("x_read", "profile"); ok {
		t.Fatal("overlapping operation hints were added into two physical slots")
	}
}

func TestAccountEligibilityHealthDoesNotReserveOrRewriteState(t *testing.T) {
	p := multiPool(t)
	saveAccountFixture(t, p, xOnlyRegistry(t, p))
	next := time.Now().Add(time.Minute)
	var inspected atomic.Int32
	p.xEligibility = func(id, operation string, now time.Time) time.Time {
		inspected.Add(1)
		if id == "123" {
			return next
		}
		return now
	}
	_ = p.health() // Initialize the private fixture's pool before the comparison.
	beforeRegistry, err := os.ReadFile(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	beforeIdentities, err := os.ReadFile(xIdentitiesPath(p.config.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	beforeRegistryInfo, err := os.Stat(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	beforeIdentitiesInfo, err := os.Stat(xIdentitiesPath(p.config.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	beforeNext := map[string]int{}
	for kind, position := range p.next {
		beforeNext[kind] = position
	}
	beforeHealth, err := json.Marshal(p.health())
	if err != nil {
		t.Fatal(err)
	}
	signals := make(chan struct{}, 1)
	p.availabilityChanges = signals
	for range 25 {
		got, err := json.Marshal(p.health())
		if err != nil || !bytes.Equal(got, beforeHealth) {
			t.Fatal("pure health inspection changed readiness or occupied capacity", err)
		}
		_ = p.accountStatus()
	}
	afterRegistry, err := os.ReadFile(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	afterIdentities, err := os.ReadFile(xIdentitiesPath(p.config.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	afterRegistryInfo, err := os.Stat(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	afterIdentitiesInfo, err := os.Stat(xIdentitiesPath(p.config.StateDir))
	if err != nil {
		t.Fatal(err)
	}
	if inspected.Load() == 0 || !bytes.Equal(beforeRegistry, afterRegistry) || !bytes.Equal(beforeIdentities, afterIdentities) || !reflect.DeepEqual(beforeNext, p.next) || len(p.xInFlight) != 0 || len(p.activeCoordinatorLeases) != 0 || len(signals) != 0 {
		t.Fatal("health inspection reserved work, signalled a change, or rewrote registrations")
	}
	if !os.SameFile(beforeRegistryInfo, afterRegistryInfo) || !os.SameFile(beforeIdentitiesInfo, afterIdentitiesInfo) || !beforeRegistryInfo.ModTime().Equal(afterRegistryInfo.ModTime()) || !beforeIdentitiesInfo.ModTime().Equal(afterIdentitiesInfo.ModTime()) {
		t.Fatal("pure health inspection rewrote unchanged private metadata")
	}
	for _, account := range p.accounts {
		if account.entry.inFlight != 0 || len(account.xLeases) != 0 {
			t.Fatal("health inspection acquired an account")
		}
	}
}

func TestAccountEligibilityQuotaResetPersistsExactDeadline(t *testing.T) {
	p := xLeasePool(t, true)
	lease, ok := p.acquireAccount("x_read", "search")
	if !ok || lease.config.AccountQuotaReset == nil {
		t.Fatal("missing authoritative-reset callback")
	}
	reset := time.Now().Add(2 * time.Minute)
	until := reset.Add(50 * time.Millisecond)
	lease.config.AccountQuotaReset(reset)
	lease.config.AccountQuotaReset(reset.Add(-time.Minute))
	if !lease.quotaUntil.Equal(until) || !lease.account.entry.restUntil.Equal(until) {
		t.Fatal("known reset was shortened or replaced by a fallback before report completion")
	}
	p.finishAccount(lease, "x_rate_limited")
	for _, current := range []*servicePool{p, newServicePool(p.config)} {
		h := healthKind(t, current, "x_read")
		statuses := current.accountStatus()
		if len(statuses) != 1 || !statuses[0].RestUntil.Equal(until) || h.NextReadyAt == nil || !h.NextReadyAt.Equal(until) {
			t.Fatalf("callback/report/restart lost exact reset or imposed fifteen minutes: %+v %+v", h, statuses)
		}
		if _, ok := current.acquireAccount("x_read", "search"); ok {
			t.Fatal("known reset allowed premature admission")
		}
	}
}

func TestAccountEligibilityUnknownCooldownKeepsFallback(t *testing.T) {
	p := xLeasePool(t, true)
	lease, ok := p.acquireAccount("x_read", "search")
	if !ok {
		t.Fatal("missing selected account")
	}
	started := time.Now()
	lease.config.AccountCooldown(time.Minute)
	p.finishAccount(lease, "x_rate_limited")
	for _, current := range []*servicePool{p, newServicePool(p.config)} {
		statuses := current.accountStatus()
		if len(statuses) != 1 || statuses[0].RestUntil.Before(started.Add(15*time.Minute)) || statuses[0].RestUntil.After(time.Now().Add(15*time.Minute+time.Second)) {
			t.Fatalf("unknown cooldown did not retain its bounded fifteen-minute fallback: %+v", statuses)
		}
		if _, ok := current.acquireAccount("x_read", "search"); ok {
			t.Fatal("unknown cooldown was lost at completion or restart")
		}
	}
}

func TestAccountEligibilityRemovedAliasKeepsIdentityCooldown(t *testing.T) {
	p := multiPool(t)
	f := xOnlyRegistry(t, p)
	saveAccountFixture(t, p, f)
	if err := writePrivateFixture(f.Accounts[1].Path, []byte(`{"auth_token":"same-user-alias-synthetic-auth","ct0":"same-user-alias-synthetic-csrf"}`), 0600); err != nil {
		t.Fatal(err)
	}
	saveVerifiedXFixture(t, p, f.Accounts[1].Path, "123", "fixture_one")
	lease, ok := p.acquireAccount("x_read", "search")
	if !ok || lease.id != "one" || lease.xIdentity != "123" {
		t.Fatal("canonical alias was not selected")
	}
	reset := time.Now().Add(2 * time.Minute)
	until := reset.Add(50 * time.Millisecond)
	lease.config.AccountQuotaReset(reset)
	f.Accounts = f.Accounts[1:]
	saveAccountFixture(t, p, f)
	h := healthKind(t, p, "x_read")
	if h.InFlight != 1 || eligibilityCount(t, h.ActiveAccounts) != 1 {
		t.Fatalf("removal lost accepted occupancy or counted the removed registration as active: %+v", h)
	}
	if _, ok := p.acquireAccount("x_read", "search"); ok {
		t.Fatal("retained alias bypassed the removed account's occupied identity")
	}
	p.finishAccount(lease, "x_rate_limited")
	for _, current := range []*servicePool{p, newServicePool(p.config)} {
		statuses := current.accountStatus()
		if len(statuses) != 1 || statuses[0].ID != "two" || !statuses[0].RestUntil.Equal(until) {
			t.Fatalf("retained alias/restart did not inherit canonical quota: %+v", statuses)
		}
		if _, ok := current.acquireAccount("x_read", "search"); ok {
			t.Fatal("removal or restart reset canonical quota")
		}
	}
}

func TestAccountEligibilityFinalCheckPreservesSelectedFence(t *testing.T) {
	for _, mutation := range []string{"quota", "session"} {
		t.Run(mutation, func(t *testing.T) {
			p := multiPool(t)
			saveAccountFixture(t, p, xOnlyRegistry(t, p))
			var cooling atomic.Bool
			next := time.Now().Add(time.Minute)
			p.xEligibility = func(id, operation string, now time.Time) time.Time {
				if cooling.Load() && id == "123" {
					return next
				}
				return now
			}
			lease, ok := p.acquireAccount("x_read", "search")
			if !ok || lease.xIdentity != "123" || !lease.config.AccountReady("search") {
				t.Fatal("selected slot was not initially ready")
			}
			defer p.finishAccount(lease, "")
			offer := eligibilityOffer()
			p.bindCoordinatorLease(lease, offer)
			if mutation == "quota" {
				cooling.Store(true)
			} else if err := writePrivateFixture(lease.config.XSession, []byte(`{"auth_token":"changed-synthetic-auth","ct0":"changed-synthetic-csrf"}`), 0600); err != nil {
				t.Fatal(err)
			}
			if lease.config.AccountReady("search") {
				t.Fatal("final selected-account check accepted changed quota/session")
			}
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			client := coordinator.New(server.URL, "synthetic-credential")
			client.HTTP = server.Client()
			selected := lease.config
			selected.Executor = config.ExecutorServices
			journal := testJournal(t, filepath.Join(privateTestDir(t), "attempts"))
			code, err := submitLease(context.Background(), client, selected, offer, nil, journal)
			if code != "service_unavailable" || err == nil || requests.Load() != 0 {
				t.Fatal("changed readiness reached funded acceptance or provider execution", code, err, requests.Load())
			}
			h := healthKind(t, p, "x_read")
			want := coordinator.ActiveLease{JobID: offer.JobID, Attempt: offer.Attempt, Fence: offer.Fence}
			if h.InFlight != 1 || len(h.ActiveLeases) != 1 || h.ActiveLeases[0] != want || lease.account.entry.inFlight != 1 {
				t.Fatalf("final readiness check released or changed the occupied fence: %+v", h)
			}
		})
	}
}

func TestAccountEligibilityInheritedJournalBlocksUntilReconciled(t *testing.T) {
	p := multiPool(t)
	journal := testJournal(t, filepath.Join(privateTestDir(t), "attempts"))
	inherited := attempts.Record{JobID: "synthetic-inherited", Attempt: "1", Fence: "old-fence", Fingerprint: strings.Repeat("a", 64), Deadline: time.Now().Add(time.Minute), ProviderService: "x_read", ProviderAccountID: "missing-retired-registration"}
	if err := journal.Begin(inherited); err != nil {
		t.Fatal(err)
	}
	p.xRecovery = inheritedPending(journal.Pending, map[string]bool{inherited.Key(): true})
	h := healthKind(t, p, "x_read")
	if h.InFlight != 0 || h.Capacity != 0 || eligibilityCount(t, h.RunnableCapacity) != 0 || len(h.ActiveLeases) != 0 || h.State != "exhausted" {
		t.Fatalf("inherited unknown work fabricated a current fence or runnable supply: %+v", h)
	}
	for _, operation := range []string{"search", "profile", "post", "thread"} {
		if hint := eligibilityOperation(t, h, operation); hint.RunnableCapacity != 0 || hint.NextReadyAt != nil {
			t.Fatalf("inherited unknown work advertised operation supply: %+v", hint)
		}
	}
	if _, ok := p.acquireAccount("x_read", "search"); ok {
		t.Fatal("unresolved inherited X work allowed a fresh identity claim")
	}
	codex, ok := p.acquireAccount("codex")
	if !ok {
		t.Fatal("X recovery blocked independent Codex admission")
	}
	p.finishAccount(codex, "")
	if err := journal.Terminal(inherited); err != nil {
		t.Fatal(err)
	}
	first, ok := p.acquireAccount("x_read", "search")
	if !ok {
		t.Fatal("terminal reconciliation did not restore X admission")
	}
	defer p.finishAccount(first, "")
	active := attempts.Record{JobID: "synthetic-active", Attempt: "1", Fence: "new-fence", Fingerprint: strings.Repeat("b", 64), Deadline: time.Now().Add(time.Minute), ProviderService: "x_read", ProviderAccountID: first.id}
	if err := journal.Begin(active); err != nil {
		t.Fatal(err)
	}
	h = healthKind(t, p, "x_read")
	if h.InFlight != 1 || eligibilityCount(t, h.RunnableCapacity) != 1 {
		t.Fatalf("current process work was double-counted as inherited: %+v", h)
	}
	second, ok := p.acquireAccount("x_read", "search")
	if !ok || second.xIdentity == first.xIdentity {
		t.Fatal("resolved inheritance blocked a distinct current identity")
	}
	p.finishAccount(second, "")
}

func TestAccountEligibilityDeadlineEndsHeldHeartbeatBeforePeriodicTick(t *testing.T) {
	p := multiPool(t)
	f := xOnlyRegistry(t, p)
	f.Accounts = f.Accounts[:1]
	saveAccountFixture(t, p, f)
	readyAt := time.Now().Add(250 * time.Millisecond)
	later := readyAt.Add(2 * time.Second)
	p.xEligibility = func(id, operation string, now time.Time) time.Time {
		if operation == "search" {
			return readyAt
		}
		return later
	}
	health := p.health()
	h := healthKind(t, p, "x_read")
	if h.NextReadyAt == nil || !h.NextReadyAt.Equal(readyAt) || eligibilityOperation(t, h, "search").NextReadyAt == nil {
		t.Fatalf("earliest eligible operation was not scheduled: %+v", h)
	}
	held := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		held <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	client := coordinator.New(server.URL, "synthetic-credential")
	client.HTTP = server.Client()
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	sent := availability{services: serviceStates(health)}
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		watchHeartbeat(ctx, cancel, sent, func() availability { return availability{services: serviceStates(p.health())} }, nil)
	}()
	polled := make(chan error, 1)
	started := time.Now()
	go func() {
		_, err := client.Poll(ctx, coordinator.Heartbeat{Version: coordinator.Version, NodeID: "synthetic-node", Profile: "standard", State: "exhausted", Capacity: 0, Services: health, WaitSeconds: coordinator.HeartbeatWaitSeconds})
		polled <- err
	}()
	select {
	case <-held:
	case <-time.After(time.Second):
		t.Fatal("coordinator did not hold the heartbeat")
	}
	select {
	case err := <-polled:
		if err == nil || context.Cause(ctx) != errHeartbeatStale {
			t.Fatal("readiness timer did not cancel the held heartbeat as stale", err)
		}
	case <-time.After(800 * time.Millisecond):
		cancel(nil)
		t.Fatal("readiness refresh waited for the periodic tick or full hold")
	}
	<-watched
	if time.Now().Before(readyAt) || time.Since(started) >= heartbeatWatchInterval {
		t.Fatal("heartbeat refreshed before eligibility or after the first periodic tick")
	}
	after := healthKind(t, p, "x_read")
	if eligibilityOperation(t, after, "search").RunnableCapacity != 1 || after.Capacity != 0 || eligibilityCount(t, after.ReadyAccounts) != 1 {
		t.Fatalf("eligible operation wake granted generic readiness or missed search supply: %+v", after)
	}
}
