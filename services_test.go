package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

func poolFixture(t *testing.T, selected ...string) *servicePool {
	t.Helper()
	dir := privateTestDir(t)
	home := filepath.Join(dir, "codex")
	privateFixtureMkdir(home, 0700)
	writePrivateFixture(filepath.Join(home, "auth.json"), freshSyntheticCodexAuth(), 0600)
	session := filepath.Join(dir, "session.json")
	writePrivateFixture(session, []byte(`{"auth_token":"synthetic-auth","ct0":"synthetic-csrf"}`), 0600)
	helper := fixtureHelperPath(dir)
	if e := installFixtureHelper(helper); e != nil {
		t.Fatal(e)
	}
	return newServicePool(config.Config{StateDir: dir, AccountsFile: filepath.Join(dir, "accounts.json"), Services: selected, CodexHome: home, XSession: session, Prover: helper, CodexConcurrency: 2, XConcurrency: 1, MaxInputBytes: 32768, MaxOutputTokens: 2048})
}

func TestMissingProofHelperNeverAdvertisesConfiguredCapacity(t *testing.T) {
	p := poolFixture(t, "codex", "x_read")
	if e := os.Remove(p.config.Prover); e != nil {
		t.Fatal(e)
	}
	if p.acquire("codex") || p.acquire("x_read") {
		t.Fatal("missing helper accepted work")
	}
	for _, s := range p.health() {
		if s.State != "unreachable" || s.LastErrorCode != "prover_error" {
			t.Fatal("helper unavailable not reported")
		}
	}
	if e := makeHelperUnusable(p.config.Prover); e != nil {
		t.Fatal(e)
	}
	if p.acquire("codex") {
		t.Fatal("nonexecutable helper accepted")
	}
	if e := restoreFixtureHelper(p.config.Prover); e != nil {
		t.Fatal(e)
	}
	if !p.acquire("codex") || !p.acquire("x_read") {
		t.Fatal("installed helper did not restore configuration")
	}
	p.finish("codex", "")
	p.finish("x_read", "")
}

// After the node catches its verifier misusing a session, the heartbeat stops
// offering relay but keeps offering MPC, and the account that carried the
// relay session stays ready rather than being penalised for the verifier.
func TestRelayHaltDropsRelayFromHeartbeatAndKeepsAccountReady(t *testing.T) {
	worker.ResetRelayHaltForTests()
	t.Cleanup(worker.ResetRelayHaltForTests)
	p := poolFixture(t, "x_read")
	p.config.XRelay = true
	if got := healthKind(t, p, "x_read").ProofModes; !reflect.DeepEqual(got, []string{"mpc", "relay"}) {
		t.Fatalf("opted-in heartbeat advertises %v", got)
	}
	if !p.acquire("x_read") {
		t.Fatal("ready account refused work")
	}
	worker.HaltRelay("test")
	p.finish("x_read", "relay_misuse")
	h := healthKind(t, p, "x_read")
	if !reflect.DeepEqual(h.ProofModes, []string{"mpc"}) {
		t.Fatalf("halted heartbeat advertises %v", h.ProofModes)
	}
	if h.State != "ready" || h.LastErrorCode != "relay_misuse" {
		t.Fatalf("account after misuse: state %q code %q, want ready with the code recorded", h.State, h.LastErrorCode)
	}
	if !p.acquire("x_read") {
		t.Fatal("account unavailable for MPC work after a relay halt")
	}
	p.finish("x_read", "")
	// The halt survives an ordinary success; only a restart clears it.
	if got := healthKind(t, p, "x_read").ProofModes; !reflect.DeepEqual(got, []string{"mpc"}) {
		t.Fatalf("halt cleared by a later success: %v", got)
	}
}
func healthKind(t *testing.T, p *servicePool, kind string) coordinator.ServiceHealth {
	t.Helper()
	for _, s := range p.health() {
		if s.Kind == kind {
			return s
		}
	}
	t.Fatal("missing service")
	return coordinator.ServiceHealth{}
}
func TestServicesIndependentCapacityQuotaAndAuthentication(t *testing.T) {
	p := poolFixture(t, "codex", "x_read")
	if p.capacity() != 3 || !p.acquire("x_read") || p.acquire("x_read") {
		t.Fatal("X capacity not bounded")
	}
	p.finish("x_read", "x_rate_limited")
	if healthKind(t, p, "x_read").State != "exhausted" || !p.acquire("codex") {
		t.Fatal("X quota disabled Codex")
	}
	p.finish("codex", "")
	if healthKind(t, p, "codex").State != "ready" {
		t.Fatal("successful local proof status missing")
	}
	p.mu.Lock()
	p.entries["x_read"].restUntil = time.Now().Add(-time.Second)
	p.mu.Unlock()
	if !p.acquire("x_read") {
		t.Fatal("quota cooldown never recovered")
	}
	p.finish("x_read", "auth_required")
	if p.acquire("x_read") || !p.acquire("codex") {
		t.Fatal("authentication blocked wrong service")
	}
	p.finish("codex", "")
	if e := writePrivateFixture(p.config.XSession, []byte(`{"auth_token":"new-synthetic-session","ct0":"synthetic-csrf"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if !p.acquire("x_read") {
		t.Fatal("changed local session did not recover")
	}
	p.finish("x_read", "")
	raw, _ := json.Marshal(p.health())
	if string(raw) == "" {
		t.Fatal("missing health")
	}
	for _, secret := range []string{"synthetic-auth", "synthetic-csrf", "new-synthetic-session"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("credential leaked in health")
		}
	}
}
func TestServiceSelectionAndConcurrentSlotClaims(t *testing.T) {
	p := poolFixture(t, "codex")
	if p.acquire("x_read") || healthKind(t, p, "x_read").State != "not_added" || p.capacity() != 2 {
		t.Fatal("disabled X served")
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if p.acquire("codex") {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 2 || healthKind(t, p, "codex").InFlight != 2 {
		t.Fatal("shared slot race exceeded quota")
	}
	p.finish("codex", "")
	p.finish("codex", "report_pending")
	if healthKind(t, p, "codex").InFlight != 0 {
		t.Fatal("slots not released")
	}
}
func TestServiceMetadataDoesNotClaimAuthenticatedReadiness(t *testing.T) {
	p := poolFixture(t, "codex", "x_read")
	if healthKind(t, p, "codex").State != "configured" || healthKind(t, p, "x_read").State != "configured" {
		t.Fatal("configuration invented provider readiness")
	}
	makeFixturePublic(p.config.XSession)
	if healthKind(t, p, "x_read").State != "auth_required" || healthKind(t, p, "codex").State != "configured" {
		t.Fatal("unsafe session affected wrong service")
	}
	os.Remove(filepath.Join(p.config.CodexHome, "auth.json"))
	if healthKind(t, p, "codex").State != "auth_required" {
		t.Fatal("missing login appears configured")
	}
}

func TestServiceLimitsUseLocalConfigWithoutSharedSlices(t *testing.T) {
	p := poolFixture(t, "codex", "x_read")
	p.config.MaxInputBytes, p.config.MaxOutputTokens = 123, 456
	c := healthKind(t, p, "codex")
	x := healthKind(t, p, "x_read")
	if c.MaxInputBytes != 123 || c.MaxOutputTokens != 456 || len(c.Models) != len(config.AvailableModelsAt(time.Now())) || x.MaxInputBytes != 123 || x.MaxOutputTokens != 0 || len(x.Models) != 0 {
		t.Fatal("local limits not reported")
	}
	c.Models[0] = "caller-mutation"
	if healthKind(t, p, "codex").Models[0] != "gpt-6.1-sol" {
		t.Fatal("health modified runtime catalog")
	}
	disabled := healthKind(t, poolFixture(t, "x_read"), "codex")
	if disabled.MaxInputBytes != 0 || disabled.MaxOutputTokens != 0 || len(disabled.Models) != 0 {
		t.Fatal("disabled service advertised capabilities")
	}
}
