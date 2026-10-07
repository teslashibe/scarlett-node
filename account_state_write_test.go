package main

import (
	"errors"
	"os"
	"testing"
	"time"
)

func failingStateWriter(fail *bool, writes *int) func(dir, name string, raw []byte) error {
	return func(dir, name string, raw []byte) error {
		*writes++
		if *fail {
			return errors.New("synthetic state write failure")
		}
		return writeLocalFile(dir, name, raw)
	}
}

func serviceState(p *servicePool, kind string) string {
	for _, s := range p.health() {
		if s.Kind == kind {
			return s.State
		}
	}
	return ""
}

func TestFailedAccountStateWriteKeepsServingAndRetries(t *testing.T) {
	p := multiPool(t)
	p.health() // Enter managed mode with the real writer.
	fail, writes := true, 0
	p.writeState = failingStateWriter(&fail, &writes)

	codex, ok := p.acquireAccount("codex")
	if !ok {
		t.Fatal("missing codex account")
	}
	p.finishAccount(codex, "capacity_unavailable")
	x, ok := p.acquireAccount("x_read")
	if !ok {
		t.Fatal("missing X account")
	}
	x.config.AccountCooldown(2 * time.Hour)
	p.finishAccount(x, "x_rate_limited")
	if writes == 0 || p.healthError || p.accountsError || p.xIdentityError || p.xIdentityHealthError {
		t.Fatalf("write failure latched: writes=%d health=%v accounts=%v x=%v", writes, p.healthError, p.accountsError, p.xIdentityError)
	}
	// The cooled accounts stay cooled in memory; the others keep serving.
	for kind, cooled := range map[string]string{"codex": codex.id, "x_read": x.id} {
		if s := serviceState(p, kind); s == "unreachable" {
			t.Fatalf("%s advertised unreachable after a write failure", kind)
		}
		l, ok := p.acquireAccount(kind)
		if !ok || l.id == cooled {
			t.Fatalf("%s: healthy account not served after a write failure", kind)
		}
		p.finishAccount(l, "")
	}
	for _, a := range p.accountStatus() {
		if a.LastError == "prover_error" {
			t.Fatal("write failure reported as prover_error")
		}
	}
	// Failures back off instead of rewriting on every refresh.
	before := writes
	p.health()
	if writes != before {
		t.Fatal("retried before backoff elapsed")
	}

	fail = false
	p.stateRetryAt = time.Time{} // The backoff has elapsed.
	p.health()
	if p.healthDirty || p.xCooldownsDirty || p.stateWriteErr != nil {
		t.Fatal("state not saved after the writer recovered")
	}
	restarted := newServicePool(p.config)
	for kind, cooled := range map[string]string{"codex": codex.id, "x_read": x.id} {
		l, ok := restarted.acquireAccount(kind)
		if !ok || l.id == cooled {
			t.Fatalf("%s: retried save lost the cooldown across restart", kind)
		}
		if _, ok := restarted.acquireAccount(kind); ok {
			t.Fatalf("%s: cooled account served after restart", kind)
		}
		restarted.finishAccount(l, "")
	}
}

func TestUnchangedAccountHealthIsNotRewritten(t *testing.T) {
	p := multiPool(t)
	p.health()
	fail, writes := false, 0
	p.writeState = failingStateWriter(&fail, &writes)
	for range 5 {
		l, ok := p.acquireAccount("codex")
		if !ok {
			t.Fatal("missing codex account")
		}
		p.finishAccount(l, "")
	}
	if writes > 1 {
		t.Fatalf("successful jobs rewrote unchanged account health %d times", writes)
	}
}

func TestAccountsModeMarkerWriteFailureRetries(t *testing.T) {
	p := multiPool(t)
	fail, writes := true, 0
	p.writeState = failingStateWriter(&fail, &writes)
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("managed accounts served before the mode marker was durable")
	}
	if p.healthError {
		t.Fatal("marker write failure latched until restart")
	}
	fail = false
	p.stateRetryAt = time.Time{}
	l, ok := p.acquireAccount("codex")
	if !ok {
		t.Fatal("managed accounts not served after the marker was saved")
	}
	p.finishAccount(l, "")
}

func TestLegacyResumesWhenAccountFileGoesBeforeMarker(t *testing.T) {
	p := multiPool(t)
	fail, writes := true, 0
	p.writeState = failingStateWriter(&fail, &writes)
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("legacy account served while the account file awaited its marker")
	}
	if err := os.Remove(p.config.AccountsFile); err != nil {
		t.Fatal(err)
	}
	p.stateRetryAt = time.Time{}
	l, ok := p.acquireAccount("codex")
	if !ok || l.id != "legacy" {
		t.Fatal("legacy account stayed blocked after the account file went away")
	}
	p.finishAccount(l, "")
	if s := serviceState(p, "codex"); s != "ready" && s != "configured" {
		t.Fatalf("legacy codex advertised %q", s)
	}
}
