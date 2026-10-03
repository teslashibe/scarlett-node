package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

type renewalFunc func(context.Context, time.Time) error

func (f renewalFunc) EnsureValidUntil(c context.Context, d time.Time) error { return f(c, d) }

// A synthetic credential inside the renewal horizon that still passes funded
// admission: renewal may refresh it while the account keeps serving work.
func renewableSyntheticCodexAuth() []byte {
	return syntheticCodexAuth(time.Now().Add(codexRenewalHorizon / 2))
}

func renewalPool(t *testing.T) *servicePool {
	t.Helper()
	p := multiPool(t)
	root, err := filepath.EvalSymlinks(p.config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	p.config.CodexManagedRoot = root
	f, err := loadAccounts(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Accounts {
		f.Accounts[i].Path, err = filepath.EvalSymlinks(f.Accounts[i].Path)
		if err != nil {
			t.Fatal(err)
		}
		if f.Accounts[i].Service == "codex" {
			if err = writePrivateFixture(filepath.Join(f.Accounts[i].Path, "auth.json"), renewableSyntheticCodexAuth(), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	saveAccountFixture(t, p, f)
	p.health()
	return p
}
func setRenewal(p *servicePool, f authenticationFactory, pending func() ([]attempts.Record, error)) {
	p.renewal = &codexRenewal{factory: f, pending: pending}
}
func noPending() ([]attempts.Record, error) { return nil, nil }
func stepRenewal(t *testing.T, p *servicePool) <-chan struct{} {
	t.Helper()
	done := p.renewCodexStep(context.Background(), time.Now())
	if done == nil {
		t.Fatal("renewal not reserved")
	}
	return done
}
func awaitRenewal(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("renewal did not join")
	}
}
func resetRenewalTimers(p *servicePool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range p.accounts {
		a.renewAfter = time.Time{}
	}
}
func writeCodexFixture(t *testing.T, p *servicePool, id string, raw []byte) {
	t.Helper()
	if err := writePrivateFixture(filepath.Join(p.accounts["codex:"+id].spec.Path, "auth.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func codexCapacity(t *testing.T, p *servicePool) int {
	t.Helper()
	return healthKind(t, p, "codex").Capacity
}

func TestCodexRenewalIdleReservationAndAcceptedContinuity(t *testing.T) {
	p := renewalPool(t)
	borrowed, ok := p.acquireAccount("codex")
	if !ok {
		t.Fatal("no selected account")
	}
	entered := make(chan string, 1)
	release := make(chan struct{})
	setRenewal(p, func(path string) (managedAuthentication, error) {
		return renewalFunc(func(ctx context.Context, d time.Time) error {
			entered <- path
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}), nil
	}, noPending)
	done := stepRenewal(t, p)
	path := <-entered
	if filepath.Dir(path) == borrowed.config.CodexHome {
		t.Fatal("accepted account renewed")
	}
	if _, ok := p.acquireAccount("codex"); ok {
		t.Fatal("renewing/borrowed account admitted")
	}
	h := p.health()[0]
	if h.InFlight != 1 || h.Capacity != 1 {
		t.Fatalf("dishonest advertised capacity: %+v", h)
	}
	status := p.accountStatus()
	seen := false
	for _, s := range status {
		if s.Service == "codex" && filepath.Join(p.config.CodexManagedRoot, "codex-"+s.ID) == filepath.Dir(path) && s.State == "unreachable" {
			seen = true
			if s.Capacity != 0 || s.InFlight != 0 {
				t.Fatal(s)
			}
		}
	}
	if !seen {
		t.Fatal("renewal status absent")
	}
	if borrowed.account.spec.Path != borrowed.config.CodexHome || borrowed.account.entry.inFlight != 1 {
		t.Fatal("selected account continuity lost")
	}
	close(release)
	awaitRenewal(t, done)
	p.finishAccount(borrowed, "")
}
func TestCodexRenewalKnownPendingBlocksOnlyPinnedAccount(t *testing.T) {
	for _, kind := range []string{"codex", "x_read", "", "no-provider"} {
		t.Run(kind, func(t *testing.T) {
			p := renewalPool(t)
			calls := make(chan string, 1)
			record := attempts.Record{ProviderAccountID: "one", ProviderService: kind}
			if kind == "no-provider" {
				record = attempts.Record{NoProvider: true}
			}
			setRenewal(p, func(path string) (managedAuthentication, error) {
				calls <- path
				return renewalFunc(func(context.Context, time.Time) error { return nil }), nil
			}, func() ([]attempts.Record, error) {
				return []attempts.Record{record}, nil
			})
			done := p.renewCodexStep(context.Background(), time.Now())
			if kind == "" {
				if p.renewal.active != nil {
					t.Fatal("unbound recovery allowed rotation")
				}
				return
			}
			if done == nil {
				t.Fatal("explicit binding blocked unrelated renewal")
			}
			awaitRenewal(t, done)
			path := <-calls
			if kind == "codex" && filepath.Base(filepath.Dir(path)) != "codex-two" {
				t.Fatal("pending account renewed")
			}
		})
	}
}
func TestCodexRenewalFailureBackoffAndDistinctAccountRecovery(t *testing.T) {
	p := renewalPool(t)
	var calls atomic.Int32
	setRenewal(p, func(path string) (managedAuthentication, error) {
		return renewalFunc(func(context.Context, time.Time) error { calls.Add(1); return errors.New("synthetic unavailable") }), nil
	}, noPending)
	awaitRenewal(t, stepRenewal(t, p))
	awaitRenewal(t, stepRenewal(t, p))
	if calls.Load() != 2 {
		t.Fatal("distinct accounts not renewed")
	}
	p.renewCodexStep(context.Background(), time.Now())
	if p.renewal.active != nil {
		t.Fatal("backoff bypassed")
	}
	resetRenewalTimers(p)
	p.renewal.factory = func(path string) (managedAuthentication, error) {
		return renewalFunc(func(context.Context, time.Time) error {
			return writePrivateFixture(path, freshSyntheticCodexAuth(), 0600)
		}), nil
	}
	awaitRenewal(t, stepRenewal(t, p))
	if _, ok := p.acquireAccount("codex"); !ok {
		t.Fatal("durable synthetic recovery not admitted")
	}
}
func TestCodexRenewalExpiryVsProviderDenialAndOldHealth(t *testing.T) {
	for _, reason := range []string{"expired-start", "aged", "denial", "denial-aged", "historical"} {
		t.Run(reason, func(t *testing.T) {
			p := renewalPool(t)
			a := p.accounts["codex:one"]
			if reason == "denial" || reason == "denial-aged" {
				l, ok := p.acquireAccount("codex")
				if !ok {
					t.Fatal("no lease")
				}
				a = l.account
				p.finishAccount(l, "auth_required")
				if reason == "denial-aged" {
					p.mu.Lock()
					p.refresh(time.Now().Add(366 * 24 * time.Hour))
					p.mu.Unlock()
				}
			}
			if reason == "historical" {
				a.entry.state = "auth_required"
				a.entry.lastError = "auth_required"
				a.entry.localAuthInvalid = false
			}
			if reason == "expired-start" || reason == "aged" {
				expiry := time.Now().Add(-time.Minute)
				if reason == "aged" {
					expiry = time.Now().Add(4 * time.Minute)
				}
				if err := writePrivateFixture(filepath.Join(a.spec.Path, "auth.json"), syntheticCodexAuth(expiry), 0600); err != nil {
					t.Fatal(err)
				}
				p.health()
				if reason == "aged" {
					p.mu.Lock()
					p.refresh(time.Now().Add(3 * time.Minute))
					p.mu.Unlock()
				}
				if !a.entry.localAuthInvalid {
					t.Fatal("local expiry mistaken for provider denial")
				}
			}

			// Saving another account's result may persist the inspected expired profile.
			p.mu.Lock()
			p.saveHealth()
			p.mu.Unlock()
			saved := p.saved["codex:"+a.spec.ID]
			if saved.LocalAuthInvalid != (reason == "expired-start" || reason == "aged") {
				t.Fatalf("incorrect health origin: %+v", saved)
			}
			// The old reader ignores the additive field and conservatively retains state.
			raw, _ := json.Marshal(saved)
			var old struct{ State string }
			if json.Unmarshal(raw, &old) != nil || old.State != "auth_required" {
				t.Fatal("older-reader compatibility")
			}
			restored := newServicePool(p.config)
			restored.health()
			a = restored.accounts["codex:"+a.spec.ID]
			calls := make(chan string, 2)
			setRenewal(restored, func(path string) (managedAuthentication, error) {
				calls <- path
				return renewalFunc(func(context.Context, time.Time) error {
					return writePrivateFixture(path, freshSyntheticCodexAuth(), 0600)
				}), nil
			}, func() ([]attempts.Record, error) {
				other := "two"
				if a.spec.ID == "two" {
					other = "one"
				}
				return []attempts.Record{{ProviderAccountID: other, ProviderService: "codex"}}, nil
			})
			done := restored.renewCodexStep(context.Background(), time.Now())
			if reason == "denial" || reason == "denial-aged" || reason == "historical" {
				if restored.renewal.active != nil {
					t.Fatal("provider/historical quarantine bypassed")
				}
				return
			}
			if done == nil {
				t.Fatal("expired profile not reserved")
			}
			awaitRenewal(t, done)
			if a.entry.state == "auth_required" {
				t.Fatal("expired profile did not recover")
			}
		})
	}
}
func TestCodexRenewalQuotaPreserved(t *testing.T) {
	p := renewalPool(t)
	a := p.accounts["codex:one"]
	until := time.Now().Add(time.Hour)
	a.entry.state, a.entry.lastError, a.entry.restUntil = "exhausted", "capacity_unavailable", until
	if err := writePrivateFixture(filepath.Join(a.spec.Path, "auth.json"), syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	setRenewal(p, func(path string) (managedAuthentication, error) {
		return renewalFunc(func(context.Context, time.Time) error {
			return writePrivateFixture(path, freshSyntheticCodexAuth(), 0600)
		}), nil
	}, noPending)
	awaitRenewal(t, stepRenewal(t, p))
	if !a.entry.restUntil.Equal(until) || a.entry.state != "exhausted" {
		t.Fatal("renewal erased quota")
	}
}
func TestCodexRenewalRemovalAndReplacementCancelJoin(t *testing.T) {
	for _, change := range []string{"remove", "path", "directory"} {
		t.Run(change, func(t *testing.T) {
			p := renewalPool(t)
			entered := make(chan struct{})
			var cancelled atomic.Bool
			setRenewal(p, func(string) (managedAuthentication, error) {
				return renewalFunc(func(ctx context.Context, d time.Time) error {
					close(entered)
					<-ctx.Done()
					cancelled.Store(true)
					return ctx.Err()
				}), nil
			}, noPending)
			done := stepRenewal(t, p)
			<-entered
			a := p.renewal.active
			f, e := loadAccounts(p.config.AccountsFile)
			if e != nil {
				t.Fatal(e)
			}
			switch change {
			case "remove":
				f.Accounts = append(f.Accounts[:0], f.Accounts[1:]...)
				saveAccountFixture(t, p, f)
			case "path":
				for i := range f.Accounts {
					if f.Accounts[i].ID == a.spec.ID && f.Accounts[i].Service == "codex" {
						f.Accounts[i].Path = filepath.Join(p.config.CodexManagedRoot, "replacement")
						privateFixtureMkdir(f.Accounts[i].Path, 0700)
						writePrivateFixture(filepath.Join(f.Accounts[i].Path, "auth.json"), freshSyntheticCodexAuth(), 0600)
					}
				}
				saveAccountFixture(t, p, f)
			case "directory":
				if e = os.Rename(a.spec.Path, a.spec.Path+"-old"); e != nil {
					t.Fatal(e)
				}
				privateFixtureMkdir(a.spec.Path, 0700)
				writePrivateFixture(filepath.Join(a.spec.Path, "auth.json"), freshSyntheticCodexAuth(), 0600)
			}
			p.renewCodexStep(context.Background(), time.Now())
			awaitRenewal(t, done)
			if !cancelled.Load() {
				t.Fatal("operation not cancelled/joined")
			}
		})
	}
}
func TestCodexRenewalShutdownJoinsAndNilFactoryInactive(t *testing.T) {
	p := renewalPool(t)
	stop := p.startCodexRenewal(context.Background(), nil, noPending)
	stop()
	if p.renewal != nil {
		t.Fatal("nil factory activated")
	}
	entered := make(chan struct{})
	finished := make(chan struct{})
	stop = p.startCodexRenewal(context.Background(), func(string) (managedAuthentication, error) {
		return renewalFunc(func(ctx context.Context, d time.Time) error {
			close(entered)
			<-ctx.Done()
			close(finished)
			return ctx.Err()
		}), nil
	}, noPending)
	<-entered
	stop()
	select {
	case <-finished:
	default:
		t.Fatal("shutdown did not join")
	}
}
func TestCodexRenewalPrivateDirectProfileOnly(t *testing.T) {
	p := renewalPool(t)
	root := p.config.CodexManagedRoot
	home := p.accounts["codex:one"].spec.Path
	if _, _, ok := managedProfile(root, home); !ok {
		t.Fatal("private owned profile rejected")
	}
	for _, path := range []string{root, filepath.Dir(root), filepath.Join(root, "nested", "home"), home + "/.."} {
		if _, _, ok := managedProfile(root, path); ok {
			t.Fatal("external/nested/unclean profile accepted")
		}
	}
	link := filepath.Join(root, "alias")
	if e := os.Symlink(home, link); e == nil {
		if _, _, ok := managedProfile(root, link); ok {
			t.Fatal("symlink accepted")
		}
	}
	// Legacy mode can never opt in even if its path happens to lie under root.
	p.config.StateDir = ""
	p.config.AccountsFile = filepath.Join(root, "missing")
	p.config.AccountsRequired = false
	p.accountMode = false
	p.accounts = nil
	setRenewal(p, func(string) (managedAuthentication, error) {
		t.Error("legacy renewal")
		return nil, errors.New("unexpected")
	}, noPending)
	p.renewCodexStep(context.Background(), time.Now())
	if p.renewal.active != nil {
		t.Fatal("legacy account reserved")
	}
}

func TestCodexRenewalDeadlineBoundAndCancelledDurableReread(t *testing.T) {
	p := renewalPool(t)
	a := p.accounts["codex:one"]
	if err := writePrivateFixture(filepath.Join(a.spec.Path, "auth.json"), syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setRenewal(p, func(path string) (managedAuthentication, error) {
		return renewalFunc(func(c context.Context, deadline time.Time) error {
			bound, ok := c.Deadline()
			if !ok || bound.After(time.Now().Add(codexRenewalTimeout)) {
				t.Error("unbounded renewal")
			}
			if deadline.Before(time.Now().Add(codexRenewalHorizon - time.Second)) {
				t.Error("late validity horizon")
			}
			if err := writePrivateFixture(path, freshSyntheticCodexAuth(), 0600); err != nil {
				return err
			}
			cancel()
			return context.Canceled
		}), nil
	}, noPending)
	done := p.renewCodexStep(ctx, time.Now())
	if done == nil {
		t.Fatal("no renewal")
	}
	awaitRenewal(t, done)
	if a.entry.state == "auth_required" || !codexAdmissionValid(a.spec.Path, codexAdmissionWindow(time.Now())) {
		t.Fatal("durably saved cancellation rotation not reread")
	}
	if time.Until(a.renewAfter) < codexRenewalBackoff-time.Second {
		t.Fatal("cancelled operation bypassed backoff")
	}
}
func TestCodexRenewalGlobalJournalFailureBlocksAndProviderDenialRepairsOnlyOnStamp(t *testing.T) {
	p := renewalPool(t)
	setRenewal(p, func(string) (managedAuthentication, error) { t.Error("journal unavailable renewal"); return nil, nil }, func() ([]attempts.Record, error) { return nil, errors.New("synthetic journal failure") })
	if p.renewCodexStep(context.Background(), time.Now()) != nil {
		t.Fatal("journal failure failed open")
	}
	l, ok := p.acquireAccount("codex")
	if !ok {
		t.Fatal("no lease")
	}
	p.finishAccount(l, "auth_required")
	p.health()
	if l.account.entry.localAuthInvalid {
		t.Fatal("provider denial reclassified")
	}
	path := filepath.Join(l.config.CodexHome, "auth.json")
	if err := writePrivateFixture(path, freshSyntheticCodexAuth(), 0600); err != nil {
		t.Fatal(err)
	}
	p.health()
	if l.account.entry.state == "auth_required" {
		t.Fatal("genuine credential change did not repair")
	}
}

// Attempts this process began never block renewal once their worker returns;
// only records left by an earlier process can mean provider work elsewhere.
func TestCodexRenewalBlocksOnlyInheritedAttempts(t *testing.T) {
	record := func(job string) attempts.Record {
		return attempts.Record{JobID: job, Attempt: "1", Fence: "f1", Fingerprint: attempts.Hash([]byte(job)), Deadline: time.Now().Add(time.Minute)}
	}
	for _, inheritedKind := range []string{"codex-one", "unbound", "no-provider"} {
		t.Run(inheritedKind, func(t *testing.T) {
			p := renewalPool(t)
			j := testJournal(t, filepath.Join(privateTestDir(t), "attempts"))
			earlier := record("earlier-process")
			switch inheritedKind {
			case "codex-one":
				earlier.ProviderAccountID, earlier.ProviderService = "one", "codex"
			case "no-provider":
				earlier.NoProvider = true
			}
			if err := j.Begin(earlier); err != nil {
				t.Fatal(err)
			}
			pending, err := j.Pending()
			if err != nil {
				t.Fatal(err)
			}
			inherited := map[string]bool{}
			for _, r := range pending {
				inherited[r.Key()] = true
			}
			// This process: an Accept failure pinned to each account, and a
			// rejection whose Accept failed, all left started with no worker.
			for _, own := range []attempts.Record{record("own-one"), record("own-two"), record("own-unbound")} {
				if own.JobID != "own-unbound" {
					own.ProviderAccountID, own.ProviderService = strings.TrimPrefix(own.JobID, "own-"), "codex"
				}
				if err := j.Begin(own); err != nil {
					t.Fatal(err)
				}
			}
			var renewed []string
			setRenewal(p, func(path string) (managedAuthentication, error) {
				renewed = append(renewed, filepath.Base(filepath.Dir(path)))
				return renewalFunc(func(context.Context, time.Time) error { return nil }), nil
			}, inheritedPending(j.Pending, inherited))
			for range 4 {
				resetRenewalTimers(p)
				if done := p.renewCodexStep(context.Background(), time.Now()); done != nil {
					awaitRenewal(t, done)
				}
			}
			want := map[string]string{"codex-one": "codex-two", "unbound": "", "no-provider": "codex-one codex-two"}[inheritedKind]
			got := map[string]bool{}
			for _, name := range renewed {
				got[name] = true
			}
			for _, name := range []string{"codex-one", "codex-two"} {
				if got[name] != strings.Contains(want, name) {
					t.Fatalf("renewed %v, want %q", renewed, want)
				}
			}
		})
	}
}

func TestInheritedPendingStopsReadingOnceResolved(t *testing.T) {
	inheritedRecord := attempts.Record{JobID: "earlier", Attempt: "1", Fence: "f1", ProviderAccountID: "one", ProviderService: "codex"}
	own := attempts.Record{JobID: "own", Attempt: "1", Fence: "f1"}
	var reads atomic.Int32
	var journal atomic.Value
	journal.Store([]attempts.Record{inheritedRecord, own})
	failing := atomic.Bool{}
	view := inheritedPending(func() ([]attempts.Record, error) {
		reads.Add(1)
		if failing.Load() {
			return nil, errors.New("synthetic transient journal failure")
		}
		return journal.Load().([]attempts.Record), nil
	}, map[string]bool{inheritedRecord.Key(): true})
	if got, err := view(); err != nil || len(got) != 1 || got[0].Key() != inheritedRecord.Key() {
		t.Fatal("inherited record not reported", got, err)
	}
	// A failed read is not evidence of resolution.
	failing.Store(true)
	if _, err := view(); err == nil {
		t.Fatal("journal failure hidden")
	}
	failing.Store(false)
	if got, _ := view(); len(got) != 1 {
		t.Fatal("inherited record forgotten after a failed read")
	}
	journal.Store([]attempts.Record{own})
	if got, err := view(); err != nil || len(got) != 0 {
		t.Fatal("resolved record still reported", got, err)
	}
	before := reads.Load()
	// Even a later record under the same key is this process's tracked work.
	journal.Store([]attempts.Record{inheritedRecord})
	for range 3 {
		if got, err := view(); err != nil || len(got) != 0 {
			t.Fatal("resolved inheritance reappeared", got, err)
		}
	}
	if reads.Load() != before {
		t.Fatal("journal still read every tick after inherited attempts resolved")
	}
}

// renewalOffer is a valid funded Codex offer with synthetic digests.
func renewalOffer() coordinator.Lease {
	l := testLease()
	l.SettlementDeadline = l.LeaseDeadline
	l.ServiceType = "codex"
	l.AcceptanceRequired = true
	l.SignedJobID = strings.Repeat("a", 64)
	l.RequestSHA256 = strings.Repeat("b", 64)
	return l
}

func TestLostAcceptanceStartedRecordReconcilesWithoutRestart(t *testing.T) {
	for _, path := range []string{"submit", "reject"} {
		t.Run(path, func(t *testing.T) {
			l := renewalOffer()
			var statusCalls, failures atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/accept"):
					w.WriteHeader(http.StatusBadGateway)
				case r.Method == http.MethodGet:
					statusCalls.Add(1)
					json.NewEncoder(w).Encode(coordinator.AttemptStatus{Version: coordinator.Version, JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence, State: "live", ReplaySafe: true})
				default:
					var f coordinator.Failure
					if json.NewDecoder(r.Body).Decode(&f) != nil || f.Code != "execution_uncertain" {
						t.Error("reconciliation changed the uncertainty report")
					}
					failures.Add(1)
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()
			client := coordinator.New(server.URL, "synthetic-credential")
			client.HTTP = server.Client()
			j := testJournal(t, filepath.Join(privateTestDir(t), "attempts"))
			home := filepath.Join(privateTestDir(t), "codex")
			privateFixtureMkdir(home, 0700)
			if err := writePrivateFixture(filepath.Join(home, "auth.json"), freshSyntheticCodexAuth(), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			if path == "submit" {
				cfg := config.Config{CodexHome: home, LocalAccountID: "one", Executor: config.ExecutorServices, Services: []string{"codex"}, Profile: l.Profile}
				var code string
				code, err = submitLease(context.Background(), client, cfg, l, nil, j)
				if code != "" {
					t.Fatal("failed acceptance reported a provider outcome", code)
				}
			} else {
				err = rejectLease(context.Background(), client, j, l, "service_unavailable")
			}
			pending, perr := j.Pending()
			if err == nil || perr != nil || len(pending) != 1 || pending[0].State != "started" {
				t.Fatal("failed acceptance did not leave one started record", err, perr)
			}
			if path == "reject" && (!pending[0].NoProvider || pending[0].ProviderAccountID != "") {
				t.Fatal("rejection record lacks its no-provider binding")
			}
			key := pending[0].Key()
			// While its worker may still run, the runtime pass leaves it alone.
			if err := reconcileIdle(context.Background(), client, j, map[string]bool{key: true}); err != nil {
				t.Fatal(err)
			}
			if statusCalls.Load() != 0 {
				t.Fatal("active attempt reconciled")
			}
			if err := reconcileIdle(context.Background(), client, j, map[string]bool{}); err != nil {
				t.Fatal(err)
			}
			if pending, perr = j.Pending(); perr != nil || len(pending) != 0 || statusCalls.Load() != 1 || failures.Load() != 1 {
				t.Fatal("idle started record waited for a restart", perr)
			}
		})
	}
}

// An exchange through the real public package, answered by an in-process
// synthetic token endpoint. No request leaves the process. The renewed file
// must pass the node's private-file check (a protected ACL on Windows).
type syntheticTokenEndpoint struct {
	t      *testing.T
	calls  atomic.Int32
	access string
}

func (s *syntheticTokenEndpoint) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls.Add(1)
	if r.Method != http.MethodPost || r.URL.Scheme != "https" || r.URL.Host != "auth.openai.com" || r.URL.Path != "/oauth/token" {
		s.t.Error("unexpected request to the synthetic token endpoint")
		return nil, errors.New("synthetic endpoint refuses other requests")
	}
	raw, err := io.ReadAll(r.Body)
	r.Body.Close()
	form, ferr := url.ParseQuery(string(raw))
	if err != nil || ferr != nil || form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "synthetic-private-refresh" {
		s.t.Error("unexpected synthetic refresh form")
	}
	reply, _ := json.Marshal(map[string]any{"access_token": s.access, "refresh_token": "synthetic-private-rotated", "expires_in": 10 * 24 * 3600})
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(reply)), Request: r}, nil
}

func syntheticAccessToken(expiry time.Time) string {
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"exp":%d}`, expiry.Unix())) + ".synthetic"
}

func TestCodexRenewalThroughPublicPackageKeepsProfilePrivate(t *testing.T) {
	if managedAuthenticationFactory == nil {
		t.Fatal("renewal factory not wired")
	}
	if _, err := managedAuthenticationFactory("relative/auth.json"); err == nil {
		t.Fatal("relative credential path accepted")
	}
	p := renewalPool(t)
	endpoint := &syntheticTokenEndpoint{t: t, access: syntheticAccessToken(time.Now().Add(10 * 24 * time.Hour))}
	previous := http.DefaultClient.Transport
	http.DefaultClient.Transport = endpoint
	t.Cleanup(func() { http.DefaultClient.Transport = previous })
	raw, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "preserved": "synthetic", "tokens": map[string]any{
		"access_token":  syntheticAccessToken(time.Now().Add(10 * time.Minute)),
		"account_id":    "synthetic-private-account",
		"refresh_token": "synthetic-private-refresh",
	}})
	writeCodexFixture(t, p, "one", raw)
	writeCodexFixture(t, p, "two", freshSyntheticCodexAuth())
	setRenewal(p, managedAuthenticationFactory, noPending)
	awaitRenewal(t, stepRenewal(t, p))
	if endpoint.calls.Load() != 1 {
		t.Fatal("synthetic exchange count", endpoint.calls.Load())
	}
	a := p.accounts["codex:one"]
	f, err := localfs.OpenPrivate(filepath.Join(a.spec.Path, "auth.json"))
	if err != nil {
		t.Fatal("renewed credential failed the private-file check:", err)
	}
	renewed, err := io.ReadAll(f)
	f.Close()
	var file struct {
		Preserved string `json:"preserved"`
		Tokens    struct {
			RefreshToken string `json:"refresh_token"`
		} `json:"tokens"`
	}
	if err != nil || json.Unmarshal(renewed, &file) != nil || file.Preserved != "synthetic" || file.Tokens.RefreshToken != "synthetic-private-rotated" {
		t.Fatal("rotation was not durably published")
	}
	if a.entry.state != "configured" || a.entry.localAuthInvalid || !codexAdmissionValid(a.spec.Path, time.Now().Add(codexRenewalHorizon)) {
		t.Fatal("renewed profile not admissible")
	}
	if time.Until(a.renewAfter) > codexRenewalCadence {
		t.Fatal("successful renewal took the failure backoff")
	}
	// Both profiles are now valid past the horizon: nothing is reserved again.
	resetRenewalTimers(p)
	if p.renewCodexStep(context.Background(), time.Now()) != nil || endpoint.calls.Load() != 1 {
		t.Fatal("valid profile renewed again")
	}
}

func TestCodexRenewalRefusesNonPrivateCredential(t *testing.T) {
	p := renewalPool(t)
	home := p.accounts["codex:one"].spec.Path
	if err := makeFixturePublic(filepath.Join(home, "auth.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := managedProfile(p.config.CodexManagedRoot, home); ok {
		t.Fatal("renewal would keep a non-private credential descriptor")
	}
	writeCodexFixture(t, p, "two", freshSyntheticCodexAuth())
	setRenewal(p, func(string) (managedAuthentication, error) {
		t.Error("non-private credential renewed")
		return nil, errors.New("unexpected")
	}, noPending)
	if p.renewCodexStep(context.Background(), time.Now()) != nil {
		t.Fatal("non-private credential reserved")
	}
}

// main.go reads the slot ceiling while renewal runs; it must be the static
// configuration, never the capacity renewal temporarily withholds.
func TestCodexRenewalStaticSlotCeiling(t *testing.T) {
	p := renewalPool(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	stop := p.startCodexRenewal(context.Background(), func(string) (managedAuthentication, error) {
		return renewalFunc(func(ctx context.Context, d time.Time) error {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil
		}), nil
	}, noPending)
	defer stop()
	ceiling := p.capacity()
	<-entered
	if ceiling != 4 || p.capacity() != 4 || codexCapacity(t, p) != 1 {
		t.Fatal("slot ceiling followed renewal-adjusted capacity", ceiling, p.capacity())
	}
	close(release)
}

func TestCodexRenewalSkipsProfileOfDrainingAlias(t *testing.T) {
	p := renewalPool(t)
	writeCodexFixture(t, p, "two", freshSyntheticCodexAuth())
	selected, ok := p.acquireAccount("codex")
	if !ok || selected.id != "one" {
		t.Fatal("expected account one selected")
	}
	// The operator removes "one" and registers its directory again as "three".
	f, err := loadAccounts(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Accounts {
		if f.Accounts[i].Service == "codex" && f.Accounts[i].ID == "one" {
			f.Accounts[i].ID = "three"
		}
	}
	saveAccountFixture(t, p, f)
	p.health()
	if p.accounts["codex:one"] == nil || !p.accounts["codex:one"].removed || p.accounts["codex:three"] == nil {
		t.Fatal("alias fixture not draining")
	}
	var finished atomic.Bool
	setRenewal(p, func(path string) (managedAuthentication, error) {
		if !finished.Load() && filepath.Dir(path) == selected.config.CodexHome {
			t.Error("renewed a profile with accepted work")
		}
		return renewalFunc(func(context.Context, time.Time) error { return nil }), nil
	}, noPending)
	if p.renewCodexStep(context.Background(), time.Now()) != nil {
		t.Fatal("draining alias profile reserved")
	}
	finished.Store(true)
	p.finishAccount(selected, "")
	resetRenewalTimers(p)
	awaitRenewal(t, stepRenewal(t, p))
}

// An inherited attempt pinned to "one" may still run in one's directory after
// "one" is removed and the directory is registered again as "three".
func TestCodexRenewalInheritedAttemptOnUnregisteredIDBlocksPool(t *testing.T) {
	p := renewalPool(t)
	f, err := loadAccounts(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Accounts {
		if f.Accounts[i].Service == "codex" && f.Accounts[i].ID == "one" {
			f.Accounts[i].ID = "three"
		}
	}
	saveAccountFixture(t, p, f)
	p.health()
	if p.accounts["codex:one"] != nil || p.accounts["codex:three"] == nil {
		t.Fatal("idle removed account not released")
	}
	setRenewal(p, func(path string) (managedAuthentication, error) {
		t.Error("renewed while an inherited attempt's directory is unknown", filepath.Base(filepath.Dir(path)))
		return nil, errors.New("unexpected")
	}, func() ([]attempts.Record, error) {
		return []attempts.Record{{ProviderAccountID: "one", ProviderService: "codex"}}, nil
	})
	if p.renewCodexStep(context.Background(), time.Now()) != nil || p.renewal.active != nil {
		t.Fatal("renewal reserved a profile while an unregistered account's attempt is pending")
	}
}

func TestCodexRenewalHoldsDirectoryAcrossReregistration(t *testing.T) {
	p := renewalPool(t)
	writeCodexFixture(t, p, "two", freshSyntheticCodexAuth())
	entered := make(chan struct{})
	release := make(chan struct{})
	setRenewal(p, func(string) (managedAuthentication, error) {
		// Like an exchange already sent, this ignores cancellation.
		return renewalFunc(func(context.Context, time.Time) error {
			close(entered)
			<-release
			return nil
		}), nil
	}, noPending)
	done := stepRenewal(t, p)
	<-entered
	if p.renewal.active.spec.ID != "one" {
		t.Fatal("expected account one reserved")
	}
	other, ok := p.acquireAccount("codex")
	if !ok || other.id != "two" {
		t.Fatal("expected account two selected")
	}
	f, err := loadAccounts(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Accounts {
		if f.Accounts[i].Service == "codex" && f.Accounts[i].ID == "one" {
			f.Accounts[i].ID = "three"
		}
	}
	saveAccountFixture(t, p, f)
	if l, ok := p.acquireAccount("codex"); ok {
		t.Fatalf("lease %q admitted on a directory still being renewed", l.id)
	}
	for _, s := range p.accountStatus() {
		if s.ID == "three" && (s.State != "unreachable" || s.Capacity != 0) {
			t.Fatal("re-registered directory advertised during renewal", s)
		}
	}
	if codexCapacity(t, p) != 1 {
		t.Fatal("renewing directory counted as free capacity")
	}
	close(release)
	awaitRenewal(t, done)
	l, ok := p.acquireAccount("codex")
	if !ok || l.id != "three" {
		t.Fatal("re-registered directory not admitted after renewal")
	}
	p.finishAccount(l, "")
	p.finishAccount(other, "")
}

func TestCodexRenewalSurvivesUnrelatedJournalObservations(t *testing.T) {
	p := renewalPool(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var cancelled atomic.Bool
	var pending atomic.Value
	pending.Store(func() ([]attempts.Record, error) { return nil, nil })
	setRenewal(p, func(string) (managedAuthentication, error) {
		return renewalFunc(func(ctx context.Context, d time.Time) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				cancelled.Store(true)
				return ctx.Err()
			}
		}), nil
	}, func() ([]attempts.Record, error) {
		return pending.Load().(func() ([]attempts.Record, error))()
	})
	done := stepRenewal(t, p)
	<-entered
	for _, observe := range []func() ([]attempts.Record, error){
		func() ([]attempts.Record, error) {
			return []attempts.Record{{JobID: "x-reject", State: "started"}}, nil
		},
		func() ([]attempts.Record, error) { return nil, errors.New("synthetic transient journal failure") },
		func() ([]attempts.Record, error) {
			return []attempts.Record{{ProviderAccountID: p.renewal.active.spec.ID, ProviderService: "codex"}}, nil
		},
	} {
		pending.Store(observe)
		p.renewCodexStep(context.Background(), time.Now())
		if cancelled.Load() {
			t.Fatal("reserved renewal cancelled by an unrelated observation")
		}
	}
	close(release)
	awaitRenewal(t, done)
	if cancelled.Load() {
		t.Fatal("reserved renewal cancelled")
	}
}

// One failed attempt, retried after the backoff, must still find the profile
// admissible: the horizon leaves several retries before the funded guard.
func TestCodexRenewalRetriesBeforeAdmissionGuard(t *testing.T) {
	guard := coordinator.MaxOfferLifetime + codexAdmissionClockMargin
	if retries := (codexRenewalHorizon + codexAdmissionClockMargin - guard - codexRenewalCadence) / codexRenewalBackoff; retries < 3 {
		t.Fatal("renewal horizon leaves too few retries before the admission guard", retries)
	}
	p := renewalPool(t)
	writeCodexFixture(t, p, "one", syntheticCodexAuth(time.Now().Add(codexRenewalHorizon)))
	writeCodexFixture(t, p, "two", freshSyntheticCodexAuth())
	var calls atomic.Int32
	setRenewal(p, func(string) (managedAuthentication, error) {
		return renewalFunc(func(context.Context, time.Time) error { calls.Add(1); return errors.New("synthetic transient failure") }), nil
	}, noPending)
	awaitRenewal(t, stepRenewal(t, p))
	a := p.accounts["codex:one"]
	retry := a.renewAfter.Add(time.Second)
	p.mu.Lock()
	p.refresh(retry)
	state := a.entry.state
	p.mu.Unlock()
	if state == "auth_required" {
		t.Fatal("one failed renewal took the account offline before its retry")
	}
	done := p.renewCodexStep(context.Background(), retry)
	if done == nil {
		t.Fatal("no retry after backoff")
	}
	awaitRenewal(t, done)
	if calls.Load() != 2 {
		t.Fatal("retry count", calls.Load())
	}
}

func TestCodexRenewalLeavesLongValidProfilesSelectable(t *testing.T) {
	p := renewalPool(t)
	writeCodexFixture(t, p, "one", freshSyntheticCodexAuth())
	writeCodexFixture(t, p, "two", freshSyntheticCodexAuth())
	before := codexCapacity(t, p)
	setRenewal(p, func(string) (managedAuthentication, error) {
		t.Error("long-valid profile reserved")
		return nil, errors.New("unexpected")
	}, noPending)
	if p.renewCodexStep(context.Background(), time.Now()) != nil || before != 2 || codexCapacity(t, p) != 2 {
		t.Fatal("long-valid profile withheld from selection")
	}
	for _, id := range []string{"one", "two"} {
		if wait := time.Until(p.accounts["codex:"+id].renewAfter); wait <= 0 || wait > codexRenewalCadence {
			t.Fatal("long-valid profile not rechecked at the cadence", wait)
		}
	}
}

func TestCodexLocalGuardIsLocalExpiryAndInvalidOfferIsNotAuth(t *testing.T) {
	for _, change := range []string{"offer-too-long", "credential-replaced"} {
		t.Run(change, func(t *testing.T) {
			p := renewalPool(t)
			writeCodexFixture(t, p, "two", freshSyntheticCodexAuth())
			selected, ok := p.acquireAccount("codex")
			if !ok || selected.id != "one" {
				t.Fatal("expected account one selected")
			}
			l := renewalOffer()
			want := codexLocalAuthExpired
			if change == "offer-too-long" {
				// A coordinator clock ahead of ours: Accept would refuse it locally.
				l.LeaseDeadline = time.Now().Add(coordinator.MaxOfferLifetime + 6*time.Second)
				l.SettlementDeadline = l.LeaseDeadline
				want = "invalid_lease"
			} else if err := writePrivateFixture(filepath.Join(selected.config.CodexHome, "auth.json"), syntheticCodexAuth(time.Now().Add(-time.Minute)), 0600); err != nil {
				t.Fatal(err)
			}
			j := testJournal(t, filepath.Join(privateTestDir(t), "attempts"))
			c := selected.config
			c.Profile = l.Profile
			// A nil client proves no acceptance HTTP is attempted.
			code, err := submitLease(context.Background(), nil, c, l, nil, j)
			if code != want || err == nil {
				t.Fatalf("code %q, want %q", code, want)
			}
			if pending, err := j.Pending(); err != nil || len(pending) != 0 {
				t.Fatal("locally refused offer left uncertainty", err)
			}
			p.finishAccount(selected, code)
			a := selected.account
			if change == "offer-too-long" {
				if a.entry.state == "auth_required" {
					t.Fatal("invalid offer recorded as an authentication failure")
				}
				return
			}
			if a.entry.state != "auth_required" || a.entry.lastError != "auth_required" || !a.entry.localAuthInvalid {
				t.Fatal("local guard recorded as provider denial")
			}
			setRenewal(p, func(path string) (managedAuthentication, error) {
				return renewalFunc(func(context.Context, time.Time) error {
					return writePrivateFixture(path, freshSyntheticCodexAuth(), 0600)
				}), nil
			}, noPending)
			awaitRenewal(t, stepRenewal(t, p))
			if a.entry.state != "configured" || a.entry.localAuthInvalid {
				t.Fatal("renewal did not repair local expiry")
			}
			first, ok1 := p.acquireAccount("codex")
			second, ok2 := p.acquireAccount("codex")
			if !ok1 || !ok2 || first.id != "one" && second.id != "one" {
				t.Fatal("repaired profile not admitted")
			}
		})
	}
}

func TestLegacyBlockedHealthDoesNotPersistLocalMarker(t *testing.T) {
	p := poolFixture(t, "codex")
	if !p.acquire("codex") {
		t.Fatal("legacy codex unavailable")
	}
	if err := writePrivateFixture(filepath.Join(p.config.CodexHome, "auth.json"), syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	p.health()
	if e := p.entries["codex"]; e.state != "auth_required" || !e.localAuthInvalid {
		t.Fatal("legacy local expiry not recorded")
	}
	// A failed health write blocks the pool and forces the shared entry away
	// from auth_required. A later successful save must not keep the marker.
	healthFile := filepath.Join(p.config.StateDir, "account-health.json")
	if err := os.Mkdir(healthFile, 0700); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.saveHealth()
	p.mu.Unlock()
	p.health()
	if err := os.Remove(healthFile); err != nil {
		t.Fatal(err)
	}
	p.finish("codex", "report_pending")
	raw, err := os.ReadFile(healthFile)
	if err != nil || bytes.Contains(raw, []byte("local_auth_invalid")) {
		t.Fatal("inconsistent local marker persisted")
	}
	if err := writePrivateFixture(filepath.Join(p.config.CodexHome, "auth.json"), freshSyntheticCodexAuth(), 0600); err != nil {
		t.Fatal(err)
	}
	restarted := newServicePool(p.config)
	if s := healthKind(t, restarted, "codex"); restarted.healthError || s.State != "configured" {
		t.Fatal("restart with a fresh credential stayed blocked", s.State)
	}
	// A file already written with the inconsistent marker is normalized, not rejected.
	if err := writeLocalFile(p.config.StateDir, "account-health.json", []byte(`{"codex:legacy":{"local_auth_invalid":true,"state":"unreachable","error":"report_pending"}}`)); err != nil {
		t.Fatal(err)
	}
	restarted = newServicePool(p.config)
	if s := healthKind(t, restarted, "codex"); restarted.healthError || s.State != "configured" {
		t.Fatal("inconsistent marker rejected the health file", s.State)
	}
}
