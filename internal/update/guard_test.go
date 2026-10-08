package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

type guardFixture struct {
	g         *Guard
	state     StateFile
	installs  atomic.Int32
	restores  atomic.Int32
	launches  atomic.Int32
	terminate atomic.Int32
	alive     atomic.Bool
	// appErr is the relaunched app's failure to report; Launch runs on the
	// goroutine that called Run.
	appErr error
}

// guardTestApp is the bundle name on every platform; AppName exists only on
// macOS.
const guardTestApp = "Scarlett Node.app"

// newGuardFixture builds a hand-off whose paths are all native absolute paths
// inside the test's own directory: the state file refuses anything else, and
// the guard's cleanup removes leftovers beside the staged bundle.
func newGuardFixture(t *testing.T, phaseAfterLaunch string) *guardFixture {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	updates := filepath.Join(dir, "updates")
	f := &guardFixture{state: StateFile{Path: filepath.Join(dir, "update-state.json")}}
	if err := f.state.Write(State{Schema: 1, Installed: "0.1.13", HighWater: "0.1.13", Pending: &Pending{Phase: PhaseHandoff, From: "0.1.13", To: "0.1.14", Kind: "mac-app",
		Staged: filepath.Join(updates, "stage-0.1.14-test", guardTestApp), App: filepath.Join(base, "Applications", guardTestApp),
		DrainOwner: "updater", ResumeServing: true, AppPID: 4242, StartedAt: time.Now().Unix()}}); err != nil {
		t.Fatal(err)
	}
	g := NewGuard(f.state, updates)
	g.Poll, g.ExitWait, g.QuitWait = 10*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond
	// An app that reports, or a node that finishes its work, is never timed
	// out however slow the machine; only the silent app waits out its limit.
	g.HealthWait, g.NodeWait = time.Minute, time.Minute
	if phaseAfterLaunch == "" {
		g.HealthWait = 200 * time.Millisecond
	}
	g.NodeStopped = func() bool { return true }
	g.Alive = func(pid int) bool { return pid == 4242 && f.alive.Load() || pid == 5151 && f.alive.Load() }
	g.Terminate = func(int, bool) { f.terminate.Add(1); f.alive.Store(false) }
	g.Install = func(_ context.Context, p *Pending) error { f.installs.Add(1); p.Previous = p.Staged; return nil }
	g.Restore = func(context.Context, *Pending) error { f.restores.Add(1); return nil }
	g.Launch = func(string) error {
		f.launches.Add(1)
		if phaseAfterLaunch == "" {
			return nil
		}
		s, err := f.state.Read()
		if err != nil {
			f.appErr = err
			return nil
		}
		// Only the new version, launched after the install, reports; the
		// previous version relaunched after a failure or rollback does not.
		if s.Pending == nil || s.Pending.Phase != PhaseInstalled {
			return nil
		}
		// The relaunched app reports, as setup() does: verifying with its own
		// pid, then its health. The guard reads the state only after Launch.
		f.alive.Store(true)
		for _, report := range []func(*Pending){
			func(p *Pending) { p.Phase, p.AppPID = PhaseVerifying, 5151 },
			func(p *Pending) {
				p.Phase = phaseAfterLaunch
				if phaseAfterLaunch == PhaseUnhealthy {
					p.Reason = "node_exited"
				}
			},
		} {
			if _, err = f.state.Update(func(s *State) error { report(s.Pending); return nil }); err != nil {
				f.appErr = err
				return nil
			}
		}
		return nil
	}
	f.g = g
	return f
}

// result is the state after Run, failing the test when it cannot be read or
// holds no install.
func (f *guardFixture) result(t *testing.T) State {
	t.Helper()
	if f.appErr != nil {
		t.Fatalf("the relaunched app could not report: %v", f.appErr)
	}
	s, err := f.state.Read()
	if err != nil {
		t.Fatal(err)
	}
	if s.Pending == nil {
		t.Fatalf("the state lost its pending install: %+v", s)
	}
	return s
}

func TestGuardInstallsRelaunchesAndKeepsAHealthyUpdate(t *testing.T) {
	f := newGuardFixture(t, PhaseHealthy)
	// Cleanup keeps the guard's copy and log and the previous bundle's
	// staging directory, and removes finished downloads.
	for _, dir := range []string{"guard", "downloads", "stage-0.1.14-test", filepath.Join("stage-0.1.14-test", guardTestApp)} {
		if err := localfs.EnsureDir(filepath.Join(f.g.Updates, dir)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(f.g.Updates, "guard.log"), []byte("log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.g.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := f.result(t)
	if f.installs.Load() != 1 || f.restores.Load() != 0 || f.launches.Load() != 1 || s.Pending.Phase != PhaseHealthy || s.HasFailed("0.1.14") {
		t.Fatalf("installs %d restores %d launches %d state %+v", f.installs.Load(), f.restores.Load(), f.launches.Load(), s.Pending)
	}
	for name, want := range map[string]bool{"guard.log": true, "guard": true, "stage-0.1.14-test": true, "downloads": false} {
		if _, err := os.Lstat(filepath.Join(f.g.Updates, name)); (err == nil) != want {
			t.Fatalf("%s kept=%v, want %v", name, err == nil, want)
		}
	}
}

func TestGuardRollsBackAnUnhealthyOrSilentUpdate(t *testing.T) {
	for _, phase := range []string{PhaseUnhealthy, ""} {
		f := newGuardFixture(t, phase)
		if err := f.g.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		s := f.result(t)
		if f.restores.Load() != 1 || f.launches.Load() != 2 || s.Pending.Phase != PhaseRolledBack || !s.HasFailed("0.1.14") {
			t.Fatalf("phase %q: restores %d launches %d state %+v", phase, f.restores.Load(), f.launches.Load(), s.Pending)
		}
		if phase == "" && s.Pending.Reason != "health_timeout" {
			t.Fatalf("reason %q", s.Pending.Reason)
		}
	}
}

func TestGuardReplacesNothingWhileTheOldAppRuns(t *testing.T) {
	f := newGuardFixture(t, PhaseHealthy)
	f.alive.Store(true)
	f.g.Terminate = func(int, bool) {}
	if err := f.g.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := f.result(t)
	if f.installs.Load() != 0 || f.launches.Load() != 0 || s.Pending.Phase != PhaseFailed || s.Pending.Reason != CodeBusy || !s.HasFailed("0.1.14") {
		t.Fatalf("state %+v", s.Pending)
	}
}

func TestGuardRelaunchesTheOldAppWhenTheInstallFails(t *testing.T) {
	f := newGuardFixture(t, PhaseHealthy)
	f.g.Install = func(context.Context, *Pending) error { return fail(CodeAppManagement, errors.New("EPERM")) }
	if err := f.g.Run(context.Background()); err == nil {
		t.Fatal("install failure not reported")
	}
	s := f.result(t)
	// Automatic mode must not retry it at once: that would quit and relaunch
	// the app on every attempt.
	if f.launches.Load() != 1 || s.Pending.Phase != PhaseFailed || s.Pending.Reason != CodeAppManagement || !s.HasFailed("0.1.14") {
		t.Fatalf("state %+v", s.Pending)
	}
}

func TestGuardRestoresOnlyAfterTheNewNodeFinishesItsWork(t *testing.T) {
	f := newGuardFixture(t, PhaseUnhealthy)
	var polls atomic.Int32
	var restoredWhileBusy atomic.Bool
	// The new version's node drains accepted work for a few polls after its
	// app has gone.
	f.g.NodeStopped = func() bool { return polls.Add(1) > 5 }
	f.g.Restore = func(context.Context, *Pending) error {
		if polls.Load() <= 5 {
			restoredWhileBusy.Store(true)
		}
		f.restores.Add(1)
		return nil
	}
	if err := f.g.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := f.result(t)
	if restoredWhileBusy.Load() || f.restores.Load() != 1 || s.Pending.Phase != PhaseRolledBack {
		t.Fatalf("restored while the node was busy: %v, state %+v", restoredWhileBusy.Load(), s.Pending)
	}
}

func TestGuardReportsARestoreThatFailed(t *testing.T) {
	f := newGuardFixture(t, PhaseUnhealthy)
	f.g.Restore = func(context.Context, *Pending) error {
		return fail(CodeBusy, errors.New("scarlett-node.exe is still running"))
	}
	if err := f.g.Run(context.Background()); err == nil {
		t.Fatal("failed restore not reported")
	}
	s := f.result(t)
	// The new version stays installed and is relaunched; it must not claim
	// that the previous version was restored.
	if f.launches.Load() != 2 || s.Pending.Phase != PhaseFailed || s.Pending.Reason != "restore_failed" || !s.HasFailed("0.1.14") {
		t.Fatalf("launches %d state %+v", f.launches.Load(), s.Pending)
	}
}

// The previous bundle's staging root is swept only when it is the private
// root beside the app; a bundle anywhere else leaves its neighbours alone.
func TestGuardCleanupSweepsOnlyTheStagingRootBesideTheApp(t *testing.T) {
	base := t.TempDir()
	updates := filepath.Join(base, "state", "updates")
	app := filepath.Join(base, "Applications", guardTestApp)
	beside := filepath.Join(base, "Applications", ".Scarlett Node.update")
	previous := filepath.Join(beside, "stage-0.1.14-new", guardTestApp)
	stale := filepath.Join(beside, "stage-0.1.13-old")
	elsewhere := filepath.Join(base, "elsewhere")
	foreign := filepath.Join(elsewhere, "stage", guardTestApp)
	neighbour := filepath.Join(elsewhere, "neighbour")
	for _, dir := range []string{updates, app, previous, stale, foreign, neighbour} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	g := NewGuard(StateFile{Path: filepath.Join(base, "state", "update-state.json")}, updates)
	g.cleanup(&Pending{Kind: "mac-app", To: "0.1.14", App: app, Previous: previous})
	g.cleanup(&Pending{Kind: "mac-app", To: "0.1.14", App: app, Previous: foreign})
	for path, want := range map[string]bool{app: true, previous: true, stale: false, foreign: true, neighbour: true} {
		if _, err := os.Lstat(path); (err == nil) != want {
			t.Errorf("%s kept=%v, want %v", path, err == nil, want)
		}
	}
}

func TestNodeStoppedFollowsTheAttemptJournalLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := localfs.EnsureDir(filepath.Join(dir, "attempts")); err != nil {
		t.Fatal(err)
	}
	if !NodeStopped(dir) {
		t.Fatal("a node that never ran is not running")
	}
	lock, err := localfs.LockPrivate(filepath.Join(dir, "attempts", ".lock"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && NodeStopped(dir) {
		t.Fatal("a held journal lock reads as stopped")
	}
	lock.Close()
	if !NodeStopped(dir) {
		t.Fatal("a released journal lock reads as running")
	}
}
