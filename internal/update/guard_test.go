package update

import (
	"context"
	"errors"
	"path/filepath"
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
}

func newGuardFixture(t *testing.T, phaseAfterLaunch string) *guardFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	f := &guardFixture{state: StateFile{Path: filepath.Join(dir, "update-state.json")}}
	if err := f.state.Write(State{Schema: 1, Installed: "0.1.13", HighWater: "0.1.13", Pending: &Pending{Phase: PhaseHandoff, From: "0.1.13", To: "0.1.14", Kind: "mac-app",
		Staged: "/tmp/stage/Scarlett Node.app", App: "/Applications/Scarlett Node.app", DrainOwner: "updater", ResumeServing: true, AppPID: 4242, StartedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	g := NewGuard(f.state, filepath.Join(dir, "updates"))
	g.Poll, g.ExitWait, g.HealthWait = 10*time.Millisecond, 100*time.Millisecond, 500*time.Millisecond
	g.Alive = func(pid int) bool { return pid == 4242 && f.alive.Load() || pid == 5151 && f.alive.Load() }
	g.Terminate = func(int, bool) { f.terminate.Add(1); f.alive.Store(false) }
	g.Install = func(_ context.Context, p *Pending) error { f.installs.Add(1); p.Previous = p.Staged; return nil }
	g.Restore = func(context.Context, *Pending) error { f.restores.Add(1); return nil }
	g.Launch = func(string) error {
		f.launches.Add(1)
		if phaseAfterLaunch == "" || f.launches.Load() > 1 {
			return nil
		}
		// The relaunched app reports, as setup() does.
		go func() {
			time.Sleep(30 * time.Millisecond)
			f.alive.Store(true)
			_, _ = f.state.Update(func(s *State) error {
				s.Pending.Phase, s.Pending.AppPID = PhaseVerifying, 5151
				return nil
			})
			time.Sleep(30 * time.Millisecond)
			_, _ = f.state.Update(func(s *State) error {
				s.Pending.Phase = phaseAfterLaunch
				if phaseAfterLaunch == PhaseUnhealthy {
					s.Pending.Reason = "node_exited"
				}
				return nil
			})
		}()
		return nil
	}
	f.g = g
	return f
}

func TestGuardInstallsRelaunchesAndKeepsAHealthyUpdate(t *testing.T) {
	f := newGuardFixture(t, PhaseHealthy)
	if err := f.g.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, _ := f.state.Read()
	if f.installs.Load() != 1 || f.restores.Load() != 0 || f.launches.Load() != 1 || s.Pending.Phase != PhaseHealthy || s.HasFailed("0.1.14") {
		t.Fatalf("installs %d restores %d launches %d state %+v", f.installs.Load(), f.restores.Load(), f.launches.Load(), s.Pending)
	}
}

func TestGuardRollsBackAnUnhealthyOrSilentUpdate(t *testing.T) {
	for _, phase := range []string{PhaseUnhealthy, ""} {
		f := newGuardFixture(t, phase)
		if err := f.g.Run(context.Background()); err != nil {
			t.Fatal(err)
		}
		s, _ := f.state.Read()
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
	s, _ := f.state.Read()
	if f.installs.Load() != 0 || f.launches.Load() != 0 || s.Pending.Phase != PhaseFailed || s.Pending.Reason != CodeBusy {
		t.Fatalf("state %+v", s.Pending)
	}
}

func TestGuardRelaunchesTheOldAppWhenTheInstallFails(t *testing.T) {
	f := newGuardFixture(t, PhaseHealthy)
	f.g.Install = func(context.Context, *Pending) error { return fail(CodeAppManagement, errors.New("EPERM")) }
	if err := f.g.Run(context.Background()); err == nil {
		t.Fatal("install failure not reported")
	}
	s, _ := f.state.Read()
	if f.launches.Load() != 1 || s.Pending.Phase != PhaseFailed || s.Pending.Reason != CodeAppManagement {
		t.Fatalf("state %+v", s.Pending)
	}
}
