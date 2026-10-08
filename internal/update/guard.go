package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Guard finishes a desktop install after the app has exited: it replaces the
// app (macOS bundle swap or Windows installer), relaunches it, waits for the
// new version to report healthy and rolls back otherwise. It runs as a copy of
// the old node binary, outside the bundle it replaces.
type Guard struct {
	State   StateFile
	Updates string
	// Hooks; tests replace them.
	Install    func(ctx context.Context, p *Pending) error
	Restore    func(ctx context.Context, p *Pending) error
	Launch     func(app string) error
	Alive      func(pid int) bool
	Terminate  func(pid int, force bool)
	ExitWait   time.Duration
	HealthWait time.Duration
	Poll       time.Duration
	Log        io.Writer
}

// NewGuard returns a guard with this platform's install steps.
func NewGuard(state StateFile, updates string) *Guard {
	g := &Guard{State: state, Updates: updates, Launch: launchApp, Alive: processAlive, Terminate: terminateProcess,
		ExitWait: 60 * time.Second, HealthWait: 5 * time.Minute, Poll: 2 * time.Second, Log: io.Discard}
	g.Install, g.Restore = g.install, g.restore
	return g
}

func (g *Guard) logf(format string, args ...any) {
	fmt.Fprintf(g.Log, time.Now().UTC().Format(time.RFC3339)+" update guard: "+format+"\n", args...)
}

func (g *Guard) setPhase(phase, reason string, change func(*State)) (State, error) {
	return g.State.Update(func(s *State) error {
		if s.Pending == nil {
			return errors.New("no pending update")
		}
		s.Pending.Phase, s.Pending.Reason = phase, reason
		if change != nil {
			change(s)
		}
		return nil
	})
}

func (g *Guard) waitExit(pid int, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for pid > 0 && g.Alive(pid) {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(g.Poll / 4)
	}
	return true
}

// Run performs the hand-off recorded in the state file.
func (g *Guard) Run(ctx context.Context) error {
	s, err := g.State.Read()
	if err != nil {
		return err
	}
	p := s.Pending
	if p == nil || p.Phase != PhaseHandoff || (p.Kind != "mac-app" && p.Kind != "nsis") || p.App == "" || p.Staged == "" {
		return errors.New("no desktop update is waiting for the guard")
	}
	pid := os.Getpid()
	if _, err = g.State.Update(func(s *State) error { s.Pending.GuardPID = pid; return nil }); err != nil {
		return err
	}
	if !g.waitExit(p.AppPID, g.ExitWait) {
		g.logf("the app did not exit; nothing was replaced")
		_, err = g.setPhase(PhaseFailed, CodeBusy, nil)
		return err
	}
	g.logf("installing %s over %s", p.To, p.From)
	if err = g.Install(ctx, p); err != nil {
		g.logf("install failed: %v", err)
		_, _ = g.setPhase(PhaseFailed, CodeOf(err), nil)
		return errors.Join(err, g.Launch(p.App))
	}
	if _, err = g.setPhase(PhaseInstalled, "", func(s *State) { s.Pending.Previous = p.Previous; s.Pending.AppPID = 0 }); err != nil {
		return err
	}
	if err = g.Launch(p.App); err != nil {
		g.logf("relaunch failed: %v", err)
		return g.rollback(ctx, p, "launch_failed")
	}
	deadline := time.Now().Add(g.HealthWait)
	for {
		time.Sleep(g.Poll)
		current, err := g.State.Read()
		if err != nil || current.Pending == nil {
			return g.rollback(ctx, p, "state_lost")
		}
		switch current.Pending.Phase {
		case PhaseHealthy:
			g.logf("%s reported healthy", p.To)
			g.cleanup(p)
			return nil
		case PhaseUnhealthy:
			return g.rollback(ctx, p, current.Pending.Reason)
		case PhaseVerifying:
			if current.Pending.AppPID > 0 && !g.Alive(current.Pending.AppPID) {
				return g.rollback(ctx, p, "app_exited")
			}
		}
		if time.Now().After(deadline) {
			return g.rollback(ctx, p, "health_timeout")
		}
	}
}

func (g *Guard) rollback(ctx context.Context, p *Pending, reason string) error {
	if reason == "" {
		reason = "unhealthy"
	}
	g.logf("rolling back %s to %s: %s", p.To, p.From, reason)
	if current, err := g.State.Read(); err == nil && current.Pending != nil && current.Pending.AppPID > 0 && g.Alive(current.Pending.AppPID) {
		// The node child drains accepted work by itself when its owner exits,
		// so the app may be stopped; installers then wait for the sidecars.
		app := current.Pending.AppPID
		g.Terminate(app, false)
		if !g.waitExit(app, 30*time.Second) {
			g.Terminate(app, true)
			g.waitExit(app, 10*time.Second)
		}
	}
	err := g.Restore(ctx, p)
	_, stateErr := g.setPhase(PhaseRolledBack, reason, func(s *State) { s.MarkFailed(p.To) })
	launchErr := g.Launch(p.App)
	return errors.Join(err, stateErr, launchErr)
}

// cleanup keeps exactly one previous app or installer and removes downloads.
func (g *Guard) cleanup(p *Pending) {
	keep := map[string]bool{}
	for _, path := range []string{p.Previous, filepath.Join(g.Updates, "installed", p.To+".exe")} {
		if path != "" {
			keep[path] = true
			keep[filepath.Dir(path)] = true
		}
	}
	entries, _ := os.ReadDir(g.Updates)
	for _, entry := range entries {
		path := filepath.Join(g.Updates, entry.Name())
		if entry.Name() == "installed" {
			cached, _ := os.ReadDir(path)
			for _, c := range cached {
				if !keep[filepath.Join(path, c.Name())] {
					_ = os.Remove(filepath.Join(path, c.Name()))
				}
			}
			continue
		}
		// The guard's own copy and log stay: the log explains the last update.
		if keep[path] || strings.HasPrefix(entry.Name(), "guard-") || entry.Name() == "guard.log" {
			continue
		}
		_ = os.RemoveAll(path)
	}
	if p.Kind == "mac-app" && p.Previous != "" {
		// A staging root beside the app holds only the previous bundle now.
		root := filepath.Dir(filepath.Dir(p.Previous))
		if root != g.Updates {
			siblings, _ := os.ReadDir(root)
			for _, s := range siblings {
				if path := filepath.Join(root, s.Name()); path != filepath.Dir(p.Previous) {
					_ = os.RemoveAll(path)
				}
			}
		}
	}
}
