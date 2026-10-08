package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// Guard finishes a desktop install after the app has exited: it replaces the
// app (macOS bundle swap or Windows installer), relaunches it, waits for the
// new version to report healthy and rolls back otherwise. It runs as a copy of
// the old node binary, outside the bundle it replaces.
type Guard struct {
	State   StateFile
	Updates string
	// Hooks; tests replace them.
	Install   func(ctx context.Context, p *Pending) error
	Restore   func(ctx context.Context, p *Pending) error
	Launch    func(app string) error
	Alive     func(pid int) bool
	Terminate func(pid int, force bool)
	// NodeStopped reports that no node process still holds the attempt
	// journal, so the restored app can start its own node.
	NodeStopped func() bool
	ExitWait    time.Duration
	HealthWait  time.Duration
	// QuitWait is how long an app that reported itself unhealthy gets to
	// finish its own draining shutdown; NodeWait how long its node gets to
	// finish accepted work after the app has gone.
	QuitWait time.Duration
	NodeWait time.Duration
	Poll     time.Duration
	Log      io.Writer
}

// NewGuard returns a guard with this platform's install steps.
func NewGuard(state StateFile, updates string) *Guard {
	g := &Guard{State: state, Updates: updates, Launch: launchApp, Alive: processAlive, Terminate: terminateProcess,
		ExitWait: 60 * time.Second, HealthWait: 5 * time.Minute, QuitWait: 150 * time.Second, NodeWait: 3 * time.Minute,
		Poll: 2 * time.Second, Log: io.Discard}
	g.Install, g.Restore = g.install, g.restore
	g.NodeStopped = func() bool { return NodeStopped(filepath.Dir(state.Path)) }
	return g
}

// NodeStopped reports whether no node process holds the attempt journal in
// stateDir. A node keeps that lock for its whole run, including the drain of
// accepted work after its owner exits.
func NodeStopped(stateDir string) bool {
	path := filepath.Join(stateDir, "attempts", ".lock")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return true
	}
	lock, err := localfs.LockPrivate(path)
	if err != nil {
		return false
	}
	_ = lock.Close()
	return true
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
	// A version that could not be installed is skipped by automatic mode
	// until the operator retries it: otherwise a lasting refusal (such as
	// macOS App Management) would quit and relaunch the app, stopping the
	// node, on every automatic attempt.
	markFailed := func(s *State) { s.MarkFailed(p.To) }
	if !g.waitExit(p.AppPID, g.ExitWait) {
		g.logf("the app did not exit; nothing was replaced")
		_, err = g.setPhase(PhaseFailed, CodeBusy, markFailed)
		return err
	}
	g.logf("installing %s over %s", p.To, p.From)
	if err = g.Install(ctx, p); err != nil {
		g.logf("install failed: %v", err)
		_, _ = g.setPhase(PhaseFailed, CodeOf(err), markFailed)
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
		app := current.Pending.AppPID
		// An app that found itself unhealthy is already quitting through its
		// draining shutdown; let it finish before asking it to stop.
		if current.Pending.Phase == PhaseUnhealthy {
			g.waitExit(app, g.QuitWait)
		}
		if g.Alive(app) {
			g.Terminate(app, false)
			if !g.waitExit(app, 30*time.Second) {
				g.Terminate(app, true)
				g.waitExit(app, 10*time.Second)
			}
		}
	}
	// A node whose app was stopped drains accepted work by itself. Restoring
	// waits for it: the Windows installer cannot replace a running node, and
	// the restored app cannot start its own node while this one holds the
	// attempt journal.
	if g.NodeStopped != nil {
		deadline := time.Now().Add(g.NodeWait)
		for !g.NodeStopped() && time.Now().Before(deadline) {
			time.Sleep(g.Poll)
		}
	}
	if err := g.Restore(ctx, p); err != nil {
		// Nothing was restored: the new version stays installed and says so
		// when it opens, instead of claiming the previous one is back.
		g.logf("restore failed: %v", err)
		_, stateErr := g.setPhase(PhaseFailed, "restore_failed", func(s *State) { s.MarkFailed(p.To) })
		return errors.Join(err, stateErr, g.Launch(p.App))
	}
	_, stateErr := g.setPhase(PhaseRolledBack, reason, func(s *State) { s.MarkFailed(p.To) })
	launchErr := g.Launch(p.App)
	return errors.Join(stateErr, launchErr)
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
		// The guard's own copy and log stay: the log explains the last update,
		// and the copy keeps one fixed path so that a macOS App Management
		// grant, if the system asks for one, still applies next time.
		if keep[path] || entry.Name() == "guard" || entry.Name() == "guard.log" {
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
