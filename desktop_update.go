package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/update"
)

// Desktop updater helpers. The native shell passes only its own state
// directory (SCARLETT_STATE_DIR) and fixed coordinator origin; the renderer
// never supplies a path, URL or version. Every network read and byte check
// happens here, in the node's Go code, so desktop and headless share it.

// desktopUpdateCheck reports the selected release without downloading it.
type desktopUpdateCheck struct {
	Running   string        `json:"running"`
	Latest    string        `json:"latest"`
	Available bool          `json:"available"`
	Signed    bool          `json:"signed"`
	CanVerify bool          `json:"can_verify"`
	Failed    bool          `json:"failed"`
	Notes     *update.Notes `json:"notes,omitempty"`
	// RolloutSeconds is this node's place in the optional-update window.
	RolloutSeconds int64 `json:"rollout_seconds"`
}

func desktopUpdateCommand(args []string, input io.Reader, out io.Writer) error {
	dir, err := desktopUpdateDir()
	if err != nil {
		return err
	}
	state := update.StateFile{Path: filepath.Join(dir, "update-state.json")}
	switch {
	case len(args) == 1 && args[0] == "update-check":
		return desktopCheck(dir, state, out)
	case len(args) == 2 && args[0] == "update-stage" && (args[1] == "auto" || args[1] == "auto-throttled" || args[1] == "manual"):
		return desktopStage(dir, state, args[1], out)
	case len(args) == 1 && args[0] == "update-state-get":
		r, err := state.ReadRevisioned()
		if err != nil {
			return errors.New("update state unavailable")
		}
		return json.NewEncoder(out).Encode(r)
	case len(args) == 1 && args[0] == "update-state-set":
		// A compare-and-swap: the shell sends the revision it read, and a state
		// changed since then is refused with {"conflict":true} so that the
		// shell reads it again and reapplies its change.
		raw, err := io.ReadAll(io.LimitReader(input, 17<<10))
		if err != nil {
			return errors.New("update state unavailable")
		}
		next, err := update.DecodeRevisioned(bytes.TrimSpace(raw))
		if err != nil {
			return err
		}
		written, err := state.CompareAndSwap(next)
		if errors.Is(err, update.ErrStateChanged) {
			return json.NewEncoder(out).Encode(map[string]bool{"conflict": true})
		}
		if err != nil {
			return errors.New("update state unavailable")
		}
		return json.NewEncoder(out).Encode(written)
	case len(args) == 1 && args[0] == "update-guard":
		return desktopGuard(dir, state)
	}
	return errors.New("usage: scarlett-node desktop update-check|update-stage auto|auto-throttled|manual|update-state-get|update-state-set|update-guard")
}

func desktopUpdateDir() (string, error) {
	dir := os.Getenv("SCARLETT_STATE_DIR")
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || localfs.CheckDir(dir) != nil {
		return "", errors.New("desktop private storage unavailable")
	}
	return dir, nil
}

func nodeIDFromIdentity(dir string) string {
	f, err := localfs.OpenPrivate(filepath.Join(dir, "identity.json"))
	if err != nil {
		return ""
	}
	defer f.Close()
	var id identity
	if raw, err := io.ReadAll(io.LimitReader(f, 8193)); err == nil && len(raw) <= 8192 && json.Unmarshal(raw, &id) == nil {
		return id.NodeID
	}
	return ""
}

func desktopCheck(dir string, state update.StateFile, out io.Writer) error {
	client, err := updateClient()
	if err != nil {
		return err
	}
	trust, err := update.LoadTrust()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	m, err := client.Manifest(ctx)
	if err != nil {
		return json.NewEncoder(out).Encode(map[string]string{"error": update.CodeOf(err)})
	}
	s, _ := state.Read()
	_, signedErr := m.Desktop(update.Platform())
	result := desktopUpdateCheck{
		Running: coordinator.NodeRelease, Latest: m.Version, Notes: m.Notes,
		Available: coordinator.CompareVersions(m.Version, coordinator.NodeRelease) > 0 && (s.HighWater == "" || coordinator.CompareVersions(m.Version, s.HighWater) >= 0),
		Signed:    signedErr == nil, CanVerify: trust.CanVerify(), Failed: s.HasFailed(m.Version),
		RolloutSeconds: int64(update.RolloutOffset(nodeIDFromIdentity(dir), m.Version) / time.Second),
	}
	return json.NewEncoder(out).Encode(result)
}

// stageEvent is one JSON line of update-stage progress.
type stageEvent struct {
	Phase    string        `json:"phase"`
	Version  string        `json:"version,omitempty"`
	Received int64         `json:"received,omitempty"`
	Total    int64         `json:"total,omitempty"`
	Kind     string        `json:"kind,omitempty"`
	Notes    *update.Notes `json:"notes,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// desktopStage downloads and verifies the selected release and leaves it
// staged in update-state.json. It reports progress as JSON lines and exits on
// the first refusal with a fixed code. The shell cancels it by closing stdin
// or ending the process.
func desktopStage(dir string, state update.StateFile, mode string, out io.Writer) error {
	var mu sync.Mutex
	emit := func(e stageEvent) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(out).Encode(e)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); cancel() }()
	staged, err := stageDesktop(ctx, dir, state, mode, emit)
	if err != nil {
		emit(stageEvent{Phase: "error", Error: update.CodeOf(err)})
		return nil
	}
	emit(staged)
	return nil
}

func stageDesktop(ctx context.Context, dir string, state update.StateFile, mode string, emit func(stageEvent)) (stageEvent, error) {
	trust, err := update.LoadTrust()
	if err != nil {
		return stageEvent{}, err
	}
	if !trust.CanVerify() {
		return stageEvent{}, &update.Error{Code: update.CodeNoKey}
	}
	exe, err := os.Executable()
	if err != nil {
		return stageEvent{}, err
	}
	app, err := installedTarget(exe)
	if err != nil {
		return stageEvent{}, err
	}
	client, err := updateClient()
	if err != nil {
		return stageEvent{}, err
	}
	emit(stageEvent{Phase: "checking"})
	m, err := client.Manifest(ctx)
	if err != nil {
		return stageEvent{}, err
	}
	s, err := state.Read()
	if err != nil {
		return stageEvent{}, err
	}
	if coordinator.CompareVersions(m.Version, coordinator.NodeRelease) <= 0 || (s.HighWater != "" && coordinator.CompareVersions(m.Version, s.HighWater) < 0) {
		return stageEvent{}, &update.Error{Code: update.CodeUnsupported, Err: errors.New("no newer release")}
	}
	if mode != "manual" && s.HasFailed(m.Version) {
		return stageEvent{}, &update.Error{Code: update.CodeInstallFailed, Err: errors.New("this version failed here before")}
	}
	target, err := m.Desktop(update.Platform())
	if err != nil {
		return stageEvent{}, &update.Error{Code: update.CodeUnsupported, Err: err}
	}
	updates := filepath.Join(dir, "updates")
	downloads := filepath.Join(updates, "downloads")
	for _, d := range []string{updates, downloads} {
		if err = localfs.EnsureDir(d); err != nil {
			return stageEvent{}, err
		}
	}
	var last time.Time
	options := update.DownloadOptions{Progress: func(received, total int64) {
		if now := time.Now(); now.Sub(last) > 500*time.Millisecond || received == total {
			last = now
			emit(stageEvent{Phase: "downloading", Version: target.Version, Received: received, Total: total})
		}
	}}
	if mode == "auto-throttled" {
		// A serving node keeps its MPC-TLS latency.
		options.RateLimit = 4 << 20
	}
	file, err := client.Download(ctx, target, downloads, trust.Keys, true, options)
	if err != nil {
		return stageEvent{}, err
	}
	emit(stageEvent{Phase: "verifying", Version: target.Version})
	pending := &update.Pending{Phase: update.PhaseStaged, From: coordinator.NodeRelease, To: target.Version, App: app, DrainOwner: "none", StartedAt: time.Now().Unix()}
	switch runtime.GOOS {
	case "darwin":
		pending.Kind = "mac-app"
		pending.Staged, err = stageMacApp(ctx, file, target, trust, app, updates)
	case "windows":
		pending.Kind = "nsis"
		pending.Staged, pending.Previous, err = stageWindowsInstaller(ctx, client, file, target, trust, updates)
	default:
		err = &update.Error{Code: update.CodeUnsupported}
	}
	if err != nil {
		return stageEvent{}, err
	}
	if _, err = state.Update(func(s *update.State) error {
		if s.Pending != nil && s.Pending.Phase != update.PhaseStaged && s.Pending.Phase != update.PhaseFailed && s.Pending.Phase != update.PhaseRolledBack && s.Pending.Phase != update.PhaseHealthy {
			return &update.Error{Code: update.CodeBusy}
		}
		s.Pending = pending
		return nil
	}); err != nil {
		return stageEvent{}, err
	}
	return stageEvent{Phase: "staged", Version: target.Version, Kind: pending.Kind, Notes: m.Notes}, nil
}

func desktopGuard(dir string, state update.StateFile) error {
	updates := filepath.Join(dir, "updates")
	log, err := os.OpenFile(filepath.Join(updates, "guard.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer log.Close()
	g := update.NewGuard(state, updates)
	g.Log = log
	return g.Run(context.Background())
}
