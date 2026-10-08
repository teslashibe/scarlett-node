package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/update"
)

const updateUsage = "usage: scarlett-node update check [--json]|apply [--yes] [--bin DIR]|rollback [--bin DIR]|--auto [--bin DIR]|version"

// updateCommand is the headless updater. It changes nothing outside an
// install.sh layout, verifies every bundle against the pinned minisign keys
// and the manifest's SHA-256, never interrupts accepted work, and rolls back
// a version that fails to start.
func updateCommand(args []string, in io.Reader, out io.Writer) error {
	if len(args) == 1 && args[0] == "version" {
		return json.NewEncoder(out).Encode(map[string]string{"release": coordinator.NodeRelease, "platform": update.Platform()})
	}
	if len(args) == 0 {
		return errors.New(updateUsage)
	}
	action, rest := args[0], args[1:]
	jsonOut, yes, bin := false, false, ""
	for i := 0; i < len(rest); i++ {
		switch {
		case rest[i] == "--json" && action == "check":
			jsonOut = true
		case rest[i] == "--yes" && action == "apply":
			yes = true
		case rest[i] == "--bin" && i+1 < len(rest) && action != "check":
			bin = rest[i+1]
			i++
		default:
			return errors.New(updateUsage)
		}
	}
	if action != "check" && action != "apply" && action != "rollback" && action != "--auto" {
		return errors.New(updateUsage)
	}
	h, err := newHeadlessUpdater(bin, out)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch action {
	case "check":
		result, _, err := h.Check(ctx)
		if err != nil {
			return err
		}
		if jsonOut {
			return json.NewEncoder(out).Encode(result)
		}
		printCheck(out, result, h.Trust.CanVerify())
		return nil
	case "apply":
		if !yes {
			result, _, err := h.Check(ctx)
			if err != nil {
				return err
			}
			printCheck(out, result, h.Trust.CanVerify())
			if !result.Available {
				return nil
			}
			fmt.Fprintf(out, "Install Scarlett Node %s now? Accepted jobs finish first. [y/N] ", result.Latest)
			answer, _ := bufio.NewReader(in).ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
				return errors.New("update cancelled")
			}
		}
		return h.Apply(ctx, update.ApplyOptions{})
	case "rollback":
		return h.Rollback(ctx)
	}
	// --auto: the systemd timer entry point. Only SCARLETT_AUTO_UPDATE=install
	// installs; the default notify mode logs what is available.
	switch mode := strings.TrimSpace(os.Getenv("SCARLETT_AUTO_UPDATE")); mode {
	case "install":
		return h.Apply(ctx, update.ApplyOptions{Auto: true})
	case "", "notify":
		result, _, err := h.Check(ctx)
		if err != nil {
			return err
		}
		printCheck(out, result, h.Trust.CanVerify())
		return nil
	default:
		return errors.New("SCARLETT_AUTO_UPDATE is notify or install")
	}
}

func printCheck(out io.Writer, r update.CheckResult, canVerify bool) {
	switch {
	case !r.Available:
		fmt.Fprintf(out, "Scarlett Node %s is up to date (latest %s)\n", r.Current, r.Latest)
		return
	case r.Required:
		fmt.Fprintf(out, "Update required: Scarlett Node %s no longer receives new jobs. Install %s\n", r.Current, r.Latest)
	default:
		fmt.Fprintf(out, "Scarlett Node %s is available (running %s)\n", r.Latest, r.Current)
	}
	if r.Notes != nil {
		fmt.Fprintf(out, "%s\n", r.Notes.Title)
		for _, h := range r.Notes.Highlights {
			fmt.Fprintf(out, "  - %s\n", h)
		}
	}
	fmt.Fprintf(out, "What's new: %s\n", r.Changelog)
	if !canVerify || !r.Signed {
		fmt.Fprintln(out, "This release cannot be installed by scarlett-node update; download it from https://network.scarlett.ai/setup/install/")
	} else if r.Failed {
		fmt.Fprintln(out, "This version failed its checks here before; scarlett-node update apply retries it")
	} else {
		fmt.Fprintln(out, "Install it with: scarlett-node update apply")
	}
}

func updateStateDir() (string, error) {
	dir := os.Getenv("SCARLETT_STATE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = config.DefaultStateDir(home)
	}
	if !filepath.IsAbs(dir) {
		return "", errors.New("state directory must be absolute")
	}
	return dir, nil
}

// updateClient reads releases from the configured coordinator origin, which
// must be HTTPS; the default is network.scarlett.ai.
func updateClient() (*update.Client, error) {
	origin := os.Getenv("SCARLETT_COORDINATOR")
	if origin == "" {
		origin = update.DefaultOrigin
	}
	return update.NewClient(origin, os.Getenv("SCARLETT_COORDINATOR_CA_FILE"))
}

func newHeadlessUpdater(bin string, out io.Writer) (*update.Headless, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	layout, err := update.DetectLayout(exe)
	if err != nil {
		return nil, err
	}
	if bin == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		bin = filepath.Join(home, ".local", "bin")
	}
	if !filepath.IsAbs(bin) {
		return nil, errors.New("--bin must be absolute")
	}
	dir, err := updateStateDir()
	if err != nil {
		return nil, err
	}
	client, err := updateClient()
	if err != nil {
		return nil, err
	}
	trust, err := update.LoadTrust()
	if err != nil {
		return nil, err
	}
	systemd := runtime.GOOS == "linux"
	return &update.Headless{
		Layout: layout, Bin: bin, Client: client, Trust: trust, Out: out, Running: coordinator.NodeRelease, Platform: update.Platform(),
		State: update.StateFile{Path: filepath.Join(layout.Root, "update-state.json")},
		Status: func() (update.NodeStatus, error) {
			var s update.NodeStatus
			raw, err := readLocalFile(filepath.Join(dir, "status.json"), 16384)
			if err == nil {
				err = json.Unmarshal(raw, &s)
			}
			return s, err
		},
		Drained: func() (bool, error) { return drainRequested(dir) },
		Drain:   func() error { return localCommandDir(dir, "drain", io.Discard) },
		Resume:  func() error { return localCommandDir(dir, "resume", io.Discard) },
		ServiceActive: func() bool {
			return systemd && exec.Command("systemctl", "--user", "is-active", "--quiet", "scarlett-node.service").Run() == nil
		},
		RestartService: func() error {
			return exec.Command("systemctl", "--user", "restart", "scarlett-node.service").Run()
		},
		DrainTimeout: 30 * time.Minute, HealthWait: 3 * time.Minute, Poll: 2 * time.Second, Now: time.Now,
	}, nil
}
