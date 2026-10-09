package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

func (g *Guard) install(_ context.Context, p *Pending) error {
	if p.Kind != "mac-app" || filepath.Base(p.Staged) != AppName || filepath.Base(p.App) != AppName {
		return fail(CodeUnsupported, errors.New("not a Mac app update"))
	}
	if err := SwapApp(p.Staged, p.App); err != nil {
		return err
	}
	// The previous bundle now sits at the staged path, on the same volume.
	p.Previous = p.Staged
	return nil
}

func (g *Guard) restore(_ context.Context, p *Pending) error {
	if p.Previous == "" {
		return errors.New("no previous app to restore")
	}
	if err := SwapApp(p.Previous, p.App); err != nil {
		return err
	}
	// The failed bundle is now at Previous; it is never launched again.
	return os.RemoveAll(filepath.Dir(p.Previous))
}

func launchApp(app string) error { return LaunchApp(app) }

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func terminateProcess(pid int, force bool) {
	if force {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	} else {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
}
