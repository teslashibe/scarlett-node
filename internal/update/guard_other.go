//go:build !darwin && !windows

package update

import (
	"context"
	"errors"
	"syscall"
)

var errNoDesktop = fail(CodeUnsupported, errors.New("desktop updates are available on macOS and Windows"))

func (g *Guard) install(context.Context, *Pending) error { return errNoDesktop }
func (g *Guard) restore(context.Context, *Pending) error { return errNoDesktop }
func launchApp(string) error                             { return errNoDesktop }

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
