//go:build unix

package webruntime

import (
	"os/exec"
	"syscall"
)

// detach starts a fixture child in its own process group, as Playwright
// starts Chrome.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

func processGone(pid int) bool {
	table, err := processTable()
	if err != nil {
		return false
	}
	for _, row := range table {
		if row.PID == pid && !row.Zombie {
			return false
		}
	}
	return true
}
