package main

import (
	"golang.org/x/sys/windows"
	"os/exec"
	"syscall"
)

// process.Run starts suspended and owns the full process tree in a kill-on-close
// Job Object. Closing the owner's input cancels that job without PID signaling.
func configureDesktopAPI(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
}
func cleanupDesktopAPI(cmd *exec.Cmd) {}
