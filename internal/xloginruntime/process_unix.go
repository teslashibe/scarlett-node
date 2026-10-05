//go:build !windows

package xloginruntime

import (
	"os/exec"
	"syscall"
)

func configureProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func killProcess(cmd *exec.Cmd)      { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }

// Reap any surviving browser children even if the Node parent crashes first.
func containProcess(cmd *exec.Cmd) (func(), error) { return func() { killProcess(cmd) }, nil }
