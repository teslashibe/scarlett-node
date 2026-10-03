//go:build unix

// Package process bounds locally configured helper process lifetimes.
package process

import (
	"os/exec"
)

func Run(cmd *exec.Cmd) error {
	return cmd.Run()
}
