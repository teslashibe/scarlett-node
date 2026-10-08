//go:build unix

package webruntime

import (
	"os/exec"
	"syscall"
)

type proc struct {
	cmd  *exec.Cmd
	done <-chan struct{} // closed once the helper has been reaped
}

// startProcess starts the helper in a new process group.
func startProcess(cmd *exec.Cmd, _ uint64) (*proc, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &proc{cmd: cmd}, nil
}

func (p *proc) pid() int { return p.cmd.Process.Pid }

func (p *proc) reaped() bool {
	if p.done == nil {
		return false
	}
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// snapshot is the helper's descendant tree now (empty once it was reaped,
// since its PID may then belong to another process).
func (p *proc) snapshot() []procInfo {
	if p.reaped() {
		return nil
	}
	table, err := processTable()
	if err != nil {
		return []procInfo{{PID: p.pid(), PGID: p.pid()}}
	}
	return descendants(table, p.pid())
}

// kill SIGKILLs every process group and PID of the helper's tree: its live
// descendants, plus every process of an earlier snapshot that still exists
// with the same process group (its children are reparented once it exits;
// the group check keeps a reused PID safe).
func (p *proc) kill(earlier []procInfo) {
	table, err := processTable()
	var targets []procInfo
	if err != nil {
		if !p.reaped() {
			_ = syscall.Kill(-p.pid(), syscall.SIGKILL)
			_ = syscall.Kill(p.pid(), syscall.SIGKILL)
		}
		return
	}
	if !p.reaped() {
		targets = descendants(table, p.pid())
	}
	current := map[int]procInfo{}
	for _, row := range table {
		current[row.PID] = row
	}
	for _, e := range earlier {
		if row, ok := current[e.PID]; ok && row.PGID == e.PGID && !row.Zombie {
			targets = append(targets, row)
		}
	}
	groups, pids := killPlan(targets, syscall.Getpgrp())
	for _, g := range groups {
		_ = syscall.Kill(-g, syscall.SIGKILL)
	}
	for _, pid := range pids {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func (p *proc) treeBytes() (uint64, error) {
	table, err := processTable()
	if err != nil {
		return 0, err
	}
	return treeMemory(descendants(table, p.pid())), nil
}

func (p *proc) release() {}

// alive reports whether any process of the snapshot still runs (same PID and
// process group, not a zombie).
func alive(tree []procInfo) bool {
	table, err := processTable()
	if err != nil {
		return false
	}
	current := map[int]procInfo{}
	for _, row := range table {
		current[row.PID] = row
	}
	for _, p := range tree {
		if row, ok := current[p.PID]; ok && row.PGID == p.PGID && !row.Zombie {
			return true
		}
	}
	return false
}
