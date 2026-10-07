package webruntime

import (
	"bufio"
	"bytes"
	"errors"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// processTable reads every process once from the fixed-path ps (the node
// builds without cgo, so proc_pid_rusage is out of reach). Bytes is RSS; the
// recycle and kill thresholds are set on RSS, which overcounts the macOS
// footprint by 1.09–1.27× (measured).
func processTable() ([]procInfo, error) {
	out, err := exec.Command("/bin/ps", "-A", "-o", "pid=,ppid=,pgid=,rss=,stat=").Output()
	if err != nil {
		return nil, errors.New("process table unavailable")
	}
	return parsePS(out), nil
}

func parsePS(out []byte) []procInfo {
	var table []procInfo
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		pid, e1 := strconv.Atoi(f[0])
		ppid, e2 := strconv.Atoi(f[1])
		pgid, e3 := strconv.Atoi(f[2])
		rss, e4 := strconv.ParseUint(f[3], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			continue
		}
		zombie := len(f) > 4 && strings.HasPrefix(f[4], "Z")
		if zombie {
			rss = 0
		}
		table = append(table, procInfo{PID: pid, PPID: ppid, PGID: pgid, Bytes: rss * 1024, Zombie: zombie})
	}
	return table
}

func treeMemory(tree []procInfo) uint64 { return sumBytes(tree) }

func physicalMemory() (uint64, error) { return unix.SysctlUint64("hw.memsize") }
