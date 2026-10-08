package webruntime

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// processTable reads parent and group from /proc/<pid>/stat. Memory is read
// per descendant (Pss, so shared pages are not counted once per process).
func processTable() ([]procInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, errors.New("process table unavailable")
	}
	var table []procInfo
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		if row, ok := parseStat(pid, raw); ok {
			table = append(table, row)
		}
	}
	return table, nil
}

func parseStat(pid int, raw []byte) (procInfo, bool) {
	// The command name may hold spaces or parentheses; fields follow the last ')'.
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return procInfo{}, false
	}
	f := strings.Fields(string(raw[end+1:]))
	if len(f) < 3 {
		return procInfo{}, false
	}
	ppid, e1 := strconv.Atoi(f[1])
	pgid, e2 := strconv.Atoi(f[2])
	if e1 != nil || e2 != nil {
		return procInfo{}, false
	}
	return procInfo{PID: pid, PPID: ppid, PGID: pgid, Zombie: f[0] == "Z"}, true
}

func treeMemory(tree []procInfo) uint64 {
	var total uint64
	for _, p := range tree {
		total += pss(p.PID)
	}
	return total
}

func pss(pid int) uint64 {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/smaps_rollup")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Pss:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				kb, _ := strconv.ParseUint(f[1], 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

func physicalMemory() (uint64, error) {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0, err
	}
	return uint64(info.Totalram) * uint64(info.Unit), nil
}
