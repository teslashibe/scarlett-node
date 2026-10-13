package worker

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"time"
)

// The adaptive web limit's host signals (weblimit_host_<os>.go). Memory is
// the share of physical memory available to new work: under
// webMemoryWarnPercent the limit holds, under webMemoryCriticalPercent it
// halves, and so does macOS's own critical pressure level. macOS's warn level
// alone is normal here, as for the browser tier (internal/webruntime): healthy
// Macs sit at warn for hours (a 64 GiB Mac with 52% of its memory free read
// warn). An unreadable signal is normal memory and unknown CPU.
const (
	webMemoryWarnPercent     = 15
	webMemoryCriticalPercent = 5
	// webCPUSpan is the least span CPU use is measured over from cumulative
	// counters (Linux and Windows); macOS reads its one-minute load average.
	webCPUSpan = 5 * time.Second
)

// memoryLevel maps the percentage of physical memory available.
func memoryLevel(availablePercent float64) MemoryLevel {
	switch {
	case availablePercent < webMemoryCriticalPercent:
		return MemoryCritical
	case availablePercent < webMemoryWarnPercent:
		return MemoryWarn
	}
	return MemoryNormal
}

// cpuWindow turns cumulative busy and total CPU time into the share that was
// busy over the last webCPUSpan or more.
type cpuWindow struct {
	at          time.Time
	busy, total uint64
	use         float64
	known       bool
}

func (w *cpuWindow) observe(now time.Time, busy, total uint64) (float64, bool) {
	switch {
	case w.at.IsZero() || now.Before(w.at) || busy < w.busy || total < w.total:
		// The first reading, or counters or a clock that went back.
		w.at, w.busy, w.total = now, busy, total
	case now.Sub(w.at) >= webCPUSpan && total > w.total:
		w.use, w.known = min(1, float64(busy-w.busy)/float64(total-w.total)), true
		w.at, w.busy, w.total = now, busy, total
	}
	return w.use, w.known
}

// parseLoadavg reads macOS's vm.loadavg (struct loadavg: three uint32
// fixed-point load averages, then a 64-bit long scale at offset 16) as the
// one-minute load per CPU, at most 1.
func parseLoadavg(raw []byte, cpus int) (float64, bool) {
	if len(raw) < 24 || cpus < 1 {
		return 0, false
	}
	scale := binary.LittleEndian.Uint64(raw[16:24])
	if scale == 0 {
		return 0, false
	}
	load := float64(binary.LittleEndian.Uint32(raw[0:4])) / float64(scale)
	return min(1, load/float64(cpus)), true
}

// parseProcStat reads the aggregate cpu line of Linux /proc/stat as busy and
// total time: user, nice, system, idle, iowait, irq, softirq and steal, with
// idle and iowait not busy. guest time is already inside user and nice.
func parseProcStat(raw []byte) (busy, total uint64, ok bool) {
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	fields := strings.Fields(string(line))
	if len(fields) < 9 || fields[0] != "cpu" {
		return 0, 0, false
	}
	var v [8]uint64
	for i := range v {
		n, err := strconv.ParseUint(fields[i+1], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		v[i] = n
	}
	for _, n := range v {
		total += n
	}
	idle := v[3] + v[4]
	if total == 0 || idle > total {
		return 0, 0, false
	}
	return total - idle, total, true
}

// parseMeminfo reads MemAvailable and MemTotal from Linux /proc/meminfo, in kB.
func parseMeminfo(raw []byte) (available, total uint64, ok bool) {
	var haveAvailable, haveTotal bool
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemAvailable:":
			available, haveAvailable = n, true
		case "MemTotal:":
			total, haveTotal = n, true
		}
	}
	return available, total, haveAvailable && haveTotal && total > 0 && available <= total
}
