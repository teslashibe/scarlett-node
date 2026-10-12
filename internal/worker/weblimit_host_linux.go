package worker

import (
	"bufio"
	"os"
	"sync"
	"time"
)

// linuxHost reads CPU use from /proc/stat and available memory from
// /proc/meminfo.
type linuxHost struct {
	mu  sync.Mutex
	cpu cpuWindow
}

// NewHostSampler samples this host for the adaptive web limit.
func NewHostSampler() HostSampler { return &linuxHost{} }

func (h *linuxHost) Sample(now time.Time) HostLoad {
	h.mu.Lock()
	defer h.mu.Unlock()
	load := HostLoad{Memory: MemoryNormal}
	// Only the aggregate first line: the rest of /proc/stat grows with cores
	// and interrupts.
	if f, err := os.Open("/proc/stat"); err == nil {
		line, _ := bufio.NewReaderSize(f, 512).ReadSlice('\n')
		f.Close()
		if busy, total, ok := parseProcStat(line); ok {
			load.CPU, load.CPUKnown = h.cpu.observe(now, busy, total)
		}
	}
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		if available, total, ok := parseMeminfo(raw); ok {
			load.Memory = memoryLevel(100 * float64(available) / float64(total))
		}
	}
	return load
}
