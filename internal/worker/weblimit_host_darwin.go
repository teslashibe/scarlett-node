package worker

import (
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// darwinPressureCritical is kern.memorystatus_vm_pressure_level's critical
// level (1 normal, 2 warn, 4 critical), the one at which the browser tier
// kills its helper (internal/webruntime pressureCritical).
const darwinPressureCritical = 4

// darwinHost reads the one-minute load average per CPU and the kernel's
// memory status, by sysctl: the node builds without cgo.
type darwinHost struct{}

// NewHostSampler samples this host for the adaptive web limit.
func NewHostSampler() HostSampler { return darwinHost{} }

func (darwinHost) Sample(time.Time) HostLoad {
	load := HostLoad{Memory: MemoryNormal}
	if raw, err := unix.SysctlRaw("vm.loadavg"); err == nil {
		load.CPU, load.CPUKnown = parseLoadavg(raw, runtime.NumCPU())
	}
	if level, err := unix.SysctlUint32("kern.memorystatus_vm_pressure_level"); err == nil && level >= darwinPressureCritical {
		load.Memory = MemoryCritical
	} else if free, err := unix.SysctlUint32("kern.memorystatus_level"); err == nil && free <= 100 {
		// The system-wide memory free percentage, as memory_pressure prints it.
		load.Memory = memoryLevel(float64(free))
	}
	return load
}
