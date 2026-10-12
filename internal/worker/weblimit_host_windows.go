package worker

import (
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	webLimitKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procWebGetSystemTimes     = webLimitKernel32.NewProc("GetSystemTimes")
	procWebGlobalMemoryStatus = webLimitKernel32.NewProc("GlobalMemoryStatusEx")
)

// webMemoryStatus is MEMORYSTATUSEX.
type webMemoryStatus struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// windowsHost reads CPU use from GetSystemTimes and memory in use from
// GlobalMemoryStatusEx.
type windowsHost struct {
	mu  sync.Mutex
	cpu cpuWindow
}

// NewHostSampler samples this host for the adaptive web limit.
func NewHostSampler() HostSampler { return &windowsHost{} }

func (h *windowsHost) Sample(now time.Time) HostLoad {
	h.mu.Lock()
	defer h.mu.Unlock()
	load := HostLoad{Memory: MemoryNormal}
	var idle, kernel, user windows.Filetime
	if r, _, _ := procWebGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user))); r != 0 {
		// Kernel time includes idle time.
		total := filetimeTicks(kernel) + filetimeTicks(user)
		if idleTicks := filetimeTicks(idle); idleTicks <= total {
			load.CPU, load.CPUKnown = h.cpu.observe(now, total-idleTicks, total)
		}
	}
	status := webMemoryStatus{Length: uint32(unsafe.Sizeof(webMemoryStatus{}))}
	if r, _, _ := procWebGlobalMemoryStatus.Call(uintptr(unsafe.Pointer(&status))); r != 0 && status.MemoryLoad <= 100 {
		load.Memory = memoryLevel(float64(100 - status.MemoryLoad))
	}
	return load
}

func filetimeTicks(f windows.Filetime) uint64 {
	return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime)
}
