package webruntime

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// processMemoryCounters is PROCESS_MEMORY_COUNTERS.
type processMemoryCounters struct {
	cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procK32GetProcessMemInfo = kernel32.NewProc("K32GetProcessMemoryInfo")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
)

// treeBytes sums the working set of every process in the Job.
func (p *proc) treeBytes() (uint64, error) {
	pids, err := p.jobPIDs()
	if err != nil {
		return 0, err
	}
	var total uint64
	for _, pid := range pids {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			continue
		}
		var counters processMemoryCounters
		counters.cb = uint32(unsafe.Sizeof(counters))
		if r, _, _ := procK32GetProcessMemInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&counters)), uintptr(counters.cb)); r != 0 {
			total += uint64(counters.WorkingSetSize)
		}
		windows.CloseHandle(h)
	}
	return total, nil
}

// memoryStatusEx is MEMORYSTATUSEX.
type memoryStatusEx struct {
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

func physicalMemory() (uint64, error) {
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	if r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status))); r == 0 {
		return 0, err
	}
	return status.TotalPhys, nil
}
