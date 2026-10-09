package webruntime

import (
	"context"
	"os/exec"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func detach(*exec.Cmd) {}

func processGone(pid int) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return true
	}
	defer windows.CloseHandle(h)
	event, _ := windows.WaitForSingleObject(h, 0)
	return event != uint32(windows.WAIT_TIMEOUT)
}

// The helper runs in a Job assigned before it ran: kill on close, a commit
// backstop of the kill threshold (from the memory rule) plus 2 GiB,
// below-normal priority.
func TestWindowsHelperJobAndPriority(t *testing.T) {
	s := newTestManager(t, "ok")
	s.prepare(t)
	if _, err := s.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.m.mu.Lock()
	h := s.m.helper
	s.m.mu.Unlock()
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(h.p.job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil); err != nil {
		t.Fatal(err)
	}
	// The test machine reports 32 GiB: kill = max(4.25 GiB, 8 GiB), so the
	// job limit follows the physical-memory rule, not the capacity alone.
	_, kill := Thresholds(2, 32<<30)
	if kill != 8*gib || limits.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 ||
		limits.BasicLimitInformation.LimitFlags&windows.JOB_OBJECT_LIMIT_JOB_MEMORY == 0 || uint64(limits.JobMemoryLimit) != jobMemoryLimit(kill) {
		t.Fatalf("job limits %+v", limits.BasicLimitInformation)
	}
	pids, err := h.p.jobPIDs()
	if err != nil || len(pids) == 0 || pids[0] != uint32(h.p.pid()) {
		t.Fatalf("helper not in its Job: %v %v", pids, err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(h.p.pid()))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(process)
	getPriority := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetPriorityClass")
	if class, _, _ := getPriority.Call(uintptr(process)); class != windows.BELOW_NORMAL_PRIORITY_CLASS {
		t.Fatalf("priority class %#x", class)
	}
}
