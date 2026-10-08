package webruntime

import (
	"errors"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// proc is the helper inside a private Job object: every descendant is in it,
// closing the last handle kills them all, and its memory limit is only a
// commit-charge backstop (recycle and kill use the working set).
type proc struct {
	cmd  *exec.Cmd
	job  windows.Handle
	done <-chan struct{}
}

// startProcess follows internal/process.Run: started suspended so nothing
// runs before the Job holds it, no window, below-normal priority (inherited
// by Python, the driver and Chrome), then resumed.
func startProcess(cmd *exec.Cmd, jobMemory uint64) (*proc, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_JOB_MEMORY
	limits.JobMemoryLimit = uintptr(jobMemory)
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
		CreationFlags: windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.BELOW_NORMAL_PRIORITY_CLASS}
	if err = cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	abort := func(err error) (*proc, error) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		windows.CloseHandle(job)
		return nil, err
	}
	child, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return abort(err)
	}
	err = windows.AssignProcessToJobObject(job, child)
	windows.CloseHandle(child)
	if err != nil {
		return abort(err)
	}
	if err = resumeInitialThread(uint32(cmd.Process.Pid)); err != nil {
		return abort(err)
	}
	return &proc{cmd: cmd, job: job}, nil
}

func resumeInitialThread(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID != pid {
			continue
		}
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
		if err != nil {
			return err
		}
		previous, err := windows.ResumeThread(thread)
		windows.CloseHandle(thread)
		if err != nil {
			return err
		}
		if previous != 1 {
			return errors.New("helper initial thread was not suspended")
		}
		return nil
	}
	return errors.New("cannot find suspended helper initial thread")
}

func (p *proc) pid() int { return p.cmd.Process.Pid }

func (p *proc) snapshot() []procInfo {
	pids, _ := p.jobPIDs()
	tree := make([]procInfo, 0, len(pids))
	for _, pid := range pids {
		tree = append(tree, procInfo{PID: int(pid)})
	}
	return tree
}

// kill terminates every process in the Job.
func (p *proc) kill(_ []procInfo) { _ = windows.TerminateJobObject(p.job, 1) }

func (p *proc) release() { windows.CloseHandle(p.job) }

func (p *proc) jobPIDs() ([]uint32, error) {
	const capacity = 4096
	buf := make([]byte, 8+capacity*unsafe.Sizeof(uintptr(0)))
	if err := windows.QueryInformationJobObject(p.job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&buf[0])), uint32(len(buf)), nil); err != nil {
		return nil, err
	}
	count := *(*uint32)(unsafe.Pointer(&buf[4]))
	pids := make([]uint32, 0, count)
	for i := uint32(0); i < count && i < capacity; i++ {
		pids = append(pids, uint32(*(*uintptr)(unsafe.Pointer(&buf[8+uintptr(i)*unsafe.Sizeof(uintptr(0))]))))
	}
	return pids, nil
}

func alive(tree []procInfo) bool {
	for _, p := range tree {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(p.PID))
		if err != nil {
			continue
		}
		event, _ := windows.WaitForSingleObject(h, 0)
		windows.CloseHandle(h)
		if event == uint32(windows.WAIT_TIMEOUT) {
			return true
		}
	}
	return false
}
