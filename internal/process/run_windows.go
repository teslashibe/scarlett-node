package process

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Start suspended so the helper cannot spawn a child before job assignment.
// No breakaway flag is granted. The non-inheritable job kills all descendants
// on cancellation, helper exit, or a node crash closing its final job handle.
func Run(cmd *exec.Cmd) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return err
	}
	flags := uint32(windows.CREATE_SUSPENDED)
	if cmd.SysProcAttr != nil {
		flags |= cmd.SysProcAttr.CreationFlags & windows.CREATE_NO_WINDOW
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags}
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error {
		// Also cover cancellation in the short suspended-start/assignment window.
		windows.TerminateJobObject(job, 1)
		return cmd.Process.Kill()
	}
	if err = cmd.Start(); err != nil {
		return err
	}
	abort := func(err error) error { cmd.Process.Kill(); cmd.Wait(); return err }
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
	return cmd.Wait()
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
