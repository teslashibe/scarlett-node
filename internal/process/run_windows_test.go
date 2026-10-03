package process

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWindowsProcessHarness(t *testing.T) {
	mode := os.Getenv("SCARLETT_PROCESS_TEST_MODE")
	if mode == "" {
		return
	}
	if mode == "grandchild" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	exe, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	child := exec.CommandContext(context.Background(), exe, "-test.run=^TestWindowsProcessHarness$")
	if mode == "owner" {
		child.Env = append(os.Environ(), "SCARLETT_PROCESS_TEST_MODE=spawn")
		if Run(child) != nil {
			os.Exit(3)
		}
		os.Exit(0)
	}
	child.Env = append(os.Environ(), "SCARLETT_PROCESS_TEST_MODE=grandchild")
	if child.Start() != nil {
		os.Exit(4)
	}
	pidPath := os.Getenv("SCARLETT_PROCESS_TEST_PID")
	// Publish only after the file is complete. The parent polls this path and
	// can otherwise read the empty file between creation and writing its PID.
	if os.WriteFile(pidPath+".tmp", []byte(strconv.Itoa(child.Process.Pid)), 0600) != nil || os.Rename(pidPath+".tmp", pidPath) != nil {
		os.Exit(5)
	}
	child.Wait()
	os.Exit(0)
}

func waitDescendant(t *testing.T, path string) windows.Handle {
	t.Helper()
	until := time.Now().Add(15 * time.Second)
	for time.Now().Before(until) {
		raw, err := os.ReadFile(path)
		if err == nil {
			pid, err := strconv.Atoi(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
			if err != nil {
				t.Fatal(err)
			}
			return h
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("helper did not start its descendant")
	return 0
}

func TestWindowsJobTerminatesDescendantsOnCancellationAndOwnerCrash(t *testing.T) {
	for _, crash := range []bool{false, true} {
		t.Run(strconv.FormatBool(crash), func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			pidFile := filepath.Join(t.TempDir(), "synthetic-child.pid")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestWindowsProcessHarness$")
			mode := "spawn"
			if crash {
				mode = "owner"
			}
			cmd.Env = append(os.Environ(), "SCARLETT_PROCESS_TEST_MODE="+mode, "SCARLETT_PROCESS_TEST_PID="+pidFile)
			done := make(chan error, 1)
			if crash {
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				go func() { done <- cmd.Wait() }()
			} else {
				go func() { done <- Run(cmd) }()
			}
			child := waitDescendant(t, pidFile)
			defer windows.CloseHandle(child)
			if crash {
				if err := cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled helper succeeded")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("helper termination exceeded bound")
			}
			state, err := windows.WaitForSingleObject(child, 5000)
			if err != nil || state != windows.WAIT_OBJECT_0 {
				t.Fatal("descendant survived helper termination", state, err)
			}
		})
	}
}
