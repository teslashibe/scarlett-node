package localfs

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestProcessCrashReleasesPrivateLock(t *testing.T) {
	if path := os.Getenv("SCARLETT_LOCALFS_CHILD_LOCK"); path != "" {
		f, err := LockPrivate(path)
		if err != nil {
			os.Exit(2)
		}
		defer f.Close()
		io.WriteString(os.Stdout, "locked\n")
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "process lock")
	cmd := exec.Command(executable, "-test.run=^TestProcessCrashReleasesPrivateLock$")
	cmd.Env = append(os.Environ(), "SCARLETT_LOCALFS_CHILD_LOCK="+path)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatal("child could not acquire lock")
	}
	if f, err := LockPrivate(path); err == nil {
		f.Close()
		t.Fatal("second process acquired live lock")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	cmd.Wait()
	f, err := LockPrivate(path)
	if err != nil {
		t.Fatal("process death did not release lock", err)
	}
	f.Close()
}

func TestExclusiveLockReleasedOnClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private lock unicode-é")
	first, err := LockPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := LockPrivate(path); err == nil {
		duplicate.Close()
		t.Fatal("duplicate lock accepted")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := LockPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
}

func TestPrivateFileRejectsDirectory(t *testing.T) {
	if f, err := OpenPrivate(t.TempDir()); err == nil {
		f.Close()
		t.Fatal("directory accepted")
	}
}

func TestPrivateMissingFileDoesNotCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")
	if f, err := OpenPrivate(path); err == nil {
		f.Close()
		t.Fatal("missing read accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("read created file")
	}
}
