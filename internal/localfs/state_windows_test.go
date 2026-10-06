package localfs

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func privateReplacementFixture(t *testing.T) (string, *os.File) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private replacement Unicode λ")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "accounts.json")
	if err := WriteAtomic(path, []byte("complete synthetic original"), false); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// A normal reader that denies delete sharing deterministically holds up
	// replacement, without changing the protected fixture's ACL.
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	blocker := os.NewFile(uintptr(h), path)
	t.Cleanup(func() { blocker.Close() })
	return path, blocker
}

func checkPrivateReplacement(t *testing.T, path string, want []byte) {
	t.Helper()
	f, err := OpenPrivate(path)
	if err != nil {
		t.Fatal("published file was not private", err)
	}
	raw, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatal("publication changed or partially wrote the expected bytes", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatal("private publication retained temporary files", err)
	}
}

func startPrivateReplacement(t *testing.T, path string, release func()) <-chan error {
	t.Helper()
	done := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		defer close(done)
		result <- WriteAtomic(path, []byte("complete synthetic replacement"), true)
	}()
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("replacement writer did not finish")
		}
	})
	return result
}

func waitForPrivateReplacementStage(t *testing.T, path string, result <-chan error) {
	t.Helper()
	// The staging handle denies all sharing until Write/Sync/Close completes.
	// Reading the whole private staging file therefore observes publication
	// readiness, rather than racing a sleep against initial Windows flushes.
	deadline := time.Now().Add(10 * time.Second)
	for {
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		staged := false
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".write-") {
				continue
			}
			f, err := OpenPrivate(filepath.Join(filepath.Dir(path), entry.Name()))
			if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
				continue
			}
			if err != nil {
				t.Fatal("private staging file did not become readable", err)
			}
			raw, err := io.ReadAll(f)
			f.Close()
			if err != nil || string(raw) != "complete synthetic replacement" {
				t.Fatal("private staging file was incomplete", err)
			}
			staged = true
		}
		if staged {
			break
		}
		select {
		case err := <-result:
			t.Fatal("replacement ended before the reader was released", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement did not stage a complete private file")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWindowsPrivateAtomicReplacementWaitsForConcurrentReader(t *testing.T) {
	path, blocker := privateReplacementFixture(t)
	reader, err := OpenPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	result := startPrivateReplacement(t, path, func() { reader.Close(); blocker.Close() })
	waitForPrivateReplacementStage(t, path, result)
	select {
	case err := <-result:
		t.Fatal("replacement did not wait for the reader", err)
	case <-time.After(25 * time.Millisecond):
	}
	old, err := io.ReadAll(reader)
	if err != nil || string(old) != "complete synthetic original" {
		t.Fatal("concurrent reader lost the original complete bytes", err)
	}
	reader.Close()
	blocker.Close()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal("replacement failed after the reader was released", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("replacement did not finish after the reader was released")
	}
	checkPrivateReplacement(t, path, []byte("complete synthetic replacement"))
}

func TestWindowsPrivateAtomicReplacementFailsClosedAtDeadline(t *testing.T) {
	path, blocker := privateReplacementFixture(t)
	started := time.Now()
	err := WriteAtomic(path, []byte("replacement must not publish"), true)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatal("blocked publication did not return its Windows conflict", err)
	}
	if !strings.Contains(err.Error(), "publish private file") {
		t.Fatal("publication error did not identify its stage", err)
	}
	if elapsed := time.Since(started); elapsed < privatePublishRetryLimit || elapsed > 5*time.Second {
		t.Fatal("publication retry was not bounded", elapsed)
	}
	blocker.Close()
	checkPrivateReplacement(t, path, []byte("complete synthetic original"))
}

func TestWindowsPrivateAtomicReplacementRechecksChangedTargetACL(t *testing.T) {
	path, blocker := privateReplacementFixture(t)
	result := startPrivateReplacement(t, path, func() { blocker.Close() })
	waitForPrivateReplacementStage(t, path, result)
	// The first target check has passed, but publication is still blocked.
	// Changing its ACL now must be detected before another replacement attempt.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "revalidate private publication target") || strings.Contains(err.Error(), path) {
			t.Fatal("retry accepted an unsafe target or disclosed its path", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("retry did not reject the changed target")
	}
	blocker.Close()
	if f, err := OpenPrivate(path); err == nil {
		f.Close()
		t.Fatal("changed broad ACL was accepted or repaired")
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "complete synthetic original" {
		t.Fatal("unsafe target was replaced", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal("rejected replacement retained temporary files", err)
	}
}
