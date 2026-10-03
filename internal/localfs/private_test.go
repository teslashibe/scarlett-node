package localfs

import (
	"os"
	"path/filepath"
	"testing"
)

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
