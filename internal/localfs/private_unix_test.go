//go:build unix

package localfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateOpenRejectsSymlinkAndBroadPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("synthetic-only"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenPrivate(link); err == nil {
		f.Close()
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenPrivate(path); err == nil {
		f.Close()
		t.Fatal("broad permission accepted")
	}
}

func TestCreateDirRequiresPrivateParentAndSkipsLinks(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "profiles")
	if err := EnsureDir(parent); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "codex-1")
	if err := os.Symlink(filepath.Join(parent, "missing-target"), link); err != nil {
		t.Fatal(err)
	}
	if err := CreateDir(link); !errors.Is(err, fs.ErrExist) {
		t.Fatal("dangling link was not reported as taken", err)
	}
	if _, err := os.Lstat(filepath.Join(parent, "missing-target")); !os.IsNotExist(err) {
		t.Fatal("link target was created")
	}
	path := filepath.Join(parent, "codex-2")
	if err := CreateDir(path); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("new directory is not exactly 0700", err)
	}
	if err := os.Chmod(parent, 0755); err != nil {
		t.Fatal(err)
	}
	if err := CreateDir(filepath.Join(parent, "codex-3")); err == nil || errors.Is(err, fs.ErrExist) {
		t.Fatal("directory claimed below a shared parent", err)
	}
}
