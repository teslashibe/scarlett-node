//go:build unix

package localfs

import (
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
