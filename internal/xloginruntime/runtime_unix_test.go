//go:build unix

package xloginruntime

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInventoryRejectsFIFOAndLinkBeforeReads(t *testing.T) {
	config, root := fixture(t)
	path := filepath.Join(root, "social-login", "src", "server.js")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err == nil {
		t.Fatal("FIFO accepted")
	}
	os.Remove(path)
	if err := os.Symlink(filepath.Join(root, nodeName()), path); err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err == nil {
		t.Fatal("link accepted")
	}
	os.Remove(path)
	os.WriteFile(path, []byte("synthetic-local-runtime"), 0600)
	if err := os.Mkdir(config.StateDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config).Start(context.Background()); err == nil {
		t.Fatal("broad state directory adopted")
	}
	info, _ := os.Stat(config.StateDir)
	if info.Mode().Perm() != 0755 {
		t.Fatal("existing state permissions repaired")
	}
}
