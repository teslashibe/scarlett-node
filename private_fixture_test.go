package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}
func writePrivateFixture(path string, raw []byte, mode os.FileMode) error {
	if mode.Perm()&0077 != 0 || mode.Perm()&0111 != 0 {
		return os.WriteFile(path, raw, mode)
	}
	return localfs.WriteAtomic(path, raw, true)
}
func privateFixtureMkdir(path string, _ os.FileMode) error { return localfs.EnsureDir(path) }
