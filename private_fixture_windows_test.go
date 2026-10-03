package main

import (
	"os"
	"path/filepath"
	"testing"
)

func createFIFOFixture(t *testing.T, _ string) error {
	t.Skip("POSIX FIFO fixture; Windows reparse fixtures run in localfs")
	return nil
}
func installFixtureHelper(path string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0700)
}

func fixtureHelperPath(dir string) string  { return filepath.Join(dir, "synthetic-prover.exe") }
func makeHelperUnusable(path string) error { return os.Mkdir(path, 0700) }
func restoreFixtureHelper(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return installFixtureHelper(path)
}
