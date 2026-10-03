//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func createFIFOFixture(_ *testing.T, path string) error { return unix.Mkfifo(path, 0600) }
func installFixtureHelper(path string) error {
	return os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0700)
}

func fixtureHelperPath(dir string) string { return filepath.Join(dir, "synthetic-prover") }
func makeHelperUnusable(path string) error {
	return os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0600)
}
func restoreFixtureHelper(path string) error { return os.Chmod(path, 0700) }
