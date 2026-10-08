package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInstalledBinDirFollowsOnlyThisLayoutsCommandLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		// install.sh layouts exist only on Linux and macOS: on Windows
		// update.DetectLayout refuses before installedBinDir is consulted, and
		// an extensionless "scarlett-node" is never found through PATHEXT.
		t.Skip("headless install.sh layouts are not installed on Windows")
	}
	base := t.TempDir()
	root := filepath.Join(base, "lib")
	custom := filepath.Join(base, "custom bin")
	other := filepath.Join(base, "other bin")
	for _, dir := range []string{filepath.Join(root, "versions", "0.1.13-test"), custom, other} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "versions", "0.1.13-test", "scarlett-node")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("versions/0.1.13-test", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	// install.sh links <bin>/scarlett-node to <root>/current/scarlett-node.
	link := filepath.Join(custom, "scarlett-node")
	if err := os.Symlink(filepath.Join(root, "current", "scarlett-node"), link); err != nil {
		t.Fatal(err)
	}
	if got := installedBinDir(link, root); got != custom {
		t.Fatalf("custom bin directory not found: %q", got)
	}
	// Found through PATH as well.
	t.Setenv("PATH", custom)
	if got := installedBinDir("scarlett-node", root); got != custom {
		t.Fatalf("PATH lookup: %q", got)
	}
	// Another installation's link, a direct binary or a missing file never count.
	foreign := filepath.Join(other, "scarlett-node")
	if err := os.Symlink(filepath.Join(base, "elsewhere", "current", "scarlett-node"), foreign); err != nil {
		t.Fatal(err)
	}
	for _, arg0 := range []string{foreign, binary, filepath.Join(other, "missing")} {
		if got := installedBinDir(arg0, root); got != "" {
			t.Fatalf("%s: %q", arg0, got)
		}
	}
}
