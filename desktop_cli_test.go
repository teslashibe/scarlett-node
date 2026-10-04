package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

func TestDesktopPrivateHelpersUseRealPrivateStorageAndStableBearer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	var out bytes.Buffer
	if err := desktopCommand([]string{"private-dir", root}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if err := localfs.CheckDir(root); err != nil {
		t.Fatal(err)
	}
	if out.String() != "{\"ok\":true}\n" {
		t.Fatal("unexpected directory response")
	}
	path := filepath.Join(root, "bearer")
	out.Reset()
	if err := desktopCommand([]string{"bearer", path}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(out.Bytes(), &response); err != nil || len(response.Key) != 64 {
		t.Fatal("invalid private bearer response")
	}
	original := response.Key
	file, err := localfs.OpenPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	key, err := desktopBearer(path)
	if err != nil || key != original {
		t.Fatal("bearer changed")
	}
	lock, err := localfs.LockPrivate(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = desktopBearer(path); err == nil {
		t.Fatal("concurrent key access acquired owned lock")
	}
	lock.Close()
	if err = localfs.WriteAtomic(path, []byte(strings.Repeat("!", 64)), true); err != nil {
		t.Fatal(err)
	}
	if _, err = desktopBearer(path); err == nil {
		t.Fatal("corrupted bearer accepted")
	}
}

// The desktop reserves each Codex login profile with private-dir-new and then
// checks it with private-dir, exactly as this test does. A name already taken
// by any entry, including an older inherited-ACL directory, is reported for the
// caller to skip and is never adopted or repaired.
func TestDesktopPrivateDirNewReservesProtectedProfilesExclusively(t *testing.T) {
	root := filepath.Join(t.TempDir(), "codex-logins")
	if err := desktopCommand([]string{"private-dir", root}, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	reserve := func(path string) string {
		t.Helper()
		var out bytes.Buffer
		if err := desktopCommand([]string{"private-dir-new", path}, strings.NewReader(""), &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	home := filepath.Join(root, "codex-1")
	if got := reserve(home); got != "{\"status\":\"created\"}\n" {
		t.Fatal("unexpected reservation response")
	}
	var out bytes.Buffer
	if err := desktopCommand([]string{"private-dir", home}, strings.NewReader(""), &out); err != nil || out.String() != "{\"ok\":true}\n" {
		t.Fatal("reserved profile failed the private directory check", err)
	}
	if got := reserve(home); got != "{\"status\":\"exists\"}\n" {
		t.Fatal("reserved profile was claimed twice")
	}
	orphan := filepath.Join(root, "codex-2")
	if err := os.Mkdir(orphan, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(orphan, 0755); err != nil {
		t.Fatal(err)
	}
	if got := reserve(orphan); got != "{\"status\":\"exists\"}\n" {
		t.Fatal("existing unprotected directory was not reported as taken")
	}
	if err := desktopCommand([]string{"private-dir", orphan}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("existing unprotected directory was adopted or repaired")
	}
	// Shared on Unix; inherited-only ACL on Windows.
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", filepath.Join(root, "missing", "codex-3"), filepath.Join(shared, "codex-4")} {
		if err := desktopCommand([]string{"private-dir-new", path}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatal("reservation accepted an invalid or unprotected parent")
		}
	}
}

func TestDesktopHelpersRejectPathsPortsAndUnknownCommands(t *testing.T) {
	for _, args := range [][]string{{"private-dir", "relative"}, {"private-dir-new", "relative"}, {"private-dir-new"}, {"bearer", "relative"}, {"api", "80"}, {"api", "65536"}, {"api", "localhost:8088"}, {"api", "8088", "extra"}, {"delete", "anything"}} {
		if err := desktopCommand(args, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid command %q", args[0])
		}
	}
	if err := desktopCommand([]string{"api", "8088"}, nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing owner accepted")
	}
	root := t.TempDir()
	file := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := desktopCommand([]string{"private-dir", file}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("regular file treated as private directory")
	}
}
