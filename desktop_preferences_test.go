package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

func TestDesktopPreferencesPersistPrivatelyWithoutChangingDefaultsOnReads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "preferences.json")
	var out bytes.Buffer
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "{\"schema\":1,\"local_api_port\":8088,\"background\":false}\n" {
		t.Fatal("unexpected defaults")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("read wrote preferences")
	}
	value := `{"schema":1,"local_api_port":18088,"background":true}`
	out.Reset()
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(value), &out); err != nil {
		t.Fatal(err)
	}
	f, err := localfs.OpenPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	out.Reset()
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || strings.TrimSpace(out.String()) != value {
		t.Fatal("preferences did not survive reopen")
	}
	for _, invalid := range []string{`{}`, `{"schema":2,"local_api_port":8088}`, `{"schema":1,"local_api_port":80}`, `{"schema":1,"local_api_port":65536}`, `{"schema":1,"local_api_port":8088,"token":"synthetic"}`, value + `{}`, strings.Repeat(" ", 1025) + value, value + strings.Repeat(" ", 1025)} {
		if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(invalid), &out); err == nil {
			t.Fatal("invalid preference input accepted")
		}
	}
	out.Reset()
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || strings.TrimSpace(out.String()) != value {
		t.Fatal("invalid write changed existing settings")
	}
	lock, err := localfs.LockPrivate(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(value), &out); err == nil {
		t.Fatal("concurrent preference writer acquired owned lock")
	}
}

func TestDesktopPreferencesRefuseInvalidPathsAndCorruption(t *testing.T) {
	var out bytes.Buffer
	for _, path := range []string{"relative/preferences.json", filepath.Join(t.TempDir(), "credentials.json")} {
		if desktopCommand([]string{"preferences-get", path}, nil, &out) == nil {
			t.Fatal("invalid preferences path accepted")
		}
	}
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "preferences.json")
	if err := localfs.WriteAtomic(path, []byte("corrupted"), false); err != nil {
		t.Fatal(err)
	}
	if desktopCommand([]string{"preferences-get", path}, nil, &out) == nil {
		t.Fatal("corruption silently reset preferences")
	}
}
