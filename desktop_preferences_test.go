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
	if out.String() != "{\"schema\":1,\"local_api_port\":8088,\"background\":false,\"x_concurrency\":2,\"updates\":\"notify\",\"resume_serving\":false}\n" {
		t.Fatal("unexpected defaults")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("read wrote preferences")
	}
	value := `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":3,"updates":"automatic","resume_serving":true}`
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

func TestDesktopPreferencesMigrateExistingSettingsAndBoundXConcurrency(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "preferences.json")
	old := []byte(`{"schema":1,"local_api_port":18088,"background":true}`)
	if err := localfs.WriteAtomic(path, old, false); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":2,"updates":"notify","resume_serving":false}` {
		t.Fatal("old preferences did not retain values with default concurrency")
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, old) {
		t.Fatal("reading old preferences rewrote disk")
	}
	for _, input := range []string{
		`{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":0}`,
		`{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":9}`,
		`{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":1.5}`,
		`{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":"2"}`,
	} {
		if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(input), &out); err == nil {
			t.Fatal("invalid concurrency accepted")
		}
	}
}

func TestSavedThroughputPreferencesRetainDesktop013RollbackRepresentation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "preferences.json")
	value := `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":4,"updates":"notify","resume_serving":false}`
	var out bytes.Buffer
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(value), &out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != `{"schema":1,"local_api_port":18088,"background":true}` {
		t.Fatal("old installer preference representation changed")
	}
	extension, err := localfs.OpenPrivate(filepath.Join(dir, "throughput-preferences-v1.json"))
	if err != nil {
		t.Fatal("capacity extension not private", err)
	}
	extension.Close()
	out.Reset()
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || strings.TrimSpace(out.String()) != value {
		t.Fatal("capacity extension did not survive reopen")
	}
	if err := localfs.WriteAtomic(filepath.Join(dir, "throughput-preferences-v1.json"), []byte(`{"schema":1,"x_concurrency":99}`), true); err != nil {
		t.Fatal(err)
	}
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err == nil {
		t.Fatal("corrupt capacity extension did not fail closed")
	}
}

// Update and resume-on-launch settings live in their own extension, so a
// rollback to 0.1.12 or earlier still reads preferences.json unchanged.
func TestLifecyclePreferencesDefaultToNotifyAndRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "preferences.json")
	var out bytes.Buffer
	value := `{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":2,"updates":"automatic","resume_serving":true}`
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(value), &out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != `{"schema":1,"local_api_port":8088,"background":false}` {
		t.Fatal("lifecycle settings leaked into the rollback-readable file")
	}
	raw, err = os.ReadFile(filepath.Join(dir, "lifecycle-preferences-v1.json"))
	if err != nil || string(raw) != `{"schema":1,"updates":"automatic","resume_serving":true}` {
		t.Fatalf("unexpected lifecycle extension %q", raw)
	}
	out.Reset()
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || strings.TrimSpace(out.String()) != value {
		t.Fatal("lifecycle settings did not survive reopen")
	}
	for _, invalid := range []string{
		`{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":2,"updates":"silent","resume_serving":false}`,
		`{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":2,"updates":"","resume_serving":false}`,
	} {
		if desktopCommand([]string{"preferences-set", path}, strings.NewReader(invalid), &out) == nil {
			t.Fatal("invalid update mode accepted")
		}
	}
	if err := localfs.WriteAtomic(filepath.Join(dir, "lifecycle-preferences-v1.json"), []byte(`{"schema":1,"updates":"always"}`), true); err != nil {
		t.Fatal(err)
	}
	if desktopCommand([]string{"preferences-get", path}, nil, &out) == nil {
		t.Fatal("corrupt lifecycle extension did not fail closed")
	}
}
