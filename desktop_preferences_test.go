package main

import (
	"bytes"
	"encoding/json"
	"io"
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
	if out.String() != "{\"schema\":1,\"local_api_port\":8088,\"background\":false,\"x_concurrency\":2,\"updates\":\"notify\",\"resume_serving\":false,\"serve_web\":true}\n" {
		t.Fatal("unexpected defaults")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("read wrote preferences")
	}
	value := `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":3,"updates":"automatic","resume_serving":true,"serve_web":false}`
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
	if strings.TrimSpace(out.String()) != `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":2,"updates":"notify","resume_serving":false,"serve_web":true}` {
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
	value := `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":4,"updates":"notify","resume_serving":false,"serve_web":true}`
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
	value := `{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":2,"updates":"automatic","resume_serving":true,"serve_web":true}`
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

// Web serving defaults on, survives reopen when turned off, and lives in its
// own extension so desktop 0.1.13 still reads every file it knows on rollback.
func TestWebPreferenceDefaultsOnPersistsOffAndKeepsDesktop013FilesReadable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "preferences.json")
	webPath := filepath.Join(dir, "web-preferences-v1.json")
	// A device updating from 0.1.13 has its files but no web extension: on.
	for name, raw := range map[string]string{
		"preferences.json":               `{"schema":1,"local_api_port":18088,"background":true}`,
		"throughput-preferences-v1.json": `{"schema":1,"x_concurrency":3}`,
		"lifecycle-preferences-v1.json":  `{"schema":1,"updates":"automatic","resume_serving":true}`,
	} {
		if err := localfs.WriteAtomic(filepath.Join(dir, name), []byte(raw), true); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil ||
		strings.TrimSpace(out.String()) != `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":3,"updates":"automatic","resume_serving":true,"serve_web":true}` {
		t.Fatalf("0.1.13 settings did not read with web on: %v %q", err, out.String())
	}
	if _, err := os.Lstat(webPath); !os.IsNotExist(err) {
		t.Fatal("read wrote the web extension")
	}
	off := `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":3,"updates":"automatic","resume_serving":true,"serve_web":false}`
	out.Reset()
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(off), &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || strings.TrimSpace(out.String()) != off {
		t.Fatal("web off did not survive reopen")
	}
	raw, err := os.ReadFile(webPath)
	if err != nil || string(raw) != `{"schema":1,"serve_web":false}` {
		t.Fatalf("unexpected web extension %q", raw)
	}
	f, err := localfs.OpenPrivate(webPath)
	if err != nil {
		t.Fatal("web extension not private", err)
	}
	f.Close()

	// Desktop 0.1.13's readers, as released: its preferences.json struct
	// decoded strictly (decodeDesktopPreferences at v0.1.13) and the two
	// extension readers, which this release leaves unchanged.
	type desktop013Preferences struct {
		Schema        int    `json:"schema"`
		LocalAPIPort  int    `json:"local_api_port"`
		Background    bool   `json:"background"`
		XConcurrency  int    `json:"x_concurrency"`
		Updates       string `json:"updates"`
		ResumeServing bool   `json:"resume_serving"`
	}
	raw, err = os.ReadFile(path)
	if err != nil || string(raw) != `{"schema":1,"local_api_port":18088,"background":true}` {
		t.Fatalf("preferences.json changed representation: %q", raw)
	}
	old := desktop013Preferences{XConcurrency: 2, Updates: "notify"}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&old) != nil || d.Decode(&struct{}{}) != io.EOF || old.LocalAPIPort != 18088 || !old.Background {
		t.Fatal("desktop 0.1.13 cannot decode preferences.json")
	}
	if throughput, err := readDesktopThroughputPreferences(filepath.Join(dir, "throughput-preferences-v1.json")); err != nil || throughput.XConcurrency != 3 {
		t.Fatal("desktop 0.1.13 cannot read the throughput extension")
	}
	if lifecycle, err := readDesktopLifecyclePreferences(filepath.Join(dir, "lifecycle-preferences-v1.json")); err != nil || lifecycle.Updates != "automatic" || !lifecycle.ResumeServing {
		t.Fatal("desktop 0.1.13 cannot read the lifecycle extension")
	}

	on := strings.Replace(off, `"serve_web":false`, `"serve_web":true`, 1)
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(on), &out); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(webPath); err != nil || string(raw) != `{"schema":1,"serve_web":true}` {
		t.Fatalf("web on not saved: %q", raw)
	}
	for _, invalid := range []string{`{"schema":1}`, `{"schema":2,"serve_web":true}`, `{"schema":1,"serve_web":"on"}`, `{"schema":1,"serve_web":true,"web_browser":"on"}`, `{"schema":1,"serve_web":true}{}`, "corrupted"} {
		if err := localfs.WriteAtomic(webPath, []byte(invalid), true); err != nil {
			t.Fatal(err)
		}
		if desktopCommand([]string{"preferences-get", path}, nil, &out) == nil {
			t.Fatalf("corrupt web extension %q did not fail closed", invalid)
		}
	}
	if err := localfs.WriteAtomic(webPath, []byte(`{"schema":1,"serve_web":false}`), true); err != nil {
		t.Fatal(err)
	}
	if desktopCommand([]string{"preferences-set", path}, strings.NewReader(`{"schema":1,"local_api_port":8088,"background":false,"serve_web":"yes"}`), &out) == nil {
		t.Fatal("invalid web preference accepted")
	}
	out.Reset()
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || strings.TrimSpace(out.String()) != off {
		t.Fatal("invalid web input changed saved settings")
	}
}
