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
	if out.String() != "{\"schema\":1,\"local_api_port\":8088,\"background\":false,\"x_concurrency\":2,\"updates\":\"notify\",\"resume_serving\":false,\"serve_web\":true,\"web_concurrency\":0,\"web_browser_concurrency\":0}\n" {
		t.Fatal("unexpected defaults")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("read wrote preferences")
	}
	value := `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":3,"updates":"automatic","resume_serving":true,"serve_web":false,"web_concurrency":0,"web_browser_concurrency":0}`
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
	if strings.TrimSpace(out.String()) != `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":2,"updates":"notify","resume_serving":false,"serve_web":true,"web_concurrency":0,"web_browser_concurrency":0}` {
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
	value := `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":4,"updates":"notify","resume_serving":false,"serve_web":true,"web_concurrency":0,"web_browser_concurrency":0}`
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
	value := `{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":2,"updates":"automatic","resume_serving":true,"serve_web":true,"web_concurrency":0,"web_browser_concurrency":0}`
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
		strings.TrimSpace(out.String()) != `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":3,"updates":"automatic","resume_serving":true,"serve_web":true,"web_concurrency":0,"web_browser_concurrency":0}` {
		t.Fatalf("0.1.13 settings did not read with web on: %v %q", err, out.String())
	}
	if _, err := os.Lstat(webPath); !os.IsNotExist(err) {
		t.Fatal("read wrote the web extension")
	}
	off := `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":3,"updates":"automatic","resume_serving":true,"serve_web":false,"web_concurrency":0,"web_browser_concurrency":0}`
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

func TestDesktopPreferencesKeepWebPagesAtOnceInItsOwnExtension(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "preferences.json")
	capacityPath := filepath.Join(dir, "web-capacity-preferences-v1.json")
	webPath := filepath.Join(dir, "web-preferences-v1.json")
	var out bytes.Buffer
	// A device that never chose reads Auto, and reading writes nothing.
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || !strings.Contains(out.String(), `"web_concurrency":0,`) {
		t.Fatalf("Web pages at once did not default to Auto: %v %q", err, out.String())
	}
	if _, err := os.Lstat(capacityPath); !os.IsNotExist(err) {
		t.Fatal("read wrote the web capacity extension")
	}
	value := `{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":2,"updates":"notify","resume_serving":false,"serve_web":true,"web_concurrency":12,"web_browser_concurrency":0}`
	out.Reset()
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(value), &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || strings.TrimSpace(out.String()) != value {
		t.Fatalf("Web pages at once did not survive reopen: %v %q", err, out.String())
	}
	if raw, err := os.ReadFile(capacityPath); err != nil || string(raw) != `{"schema":1,"web_concurrency":12}` {
		t.Fatalf("unexpected web capacity extension %q", raw)
	}
	f, err := localfs.OpenPrivate(capacityPath)
	if err != nil {
		t.Fatal("web capacity extension not private", err)
	}
	f.Close()
	// The serve-web extension keeps the representation 0.1.14-0.1.16 decode
	// strictly, so a rollback still starts.
	if raw, err := os.ReadFile(webPath); err != nil || string(raw) != `{"schema":1,"serve_web":true}` {
		t.Fatalf("serve-web extension changed representation: %q", raw)
	}
	if on, err := readDesktopWebPreference(webPath); err != nil || !on {
		t.Fatal("an earlier release cannot read the serve-web extension")
	}
	for _, invalid := range []string{
		strings.Replace(value, `"web_concurrency":12`, `"web_concurrency":-1`, 1),
		strings.Replace(value, `"web_concurrency":12`, `"web_concurrency":17`, 1),
		strings.Replace(value, `"web_concurrency":12`, `"web_concurrency":1.5`, 1),
		strings.Replace(value, `"web_concurrency":12`, `"web_concurrency":"8"`, 1),
	} {
		if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(invalid), &out); err == nil {
			t.Fatalf("invalid Web pages at once accepted: %s", invalid)
		}
	}
	out.Reset()
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || strings.TrimSpace(out.String()) != value {
		t.Fatal("an invalid write changed Web pages at once")
	}
	// Auto is saved explicitly, and a corrupt extension is reported, not reset.
	auto := strings.Replace(value, `"web_concurrency":12`, `"web_concurrency":0`, 1)
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(auto), &out); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(capacityPath); err != nil || string(raw) != `{"schema":1,"web_concurrency":0}` {
		t.Fatalf("Auto not saved: %q", raw)
	}
	for _, corrupt := range []string{`{"schema":1,"web_concurrency":99}`, `{"schema":1}`, `{"schema":2,"web_concurrency":4}`, `{"schema":1,"web_concurrency":4,"extra":1}`} {
		if err := localfs.WriteAtomic(capacityPath, []byte(corrupt), true); err != nil {
			t.Fatal(err)
		}
		if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err == nil {
			t.Fatalf("corrupt web capacity extension accepted: %s", corrupt)
		}
	}
}

// Browser pages at once lives in its own extension: a device that never chose
// reads Auto, and every file 0.1.17 decodes strictly keeps its representation,
// so a rollback still starts.
func TestDesktopPreferencesKeepBrowserPagesAtOnceInItsOwnExtension(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "preferences.json")
	browserPath := filepath.Join(dir, "browser-capacity-preferences-v1.json")
	webCapacityPath := filepath.Join(dir, "web-capacity-preferences-v1.json")
	// A device updating from 0.1.17 has every earlier file but this one.
	for name, raw := range map[string]string{
		"preferences.json":                 `{"schema":1,"local_api_port":18088,"background":true}`,
		"throughput-preferences-v1.json":   `{"schema":1,"x_concurrency":6}`,
		"lifecycle-preferences-v1.json":    `{"schema":1,"updates":"automatic","resume_serving":true}`,
		"web-preferences-v1.json":          `{"schema":1,"serve_web":true}`,
		"web-capacity-preferences-v1.json": `{"schema":1,"web_concurrency":16}`,
	} {
		if err := localfs.WriteAtomic(filepath.Join(dir, name), []byte(raw), true); err != nil {
			t.Fatal(err)
		}
	}
	var out bytes.Buffer
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil ||
		strings.TrimSpace(out.String()) != `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":6,"updates":"automatic","resume_serving":true,"serve_web":true,"web_concurrency":16,"web_browser_concurrency":0}` {
		t.Fatalf("0.1.17 settings did not read with Browser pages at once on Auto: %v %q", err, out.String())
	}
	if _, err := os.Lstat(browserPath); !os.IsNotExist(err) {
		t.Fatal("read wrote the browser capacity extension")
	}
	value := `{"schema":1,"local_api_port":18088,"background":true,"x_concurrency":6,"updates":"automatic","resume_serving":true,"serve_web":true,"web_concurrency":16,"web_browser_concurrency":4}`
	out.Reset()
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(value), &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || strings.TrimSpace(out.String()) != value {
		t.Fatalf("Browser pages at once did not survive reopen: %v %q", err, out.String())
	}
	if raw, err := os.ReadFile(browserPath); err != nil || string(raw) != `{"schema":1,"web_browser_concurrency":4}` {
		t.Fatalf("unexpected browser capacity extension %q", raw)
	}
	f, err := localfs.OpenPrivate(browserPath)
	if err != nil {
		t.Fatal("browser capacity extension not private", err)
	}
	f.Close()
	// What 0.1.17 reads is unchanged: preferences.json and the web capacity
	// extension keep their representations, and its reader still takes them.
	if raw, err := os.ReadFile(path); err != nil || string(raw) != `{"schema":1,"local_api_port":18088,"background":true}` {
		t.Fatalf("preferences.json changed representation: %q", raw)
	}
	if raw, err := os.ReadFile(webCapacityPath); err != nil || string(raw) != `{"schema":1,"web_concurrency":16}` {
		t.Fatalf("web capacity extension changed representation: %q", raw)
	}
	if n, err := readDesktopWebConcurrency(webCapacityPath); err != nil || n != 16 {
		t.Fatal("0.1.17 cannot read the web capacity extension")
	}
	// The helper keeps the operator's choice even above a fixed web limit;
	// the app passes at most Web pages at once to the node it starts.
	above := strings.Replace(value, `"web_concurrency":16`, `"web_concurrency":2`, 1)
	out.Reset()
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(above), &out); err != nil || strings.TrimSpace(out.String()) != above {
		t.Fatalf("Browser pages at once above a fixed web limit not kept: %v %q", err, out.String())
	}
	for _, invalid := range []string{
		strings.Replace(value, `"web_browser_concurrency":4`, `"web_browser_concurrency":-1`, 1),
		strings.Replace(value, `"web_browser_concurrency":4`, `"web_browser_concurrency":5`, 1),
		strings.Replace(value, `"web_browser_concurrency":4`, `"web_browser_concurrency":1.5`, 1),
		strings.Replace(value, `"web_browser_concurrency":4`, `"web_browser_concurrency":"2"`, 1),
	} {
		if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(invalid), &out); err == nil {
			t.Fatalf("invalid Browser pages at once accepted: %s", invalid)
		}
	}
	out.Reset()
	if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err != nil || strings.TrimSpace(out.String()) != above {
		t.Fatal("an invalid write changed Browser pages at once")
	}
	// Auto is saved explicitly, and a corrupt extension is reported, not reset.
	auto := strings.Replace(value, `"web_browser_concurrency":4`, `"web_browser_concurrency":0`, 1)
	if err := desktopCommand([]string{"preferences-set", path}, strings.NewReader(auto), &out); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(browserPath); err != nil || string(raw) != `{"schema":1,"web_browser_concurrency":0}` {
		t.Fatalf("Auto not saved: %q", raw)
	}
	for _, corrupt := range []string{`{"schema":1,"web_browser_concurrency":5}`, `{"schema":1,"web_browser_concurrency":-1}`, `{"schema":1}`, `{"schema":2,"web_browser_concurrency":2}`, `{"schema":1,"web_browser_concurrency":2,"extra":1}`, `{"schema":1,"web_browser_concurrency":2}{}`, "corrupted"} {
		if err := localfs.WriteAtomic(browserPath, []byte(corrupt), true); err != nil {
			t.Fatal(err)
		}
		if err := desktopCommand([]string{"preferences-get", path}, nil, &out); err == nil {
			t.Fatalf("corrupt browser capacity extension accepted: %s", corrupt)
		}
	}
}
