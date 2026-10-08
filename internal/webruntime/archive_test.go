package webruntime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// fixtureRuntime is a synthetic packaged runtime: a resource directory with
// web-runtime.json, the archive and x-login-runtime/node.
type fixtureRuntime struct {
	resources string
	state     string
	pins      Pins
	files     map[string][]byte
}

type archiveOptions struct {
	platform  string
	mutate    func(files map[string][]byte, manifest *Manifest) // before the manifest digest
	entries   func(order []string) []string                     // the archive's entry order (manifest first)
	rawEntry  func(tw *tar.Writer)                              // an extra raw entry appended
	pinsHook  func(p *Pins)                                     // after computing pins
	content   func(name string, data []byte) []byte             // archive bytes for a listed file
	inventory func(inv *Inventory)                              // the pinned browser inventory
	pin       func(pin *BrowserPin)                             // the pinned browser
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func testInventory() (Inventory, map[string][]byte) {
	exe := "chrome-test/chrome"
	data := map[string][]byte{exe: []byte("#!/bin/sh\nexit 0\n"), "chrome-test/lib/data.bin": []byte("browser data")}
	inv := Inventory{Files: []InventoryFile{
		{Path: exe, SHA256: digest(data[exe]), Bytes: int64(len(data[exe])), Mode: "0755"},
		{Path: "chrome-test/lib/data.bin", SHA256: digest(data["chrome-test/lib/data.bin"]), Bytes: int64(len(data["chrome-test/lib/data.bin"])), Mode: "0644"},
	}}
	if runtime.GOOS != "windows" {
		inv.Links = []InventoryLink{{Path: "chrome-test/Current", Target: "lib"}}
	}
	return inv, data
}

func buildRuntime(t *testing.T, opts archiveOptions) *fixtureRuntime {
	t.Helper()
	platform := opts.platform
	if platform == "" {
		platform = goPlatform()
	}
	if cftNames[platform] == "" {
		t.Skip("no Chrome for Testing pin for this platform")
	}
	resources := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	node := []byte("synthetic node")
	if err := os.MkdirAll(filepath.Join(resources, "x-login-runtime"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, "x-login-runtime", nodeName()), node, 0o700); err != nil {
		t.Fatal(err)
	}
	inv, browserData := testInventory()
	if opts.inventory != nil {
		opts.inventory(&inv)
	}
	invRaw, _ := json.Marshal(inv)
	var unpacked int64
	for _, f := range inv.Files {
		unpacked += f.Bytes
	}
	zipRaw := buildZip(t, inv, browserData, nil)
	pin := BrowserPin{Version: PinnedVersion, Platform: platform, URL: "https://storage.googleapis.com/chrome-for-testing-public/" + PinnedVersion + "/" + cftNames[platform] + "/chrome-" + cftNames[platform] + ".zip",
		SHA256: digest(zipRaw), Bytes: int64(len(zipRaw)), Executable: "chrome-test/chrome", InventorySHA256: digest(invRaw), UnpackedBytes: unpacked}
	if opts.pin != nil {
		opts.pin(&pin)
	}
	pinRaw, _ := json.Marshal(pin)
	files := map[string][]byte{
		interpreterPath(platform):                                    []byte("#!/bin/sh\n"),
		"python/lib/python3.13/site-packages/scarlett_web_helper.py": []byte("helper"),
		"python/lib/python3.13/__pycache__/os.cpython-313.pyc":       []byte("compiled bytecode"),
		"browser/pin.json":                                           pinRaw,
		"browser/inventory.json":                                     invRaw,
	}
	manifest := Manifest{SchemaVersion: 1, Platform: platform, PythonVersion: pythonVersion, PBSRelease: "20261003", ScraplingVersion: scraplingVersion,
		LockSHA256: strings.Repeat("a", 64), DriverNode: DriverNode{Path: "x-login-runtime/" + map[bool]string{true: "node.exe", false: "node"}[strings.HasPrefix(platform, "windows-")], SHA256: digest(node), Version: driverNodeVer},
		Interpreter: interpreterPath(platform), BrowserVersion: PinnedVersion}
	if opts.mutate != nil {
		opts.mutate(files, &manifest)
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	manifest.Files = nil
	var total int64
	for _, name := range names {
		manifest.Files = append(manifest.Files, Entry{Path: name, SHA256: digest(files[name]), Bytes: int64(len(files[name])), Exec: name == interpreterPath(platform)})
		total += int64(len(files[name]))
	}
	if opts.mutate != nil {
		opts.mutate(nil, &manifest)
	}
	manifestRaw, _ := json.Marshal(manifest)
	order := append([]string{"manifest.json"}, names...)
	if opts.entries != nil {
		order = opts.entries(order)
	}
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	tw := tar.NewWriter(gz)
	for _, name := range order {
		data := files[name]
		if name == "manifest.json" {
			data = manifestRaw
		} else if opts.content != nil {
			data = opts.content(name, data)
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
		tw.Write(data)
	}
	if opts.rawEntry != nil {
		opts.rawEntry(tw)
	}
	tw.Close()
	gz.Close()
	archive := buf.Bytes()
	pins := Pins{SchemaVersion: 1, Platform: platform, Archive: "web-runtime-" + platform + ".tar.gz", ArchiveSHA256: digest(archive), ArchiveBytes: int64(len(archive)),
		ManifestSHA256: digest(manifestRaw), UnpackedBytes: total, Files: len(names), PythonVersion: pythonVersion, ScraplingVersion: scraplingVersion,
		BrowserVersion: PinnedVersion, BrowserZipSHA256: pin.SHA256}
	if opts.pinsHook != nil {
		opts.pinsHook(&pins)
	}
	pinsRaw, _ := json.Marshal(pins)
	if err := os.WriteFile(filepath.Join(resources, "web-runtime.json"), pinsRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resources, pins.Archive), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	return &fixtureRuntime{resources: resources, state: state, pins: pins, files: files}
}

func (f *fixtureRuntime) config() Config {
	return Config{ResourceDir: f.resources, StateDir: f.state}.withDefaults()
}

func reasonIs(t *testing.T, err error, want Reason) {
	t.Helper()
	if ReasonOf(err) != want {
		t.Fatalf("got %v, want reason %s", err, want)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v does not wrap ErrUnavailable", err)
	}
}

func TestEnsureExtractsVerifiesAndReuses(t *testing.T) {
	f := buildRuntime(t, archiveOptions{})
	root, err := Ensure(f.config())
	if err != nil {
		t.Fatal(err)
	}
	if root.Dir != filepath.Join(f.state, "web-runtime", f.pins.ArchiveSHA256[:16]) || root.Browser.Executable != "chrome-test/chrome" {
		t.Fatalf("unexpected root %s", root.Dir)
	}
	if err = Verify(root); err != nil {
		t.Fatal(err)
	}
	if err = verifyQuick(root); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(root.Python())
		if info.Mode().Perm() != 0o500 {
			t.Fatalf("interpreter mode %v", info.Mode().Perm())
		}
		dir, _ := os.Stat(root.Dir)
		if dir.Mode().Perm() != 0o700 {
			t.Fatalf("runtime directory mode %v", dir.Mode().Perm())
		}
	}
	again, err := Ensure(f.config())
	if err != nil || again.Dir != root.Dir {
		t.Fatalf("second Ensure: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.state, "web-runtime")); len(entries) != 2 { // the version and extract.lock
		t.Fatalf("unexpected runtime state entries: %d", len(entries))
	}
}

func TestEnsureRefusesBadArchives(t *testing.T) {
	cases := map[string]archiveOptions{
		"manifest not first": {entries: func(order []string) []string { return append(order[1:2], append([]string{order[0]}, order[2:]...)...) }},
		"traversal": {rawEntry: func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}},
		"symlink": {rawEntry: func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "python/link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
		}},
		"extra file": {rawEntry: func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "python/extra.py", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}},
		"missing file": {entries: func(order []string) []string { return order[:len(order)-1] }},
		"digest": {content: func(name string, data []byte) []byte {
			if strings.HasSuffix(name, ".pyc") {
				return bytes.ToUpper(data)
			}
			return data
		}},
		"size": {content: func(name string, data []byte) []byte {
			if strings.HasSuffix(name, ".pyc") {
				return append(data, '!')
			}
			return data
		}},
		"archive digest":  {pinsHook: func(p *Pins) { p.ArchiveSHA256 = strings.Repeat("0", 64) }},
		"manifest digest": {pinsHook: func(p *Pins) { p.ManifestSHA256 = strings.Repeat("0", 64) }},
		"unsafe manifest path": {mutate: func(files map[string][]byte, m *Manifest) {
			if files == nil {
				m.Files = append(m.Files, Entry{Path: "python/../../x", SHA256: strings.Repeat("0", 64)})
			}
		}},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			f := buildRuntime(t, opts)
			_, err := Ensure(f.config())
			reasonIs(t, err, ReasonRuntimeInvalid)
			if entries, _ := os.ReadDir(filepath.Join(f.state, "web-runtime")); len(entries) > 1 {
				t.Fatal("a refused archive left an extraction behind")
			}
		})
	}
}

func TestEnsureReasons(t *testing.T) {
	f := buildRuntime(t, archiveOptions{})
	os.Remove(filepath.Join(f.resources, "web-runtime.json"))
	_, err := Ensure(f.config())
	reasonIs(t, err, ReasonRuntimeMissing)

	f = buildRuntime(t, archiveOptions{})
	os.Remove(filepath.Join(f.resources, f.pins.Archive))
	_, err = Ensure(f.config())
	reasonIs(t, err, ReasonRuntimeMissing)

	other := "linux-amd64"
	if goPlatform() == other {
		other = "darwin-arm64"
	}
	f = buildRuntime(t, archiveOptions{platform: other})
	_, err = Ensure(f.config())
	reasonIs(t, err, ReasonRuntimeInvalid)

	f = buildRuntime(t, archiveOptions{})
	diskFree = func(string) (uint64, error) { return minFreeBytes - 1, nil }
	defer func() { diskFree = freeBytes }()
	_, err = Ensure(f.config())
	reasonIs(t, err, ReasonDiskLow)
}

func TestVerifyCatchesTamperAndUnlistedFiles(t *testing.T) {
	f := buildRuntime(t, archiveOptions{})
	root, err := Ensure(f.config())
	if err != nil {
		t.Fatal(err)
	}
	pyc := filepath.Join(root.Dir, "python", "lib", "python3.13", "__pycache__", "os.cpython-313.pyc")
	os.Chmod(pyc, 0o600)
	raw, _ := os.ReadFile(pyc)
	raw[0] ^= 1 // one byte, same size: verifyQuick cannot see it, Verify must
	os.WriteFile(pyc, raw, 0o400)
	if err = verifyQuick(root); err != nil {
		t.Fatalf("quick check hashed a file: %v", err)
	}
	reasonIs(t, Verify(root), ReasonRuntimeInvalid)
	raw[0] ^= 1
	os.Chmod(pyc, 0o600)
	os.WriteFile(pyc, raw, 0o400)
	if err = Verify(root); err != nil {
		t.Fatal(err)
	}
	os.Chmod(root.Dir, 0o700)
	os.WriteFile(filepath.Join(root.Dir, "python", "unlisted"), []byte("x"), 0o600)
	reasonIs(t, Verify(root), ReasonRuntimeInvalid)
	os.Remove(filepath.Join(root.Dir, "python", "unlisted"))
	if runtime.GOOS != "windows" {
		os.Symlink("/etc/hosts", filepath.Join(root.Dir, "python", "link"))
		reasonIs(t, Verify(root), ReasonRuntimeInvalid)
		os.Remove(filepath.Join(root.Dir, "python", "link"))
	}
	// The driver Node must stay the one the runtime was built against.
	os.WriteFile(filepath.Join(f.resources, "x-login-runtime", nodeName()), []byte("other node"), 0o700)
	reasonIs(t, Verify(root), ReasonRuntimeInvalid)
}

func TestEnsureRebuildsDamagedExtractionAndCollectsOldVersions(t *testing.T) {
	f := buildRuntime(t, archiveOptions{})
	root, err := Ensure(f.config())
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(root.Dir, "manifest.json"), 0o600)
	os.WriteFile(filepath.Join(root.Dir, "manifest.json"), []byte("{}"), 0o400)
	if root, err = Ensure(f.config()); err != nil || Verify(root) != nil {
		t.Fatalf("damaged extraction not rebuilt: %v", err)
	}
	// An upgrade brings a new archive digest, so a new directory; the old one
	// and any partial extraction go once the new helper has started.
	old := filepath.Join(f.state, "web-runtime", "0123456789abcdef")
	os.MkdirAll(filepath.Join(old, "python"), 0o700)
	os.WriteFile(filepath.Join(old, "python", "x"), []byte("x"), 0o400)
	os.Chmod(filepath.Join(old, "python"), 0o500)
	os.MkdirAll(filepath.Join(f.state, "web-runtime", ".extract-123"), 0o700)
	if err = gcRuntimes(f.state, filepath.Base(root.Dir)); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(f.state, "web-runtime"))
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if strings.Join(names, ",") != filepath.Base(root.Dir)+",extract.lock" {
		t.Fatalf("after GC: %v", names)
	}
}

func TestPinsRefuseIncompatibleVersions(t *testing.T) {
	for name, hook := range map[string]func(*Pins){
		"python":    func(p *Pins) { p.PythonVersion = "3.14.0" },
		"scrapling": func(p *Pins) { p.ScraplingVersion = "0.4.16" },
		"browser":   func(p *Pins) { p.BrowserVersion = "156.0.0.1" },
		"name":      func(p *Pins) { p.Archive = "other.tar.gz" },
	} {
		t.Run(name, func(t *testing.T) {
			f := buildRuntime(t, archiveOptions{pinsHook: hook})
			_, err := Ensure(f.config())
			reasonIs(t, err, ReasonRuntimeInvalid)
		})
	}
}

func TestUserAgent(t *testing.T) {
	want := map[string]string{
		"darwin":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
		"windows": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
		"linux":   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
	}
	for goos, ua := range want {
		if got := UserAgent(goos, PinnedMajor); got != ua {
			t.Errorf("%s: %q", goos, got)
		}
	}
	if UserAgent("freebsd", PinnedMajor) != "" || PinnedVersion[:4] != "155." {
		t.Fatal("unexpected user agent pin")
	}
}
