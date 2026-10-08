// Package webruntime supervises the node's web browser tier: the packaged
// Python runtime (extracted from one pinned archive), the pinned Chrome for
// Testing (downloaded and verified by the node), the loopback egress proxy and
// deny listener, and the scarlett_web_helper process that renders pages.
//
// Nothing here logs a URL, host, header, cookie, page or path.
package webruntime

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

const (
	pythonVersion    = "3.13.16"
	scraplingVersion = "0.4.15+scarlett.1"
	driverNodeVer    = "22.23.3"
	maxPinsBytes     = 64 << 10
	maxManifestBytes = 4 << 20
	// Free space required before extracting or downloading, and at helper start.
	minFreeBytes      = 3 << 29 // 1.5 GiB
	minStartFreeBytes = 512 << 20
)

// Test hooks.
var diskFree = freeBytes

// Pins is web-runtime.json, shipped beside the archive in the resource directory.
type Pins struct {
	SchemaVersion    int    `json:"schemaVersion"`
	Platform         string `json:"platform"`
	Archive          string `json:"archive"`
	ArchiveSHA256    string `json:"archiveSha256"`
	ArchiveBytes     int64  `json:"archiveBytes"`
	ManifestSHA256   string `json:"manifestSha256"`
	UnpackedBytes    int64  `json:"unpackedBytes"`
	Files            int    `json:"files"`
	PythonVersion    string `json:"pythonVersion"`
	ScraplingVersion string `json:"scraplingVersion"`
	BrowserVersion   string `json:"browserVersion"`
	BrowserZipSHA256 string `json:"browserZipSha256"`
}

// Manifest is the archive's first entry: the exact extracted tree.
type Manifest struct {
	SchemaVersion    int        `json:"schemaVersion"`
	Platform         string     `json:"platform"`
	PythonVersion    string     `json:"pythonVersion"`
	PBSRelease       string     `json:"pbsRelease"`
	ScraplingVersion string     `json:"scraplingVersion"`
	LockSHA256       string     `json:"lockSha256"`
	DriverNode       DriverNode `json:"driverNode"`
	Interpreter      string     `json:"interpreter"`
	BrowserVersion   string     `json:"browserVersion"`
	Files            []Entry    `json:"files"`
}

// DriverNode is the x-login runtime's Node that runs the Playwright driver.
type DriverNode struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
}

// Entry is one regular file of the extracted runtime.
type Entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Exec   bool   `json:"exec,omitempty"`
}

// Root is an extracted runtime with its parsed pins and browser pin.
type Root struct {
	Dir      string
	Resource string
	Pins     Pins
	Manifest Manifest
	Browser  BrowserPin
}

// Python is the interpreter's absolute path.
func (r Root) Python() string {
	return filepath.Join(r.Dir, filepath.FromSlash(r.Manifest.Interpreter))
}

func goPlatform() string { return runtime.GOOS + "-" + runtime.GOARCH }

func interpreterPath(platform string) string {
	if strings.HasPrefix(platform, "windows-") {
		return "python/python.exe"
	}
	return "python/bin/python3.13"
}

func nodeName() string {
	if runtime.GOOS == "windows" {
		return "node.exe"
	}
	return "node"
}

// readPins reads and checks web-runtime.json for this host.
func readPins(resourceDir string) (Pins, error) {
	var p Pins
	info, err := os.Lstat(filepath.Join(resourceDir, "web-runtime.json"))
	if os.IsNotExist(err) {
		return p, fail(ReasonRuntimeMissing, "no packaged web runtime")
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxPinsBytes {
		return p, fail(ReasonRuntimeInvalid, "runtime pins unreadable")
	}
	raw, err := os.ReadFile(filepath.Join(resourceDir, "web-runtime.json"))
	if err != nil {
		return p, fail(ReasonRuntimeInvalid, "runtime pins unreadable")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil || p.SchemaVersion != 1 || p.Archive != "web-runtime-"+p.Platform+".tar.gz" ||
		!hex64(p.ArchiveSHA256) || !hex64(p.ManifestSHA256) || !hex64(p.BrowserZipSHA256) || p.ArchiveBytes <= 0 ||
		p.UnpackedBytes <= 0 || p.Files <= 0 || p.PythonVersion != pythonVersion || p.ScraplingVersion != scraplingVersion ||
		p.BrowserVersion != PinnedVersion {
		return p, fail(ReasonRuntimeInvalid, "runtime pins incompatible")
	}
	if p.Platform != goPlatform() {
		return p, fail(ReasonRuntimeInvalid, "runtime archive is for another platform")
	}
	return p, nil
}

// Ensure returns the extracted runtime for the packaged archive, extracting it
// on first use into <state>/web-runtime/<archiveSha256[:16]>. Extraction
// streams the archive once: the manifest must come first and match its pin,
// every later entry must be a listed regular file with its exact size and
// hash, nothing may be missing, and the whole archive must match its digest.
// Only then is the staging directory renamed into place. Ensure does not hash
// an existing extraction; Verify does.
func Ensure(cfg Config) (Root, error) {
	if !filepath.IsAbs(cfg.ResourceDir) || !filepath.IsAbs(cfg.StateDir) {
		return Root{}, fail(ReasonRuntimeMissing, "fixed absolute resource and state paths required")
	}
	pins, err := readPins(cfg.ResourceDir)
	if err != nil {
		return Root{}, err
	}
	archive := filepath.Join(cfg.ResourceDir, pins.Archive)
	info, err := os.Lstat(archive)
	if os.IsNotExist(err) {
		return Root{}, fail(ReasonRuntimeMissing, "runtime archive missing")
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() != pins.ArchiveBytes {
		return Root{}, fail(ReasonRuntimeInvalid, "runtime archive size mismatch")
	}
	base := filepath.Join(cfg.StateDir, "web-runtime")
	if err = stateDir(cfg.StateDir); err == nil {
		err = privateDir(base)
	}
	if err != nil {
		return Root{}, fail(ReasonRuntimeInvalid, "private runtime state inaccessible")
	}
	lock, err := localfs.LockPrivateWait(filepath.Join(base, "extract.lock"))
	if err != nil {
		return Root{}, fail(ReasonRuntimeInvalid, "runtime extraction lock unavailable")
	}
	defer lock.Close()
	final := filepath.Join(base, pins.ArchiveSHA256[:16])
	if _, err = os.Lstat(final); err == nil {
		root, err := loadRoot(final, cfg.ResourceDir, pins)
		if err == nil {
			return root, nil
		}
		// A damaged extraction is rebuilt from the verified archive.
		if err = removeTree(final); err != nil {
			return Root{}, fail(ReasonRuntimeInvalid, "damaged runtime could not be removed")
		}
	}
	free, err := diskFree(base)
	if err != nil || free < max(uint64(minFreeBytes), uint64(pins.UnpackedBytes)+64<<20) {
		return Root{}, fail(ReasonDiskLow, "not enough free disk to extract the runtime")
	}
	staging, err := os.MkdirTemp(base, ".extract-")
	if err != nil {
		return Root{}, fail(ReasonRuntimeInvalid, "runtime staging unavailable")
	}
	defer removeTree(staging)
	if err = extract(archive, staging, pins); err != nil {
		return Root{}, err
	}
	if err = os.Rename(staging, final); err != nil {
		return Root{}, fail(ReasonRuntimeInvalid, "runtime publication failed")
	}
	return loadRoot(final, cfg.ResourceDir, pins)
}

func extract(archive, staging string, pins Pins) error {
	invalid := func(what string) error { return fail(ReasonRuntimeInvalid, what) }
	f, err := os.Open(archive)
	if err != nil {
		return fail(ReasonRuntimeMissing, "runtime archive unreadable")
	}
	defer f.Close()
	whole := sha256.New()
	counted := io.TeeReader(io.LimitReader(f, pins.ArchiveBytes+1), whole)
	gz, err := gzip.NewReader(counted)
	if err != nil {
		return invalid("runtime archive is not gzip")
	}
	gz.Multistream(false)
	tr := tar.NewReader(gz)
	var manifest *Manifest
	want := map[string]Entry{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || h.Typeflag != tar.TypeReg || !cleanRel(h.Name) || h.Size < 0 || total+h.Size > pins.UnpackedBytes+maxManifestBytes {
			return invalid("runtime archive entry refused")
		}
		total += h.Size
		if manifest == nil {
			if h.Name != "manifest.json" || h.Size > maxManifestBytes {
				return invalid("runtime manifest must come first")
			}
			raw, err := io.ReadAll(tr)
			if err != nil || sha(raw) != pins.ManifestSHA256 {
				return invalid("runtime manifest digest mismatch")
			}
			m, err := parseManifest(raw, pins)
			if err != nil {
				return err
			}
			manifest = &m
			for _, e := range m.Files {
				want[e.Path] = e
			}
			if err = os.WriteFile(filepath.Join(staging, "manifest.json"), raw, 0o400); err != nil {
				return invalid("runtime staging write failed")
			}
			continue
		}
		e, ok := want[h.Name]
		if !ok || e.Bytes != h.Size {
			return invalid("unlisted or resized runtime entry")
		}
		delete(want, h.Name)
		dst := filepath.Join(staging, filepath.FromSlash(h.Name))
		if err = os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return invalid("runtime staging write failed")
		}
		mode := os.FileMode(0o400)
		if e.Exec {
			mode = 0o500
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return invalid("runtime staging write failed")
		}
		hs := sha256.New()
		n, err := io.Copy(io.MultiWriter(out, hs), io.LimitReader(tr, e.Bytes+1))
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil || n != e.Bytes || hex.EncodeToString(hs.Sum(nil)) != e.SHA256 {
			return invalid("runtime entry digest mismatch")
		}
	}
	if _, err = io.Copy(io.Discard, gz); err != nil {
		return invalid("runtime archive trailer invalid")
	}
	if _, err = io.Copy(io.Discard, counted); err != nil {
		return invalid("runtime archive unreadable")
	}
	if manifest == nil || len(want) != 0 || hex.EncodeToString(whole.Sum(nil)) != pins.ArchiveSHA256 {
		return invalid("runtime archive incomplete or digest mismatch")
	}
	return nil
}

func sha(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func parseManifest(raw []byte, pins Pins) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil || m.SchemaVersion != 1 || m.Platform != pins.Platform || m.PythonVersion != pins.PythonVersion ||
		m.ScraplingVersion != pins.ScraplingVersion || m.BrowserVersion != pins.BrowserVersion || len(m.Files) != pins.Files ||
		m.Interpreter != interpreterPath(pins.Platform) || m.DriverNode.Version != driverNodeVer || !hex64(m.DriverNode.SHA256) ||
		m.DriverNode.Path != "x-login-runtime/"+map[bool]string{true: "node.exe", false: "node"}[strings.HasPrefix(pins.Platform, "windows-")] {
		return m, fail(ReasonRuntimeInvalid, "runtime manifest incompatible")
	}
	seen := map[string]bool{}
	var total int64
	for _, e := range m.Files {
		if !cleanRel(e.Path) || e.Path == "manifest.json" || seen[e.Path] || !hex64(e.SHA256) || e.Bytes < 0 {
			return m, fail(ReasonRuntimeInvalid, "runtime inventory invalid")
		}
		seen[e.Path] = true
		total += e.Bytes
	}
	if total != pins.UnpackedBytes || !seen[m.Interpreter] || !seen["browser/pin.json"] || !seen["browser/inventory.json"] {
		return m, fail(ReasonRuntimeInvalid, "runtime inventory incomplete")
	}
	return m, nil
}

// loadRoot parses an extracted runtime: the manifest against its pin, and
// the pinned browser files against their manifest entries.
func loadRoot(dir, resource string, pins Pins) (Root, error) {
	root := Root{Dir: dir, Resource: resource, Pins: pins}
	raw, err := readSmall(filepath.Join(dir, "manifest.json"), maxManifestBytes)
	if err != nil || sha(raw) != pins.ManifestSHA256 {
		return root, fail(ReasonRuntimeInvalid, "runtime manifest digest mismatch")
	}
	if root.Manifest, err = parseManifest(raw, pins); err != nil {
		return root, err
	}
	listed := map[string]Entry{}
	for _, e := range root.Manifest.Files {
		listed[e.Path] = e
	}
	files := map[string][]byte{}
	for _, name := range []string{"browser/pin.json", "browser/inventory.json"} {
		raw, err := readSmall(filepath.Join(dir, filepath.FromSlash(name)), maxManifestBytes)
		if err != nil || sha(raw) != listed[name].SHA256 {
			return root, fail(ReasonRuntimeInvalid, "pinned browser files invalid")
		}
		files[name] = raw
	}
	if root.Browser, err = parseBrowserPin(files["browser/pin.json"], files["browser/inventory.json"], pins); err != nil {
		return root, err
	}
	return root, nil
}

func readSmall(p string, limit int64) ([]byte, error) {
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("not a small regular file")
	}
	return os.ReadFile(p)
}

// Verify hashes the whole extracted runtime: no links or special files,
// every listed file with its exact size and hash, nothing unlisted, and the
// x-login Node the driver runs on equal to the manifest's pin.
func Verify(root Root) error {
	invalid := func(what string) error { return fail(ReasonRuntimeInvalid, what) }
	raw, err := readSmall(filepath.Join(root.Dir, "manifest.json"), maxManifestBytes)
	if err != nil || sha(raw) != root.Pins.ManifestSHA256 {
		return invalid("runtime manifest digest mismatch")
	}
	listed := map[string]Entry{}
	for _, e := range root.Manifest.Files {
		listed[e.Path] = e
	}
	seen := 0
	err = filepath.WalkDir(root.Dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type()&fs.ModeSymlink != 0 || (!d.IsDir() && !d.Type().IsRegular()) {
			return errors.New("link or special file")
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root.Dir, p)
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" {
			return nil
		}
		e, ok := listed[rel]
		if !ok {
			return errors.New("unlisted file")
		}
		digest, n, err := fileSHA256(p)
		if err != nil || n != e.Bytes || digest != e.SHA256 {
			return errors.New("modified file")
		}
		seen++
		return nil
	})
	if err != nil || seen != len(root.Manifest.Files) {
		return invalid("runtime inventory mismatch")
	}
	node := filepath.Join(root.Resource, "x-login-runtime", nodeName())
	if digest, _, err := fileSHA256(node); err != nil || digest != root.Manifest.DriverNode.SHA256 {
		return invalid("driver Node differs from the runtime's pin")
	}
	return nil
}

// verifyQuick is the per-start check: every listed file is present, regular,
// with its exact size and (on Unix) its executable bit. It hashes nothing.
func verifyQuick(root Root) error {
	for _, e := range root.Manifest.Files {
		info, err := os.Lstat(filepath.Join(root.Dir, filepath.FromSlash(e.Path)))
		if err != nil || !info.Mode().IsRegular() || info.Size() != e.Bytes ||
			(runtime.GOOS != "windows" && (info.Mode().Perm()&0o100 != 0) != e.Exec) {
			return fail(ReasonRuntimeInvalid, "runtime file missing or changed")
		}
	}
	return nil
}

// gcRuntimes removes every other extracted runtime version and any partial
// extraction. Call it only once the current runtime's helper has started.
func gcRuntimes(stateDir, keep string) error {
	base := filepath.Join(stateDir, "web-runtime")
	entries, err := os.ReadDir(base)
	if err != nil {
		return errors.New("runtime state unreadable")
	}
	var firstErr error
	for _, entry := range entries {
		name := entry.Name()
		if name == keep || name == "extract.lock" {
			continue
		}
		if err := removeTree(filepath.Join(base, name)); err != nil && firstErr == nil {
			firstErr = errors.New("old runtime removal failed")
		}
	}
	return firstErr
}
