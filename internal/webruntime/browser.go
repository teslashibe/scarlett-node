package webruntime

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// BrowserPin is browser/pin.json from the runtime archive: where the node
// downloads Chrome for Testing and the exact tree it must extract to.
type BrowserPin struct {
	Version         string    `json:"version"`
	Platform        string    `json:"platform"`
	URL             string    `json:"url"`
	SHA256          string    `json:"sha256"`
	Bytes           int64     `json:"bytes"`
	Executable      string    `json:"executable"`
	InventorySHA256 string    `json:"inventory_sha256"`
	UnpackedBytes   int64     `json:"unpacked_bytes"`
	Inventory       Inventory `json:"-"`
}

// Inventory is the exact extracted Chrome for Testing tree.
type Inventory struct {
	Files []InventoryFile `json:"files"`
	Links []InventoryLink `json:"links"`
}

type InventoryFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Mode   string `json:"mode"`
}

type InventoryLink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// Browser is a verified extracted Chrome for Testing.
type Browser struct {
	Dir        string
	Executable string
	Version    string
}

// Test hooks: the download host, the HTTP transport and the time source.
var (
	browserDownloadHost                   = "storage.googleapis.com"
	browserTransport    http.RoundTripper = nil
	browserTimeout                        = 15 * time.Minute
)

var cftNames = map[string]string{"darwin-arm64": "mac-arm64", "darwin-amd64": "mac-x64", "windows-amd64": "win64", "linux-amd64": "linux64"}

func parseBrowserPin(pinRaw, inventoryRaw []byte, pins Pins) (BrowserPin, error) {
	invalid := fail(ReasonRuntimeInvalid, "pinned browser files invalid")
	var pin BrowserPin
	dec := json.NewDecoder(strings.NewReader(string(pinRaw)))
	dec.DisallowUnknownFields()
	cft := cftNames[pins.Platform]
	if dec.Decode(&pin) != nil || pin.Version != pins.BrowserVersion || pin.Platform != pins.Platform || pin.SHA256 != pins.BrowserZipSHA256 ||
		pin.InventorySHA256 != sha(inventoryRaw) || pin.Bytes <= 0 || pin.UnpackedBytes <= 0 || !cleanRel(pin.Executable) || cft == "" ||
		pin.URL != "https://"+browserDownloadHost+"/chrome-for-testing-public/"+pin.Version+"/"+cft+"/chrome-"+cft+".zip" {
		return pin, invalid
	}
	dec = json.NewDecoder(strings.NewReader(string(inventoryRaw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&pin.Inventory) != nil || validInventory(pin) != nil {
		return pin, invalid
	}
	return pin, nil
}

// validInventory refuses unsafe names, duplicates, links that leave the tree
// or that another listed path would pass through, and a missing executable.
func validInventory(pin BrowserPin) error {
	seen := map[string]bool{}
	links := map[string]bool{}
	var total int64
	exe := false
	for _, f := range pin.Inventory.Files {
		if !cleanRel(f.Path) || seen[f.Path] || !hex64(f.SHA256) || f.Bytes < 0 || (f.Mode != "0755" && f.Mode != "0644") {
			return errors.New("inventory file invalid")
		}
		seen[f.Path] = true
		total += f.Bytes
		exe = exe || f.Path == pin.Executable && (f.Mode == "0755" || strings.HasPrefix(pin.Platform, "windows-"))
	}
	for _, l := range pin.Inventory.Links {
		if !cleanRel(l.Path) || seen[l.Path] || !linkInside(l.Path, l.Target) || strings.HasPrefix(pin.Platform, "windows-") {
			return errors.New("inventory link invalid")
		}
		seen[l.Path] = true
		links[l.Path] = true
	}
	for p := range seen {
		for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
			if links[dir] {
				return errors.New("inventory path passes through a link")
			}
		}
	}
	if !exe || total != pin.UnpackedBytes {
		return errors.New("inventory incomplete")
	}
	return nil
}

func linkInside(p, target string) bool {
	if target == "" || len(target) > 1024 || strings.ContainsAny(target, "\\:\x00") || path.IsAbs(target) {
		return false
	}
	joined := path.Clean(path.Join(path.Dir(p), target))
	return joined != "." && joined != ".." && !strings.HasPrefix(joined, "../") && cleanRel(joined)
}

func browserBase(stateDir string) string { return filepath.Join(stateDir, "web-browser-bin") }

// browserDir is where a pinned zip extracts: content-addressed by its digest.
func browserDir(stateDir string, pin BrowserPin) string {
	return filepath.Join(browserBase(stateDir), pin.SHA256[:16])
}

func (pin BrowserPin) browser(stateDir string) Browser {
	dir := browserDir(stateDir, pin)
	return Browser{Dir: dir, Executable: filepath.Join(dir, filepath.FromSlash(pin.Executable)), Version: pin.Version}
}

// EnsureBrowser returns the extracted pinned browser, downloading it first if
// it is not there. The download uses normal system networking (never the web
// egress proxy), Go's default roots, redirects only to the pinned host, a
// byte cap of the pinned size and the pinned sha256. Extraction accepts only
// inventory paths, with exact size, hash and mode, and symlinks only where
// listed with their exact target. One attempt; the Manager retries with
// backoff. It does not hash an existing extraction; VerifyBrowser does.
func EnsureBrowser(ctx context.Context, cfg Config, pin BrowserPin) (Browser, error) {
	base := browserBase(cfg.StateDir)
	if err := stateDir(cfg.StateDir); err != nil {
		return Browser{}, fail(ReasonBrowserInvalid, "private browser state inaccessible")
	}
	if err := privateDir(base); err != nil {
		return Browser{}, fail(ReasonBrowserInvalid, "private browser state inaccessible")
	}
	lock, err := localfs.LockPrivateWait(filepath.Join(base, "download.lock"))
	if err != nil {
		return Browser{}, fail(ReasonBrowserInvalid, "browser download lock unavailable")
	}
	defer lock.Close()
	browser := pin.browser(cfg.StateDir)
	if info, err := os.Lstat(browser.Dir); err == nil && info.IsDir() {
		return browser, nil
	}
	free, err := diskFree(base)
	if err != nil || free < max(uint64(minFreeBytes), uint64(pin.Bytes+pin.UnpackedBytes)+64<<20) {
		return Browser{}, fail(ReasonDiskLow, "not enough free disk to download the browser")
	}
	zipPath, err := downloadBrowser(ctx, base, pin)
	if zipPath != "" {
		defer os.Remove(zipPath)
	}
	if err != nil {
		return Browser{}, err
	}
	staging, err := os.MkdirTemp(base, ".extract-")
	if err != nil {
		return Browser{}, fail(ReasonBrowserInvalid, "browser staging unavailable")
	}
	defer removeTree(staging)
	if err = extractBrowser(zipPath, staging, pin); err != nil {
		return Browser{}, err
	}
	if err = os.Rename(staging, browser.Dir); err != nil {
		return Browser{}, fail(ReasonBrowserInvalid, "browser publication failed")
	}
	return browser, nil
}

func downloadBrowser(ctx context.Context, base string, pin BrowserPin) (string, error) {
	failed := func(what string) error { return fail(ReasonBrowserDownloadFailed, what) }
	transport := browserTransport
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	client := &http.Client{Transport: transport, Timeout: browserTimeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.Hostname() != browserDownloadHost || req.URL.Port() != "" {
			return errors.New("browser download redirect refused")
		}
		return nil
	}}
	defer client.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pin.URL, nil)
	if err != nil {
		return "", failed("browser download request invalid")
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", failed("browser download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > pin.Bytes {
		return "", failed("browser download refused")
	}
	out, err := os.CreateTemp(base, ".download-")
	if err != nil {
		return "", failed("browser download file unavailable")
	}
	name := out.Name()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, pin.Bytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return name, failed("browser download interrupted")
	}
	if n != pin.Bytes || hex.EncodeToString(h.Sum(nil)) != pin.SHA256 {
		return name, failed("browser download size or digest mismatch")
	}
	return name, nil
}

func extractBrowser(zipPath, staging string, pin BrowserPin) error {
	invalid := func(what string) error { return fail(ReasonBrowserInvalid, what) }
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return invalid("browser zip unreadable")
	}
	defer r.Close()
	files := map[string]InventoryFile{}
	links := map[string]string{}
	parents := map[string]bool{}
	for _, f := range pin.Inventory.Files {
		files[f.Path] = f
	}
	for _, l := range pin.Inventory.Links {
		links[l.Path] = l.Target
	}
	for p := range files {
		for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
			parents[dir] = true
		}
	}
	for p := range links {
		for dir := path.Dir(p); dir != "."; dir = path.Dir(dir) {
			parents[dir] = true
		}
	}
	seen := map[string]bool{}
	var pending []InventoryLink
	for _, entry := range r.File {
		name := entry.Name
		if strings.HasSuffix(name, "/") {
			name = strings.TrimSuffix(name, "/")
			if !cleanRel(name) || !parents[name] || entry.Mode()&fs.ModeType&^fs.ModeDir != 0 {
				return invalid("unlisted browser directory")
			}
			continue
		}
		if !cleanRel(name) || seen[name] {
			return invalid("unsafe or duplicate browser entry")
		}
		seen[name] = true
		mode := entry.Mode()
		if target, ok := links[name]; ok {
			if mode&fs.ModeSymlink == 0 || entry.UncompressedSize64 > 1024 {
				return invalid("browser link entry invalid")
			}
			rc, err := entry.Open()
			if err != nil {
				return invalid("browser link entry unreadable")
			}
			raw, err := io.ReadAll(io.LimitReader(rc, 1025))
			rc.Close()
			if err != nil || string(raw) != target {
				return invalid("browser link target mismatch")
			}
			pending = append(pending, InventoryLink{Path: name, Target: target})
			continue
		}
		want, ok := files[name]
		if !ok || mode&fs.ModeType != 0 || entry.UncompressedSize64 != uint64(want.Bytes) {
			return invalid("unlisted or resized browser entry")
		}
		if runtime.GOOS != "windows" && (mode.Perm()&0o100 != 0) != (want.Mode == "0755") {
			return invalid("browser entry mode mismatch")
		}
		dst := filepath.Join(staging, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return invalid("browser staging write failed")
		}
		perm := os.FileMode(0o400)
		if want.Mode == "0755" {
			perm = 0o500
		}
		rc, err := entry.Open()
		if err != nil {
			return invalid("browser entry unreadable")
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err != nil {
			rc.Close()
			return invalid("browser staging write failed")
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(rc, want.Bytes+1))
		rc.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil || n != want.Bytes || hex.EncodeToString(h.Sum(nil)) != want.SHA256 {
			return invalid("browser entry digest mismatch")
		}
	}
	// Links last, so no file is ever written through one.
	for _, l := range pending {
		dst := filepath.Join(staging, filepath.FromSlash(l.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil || os.Symlink(l.Target, dst) != nil {
			return invalid("browser link creation failed")
		}
	}
	if len(seen) != len(files)+len(links) {
		return invalid("browser zip is missing listed entries")
	}
	return nil
}

// VerifyBrowser hashes the whole extracted browser against its inventory:
// every listed file with its exact size, hash and (on Unix) mode, every listed
// link with its exact target, and nothing else.
func VerifyBrowser(dir string, inventory Inventory) error {
	files := map[string]InventoryFile{}
	links := map[string]string{}
	for _, f := range inventory.Files {
		files[f.Path] = f
	}
	for _, l := range inventory.Links {
		links[l.Path] = l.Target
	}
	seen := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if want, ok := links[rel]; !ok || err != nil || target != want {
				return errors.New("unlisted or changed link")
			}
			seen++
		case d.IsDir():
		case d.Type().IsRegular():
			want, ok := files[rel]
			if !ok {
				return errors.New("unlisted file")
			}
			info, err := d.Info()
			if err != nil || (runtime.GOOS != "windows" && (info.Mode().Perm()&0o100 != 0) != (want.Mode == "0755")) {
				return errors.New("mode changed")
			}
			digest, n, err := fileSHA256(p)
			if err != nil || n != want.Bytes || digest != want.SHA256 {
				return errors.New("modified file")
			}
			seen++
		default:
			return errors.New("special file")
		}
		return nil
	})
	if err != nil || seen != len(files)+len(links) {
		return fail(ReasonBrowserInvalid, "browser inventory mismatch")
	}
	return nil
}

// verifyBrowserQuick is the per-start check: sizes, modes and link targets only.
func verifyBrowserQuick(dir string, inventory Inventory) error {
	for _, f := range inventory.Files {
		info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil || !info.Mode().IsRegular() || info.Size() != f.Bytes ||
			(runtime.GOOS != "windows" && (info.Mode().Perm()&0o100 != 0) != (f.Mode == "0755")) {
			return fail(ReasonBrowserInvalid, "browser file missing or changed")
		}
	}
	for _, l := range inventory.Links {
		if target, err := os.Readlink(filepath.Join(dir, filepath.FromSlash(l.Path))); err != nil || target != l.Target {
			return fail(ReasonBrowserInvalid, "browser link missing or changed")
		}
	}
	return nil
}

// appBundle is the macOS .app that holds a CfT executable, or "".
func appBundle(executable string) string {
	if i := strings.Index(executable, ".app"+string(filepath.Separator)+"Contents"); i >= 0 {
		return executable[:i+len(".app")]
	}
	return ""
}

// cleanBrowserPartials removes interrupted downloads and extractions.
func cleanBrowserPartials(stateDir string) {
	for _, base := range []string{browserBase(stateDir), filepath.Join(stateDir, "web-runtime")} {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), ".download-") || strings.HasPrefix(entry.Name(), ".extract-") {
				_ = removeTree(filepath.Join(base, entry.Name()))
			}
		}
	}
}

// gcBrowsers removes every other extracted browser version once the current
// one has passed its launch probe. On macOS each old .app is unregistered
// from LaunchServices first, so no record outlives its files.
func gcBrowsers(stateDir, keep string, unregister func(app string)) error {
	base := browserBase(stateDir)
	entries, err := os.ReadDir(base)
	if err != nil {
		return errors.New("browser state unreadable")
	}
	var firstErr error
	for _, entry := range entries {
		name := entry.Name()
		if name == keep || name == "download.lock" {
			continue
		}
		dir := filepath.Join(base, name)
		if entry.IsDir() && len(name) == 16 && runtime.GOOS == "darwin" {
			apps, _ := filepath.Glob(filepath.Join(dir, "chrome-mac-*", "Google Chrome for Testing.app"))
			for _, app := range apps {
				unregister(app)
			}
		}
		if err := removeTree(dir); err != nil && firstErr == nil {
			firstErr = errors.New("old browser removal failed")
		}
	}
	return firstErr
}
