package webruntime

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

type zipOptions struct {
	extra    func(w *zip.Writer)
	skip     string
	mode     map[string]fs.FileMode
	content  map[string][]byte
	linkDest map[string]string
}

func buildZip(t *testing.T, inv Inventory, data map[string][]byte, opts *zipOptions) []byte {
	t.Helper()
	if opts == nil {
		opts = &zipOptions{}
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	dir := &zip.FileHeader{Name: "chrome-test/", Method: zip.Store}
	dir.SetMode(fs.ModeDir | 0o755)
	w.CreateHeader(dir)
	for _, f := range inv.Files {
		if f.Path == opts.skip {
			continue
		}
		h := &zip.FileHeader{Name: f.Path, Method: zip.Deflate}
		mode := fs.FileMode(0o644)
		if f.Mode == "0755" {
			mode = 0o755
		}
		if m, ok := opts.mode[f.Path]; ok {
			mode = m
		}
		h.SetMode(mode)
		fw, _ := w.CreateHeader(h)
		content := data[f.Path]
		if c, ok := opts.content[f.Path]; ok {
			content = c
		}
		fw.Write(content)
	}
	for _, l := range inv.Links {
		h := &zip.FileHeader{Name: l.Path, Method: zip.Store}
		h.SetMode(fs.ModeSymlink | 0o755)
		fw, _ := w.CreateHeader(h)
		target := l.Target
		if d, ok := opts.linkDest[l.Path]; ok {
			target = d
		}
		fw.Write([]byte(target))
	}
	if opts.extra != nil {
		opts.extra(w)
	}
	w.Close()
	return buf.Bytes()
}

// zipServer serves the zip as storage.googleapis.com over loopback TLS.
type zipServer struct {
	server *httptest.Server
	hits   atomic.Int64
}

func serveZip(t *testing.T, handler http.HandlerFunc) *zipServer {
	t.Helper()
	z := &zipServer{}
	z.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		z.hits.Add(1)
		handler(w, r)
	}))
	t.Cleanup(z.server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(z.server.Certificate())
	browserTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, z.server.Listener.Addr().String())
		}}
	t.Cleanup(func() { browserTransport = nil })
	return z
}

// browserFixture is an extracted runtime whose pin names a zip built here.
func browserFixture(t *testing.T, opts *zipOptions, inventory func(*Inventory)) (*fixtureRuntime, Root, []byte) {
	t.Helper()
	inv, data := testInventory()
	if inventory != nil {
		inventory(&inv)
	}
	raw := buildZip(t, inv, data, opts)
	f := buildRuntime(t, archiveOptions{inventory: func(i *Inventory) { *i = inv }, pin: func(p *BrowserPin) {
		p.SHA256, p.Bytes = digest(raw), int64(len(raw))
	}})
	root, err := Ensure(f.config())
	if err != nil {
		t.Fatal(err)
	}
	return f, root, raw
}

func TestEnsureBrowserDownloadsVerifiesAndReuses(t *testing.T) {
	f, root, raw := browserFixture(t, nil, nil)
	z := serveZip(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chrome-for-testing-public/"+PinnedVersion+"/"+cftNames[goPlatform()]+"/chrome-"+cftNames[goPlatform()]+".zip" {
			http.NotFound(w, r)
			return
		}
		w.Write(raw)
	})
	b, err := EnsureBrowser(context.Background(), f.config(), root.Browser)
	if err != nil {
		t.Fatal(err)
	}
	if b.Executable != filepath.Join(f.state, "web-browser-bin", root.Browser.SHA256[:16], "chrome-test", "chrome") || b.Version != PinnedVersion {
		t.Fatalf("browser %+v", b)
	}
	if err = VerifyBrowser(b.Dir, root.Browser.Inventory); err != nil {
		t.Fatal(err)
	}
	if err = verifyBrowserQuick(b.Dir, root.Browser.Inventory); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if target, err := os.Readlink(filepath.Join(b.Dir, "chrome-test", "Current")); err != nil || target != "lib" {
			t.Fatalf("framework link %q %v", target, err)
		}
	}
	if _, err = EnsureBrowser(context.Background(), f.config(), root.Browser); err != nil || z.hits.Load() != 1 {
		t.Fatalf("second EnsureBrowser downloaded again (%d hits): %v", z.hits.Load(), err)
	}
	entries, _ := os.ReadDir(filepath.Join(f.state, "web-browser-bin"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("partial left behind: %s", e.Name())
		}
	}
	// Tamper after extraction: one byte, then a mode bit.
	data := filepath.Join(b.Dir, "chrome-test", "lib", "data.bin")
	os.Chmod(data, 0o600)
	os.WriteFile(data, []byte("Browser data"), 0o400)
	reasonIs(t, VerifyBrowser(b.Dir, root.Browser.Inventory), ReasonBrowserInvalid)
	os.Chmod(data, 0o600)
	os.WriteFile(data, []byte("browser data"), 0o400)
	if runtime.GOOS != "windows" {
		os.Chmod(data, 0o500)
		reasonIs(t, VerifyBrowser(b.Dir, root.Browser.Inventory), ReasonBrowserInvalid)
		reasonIs(t, verifyBrowserQuick(b.Dir, root.Browser.Inventory), ReasonBrowserInvalid)
	}
}

func TestEnsureBrowserRefusals(t *testing.T) {
	type tc struct {
		opts      *zipOptions
		inventory func(*Inventory)
		serve     func(raw []byte) http.HandlerFunc
		pin       func(*BrowserPin)
		reason    Reason
	}
	ok := func(raw []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { w.Write(raw) }
	}
	cases := map[string]tc{
		"sha mismatch": {serve: func(raw []byte) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { c := bytes.Clone(raw); c[len(c)/2] ^= 1; w.Write(c) }
		}, reason: ReasonBrowserDownloadFailed},
		"oversize": {serve: func(raw []byte) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { w.Write(append(bytes.Clone(raw), make([]byte, 4096)...)) }
		}, reason: ReasonBrowserDownloadFailed},
		"truncated": {serve: func(raw []byte) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "100000000")
				w.Write(raw[:len(raw)/2])
			}
		}, reason: ReasonBrowserDownloadFailed},
		"redirect elsewhere": {serve: func(raw []byte) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "https://evil.example/chrome.zip", http.StatusFound)
			}
		}, reason: ReasonBrowserDownloadFailed},
		"http status": {serve: func([]byte) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { http.Error(w, "gone", http.StatusNotFound) }
		}, reason: ReasonBrowserDownloadFailed},
		"unlisted entry": {opts: &zipOptions{extra: func(w *zip.Writer) {
			fw, _ := w.Create("chrome-test/extra.bin")
			fw.Write([]byte("x"))
		}}, serve: ok, reason: ReasonBrowserInvalid},
		"missing entry":  {opts: &zipOptions{skip: "chrome-test/lib/data.bin"}, serve: ok, reason: ReasonBrowserInvalid},
		"content change": {opts: &zipOptions{content: map[string][]byte{"chrome-test/lib/data.bin": []byte("Browser data")}}, serve: ok, reason: ReasonBrowserInvalid},
		"unlisted directory": {opts: &zipOptions{extra: func(w *zip.Writer) {
			h := &zip.FileHeader{Name: "chrome-test/empty/"}
			h.SetMode(fs.ModeDir | 0o755)
			w.CreateHeader(h)
		}}, serve: ok, reason: ReasonBrowserInvalid},
		"traversal": {opts: &zipOptions{extra: func(w *zip.Writer) {
			fw, _ := w.Create("../escape")
			fw.Write([]byte("x"))
		}}, serve: ok, reason: ReasonBrowserInvalid},
	}
	if runtime.GOOS != "windows" {
		cases["mode mismatch"] = tc{opts: &zipOptions{mode: map[string]fs.FileMode{"chrome-test/lib/data.bin": 0o755}}, serve: ok, reason: ReasonBrowserInvalid}
		cases["link retargeted"] = tc{opts: &zipOptions{linkDest: map[string]string{"chrome-test/Current": "../../outside"}}, serve: ok, reason: ReasonBrowserInvalid}
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f, root, raw := browserFixture(t, c.opts, c.inventory)
			serveZip(t, c.serve(raw))
			_, err := EnsureBrowser(context.Background(), f.config(), root.Browser)
			reasonIs(t, err, c.reason)
			entries, _ := os.ReadDir(filepath.Join(f.state, "web-browser-bin"))
			for _, e := range entries {
				if e.Name() != "download.lock" {
					t.Fatalf("a refused browser left %s behind", e.Name())
				}
			}
		})
	}
}

func TestBrowserInventoryRefusesLinksThatEscapeOrShadow(t *testing.T) {
	base := func() BrowserPin {
		inv, _ := testInventory()
		pin := BrowserPin{Platform: "darwin-arm64", Executable: "chrome-test/chrome", Inventory: inv}
		for _, f := range inv.Files {
			pin.UnpackedBytes += f.Bytes
		}
		return pin
	}
	if err := validInventory(base()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*BrowserPin){
		"escape":        func(p *BrowserPin) { p.Inventory.Links = []InventoryLink{{Path: "chrome-test/x", Target: "../../etc"}} },
		"absolute":      func(p *BrowserPin) { p.Inventory.Links = []InventoryLink{{Path: "chrome-test/x", Target: "/etc"}} },
		"through link":  func(p *BrowserPin) { p.Inventory.Links = []InventoryLink{{Path: "chrome-test/lib", Target: "other"}} },
		"windows link":  func(p *BrowserPin) { p.Platform = "windows-amd64" },
		"no executable": func(p *BrowserPin) { p.Executable = "chrome-test/missing" },
		"bad mode":      func(p *BrowserPin) { p.Inventory.Files[0].Mode = "0777" },
		"duplicate":     func(p *BrowserPin) { p.Inventory.Files = append(p.Inventory.Files, p.Inventory.Files[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			pin := base()
			pin.Inventory.Links = []InventoryLink{{Path: "chrome-test/Current", Target: "lib"}}
			mutate(&pin)
			if validInventory(pin) == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestBrowserPartialsAndOldVersionsAreCollected(t *testing.T) {
	f, root, raw := browserFixture(t, nil, nil)
	serveZip(t, func(w http.ResponseWriter, r *http.Request) { w.Write(raw) })
	base := filepath.Join(f.state, "web-browser-bin")
	// A download interrupted by a restart is simply downloaded again.
	if err := privateDir(base); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(base, ".download-123"), raw[:10], 0o600)
	os.MkdirAll(filepath.Join(base, ".extract-456", "chrome-test"), 0o700)
	cleanBrowserPartials(f.state)
	if entries, _ := os.ReadDir(base); len(entries) != 0 {
		t.Fatalf("partials survived: %d", len(entries))
	}
	b, err := EnsureBrowser(context.Background(), f.config(), root.Browser)
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(base, "fedcba9876543210")
	os.MkdirAll(filepath.Join(old, "chrome-mac-arm64", "Google Chrome for Testing.app", "Contents"), 0o700)
	var order []string
	unregister := func(app string) {
		if _, err := os.Stat(app); err != nil {
			t.Error("unregistered after deletion")
		}
		order = append(order, filepath.Base(app))
	}
	if err = gcBrowsers(f.state, filepath.Base(b.Dir), unregister); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old browser version kept")
	}
	if _, err = os.Stat(b.Dir); err != nil {
		t.Fatal("current browser removed")
	}
	if runtime.GOOS == "darwin" && (len(order) != 1 || order[0] != "Google Chrome for Testing.app") {
		t.Fatalf("lsregister -u not run first: %v", order)
	}
	if appBundle(filepath.Join("/x", "chrome-mac-arm64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing")) != filepath.Join("/x", "chrome-mac-arm64", "Google Chrome for Testing.app") {
		t.Fatal("app bundle path")
	}
}

func TestBrowserPinMustMatchTheRuntime(t *testing.T) {
	inv, _ := testInventory()
	invRaw, _ := json.Marshal(inv)
	var unpacked int64
	for _, f := range inv.Files {
		unpacked += f.Bytes
	}
	pins := Pins{Platform: "linux-amd64", BrowserVersion: PinnedVersion, BrowserZipSHA256: strings.Repeat("b", 64)}
	good := BrowserPin{Version: PinnedVersion, Platform: "linux-amd64", URL: "https://storage.googleapis.com/chrome-for-testing-public/" + PinnedVersion + "/linux64/chrome-linux64.zip",
		SHA256: strings.Repeat("b", 64), Bytes: 10, Executable: "chrome-test/chrome", InventorySHA256: digest(invRaw), UnpackedBytes: unpacked}
	raw, _ := json.Marshal(good)
	if _, err := parseBrowserPin(raw, invRaw, pins); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*BrowserPin){
		"other host": func(p *BrowserPin) { p.URL = strings.Replace(p.URL, "storage.googleapis.com", "example.com", 1) },
		"http":       func(p *BrowserPin) { p.URL = strings.Replace(p.URL, "https:", "http:", 1) },
		"other zip":  func(p *BrowserPin) { p.SHA256 = strings.Repeat("c", 64) },
		"inventory":  func(p *BrowserPin) { p.InventorySHA256 = strings.Repeat("c", 64) },
		"version":    func(p *BrowserPin) { p.Version = "156.0.0.0" },
	} {
		bad := good
		mutate(&bad)
		raw, _ := json.Marshal(bad)
		if _, err := parseBrowserPin(raw, invRaw, pins); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
