//go:build webbrowser_measure

package webruntime

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMeasurePages renders public pages with this checkout's helper and the
// pinned Chrome for Testing, through the node's own Manager, sampler and
// egress proxy, and reports each page's DOM size and the helper tree's peak
// while it loaded (large pages, design §5.3). It reaches the public internet
// and needs no download: the runtime comes from an existing archive and the
// browser from an extracted, verified copy.
//
//	SCARLETT_MEASURE_RESOURCES  absolute dir with web-runtime.json and its archive
//	                            (for example the desktop app's Contents/Resources/runtime)
//	SCARLETT_MEASURE_BROWSER    absolute dir of an extracted Chrome for Testing for the pinned
//	                            version (for example <state>/web-browser-bin/<digest>)
//	SCARLETT_MEASURE_URLS       space-separated https URLs
//
//	go test -tags webbrowser_measure -run TestMeasurePages -v -timeout 30m ./internal/webruntime
func TestMeasurePages(t *testing.T) {
	resources, browserDir, urls := os.Getenv("SCARLETT_MEASURE_RESOURCES"), os.Getenv("SCARLETT_MEASURE_BROWSER"), strings.Fields(os.Getenv("SCARLETT_MEASURE_URLS"))
	if resources == "" || browserDir == "" || len(urls) == 0 {
		t.Skip("SCARLETT_MEASURE_RESOURCES, SCARLETT_MEASURE_BROWSER and SCARLETT_MEASURE_URLS are not all set")
	}
	helper, err := filepath.Abs("../../third_party/web-browser/scarlett_web_helper.py")
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	m := New(Config{ResourceDir: resources, StateDir: state, Guard: publicOnly{}, Capacity: 1, IdleTimeout: 10 * time.Minute,
		Logf: func(format string, args ...any) { t.Logf(format, args...) }})
	// The browser that is already there, and this checkout's helper on the
	// archive's interpreter.
	m.d.ensureBrowser = func(_ context.Context, _ Config, pin BrowserPin) (Browser, error) {
		return Browser{Dir: browserDir, Executable: filepath.Join(browserDir, filepath.FromSlash(pin.Executable)), Version: pin.Version}, nil
	}
	m.d.command = func(r Root) (string, []string) {
		return r.Python(), []string{"-I", "-B", "-X", "utf8", helper}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	go m.Run(ctx)
	for m.Health().State != "ready" {
		if ctx.Err() != nil {
			t.Fatal("browser tier never ready:", m.Health().Reason)
		}
		time.Sleep(200 * time.Millisecond)
	}
	h := m.Health()
	recycle, kill := Thresholds(h.Capacity, m.physical)
	t.Logf("ready: capacity %d, physical %.1f GiB, recycle %.2f GiB, kill %.2f GiB (kill_bytes %d)", h.Capacity, float64(m.physical)/gib, float64(recycle)/gib, float64(kill)/gib, h.KillBytes)
	for _, url := range urls {
		started := time.Now()
		res, err := m.Fetch(ctx, FetchRequest{URL: url, Wait: "load", TimeoutMS: 45000})
		if err != nil {
			t.Errorf("%s: %v", url, err)
			continue
		}
		size := int64(-1)
		if res.HTMLPath != "" {
			if info, err := os.Stat(res.HTMLPath); err == nil {
				size = info.Size()
			}
			_ = os.Remove(res.HTMLPath)
		}
		t.Logf("MEASURE %s outcome=%s error=%q status=%d html_bytes=%d file_bytes=%d tree_peak=%.2f GiB pressure=%d in %s",
			url, res.Outcome, res.Error, res.StatusCode, res.HTMLBytes, size, float64(res.TreePeakBytes)/gib, m.d.pressure(), time.Since(started).Round(time.Millisecond))
	}
}

// publicOnly lets the browser reach public addresses only, as the node's
// egress guard does.
type publicOnly struct{}

func (publicOnly) Allowed(_ context.Context, a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	if a.Is4() {
		b := a.As4()
		return !(b[0] == 0 || b[0] == 100 && b[1]&0xc0 == 64 || b[0] >= 224)
	}
	return true
}
