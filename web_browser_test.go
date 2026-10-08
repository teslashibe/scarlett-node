package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

func TestWebRuntimeCheckCommand(t *testing.T) {
	state := privateTestDir(t)
	resources := filepath.Join(privateTestDir(t), "runtime")
	t.Setenv("SCARLETT_STATE_DIR", state)
	previous := checkWebRuntime
	t.Cleanup(func() { checkWebRuntime = previous })
	var got []any
	checkWebRuntime = func(_ context.Context, dir, stateDir string, withBrowser bool) error {
		got = []any{dir, stateDir, withBrowser}
		return nil
	}
	var out strings.Builder
	if err := webRuntimeCommand([]string{"check", "--resources", resources}, &out); err != nil || out.String() != "{\"webRuntime\":\"passed\"}\n" || got[0] != resources || got[1] != state || got[2] != false {
		t.Fatal("check", err, out.String(), got)
	}
	// Without --resources the X login runtime's order applies: the desktop's
	// SCARLETT_X_LOGIN_RESOURCE_DIR first.
	t.Setenv("SCARLETT_X_LOGIN_RESOURCE_DIR", resources)
	out.Reset()
	if err := webRuntimeCommand([]string{"check", "--with-browser"}, &out); err != nil || got[0] != resources || got[2] != true {
		t.Fatal("check with browser", err, got)
	}
	for _, args := range [][]string{nil, {"verify"}, {"check", "extra"}, {"check", "--unknown"}, {"check", "--resources", "relative/dir"}} {
		if err := webRuntimeCommand(args, &out); err == nil {
			t.Fatal("accepted", args)
		}
	}
	t.Setenv("SCARLETT_X_LOGIN_RESOURCE_DIR", "relative")
	if _, err := webRuntimeResourceDir(); err == nil {
		t.Fatal("relative resource directory accepted")
	}
	checkWebRuntime = func(context.Context, string, string, bool) error { return errors.New("archive digest mismatch") }
	out.Reset()
	if err := webRuntimeCommand([]string{"check", "--resources", resources}, &out); err == nil || out.Len() != 0 {
		t.Fatal("failed check printed passed")
	}
	// The real check refuses a directory without a runtime archive.
	checkWebRuntime = previous
	out.Reset()
	if err := webRuntimeCommand([]string{"check", "--resources", resources}, &out); err == nil || out.Len() != 0 {
		t.Fatal("check passed without a runtime archive")
	}
	none := unavailableBrowser{reason: "runtime_missing"}
	if s := none.Status(); s.Ready || s.Reason != "runtime_missing" {
		t.Fatalf("tier without a runtime: %+v", s)
	}
	if _, err := none.Fetch(context.Background(), worker.BrowserFetchRequest{}); !errors.Is(err, worker.ErrBrowserUnavailable) {
		t.Fatal("tier without a runtime fetched", err)
	}
	// An unresolvable resource directory gives no runtime at all.
	tier, stop := startRuntimeBrowser(context.Background(), config.Config{StateDir: state})
	stop()
	if s := tier.Status(); s.Ready || s.Reason != "runtime_missing" {
		t.Fatalf("tier without resources: %+v", s)
	}
}

// The real runtime manager behind the tier: with no runtime archive in the
// resource directory it settles on a closed reason, refuses fetches as
// unavailable, and stops cleanly.
func TestRuntimeBrowserWithoutArchive(t *testing.T) {
	resources, state := privateTestDir(t), privateTestDir(t)
	t.Setenv("SCARLETT_X_LOGIN_RESOURCE_DIR", resources)
	tier, stop := startRuntimeBrowser(context.Background(), config.Config{StateDir: state, WebBrowser: true, WebBrowserIdle: 120 * time.Second})
	var s worker.BrowserStatus
	for start := time.Now(); time.Since(start) < 10*time.Second; time.Sleep(20 * time.Millisecond) {
		if s = tier.Status(); s.Reason != "browser_downloading" {
			break
		}
	}
	if s.Ready || s.Reason != "runtime_missing" && s.Reason != "memory_low" || s.UserAgent == "" || s.Engine != "scrapling/0.4.15+scarlett.2" {
		t.Fatalf("status without an archive: %+v", s)
	}
	if _, err := tier.Fetch(context.Background(), worker.BrowserFetchRequest{URL: "https://example.com/", Wait: "load", TimeoutMS: 5000}); !errors.Is(err, worker.ErrBrowserUnavailable) {
		t.Fatal("fetch without a runtime", err)
	}
	tier.Prewarm()
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("runtime tier did not stop")
	}
}

func TestBrowserRuntimeInputs(t *testing.T) {
	if upstreamProxyURL(nil) != nil {
		t.Fatal("proxy without configuration")
	}
	proxy, err := config.ParseWebProxy("http://synthetic-user:synthetic-pass@proxy.synthetic.invalid:3128")
	if err != nil {
		t.Fatal(err)
	}
	// The address only; the credentials travel as the configured
	// Proxy-Authorization value.
	if u := upstreamProxyURL(proxy); u.String() != "http://proxy.synthetic.invalid:3128" || u.User != nil || proxy.Authorization == "" {
		t.Fatal("proxy URL", u.Redacted())
	}
	plain, _ := config.ParseWebProxy("http://[2001:db8::1]:8080")
	if u := upstreamProxyURL(plain); u.Host != "[2001:db8::1]:8080" || u.User != nil {
		t.Fatal("plain proxy URL", u.String())
	}
	if !strings.HasSuffix(xLoginNode("/r"), filepath.Join("x-login-runtime", "node")) && !strings.HasSuffix(xLoginNode("/r"), "node.exe") {
		t.Fatal("x-login node path", xLoginNode("/r"))
	}
}

// A browser result the coordinator does not store is logged with its status
// and code, and the error still reaches the worker. In production the network
// host gate answered every upload with Go's plain 404 while the node logged
// nothing; the job was served from the re-fetch and the gap went unseen.
func TestLogBrowserUploadRefusal(t *testing.T) {
	const job = "11111111-1111-4111-8111-111111111111"
	manifest := coordinator.BrowserResult{
		Version: "node-v1", Attempt: "22222222-2222-4222-8222-222222222222", Fence: "33333333-3333-4333-8333-333333333333",
		RequestSHA256: strings.Repeat("a", 64), URL: "https://example.com/", DOM: coordinator.DOMMemory, TreePeakBytes: 1 << 30,
		Challenge: "none", Browser: coordinator.BrowserInfo{Engine: "chromium", Version: "1", UserAgent: "ua"},
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
		log    string
	}{
		{"host gate 404", http.StatusNotFound, "404 page not found\n", "web browser: result upload not stored (dom memory, 0 parts sent, 0 skipped, 0 retries): POST manifest: coordinator HTTP 404\n"},
		{"fenced", http.StatusConflict, `{"error":{"code":"fenced","message":"The browser result does not match the current accepted lease."}}`, "web browser: result upload not stored (dom memory, 0 parts sent, 0 skipped, 0 retries): POST manifest: coordinator HTTP 409 fenced\n"},
		{"stored", http.StatusOK, `{"status":"stored"}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/node/v1/jobs/"+job+"/browser-result" {
					t.Error("unexpected request", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			t.Cleanup(server.Close)
			var out strings.Builder
			upload := logBrowserUpload(coordinator.New(server.URL, "synthetic-credential").UploadBrowserResult, &out)
			err := upload(context.Background(), job, manifest, "", time.Now().Add(time.Minute))
			if (err == nil) != (tc.status == http.StatusOK) || out.String() != tc.log {
				t.Fatalf("err %v, log %q", err, out.String())
			}
			if strings.Contains(out.String(), "synthetic-credential") {
				t.Fatal("credential logged")
			}
		})
	}
}

func TestRuntimeSolversCarryTheOperatorsKeys(t *testing.T) {
	if runtimeSolvers(nil) != nil {
		t.Fatal("solvers without a configuration")
	}
	s, err := config.NewWebSolvers(map[string]string{"2captcha": "synthetic-2captcha-key", "capmonster": "synthetic-capmonster-key"}, 3, 2_500_000, true)
	if err != nil {
		t.Fatal(err)
	}
	r := runtimeSolvers(s)
	if r == nil || len(r.Keys) != 2 || r.Keys["capmonster"] != "synthetic-capmonster-key" || r.Keys["2captcha"] != "synthetic-2captcha-key" ||
		r.MaxSolvesPerFetch != 3 || r.MaxMicroUSDPerDay != 2_500_000 || !r.Experimental || strings.Join(r.Providers(), ",") != "capmonster,2captcha" {
		t.Fatalf("runtime solvers %v", r.Providers())
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v %v", r, *r, r, s), "synthetic") {
		t.Fatal("solver keys formatted")
	}
}
