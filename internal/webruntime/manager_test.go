package webruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFakeHelperProcess is the helper when the Manager starts this test
// binary with "-- <mode> <dump dir>". It speaks the helper's HTTP API with
// the same environment contract and never touches the network.
func TestFakeHelperProcess(t *testing.T) {
	i := slices.Index(os.Args, "--")
	if i < 0 || len(os.Args) < i+3 {
		return
	}
	mode, dump := os.Args[i+1], os.Args[i+2]
	os.Exit(fakeHelper(mode, dump))
}

func fakeHelper(mode, dump string) int {
	keys := []string{}
	for _, kv := range os.Environ() {
		keys = append(keys, strings.SplitN(kv, "=", 2)[0])
	}
	sort.Strings(keys)
	env, _ := json.Marshal(map[string]any{"keys": keys, "pid": os.Getpid(), "deny": os.Getenv("WEB_DENY_PROXY"), "proxy": os.Getenv("WEB_EGRESS_PROXY"),
		"tmp": os.Getenv("TMPDIR"), "home": os.Getenv("HOME"), "pages": os.Getenv("WEB_MAX_PAGES"), "ua": os.Getenv("WEB_USER_AGENT"),
		"solver_config": os.Getenv("WEB_SOLVER_CONFIG")})
	os.WriteFile(filepath.Join(dump, "env-"+strconv.Itoa(os.Getpid())+".json"), env, 0o600)
	switch mode {
	case "exit":
		return 1
	case "launch-failed", "deps", "sandbox":
		marker := map[string]string{"launch-failed": "launch_failed", "deps": "deps_missing", "sandbox": "sandbox_unavailable"}[mode]
		fmt.Fprintln(os.Stderr, "Traceback: chrome said something about https://secret.example/")
		fmt.Fprintln(os.Stderr, "SCARLETT_WEB_BROWSER_ERROR="+marker)
		return 3
	case "flood":
		junk := strings.Repeat("x", 4096)
		for i := 0; i < 256; i++ {
			fmt.Fprint(os.Stderr, junk)
		}
		fmt.Fprintln(os.Stderr, "\nSCARLETT_WEB_BROWSER_ERROR=deps_missing trailing words")
	case "child":
		self, _ := os.Executable()
		cmd := exec.Command(self, "-test.run=^TestFakeHelperProcess$", "--", "sleeper", dump)
		detach(cmd)
		if cmd.Start() == nil {
			os.WriteFile(filepath.Join(dump, "child.pid"), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
		}
	case "sleeper":
		time.Sleep(10 * time.Minute)
		return 0
	}
	bearer := os.Getenv("WEB_HELPER_BEARER")
	pages, _ := strconv.Atoi(os.Getenv("WEB_MAX_PAGES"))
	if mode == "wrong-caps" {
		pages++
	}
	stop := make(chan struct{})
	go func() { io.Copy(io.Discard, os.Stdin); close(stop) }()
	var fetches atomic.Int64
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+bearer {
				http.Error(w, "{}", 401)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("/v1/ready", auth(func(w http.ResponseWriter, r *http.Request) {
		status := "ready"
		if mode == "never-ready" {
			status = "starting"
		}
		fmt.Fprintf(w, `{"data":{"status":%q}}`, status)
	}))
	// The providers the helper built from WEB_SOLVER_CONFIG, as the real
	// helper names them (sorted), or a wrong list in mode wrong-solvers.
	solvers := []string{}
	var solverConfig map[string]any
	if json.Unmarshal([]byte(os.Getenv("WEB_SOLVER_CONFIG")), &solverConfig) == nil {
		for name := range solverConfig {
			if slices.Contains(SolverProviders, name) {
				solvers = append(solvers, name)
			}
		}
	}
	sort.Strings(solvers)
	if mode == "wrong-solvers" {
		solvers = append(solvers, "anticaptcha")
	}
	mux.HandleFunc("/v1/capabilities", auth(func(w http.ResponseWriter, r *http.Request) {
		names, _ := json.Marshal(solvers)
		fmt.Fprintf(w, `{"data":{"web_browser":1,"engine":%q,"browser_version":%q,"max_pages":%d,"solvers":%s}}`, Engine, PinnedVersion, pages, names)
	}))
	mux.HandleFunc("/v1/fetch", auth(func(w http.ResponseWriter, r *http.Request) {
		var req helperFetch
		if json.NewDecoder(r.Body).Decode(&req) != nil || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "{}", 400)
			return
		}
		n := fetches.Add(1)
		os.WriteFile(filepath.Join(dump, "solver-"+strconv.FormatInt(n, 10)), []byte(strconv.FormatBool(req.Solver)), 0o600)
		// The DOM goes to a private file in TMPDIR, as the real helper writes
		// it; the answer names the file, its size and its sha256.
		dom := fakeDOM(mode, dump)
		if mode == "too-large" {
			fmt.Fprintf(w, `{"data":{"outcome":"failed","error":"too_large","final_url":%q,"status_code":200,"headers":[],"set_cookie_names":[],"content_type":"text/html",
				"html_path":"","html_bytes":67108865,"html_sha256":"","cookies":[],"challenge":"none","redirects":[],"started_at_ms":1,
				"timings":{"context_ms":1,"navigate_ms":1,"settle_ms":1,"challenge_ms":0,"total_ms":3},"solver":"","solver_cost_micro_usd":0}}`, req.URL)
			return
		}
		if mode == "solver-cost" {
			fmt.Fprintf(w, `{"data":{"outcome":"ok","error":"","final_url":%q,"status_code":200,"headers":[],"set_cookie_names":[],"content_type":"text/html",
				%s,"cookies":[],"challenge":"solved","redirects":[],"started_at_ms":1,
				"timings":{"context_ms":1,"navigate_ms":1,"settle_ms":1,"challenge_ms":1,"total_ms":4},"solver":"used","solver_cost_micro_usd":600000}}`, req.URL, dom)
			return
		}
		if mode == "hang" || mode == "hang-once" && os.WriteFile(filepath.Join(dump, "hung"), nil, 0o600) == nil && !exists(filepath.Join(dump, "hung-done")) {
			os.WriteFile(filepath.Join(dump, "hung-done"), nil, 0o600)
			<-stop
			return
		}
		fmt.Fprintf(w, `{"data":{"outcome":"ok","error":"","final_url":%q,"status_code":200,"headers":[["content-type","text/html"]],
			"set_cookie_names":["sid"],"content_type":"text/html",%s,
			"cookies":[{"name":"cf_clearance","value":"secret","domain":".example.com","path":"/","expires":-1,"secure":true,"http_only":true}],
			"challenge":"none","redirects":[],"started_at_ms":1,"timings":{"context_ms":1,"navigate_ms":1,"settle_ms":1,"challenge_ms":0,"total_ms":3},
			"solver":"","solver_cost_micro_usd":0}}`, req.URL, dom)
	}))
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 4
	}
	go http.Serve(ln, mux)
	// The helper binds its own port and names it on its first stdout line.
	switch mode {
	case "bad-port":
		fmt.Println(helperPortPrefix + "http://127.0.0.1:1")
	case "silent":
	default:
		fmt.Printf("%s%d\n", helperPortPrefix, ln.Addr().(*net.TCPAddr).Port)
		fmt.Println("anything later on stdout is ignored")
	}
	<-stop
	if mode == "ignore-eof" {
		time.Sleep(10 * time.Minute)
	}
	return 0
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// fakeDOMPage is what the fake helper renders.
const fakeDOMPage = "<p>ok é</p>"

// fakeDOM writes the page to a new dom-*.html file in TMPDIR and returns the
// answer's html_path, html_bytes and html_sha256 members. The dom-* modes
// break one rule each.
func fakeDOM(mode, dump string) string {
	f, err := os.CreateTemp(os.TempDir(), "dom-*.html")
	if err != nil {
		return `"html_path":"","html_bytes":0,"html_sha256":""`
	}
	f.WriteString(fakeDOMPage)
	f.Close()
	path, size, sum := f.Name(), len(fakeDOMPage), sha256.Sum256([]byte(fakeDOMPage))
	digest := hex.EncodeToString(sum[:])
	switch mode {
	case "dom-outside":
		outside := filepath.Join(dump, "dom-outside.html")
		os.Rename(path, outside)
		path = outside
	case "dom-symlink":
		link := filepath.Join(os.TempDir(), "dom-link.html")
		os.Symlink(path, link)
		path = link
	case "dom-size":
		size++
	case "dom-sha":
		digest = strings.Repeat("0", 64)
	case "dom-name":
		renamed := filepath.Join(os.TempDir(), "page.html")
		os.Rename(path, renamed)
		path = renamed
	}
	os.WriteFile(filepath.Join(dump, "dom-path"), []byte(path), 0o600)
	raw, _ := json.Marshal(map[string]any{"html_path": path, "html_bytes": size, "html_sha256": digest})
	return string(raw[1 : len(raw)-1])
}

// testSolverKey is a synthetic provider key.
const testSolverKey = "synthetic-capmonster-key-0123456789"

// testSolvers configures a solver for the solver modes only.
func testSolvers(mode string) *Solvers {
	if mode != "solver-cost" && mode != "wrong-solvers" {
		return nil
	}
	return &Solvers{Keys: map[string]string{"capmonster": testSolverKey}, MaxSolvesPerFetch: 2, MaxMicroUSDPerDay: 1_000_000}
}

type verifyResult struct{ err error }

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type testManagerSetup struct {
	m       *Manager
	clock   *fakeClock
	dump    string
	state   string
	mode    *atomic.Value
	sample  *atomic.Uint64
	level   *atomic.Int64 // host memory pressure
	samples *atomic.Int64
	verifyN *atomic.Int64
	verify  *atomic.Value // error
}

func newTestManager(t *testing.T, mode string) *testManagerSetup {
	t.Helper()
	dump := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	s := &testManagerSetup{clock: &fakeClock{now: time.Unix(1_800_000_000, 0)}, dump: dump, state: state, mode: &atomic.Value{}, sample: &atomic.Uint64{},
		level: &atomic.Int64{}, samples: &atomic.Int64{}, verifyN: &atomic.Int64{}, verify: &atomic.Value{}}
	s.level.Store(1)
	s.mode.Store(mode)
	s.verify.Store(verifyResult{})
	m := New(Config{ResourceDir: t.TempDir(), StateDir: state, Guard: testGuard{}, Capacity: 2, IdleTimeout: 120 * time.Second, Solvers: testSolvers(mode)})
	root := Root{Dir: t.TempDir()}
	browser := Browser{Dir: t.TempDir(), Executable: filepath.Join(t.TempDir(), "chrome"), Version: PinnedVersion}
	m.d.now = s.clock.Now
	m.d.physical = func() (uint64, error) { return 32 << 30, nil }
	m.d.ensure = func(Config) (Root, error) { return root, nil }
	m.d.verify = func(Root) error {
		s.verifyN.Add(1)
		return s.verify.Load().(verifyResult).err
	}
	m.d.ensureBrowser = func(context.Context, Config, BrowserPin) (Browser, error) { return browser, nil }
	m.d.verifyBrowser = func(string, Inventory) error { return nil }
	m.d.quick = func(Root, Browser) error { return nil }
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m.d.command = func(Root) (string, []string) {
		return self, []string{"-test.run=^TestFakeHelperProcess$", "--", s.mode.Load().(string), dump}
	}
	m.d.sample = func(p *proc) (uint64, []procInfo, error) { s.samples.Add(1); return s.sample.Load(), p.snapshot(), nil }
	m.d.pressure = func() int { return int(s.level.Load()) }
	m.d.unregister = func(string) {}
	m.d.readyTimeout = 5 * time.Second
	m.d.stopGrace = 2 * time.Second
	s.m = m
	t.Cleanup(func() { m.Close(context.Background()) })
	return s
}

func (s *testManagerSetup) prepare(t *testing.T) {
	t.Helper()
	if err := s.m.prepare(context.Background()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if h := s.m.Health(); h.State != "ready" || h.Capacity != 2 || h.Version != PinnedVersion {
		t.Fatalf("health %+v", h)
	}
}

func (s *testManagerSetup) fetch(ctx context.Context) (FetchResult, error) {
	return s.m.Fetch(ctx, FetchRequest{URL: "https://example.com/", Wait: "load", TimeoutMS: 5000})
}

func (s *testManagerSetup) helperPID(t *testing.T) int {
	t.Helper()
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if s.m.helper == nil {
		return 0
	}
	return s.m.helper.p.pid()
}

// waitStopped waits until no helper is attached or stopping.
func (s *testManagerSetup) waitStopped(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s.m.mu.Lock()
		idle := s.m.helper == nil && s.m.stopping == nil
		s.m.mu.Unlock()
		if idle {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("helper did not stop")
}

func TestManagerStartsHelperWithPrivateStateAndAllowlistedEnv(t *testing.T) {
	s := newTestManager(t, "ok")
	s.prepare(t)
	res, err := s.fetch(context.Background())
	if err != nil || res.Outcome != "ok" || res.StatusCode != 200 || res.FinalURL != "https://example.com/" || len(res.Cookies) != 1 {
		t.Fatalf("fetch: %v %+v", err, res.Outcome)
	}
	if fmt.Sprint(res) == "" || strings.Contains(fmt.Sprintf("%v %+v %#v", res, res, res.Cookies[0]), "secret") {
		t.Fatal("a result or cookie formats its values")
	}
	pid := s.helperPID(t)
	raw, err := os.ReadFile(filepath.Join(s.dump, "env-"+strconv.Itoa(pid)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Keys  []string `json:"keys"`
		Deny  string   `json:"deny"`
		Proxy string   `json:"proxy"`
		Tmp   string   `json:"tmp"`
		Home  string   `json:"home"`
		Pages string   `json:"pages"`
		UA    string   `json:"ua"`
	}
	json.Unmarshal(raw, &env)
	want := []string{"APPDATA", "BREAKPAD_DUMP_LOCATION", "HOME", "LOCALAPPDATA", "PLAYWRIGHT_BROWSERS_PATH", "PLAYWRIGHT_NODEJS_PATH",
		"PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "TEMP", "TMP", "TMPDIR", "USERPROFILE", "WEB_BROWSER_EXECUTABLE", "WEB_BROWSER_VERSION",
		"WEB_DENY_PROXY", "WEB_EGRESS_PROXY", "WEB_HELPER_BEARER", "WEB_MAX_PAGES", "WEB_USER_AGENT",
		"XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"}
	if runtime.GOOS == "windows" {
		want = append(want, "SystemRoot", "WINDIR")
	}
	sort.Strings(want)
	got := slices.DeleteFunc(slices.Clone(env.Keys), func(k string) bool { return runtime.GOOS == "darwin" && k == "__CF_USER_TEXT_ENCODING" })
	if !slices.Equal(got, want) {
		t.Fatalf("helper environment\n got %v\nwant %v", got, want)
	}
	if !strings.HasPrefix(env.Deny, "http://127.0.0.1:") || !strings.HasPrefix(env.Proxy, "http://127.0.0.1:") || env.Deny == env.Proxy ||
		env.Pages != "2" || env.UA != UserAgent(runtime.GOOS, PinnedMajor) ||
		env.Tmp != filepath.Join(s.state, "web-browser", "tmp") || env.Home != filepath.Join(s.state, "web-browser", "home") {
		t.Fatalf("environment values %+v", env)
	}
	if runtime.GOOS != "windows" {
		for _, dir := range []string{"web-browser", "web-browser/home", "web-browser/tmp", "web-browser/crashpad"} {
			info, err := os.Stat(filepath.Join(s.state, dir))
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatalf("%s not private: %v", dir, err)
			}
		}
		info, err := os.Stat(filepath.Join(s.state, "web-browser", "bearer"))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("bearer not private: %v", err)
		}
	}
	if h := s.m.Health(); h.InFlight != 0 {
		t.Fatalf("in flight after fetch: %d", h.InFlight)
	}
}

func TestManagerReadinessTimeoutAndStartFailures(t *testing.T) {
	for _, mode := range []string{"never-ready", "wrong-caps", "wrong-solvers", "exit", "launch-failed", "bad-port", "silent"} {
		t.Run(mode, func(t *testing.T) {
			s := newTestManager(t, mode)
			s.m.d.readyTimeout = time.Second
			err := s.m.prepare(context.Background())
			reasonIs(t, err, ReasonHelperFailed)
			if h := s.m.Health(); h.State != "unavailable" || h.Reason != ReasonHelperFailed {
				t.Fatalf("health %+v", h)
			}
			matches, _ := filepath.Glob(filepath.Join(s.dump, "env-*.json"))
			for _, m := range matches {
				pid, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), "env-"), ".json"))
				if !processGone(pid) {
					t.Fatalf("failed helper %d still running", pid)
				}
			}
		})
	}
	for mode, reason := range map[string]Reason{"deps": ReasonDepsMissing, "sandbox": ReasonSandboxUnavailable} {
		t.Run(mode, func(t *testing.T) {
			s := newTestManager(t, mode)
			reasonIs(t, s.m.prepare(context.Background()), reason)
			if h := s.m.Health(); h.Reason != reason {
				t.Fatalf("health %+v", h)
			}
		})
	}
}

func TestManagerThreeStartFailuresHoldHelperFailed(t *testing.T) {
	s := newTestManager(t, "ok")
	s.prepare(t)
	s.mode.Store("launch-failed")
	for i := 0; i < 3; i++ {
		if _, err := s.fetch(context.Background()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if h := s.m.Health(); (i < 2) != (h.State == "ready") {
			t.Fatalf("after %d failures: %+v", i+1, h)
		}
	}
	if h := s.m.Health(); h.Reason != ReasonHelperFailed {
		t.Fatalf("health %+v", h)
	}
	s.mode.Store("ok")
	s.clock.Add(10*time.Minute + time.Second)
	if h := s.m.Health(); h.State != "ready" {
		t.Fatalf("hold did not end: %+v", h)
	}
	if _, err := s.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestManagerIdleAndPrewarmStops(t *testing.T) {
	s := newTestManager(t, "ok")
	s.prepare(t)
	if _, err := s.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	pid := s.helperPID(t)
	s.clock.Add(119 * time.Second)
	s.m.tick()
	if s.helperPID(t) != pid {
		t.Fatal("stopped before the idle timeout")
	}
	s.clock.Add(2 * time.Second)
	s.m.tick()
	s.waitStopped(t)
	if !processGone(pid) {
		t.Fatal("idle helper still running")
	}
	// A pre-warm that serves nothing stops after 30 s.
	s.m.Prewarm()
	deadline := time.Now().Add(10 * time.Second)
	for s.helperPID(t) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if s.helperPID(t) == 0 {
		t.Fatal("pre-warm did not start the helper")
	}
	s.clock.Add(29 * time.Second)
	s.m.tick()
	if s.helperPID(t) == 0 {
		t.Fatal("pre-warm stopped early")
	}
	s.clock.Add(2 * time.Second)
	s.m.tick()
	s.waitStopped(t)
	// A pre-warmed helper that then serves follows the normal idle timeout.
	s.m.Prewarm()
	for s.helperPID(t) == 0 && time.Now().Before(deadline.Add(10*time.Second)) {
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := s.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.clock.Add(31 * time.Second)
	s.m.tick()
	if s.helperPID(t) == 0 {
		t.Fatal("a serving helper used the pre-warm timeout")
	}
}

func TestManagerRecyclesAfter50Fetches(t *testing.T) {
	s := newTestManager(t, "ok")
	s.prepare(t)
	var first int
	for i := 0; i < recycleAfter; i++ {
		if _, err := s.fetch(context.Background()); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = s.helperPID(t)
		}
	}
	s.m.mu.Lock()
	draining := s.m.helper != nil && s.m.helper.draining
	s.m.mu.Unlock()
	if !draining {
		t.Fatal("not draining after 50 fetches")
	}
	if _, err := s.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if second := s.helperPID(t); second == first || second == 0 || !processGone(first) {
		t.Fatalf("not recycled: %d → %d", first, second)
	}
}

func TestManagerMemoryRecycleAndKill(t *testing.T) {
	s := newTestManager(t, "ok")
	s.prepare(t)
	res, err := s.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(res.HTMLPath)
	recycle, kill := Thresholds(2, 32<<30)
	s.sample.Store(recycle)
	s.m.tick()
	s.m.mu.Lock()
	draining := s.m.helper.draining
	s.m.mu.Unlock()
	if draining {
		t.Fatal("drained at the threshold, not above it")
	}
	s.sample.Store(recycle + 1)
	s.m.tick()
	s.m.tick() // the drained, idle helper stops on the next tick
	s.waitStopped(t)
	if res, err = s.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	os.Remove(res.HTMLPath)
	pid := s.helperPID(t)
	s.sample.Store(kill + 1)
	s.m.tick()
	deadline := time.Now().Add(5 * time.Second)
	for !processGone(pid) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !processGone(pid) {
		t.Fatal("helper above the kill threshold still running")
	}
}

// The memory rule with a page in flight: above recycle the helper only
// drains, at macOS pressure warn too (the page finishes; html.spec.whatwg.org
// was killed at warn under the old rule); critical pressure or a tree above
// the kill size kills it, and the fetch answers ErrorMemory with the tree
// peak it reached. An idle helper is never killed for pressure.
func TestManagerMemoryRuleWithAPageInFlight(t *testing.T) {
	recycle, kill := Thresholds(2, 32<<30)
	for _, c := range []struct {
		name   string
		level  int64
		bytes  uint64
		killed bool
	}{
		{"normal above recycle", 1, recycle + 1, false},
		{"warn below recycle", pressureWarn, recycle, false},
		{"warn above recycle", pressureWarn, recycle + 1, false},
		{"warn just under kill", pressureWarn, kill, false},
		{"critical", pressureCritical, 1 << 20, true},
		{"above kill", 1, kill + 1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newTestManager(t, "hang")
			s.prepare(t)
			type answer struct {
				res FetchResult
				err error
			}
			done := make(chan answer, 1)
			go func() { res, err := s.fetch(context.Background()); done <- answer{res, err} }()
			deadline := time.Now().Add(5 * time.Second)
			for {
				s.m.mu.Lock()
				busy := s.m.helper != nil && s.m.helper.inFlight == 1 && len(s.m.helper.watches) == 1
				s.m.mu.Unlock()
				if busy || time.Now().After(deadline) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			pid := s.helperPID(t)
			// A smaller sample first: the peak is the largest one.
			s.sample.Store(c.bytes / 2)
			s.m.tick()
			s.level.Store(c.level)
			s.sample.Store(c.bytes)
			s.m.tick()
			gone := false
			for end := time.Now().Add(3 * time.Second); time.Now().Before(end) && !gone; time.Sleep(20 * time.Millisecond) {
				gone = processGone(pid)
			}
			if gone != c.killed {
				t.Fatalf("killed = %v, want %v", gone, c.killed)
			}
			s.m.mu.Lock()
			draining := s.m.helper != nil && s.m.helper.draining
			s.m.mu.Unlock()
			if !c.killed && draining != (c.bytes > recycle) {
				t.Fatalf("draining = %v", draining)
			}
			if c.killed {
				a := <-done
				if a.err != nil || a.res.Outcome != "failed" || a.res.Error != ErrorMemory || a.res.TreePeakBytes != c.bytes || a.res.HTMLPath != "" {
					t.Fatalf("in-flight fetch: %v %+v", a.err, a.res.Error)
				}
			}
		})
	}
	// Without a page in flight, critical pressure does not kill.
	s := newTestManager(t, "ok")
	s.prepare(t)
	res, err := s.fetch(context.Background())
	if err != nil || res.TreePeakBytes != 0 {
		t.Fatal(err, res.TreePeakBytes)
	}
	os.Remove(res.HTMLPath)
	pid := s.helperPID(t)
	s.level.Store(pressureCritical)
	s.m.tick()
	time.Sleep(200 * time.Millisecond)
	if processGone(pid) {
		t.Fatal("an idle helper was killed for pressure")
	}
}

// Run samples at the busy rate while a page renders.
func TestManagerSamplesFasterWhileBusy(t *testing.T) {
	s := newTestManager(t, "hang")
	s.prepare(t)
	s.m.d.tick, s.m.d.busyTick = time.Hour, 20*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { s.m.Run(ctx); close(stopped) }()
	defer func() { cancel(); <-stopped }()
	time.Sleep(100 * time.Millisecond)
	idle := s.samples.Load()
	fetchCtx, stop := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer stop()
	go s.fetch(fetchCtx)
	time.Sleep(500 * time.Millisecond)
	if busy := s.samples.Load() - idle; busy < 5 {
		t.Fatalf("%d samples in 500 ms while busy", busy)
	}
}

func TestThresholdsScaleWithCapacityAndMemory(t *testing.T) {
	for _, c := range []struct {
		capacity      int
		physical      uint64
		recycle, kill float64
	}{
		{1, 0, 2.0, 3.5}, {2, 0, 2.75, 4.25}, {4, 0, 4.25, 5.75},
		// kill = max(recycle + 1.5 GiB, physical / 4)
		{1, 8 << 30, 2.0, 3.5}, {2, 16 << 30, 2.75, 4.25}, {2, 24 << 30, 2.75, 6}, {2, 64 << 30, 2.75, 16}, {4, 32 << 30, 4.25, 8},
	} {
		recycle, kill := Thresholds(c.capacity, c.physical)
		if float64(recycle)/gib != c.recycle || float64(kill)/gib != c.kill {
			t.Errorf("capacity %d, %d GiB: %v / %v GiB", c.capacity, c.physical>>30, float64(recycle)/gib, float64(kill)/gib)
		}
		if jobMemoryLimit(kill) != kill+2*gib {
			t.Errorf("job limit for %d", kill)
		}
	}
}

// Health reports the kill size the heartbeat sends as browser.kill_bytes.
func TestHealthReportsKillBytes(t *testing.T) {
	s := newTestManager(t, "ok")
	s.prepare(t)
	if h := s.m.Health(); h.KillBytes != 8<<30 {
		t.Fatalf("kill bytes %d", h.KillBytes)
	}
}

// The DOM comes back as a file: moved out of the helper's TMPDIR into the
// node's private DOM directory under a fresh name, checked for size and
// sha256. The caller owns it.
func TestManagerAdoptsTheDOMFile(t *testing.T) {
	s := newTestManager(t, "ok")
	s.prepare(t)
	res, err := s.fetch(context.Background())
	if err != nil || res.Outcome != "ok" {
		t.Fatal(err)
	}
	if filepath.Dir(res.HTMLPath) != filepath.Join(s.state, "web-browser", "dom") || !domName(filepath.Base(res.HTMLPath)) || res.HTMLBytes != int64(len(fakeDOMPage)) {
		t.Fatalf("path %s bytes %d", res.HTMLPath, res.HTMLBytes)
	}
	raw, err := os.ReadFile(res.HTMLPath)
	sum := sha256.Sum256(raw)
	if err != nil || string(raw) != fakeDOMPage || hex.EncodeToString(sum[:]) != res.HTMLSHA256 {
		t.Fatal("DOM file content")
	}
	helperPath, _ := os.ReadFile(filepath.Join(s.dump, "dom-path"))
	if exists(string(helperPath)) {
		t.Fatal("the helper's copy stayed in TMPDIR")
	}
	if info, _ := os.Stat(filepath.Dir(res.HTMLPath)); runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatal("DOM directory not private", info.Mode())
	}
	// A stale DOM survives a helper restart (an upload may still read it);
	// only the first prepare of a process clears the directory.
	s.m.mu.Lock()
	s.m.helper.draining = true
	s.m.mu.Unlock()
	next, err := s.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(next.HTMLPath)
	if !exists(res.HTMLPath) {
		t.Fatal("a helper restart removed a DOM file")
	}
	s.m.mu.Lock()
	s.m.helper.draining = true
	s.m.mu.Unlock()
	s.m.tick()
	s.waitStopped(t)
	if err := s.m.prepare(context.Background()); err != nil || !exists(res.HTMLPath) {
		t.Fatal("a later prepare removed a DOM file", err)
	}
	fresh := New(s.m.cfg)
	fresh.d = s.m.d
	if err := fresh.prepare(context.Background()); err != nil || exists(res.HTMLPath) {
		t.Fatal("a new process kept a stale DOM file", err)
	}
	fresh.Close(context.Background())
}

func TestManagerRefusesBadDOMFiles(t *testing.T) {
	for _, mode := range []string{"dom-outside", "dom-symlink", "dom-size", "dom-sha", "dom-name"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "dom-symlink" && runtime.GOOS == "windows" {
				t.Skip("symlinks need privileges on Windows")
			}
			s := newTestManager(t, mode)
			s.prepare(t)
			res, err := s.fetch(context.Background())
			if !errors.Is(err, ErrHelper) || res.HTMLPath != "" {
				t.Fatalf("%v %+v", err, res.HTMLPath)
			}
			entries, _ := os.ReadDir(filepath.Join(s.state, "web-browser", "dom"))
			if len(entries) != 0 {
				t.Fatal("a refused DOM was kept")
			}
			if mode == "dom-outside" {
				// A path outside the helper's directory is never touched.
				if !exists(filepath.Join(s.dump, "dom-outside.html")) {
					t.Fatal("removed a file outside TMPDIR")
				}
			}
		})
	}
}

// A DOM over the ceiling is reported, never cut, and has no file.
func TestManagerReportsATooLargeDOM(t *testing.T) {
	s := newTestManager(t, "too-large")
	s.prepare(t)
	res, err := s.fetch(context.Background())
	if err != nil || res.Outcome != "failed" || res.Error != "too_large" || res.HTMLBytes != htmlCap+1 || res.HTMLPath != "" || res.StatusCode != 200 {
		t.Fatalf("%v %+v", err, res.Error)
	}
	for _, bad := range []FetchResult{
		{Outcome: "failed", Error: "too_large", HTMLBytes: htmlCap, Challenge: "none"},
		{Outcome: "failed", Error: "too_large", HTMLBytes: htmlCap + 1, HTMLPath: "/x", Challenge: "none"},
		{Outcome: "ok", StatusCode: 200, HTMLBytes: htmlCap + 1, HTMLPath: "/x", HTMLSHA256: strings.Repeat("a", 64), Challenge: "none"},
		{Outcome: "ok", StatusCode: 200, Challenge: "none"},
		{Outcome: "timeout", Error: "timeout", HTMLPath: "/x", Challenge: "none"},
	} {
		if bad.validate() == nil {
			t.Errorf("accepted %+v", bad.Outcome)
		}
	}
}

func TestManagerGoDeadlineDrainsAndRestarts(t *testing.T) {
	s := newTestManager(t, "hang-once")
	s.prepare(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	_, err := s.fetch(ctx)
	cancel()
	if !errors.Is(err, ErrHelper) {
		t.Fatalf("deadline: %v", err)
	}
	first := s.helperPID(t)
	s.m.mu.Lock()
	draining := s.m.helper != nil && s.m.helper.draining
	s.m.mu.Unlock()
	if !draining {
		t.Fatal("a Go-side deadline did not drain the helper")
	}
	if _, err = s.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if second := s.helperPID(t); second == first {
		t.Fatal("helper not restarted")
	}
}

func TestMarkerWriterReadsOnlyTheMarkerAndStaysBounded(t *testing.T) {
	w := &markerWriter{}
	junk := strings.Repeat("y", 1<<20)
	w.Write([]byte(junk))
	w.Write([]byte("\nSCARLETT_WEB_BROWSER_ERROR=bogus\nnoise SCARLETT_WEB_BROWSER_ERROR=deps_missing\n"))
	if w.Marker() != "" || len(w.line) > 256 || cap(w.line) > 1024 {
		t.Fatalf("marker %q, held %d bytes", w.Marker(), cap(w.line))
	}
	for _, chunk := range []string{"SCARLETT_WEB_BROWSER_", "ERROR=sandbox_unavailable", "\r\n"} {
		w.Write([]byte(chunk))
	}
	if w.Marker() != "sandbox_unavailable" {
		t.Fatalf("split marker not read: %q", w.Marker())
	}
	// A 1 MiB flood on the real helper's stderr does not stop a start; a
	// marker inside a longer line is not a marker.
	s := newTestManager(t, "flood")
	s.prepare(t)
}

func TestManagerVerifiesOffTheFetchPath(t *testing.T) {
	s := newTestManager(t, "ok")
	s.prepare(t)
	after := s.verifyN.Load()
	for i := 0; i < 3; i++ {
		if _, err := s.fetch(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if s.verifyN.Load() != after {
		t.Fatal("Verify ran on the fetch path")
	}
	// Not while a helper is warm; then a failing re-verify drains the tier.
	s.clock.Add(verifyEvery)
	s.m.tick()
	if s.verifyN.Load() != after {
		t.Fatal("Verify ran while a helper was warm")
	}
	s.clock.Add(defaultIdle)
	s.m.tick()
	s.waitStopped(t)
	s.verify.Store(verifyResult{fail(ReasonRuntimeInvalid, "tampered")})
	s.m.tick()
	s.m.tick() // a verify in progress is not started twice
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.m.mu.Lock()
		verifying := s.m.verifying
		s.m.mu.Unlock()
		if !verifying || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if s.verifyN.Load() != after+1 {
		t.Fatalf("background Verify did not run once (%d)", s.verifyN.Load()-after)
	}
	if h := s.m.Health(); h.State != "unavailable" || h.Reason != ReasonRuntimeInvalid {
		t.Fatalf("health %+v", h)
	}
	if _, err := s.fetch(context.Background()); ReasonOf(err) != ReasonRuntimeInvalid {
		t.Fatalf("fetch on an invalid runtime: %v", err)
	}
}

func TestManagerStopLeavesNoProcesses(t *testing.T) {
	s := newTestManager(t, "child")
	s.prepare(t)
	if _, err := s.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	pid := s.helperPID(t)
	raw, err := os.ReadFile(filepath.Join(s.dump, "child.pid"))
	if err != nil {
		t.Fatal(err)
	}
	child, _ := strconv.Atoi(string(raw))
	if processGone(child) {
		t.Fatal("fixture child not running")
	}
	// The helper exits on stdin EOF and leaves a child in its own process
	// group, as Playwright's detached Chrome would.
	if err = s.m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for !(processGone(pid) && processGone(child)) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if !processGone(pid) || !processGone(child) {
		t.Fatalf("processes survived the stop: helper %v child %v", !processGone(pid), !processGone(child))
	}
	if h := s.m.Health(); h.State != "unavailable" {
		t.Fatal("closed manager reports ready")
	}
}

func TestManagerKillsAHelperThatIgnoresEOF(t *testing.T) {
	s := newTestManager(t, "ignore-eof")
	s.m.d.stopGrace = 500 * time.Millisecond
	s.prepare(t)
	if _, err := s.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	pid := s.helperPID(t)
	start := time.Now()
	s.m.Close(context.Background())
	if !processGone(pid) || time.Since(start) > 5*time.Second {
		t.Fatal("a helper ignoring EOF was not killed after the grace period")
	}
}

func TestFetchRequestValidationAndBusy(t *testing.T) {
	s := newTestManager(t, "hang")
	s.prepare(t)
	for _, req := range []FetchRequest{
		{URL: "ftp://example.com/", Wait: "load", TimeoutMS: 5000},
		{URL: "https://example.com/ x", Wait: "load", TimeoutMS: 5000},
		{URL: "https://example.com/", Wait: "idle", TimeoutMS: 5000},
		{URL: "https://example.com/", Wait: "load", TimeoutMS: 4999},
		{URL: "https://example.com/", Wait: "load", TimeoutMS: 45001},
		{URL: "https://example.com/", Wait: "load", TimeoutMS: 5000, WaitMS: 15001},
		{URL: "https://example.com/", Wait: "load", TimeoutMS: 5000, WaitSelector: "a\x00"},
	} {
		if _, err := s.m.Fetch(context.Background(), req); err == nil || errors.Is(err, ErrUnavailable) {
			t.Fatalf("accepted %+v", req.Wait)
		}
	}
	// Capacity 2: two hanging fetches hold both slots; a third is busy.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.fetch(ctx) }()
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.m.Health().InFlight < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := s.fetch(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("third fetch at capacity: %v", err)
	}
	cancel()
	wg.Wait()
}

func TestDescendantsWalkParentsAcrossProcessGroups(t *testing.T) {
	// helper 100 (group 100) → driver 101 (group 100) → Chrome 200, detached
	// into group 200 → renderers 201, 202 (group 200). Unrelated 300 in 100.
	table := []procInfo{
		{PID: 1, PPID: 0, PGID: 1, Bytes: 1},
		{PID: 100, PPID: 1, PGID: 100, Bytes: 10},
		{PID: 101, PPID: 100, PGID: 100, Bytes: 20},
		{PID: 200, PPID: 101, PGID: 200, Bytes: 300},
		{PID: 201, PPID: 200, PGID: 200, Bytes: 400},
		{PID: 202, PPID: 200, PGID: 200, Bytes: 500},
		{PID: 300, PPID: 1, PGID: 100, Bytes: 9999},
		{PID: 400, PPID: 1, PGID: 400, Bytes: 9999},
	}
	tree := descendants(table, 100)
	if sumBytes(tree) != 10+20+300+400+500 {
		t.Fatalf("tree bytes %d", sumBytes(tree))
	}
	groups, pids := killPlan(tree, 400)
	if !slices.Equal(groups, []int{100, 200}) || !slices.Equal(pids, []int{100, 101, 200, 201, 202}) {
		t.Fatalf("kill plan groups %v pids %v", groups, pids)
	}
	if groups, _ = killPlan(tree, 200); !slices.Equal(groups, []int{100}) {
		t.Fatal("the caller's own group would be signalled")
	}
	if descendants(table, 999) != nil {
		t.Fatal("a missing root has descendants")
	}
}

func TestHealthReportsPreparing(t *testing.T) {
	m := New(Config{StateDir: t.TempDir(), ResourceDir: t.TempDir()})
	if h := m.Health(); h.State != "unavailable" || h.Reason != ReasonBrowserDownloading || h.Version != "" {
		t.Fatalf("health %+v", h)
	}
	var logs []string
	m.cfg.Logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	m.mu.Lock()
	m.notify()
	m.mu.Unlock()
	if len(logs) != 1 || logs[0] != "web browser: preparing" {
		t.Fatalf("logs %v", logs)
	}
}

func TestManagerRunRetriesPrepareWithBackoff(t *testing.T) {
	s := newTestManager(t, "ok")
	var attempts atomic.Int64
	failing := atomic.Bool{}
	failing.Store(true)
	s.m.d.ensureBrowser = func(context.Context, Config, BrowserPin) (Browser, error) {
		attempts.Add(1)
		if failing.Load() {
			return Browser{}, fail(ReasonBrowserDownloadFailed, "synthetic")
		}
		return Browser{Dir: t.TempDir(), Executable: filepath.Join(t.TempDir(), "chrome"), Version: PinnedVersion}, nil
	}
	s.m.d.tick = 5 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.m.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor := func(n int64) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for attempts.Load() < n && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		if attempts.Load() != n {
			t.Fatalf("attempts %d, want %d", attempts.Load(), n)
		}
	}
	waitFor(1)
	if h := s.m.Health(); h.Reason != ReasonBrowserDownloadFailed {
		t.Fatalf("health %+v", h)
	}
	for i, wait := range []time.Duration{60 * time.Second, 120 * time.Second, 240 * time.Second} {
		s.clock.Add(wait - time.Second)
		time.Sleep(50 * time.Millisecond)
		if attempts.Load() != int64(i+1) {
			t.Fatalf("retried before %s", wait)
		}
		s.clock.Add(time.Second)
		waitFor(int64(i + 2))
	}
	failing.Store(false)
	s.clock.Add(480 * time.Second)
	waitFor(5)
	deadline := time.Now().Add(5 * time.Second)
	for s.m.Health().State != "ready" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h := s.m.Health(); h.State != "ready" {
		t.Fatalf("health after recovery %+v", h)
	}
}

func TestManagerSolversAndDailyCap(t *testing.T) {
	s := newTestManager(t, "solver-cost")
	s.prepare(t)
	if h := s.m.Health(); !slices.Equal(h.Solvers, []string{"capmonster"}) {
		t.Fatalf("solvers before any spend: %+v", h)
	}
	for i := 1; i <= 3; i++ {
		res, err := s.fetch(context.Background())
		if err != nil || res.Solver != "used" || res.SolverCostMicroUSD != 600_000 {
			t.Fatalf("fetch %d: %v %+v", i, err, res.Solver)
		}
	}
	// $0.60 a fetch against a $1.00 day: the first two may use the solver,
	// the third may not, and the heartbeat stops naming it.
	for i, want := range []string{"true", "true", "false"} {
		raw, _ := os.ReadFile(filepath.Join(s.dump, "solver-"+strconv.Itoa(i+1)))
		if string(raw) != want {
			t.Fatalf("fetch %d solver flag %q", i+1, raw)
		}
	}
	if h := s.m.Health(); h.State != "ready" || h.Solvers != nil {
		t.Fatalf("solvers after the cap: %+v", h)
	}
	// The key reaches the helper only in WEB_SOLVER_CONFIG, with the caps.
	raw, err := os.ReadFile(filepath.Join(s.dump, "env-"+strconv.Itoa(s.helperPID(t))+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Keys         []string `json:"keys"`
		SolverConfig string   `json:"solver_config"`
	}
	json.Unmarshal(raw, &env)
	var config map[string]any
	if json.Unmarshal([]byte(env.SolverConfig), &config) != nil || config["capmonster"] != testSolverKey || config["max_solves_per_fetch"] != float64(2) || config["experimental"] != false || len(config) != 3 {
		t.Fatalf("solver config %v", config)
	}
	if !slices.Contains(env.Keys, "WEB_SOLVER_CONFIG") {
		t.Fatal("no WEB_SOLVER_CONFIG")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", s.m.cfg, s.m.cfg, s.m.cfg.Solvers), testSolverKey) {
		t.Fatal("a configuration formats the key")
	}
	// The day's spend survives a restart, privately, and resets the next UTC day.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(s.state, "web-browser", spendFile))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("spend file not private: %v", err)
		}
	}
	again := New(Config{StateDir: s.state, Solvers: testSolvers("solver-cost")})
	again.d.now = s.clock.Now
	again.mu.Lock()
	allowed, spent := again.solverAllowedLocked(), again.spentLocked()
	again.mu.Unlock()
	if allowed || spent != 1_800_000 {
		t.Fatalf("after restart: allowed %v spent %d", allowed, spent)
	}
	s.clock.Add(24 * time.Hour)
	if h := s.m.Health(); !slices.Equal(h.Solvers, []string{"capmonster"}) {
		t.Fatalf("solvers the next day: %+v", h)
	}
}

func TestSolverResultValidation(t *testing.T) {
	ok := FetchResult{Outcome: "ok", StatusCode: 200, Challenge: "solved", Solver: "used", SolverCostMicroUSD: 1200, HTMLPath: "/dom-x.html", HTMLSHA256: strings.Repeat("a", 64)}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []FetchResult{
		{Outcome: "ok", StatusCode: 200, Challenge: "none", Solver: "maybe"},
		{Outcome: "ok", StatusCode: 200, Challenge: "none", SolverCostMicroUSD: -1},
		{Outcome: "ok", StatusCode: 200, Challenge: "none", SolverCostMicroUSD: maxFetchMicroUSD + 1},
	} {
		if bad.validate() == nil {
			t.Fatalf("accepted %+v", bad.Solver)
		}
	}
	if (&Solvers{Keys: map[string]string{"capmonster": "k"}, MaxSolvesPerFetch: 5, MaxMicroUSDPerDay: 1}).valid() ||
		(&Solvers{Keys: map[string]string{"anticaptcha": "k"}, MaxSolvesPerFetch: 2, MaxMicroUSDPerDay: 1}).valid() ||
		(&Solvers{Keys: map[string]string{"capmonster": "k"}, MaxSolvesPerFetch: 2}).valid() || (*Solvers)(nil).valid() {
		t.Fatal("invalid solver configuration accepted")
	}
}
