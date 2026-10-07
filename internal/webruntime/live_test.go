//go:build webbrowser_live

package webruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLive runs the packaged Python, the helper and the pinned Chrome for
// Testing against loopback fixture pages only. The guard and the port policy
// allow nothing but the fixture listeners; every page-chosen name goes to a
// counting resolver that answers only fixture names.
//
//	SCARLETT_TEST_WEB_RUNTIME      resource dir: web-runtime.json, the archive, x-login-runtime/
//	SCARLETT_TEST_WEB_BROWSER_ZIP  optional local copy of the pinned zip (else it is downloaded)
//	SCARLETT_TEST_WEB_LAN_IPV4     optional: this host's LAN IPv4 for a second STUN listener
func TestLive(t *testing.T) {
	resources := os.Getenv("SCARLETT_TEST_WEB_RUNTIME")
	if resources == "" {
		t.Skip("SCARLETT_TEST_WEB_RUNTIME not set")
	}
	if zip := os.Getenv("SCARLETT_TEST_WEB_BROWSER_ZIP"); zip != "" {
		serveLocalZip(t, zip)
	}
	state := filepath.Join(t.TempDir(), "state") // created private by the runtime
	before := outsideState(t)
	platform := platformState(t)

	// Fixture origin (plain HTTP) and a self-signed TLS origin, both loopback.
	hang := make(chan struct{})
	var pageHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
		pageHits.Add(1)
		http.SetCookie(w, &http.Cookie{Name: "fixture_session", Value: "one", Path: "/"})
		w.Header().Set("X-Fixture", "last-document")
		fmt.Fprint(w, `<!doctype html><title>page</title><script>
(async () => {
  const d = navigator.userAgentData;
  const he = await d.getHighEntropyValues(['fullVersionList']);
  const out = {ua: navigator.userAgent, brands: d.brands.map(b => b.brand + '/' + b.version), fvl: he.fullVersionList.length,
    notification: Notification.permission};
  const el = document.createElement('div'); el.id = 'done'; el.textContent = JSON.stringify(out); document.body.appendChild(el);
})();
</script><body></body>`)
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/page", http.StatusFound) })
	mux.HandleFunc("/cookies", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<!doctype html><body><div id="cookies">%d</div></body>`, len(r.Cookies()))
	})
	mux.HandleFunc("/hang", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("/never-idle", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!doctype html><body>idle<script>addEventListener('load', () => fetch('/hang'))</script></body>`)
	})
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	var datagrams atomic.Int64
	go countDatagrams(udp, &datagrams)
	stunTargets := []string{udp.LocalAddr().String()}
	if lan := os.Getenv("SCARLETT_TEST_WEB_LAN_IPV4"); lan != "" {
		lanUDP, err := net.ListenPacket("udp4", net.JoinHostPort(lan, "3478"))
		if err != nil {
			t.Fatal(err)
		}
		defer lanUDP.Close()
		go countDatagrams(lanUDP, &datagrams)
		stunTargets = append(stunTargets, lanUDP.LocalAddr().String())
	}
	mux.HandleFunc("/rtc", func(w http.ResponseWriter, r *http.Request) {
		servers, _ := json.Marshal(stunTargets)
		fmt.Fprintf(w, `<!doctype html><body><script>
(async () => {
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const out = {candidates: 0};
  try {
    const pc = new RTCPeerConnection({iceServers: %s.map(a => ({urls: 'stun:' + a}))});
    pc.onicecandidate = e => { if (e.candidate && e.candidate.candidate) out.candidates++ };
    pc.createDataChannel('x'); await pc.setLocalDescription(await pc.createOffer());
    await sleep(3000); pc.close();
  } catch (e) { out.error = String(e).slice(0, 80) }
  for (const u of ['http://printer.local/x.png', 'https://printer.local/x.png', 'http://intranet/x.png', 'https://intranet/x.png',
                   'http://router.lan/x.png', 'https://router.lan/x.png', 'http://x.home.arpa/x.png', 'https://x.home.arpa/x.png',
                   'http://a.localhost/x.png', 'https://x.internal/x.png', 'http://1.2.3/x.png']) {
    try { await Promise.race([fetch(u, {mode: 'no-cors'}), sleep(1500)]) } catch (e) {}
  }
  const el = document.createElement('div'); el.id = 'done'; el.textContent = JSON.stringify(out); document.body.appendChild(el);
})();
</script></body>`, servers)
	})
	plain := httptest.NewServer(mux)
	defer plain.Close()
	defer close(hang) // before Close, which waits for the hanging request
	secure := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "secret") }))
	secure.Config.ErrorLog = log.New(io.Discard, "", 0) // the browser refuses its certificate, as it must
	secure.StartTLS()
	defer secure.Close()
	_, plainPort, _ := net.SplitHostPort(plain.Listener.Addr().String())
	_, securePort, _ := net.SplitHostPort(secure.Listener.Addr().String())
	connectPorts[securePort] = true
	forwardPorts[plainPort] = true
	defer delete(connectPorts, securePort)
	defer delete(forwardPorts, plainPort)

	fixtures := map[string]bool{"fixture.webruntime.example": true, "other.webruntime.example": true, "tls.webruntime.example": true}
	resolver := &countingResolver{answers: fixtures}
	m := New(Config{ResourceDir: resources, StateDir: state, Guard: loopbackOnly{}, Resolver: resolver.resolve, Capacity: 2,
		Logf: func(format string, args ...any) { t.Logf(format, args...) }})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if err := m.prepare(ctx); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if h := m.Health(); h.State != "ready" || h.Capacity != 2 || h.Version != PinnedVersion {
		t.Fatalf("health %+v", h)
	}
	// Named origins exercise the resolver; the loopback literal is a secure
	// context, which client hints and the permission APIs need.
	origin := "http://fixture.webruntime.example:" + plainPort
	loopback := "http://127.0.0.1:" + plainPort
	fetch := func(url, wait, selector string) FetchResult {
		t.Helper()
		res, err := m.Fetch(ctx, FetchRequest{URL: url, Wait: wait, WaitSelector: selector, TimeoutMS: 30000, SolveChallenge: true})
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		return res
	}

	// 200, final URL, the last document's headers and the cookies.
	res := fetch(loopback+"/redirect", "load", "#done")
	if res.Outcome != "ok" || res.StatusCode != 200 || res.FinalURL != loopback+"/page" || len(res.Redirects) != 1 || res.Redirects[0].StatusCode != 302 {
		t.Fatalf("redirected page: outcome %s status %d redirects %d", res.Outcome, res.StatusCode, len(res.Redirects))
	}
	if !hasHeader(res.Headers, "x-fixture", "last-document") || !slices.Contains(res.SetCookieNames, "fixture_session") || !hasCookie(res.Cookies, "fixture_session") {
		t.Fatal("last-document headers, Set-Cookie names or cookies missing")
	}
	var page struct {
		UA           string   `json:"ua"`
		Brands       []string `json:"brands"`
		FVL          int      `json:"fvl"`
		Notification string   `json:"notification"`
	}
	if err := json.Unmarshal([]byte(between(res.HTML, `<div id="done">`, `</div>`)), &page); err != nil {
		t.Fatalf("page report missing: %v", err)
	}
	if page.UA != m.UserAgent() || page.FVL == 0 || page.Notification != "denied" || !slices.ContainsFunc(page.Brands, func(b string) bool { return strings.HasSuffix(b, "/"+strconv.Itoa(PinnedMajor)) }) {
		t.Fatalf("UA, client hints or permissions inconsistent: %+v", page)
	}

	// A second fetch sees no cookies from the first (fresh context per job).
	if res = fetch(loopback+"/cookies", "load", ""); between(res.HTML, `<div id="cookies">`, `</div>`) != "0" {
		t.Fatal("a later fetch saw an earlier fetch's cookies")
	}
	if res = fetch(origin+"/cookies", "load", ""); res.Outcome != "ok" || res.StatusCode != 200 || res.FinalURL != origin+"/cookies" {
		t.Fatalf("named fixture origin: outcome %s status %d", res.Outcome, res.StatusCode)
	}

	// Two concurrent fetches at capacity 2.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := m.Fetch(ctx, FetchRequest{URL: origin + "/cookies", Wait: "load", TimeoutMS: 30000})
			if err == nil && (r.Outcome != "ok" || r.StatusCode != 200) {
				err = fmt.Errorf("outcome %s status %d", r.Outcome, r.StatusCode)
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent fetch: %v", err)
		}
	}

	// WebRTC and LAN names: no datagram, no candidate, no lookup.
	res = fetch(origin+"/rtc", "load", "#done")
	var rtc struct {
		Candidates int    `json:"candidates"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal([]byte(between(res.HTML, `<div id="done">`, `</div>`)), &rtc); err != nil || rtc.Candidates != 0 {
		t.Fatalf("WebRTC produced candidates: %+v %v", rtc, err)
	}
	if n := datagrams.Load(); n != 0 {
		t.Fatalf("%d UDP datagrams reached a STUN listener", n)
	}
	for _, name := range resolver.names() {
		if !fixtures[name] && name != "www.google.com" && name != "connectivitycheck.gstatic.com" {
			t.Fatalf("a page-chosen name outside the fixtures was resolved: %s", name)
		}
	}
	if m.stats.RefusedName.Load() == 0 {
		t.Fatal("LAN names never reached the proxy's name check")
	}

	// A page that never goes idle returns within load plus the 3 s cap.
	start := time.Now()
	if res = fetch(origin+"/never-idle", "networkidle", ""); res.Outcome != "ok" || time.Since(start) > 8*time.Second || res.Timings.TotalMS > 6500 {
		t.Fatalf("never-idle page: outcome %s in %s", res.Outcome, time.Since(start))
	}

	// An invalid certificate fails the main document as tls.
	res, err = m.Fetch(ctx, FetchRequest{URL: "https://tls.webruntime.example:" + securePort + "/", Wait: "load", TimeoutMS: 15000})
	if err != nil || res.Outcome != "failed" || res.Error != "tls" || res.HTML != "" {
		t.Fatalf("self-signed origin: %v outcome %s error %s", err, res.Outcome, res.Error)
	}

	// The live browser: argv, sockets, memory.
	m.mu.Lock()
	h := m.helper
	m.mu.Unlock()
	if h == nil {
		t.Fatal("no warm helper")
	}
	bytes, tree, err := m.d.sample(h.p)
	if err != nil || bytes < 500<<20 {
		t.Fatalf("tree memory %d bytes (%v) while Chrome is up", bytes, err)
	}
	checkArgv(t, m, h, tree)
	checkSockets(t, tree)
	checkPlatform(t, platform, h, tree)

	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	if alive(tree) {
		t.Fatal("a helper or browser process survived the stop")
	}
	checkUnregistered(t, state)
	if after := outsideState(t); !sameMap(before, after) {
		t.Fatalf("files changed outside node state:\nbefore %v\nafter  %v", before, after)
	}
	t.Logf("background requests denied: %d; names refused unresolved: %d; addresses refused: %d", m.stats.BackgroundDenied.Load(), m.stats.RefusedName.Load(), m.stats.RefusedAddress.Load())
}

type loopbackOnly struct{}

func (loopbackOnly) Allowed(_ context.Context, a netip.Addr) bool {
	return a == netip.MustParseAddr("127.0.0.1")
}

type countingResolver struct {
	mu      sync.Mutex
	answers map[string]bool
	asked   []string
}

func (r *countingResolver) resolve(_ context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, host)
	if r.answers[host] {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return nil, fmt.Errorf("no fixture answer")
}

func (r *countingResolver) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.asked)
}

func countDatagrams(c net.PacketConn, n *atomic.Int64) {
	buf := make([]byte, 2048)
	for {
		if _, _, err := c.ReadFrom(buf); err != nil {
			return
		}
		n.Add(1)
	}
}

func between(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	s = s[i+len(open):]
	if j := strings.Index(s, close); j >= 0 {
		return strings.ReplaceAll(s[:j], "&quot;", `"`)
	}
	return ""
}

func hasHeader(headers [][2]string, name, value string) bool {
	return slices.ContainsFunc(headers, func(h [2]string) bool { return h[0] == name && h[1] == value })
}

func hasCookie(cookies []Cookie, name string) bool {
	return slices.ContainsFunc(cookies, func(c Cookie) bool { return c.Name == name })
}

// serveLocalZip serves a local copy of the pinned zip over loopback TLS in
// place of storage.googleapis.com, with the same pin checks.
func serveLocalZip(t *testing.T, zip string) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, zip) }))
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	browserTransport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}}
	t.Cleanup(func() { browserTransport = nil })
}

func checkArgv(t *testing.T, m *Manager, h *helper, tree []procInfo) {
	t.Helper()
	argv := browserArgv(t, m, tree)
	stealth := stealthArgs(t, m)
	count := func(prefix string) int {
		n := 0
		for _, a := range argv {
			if strings.HasPrefix(a, prefix) {
				n++
			}
		}
		return n
	}
	if count("--disable-features=") != 1 || count("--enable-features=") != 1 {
		t.Fatal("feature switches not merged into one pair")
	}
	for _, a := range argv {
		if strings.HasPrefix(a, "--disable-features=") {
			for _, f := range []string{"WebRtcHideLocalIpsWithMdns", "MediaRouter", "CastMediaRouteProvider", "HttpsUpgrades", "AudioServiceOutOfProcess"} {
				if !slices.Contains(strings.Split(strings.TrimPrefix(a, "--disable-features="), ","), f) {
					t.Fatalf("feature %s not disabled", f)
				}
			}
		}
	}
	want := []string{"--webrtc-ip-handling-policy=disable_non_proxied_udp", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--disable-blink-features=AutomationControlled", "--deny-permission-prompts", "--disable-quic", "--disable-component-update",
		"--proxy-server=" + h.deny.URL(), "--mute-audio", "--use-mock-keychain"}
	for _, a := range stealth {
		if !strings.HasPrefix(a, "--disable-features=") && !strings.HasPrefix(a, "--enable-features=") {
			want = append(want, a)
		}
	}
	for _, a := range want {
		if !slices.Contains(argv, a) {
			t.Fatalf("live argv lacks %s", a)
		}
	}
	for _, a := range argv {
		if a == "--no-sandbox" || a == "--force-webrtc-ip-handling-policy" {
			t.Fatalf("live argv has %s", a)
		}
	}
}

func stealthArgs(t *testing.T, m *Manager) []string {
	out, err := exec.Command(m.root.Python(), "-I", "-B", "-c", "import json; from scrapling.engines.constants import STEALTH_ARGS; print(json.dumps(STEALTH_ARGS))").Output()
	var args []string
	if err != nil || json.Unmarshal(out, &args) != nil || len(args) < 40 {
		t.Fatalf("Scrapling STEALTH_ARGS unreadable: %v", err)
	}
	return args
}

// outsideState fingerprints places a browser could write outside node state.
func outsideState(t *testing.T) map[string]string {
	home, _ := os.UserHomeDir()
	var paths []string
	switch runtime.GOOS {
	case "darwin":
		paths = []string{"Library/Application Support/Google/Chrome for Testing", "Library/Caches/Google/Chrome for Testing",
			"Library/Caches/ms-playwright", "Library/Saved Application State/com.google.chrome.for.testing.savedState",
			"Library/Application Support/Google/Chrome/Crashpad", "Library/Application Support/Google/Chrome for Testing/Crashpad"}
	case "linux":
		paths = []string{".config/google-chrome-for-testing", ".cache/google-chrome-for-testing", ".cache/ms-playwright", ".pki", ".local/share/applications"}
	case "windows":
		paths = []string{filepath.Join("AppData", "Local", "Google"), filepath.Join("AppData", "Local", "ms-playwright")}
	}
	out := map[string]string{}
	for _, p := range paths {
		full := filepath.Join(home, filepath.FromSlash(p))
		info, err := os.Stat(full)
		if err != nil {
			out[p] = "absent"
			continue
		}
		out[p] = info.ModTime().UTC().Format(time.RFC3339Nano)
	}
	return out
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
