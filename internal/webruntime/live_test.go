//go:build webbrowser_live

package webruntime

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
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
	// External protocols without a gesture: mailto: (which Chrome 155 hands
	// to the OS mail client without asking) and news: by frame, by frame
	// location and by a frame's 3xx. Handed to the OS, a frame stays on its
	// same-origin about:blank; kept in the browser (the seeded URL blocklist,
	// then the seeded handlers, and the redirect guard for the 3xx) it shows
	// a cross-origin error page, so its contentDocument is null.
	mux.HandleFunc("/to-mailto", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "mailto:scarlett-live-redirect@example.invalid")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/external", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!doctype html><body><script>
const frames = [];
const frame = () => { const f = document.createElement('iframe'); document.body.appendChild(f); frames.push(f); return f; };
for (const src of ['mailto:scarlett-live@example.invalid', 'news:scarlett-live', '/to-mailto']) frame().src = src;
frame().contentWindow.location = 'mailto:scarlett-live-location@example.invalid';
setTimeout(() => {
  const el = document.createElement('div'); el.id = 'done'; el.textContent = String(frames.filter(f => f.contentDocument === null).length);
  document.body.appendChild(el);
}, 2500);
</script></body>`)
	})
	// A page that looks like a managed Cloudflare interstitial, so the
	// solver clicks it; the click handler calls APIs that need a user
	// gesture. None may reach the operator's clipboard, a device, the
	// screen or an app: the device choosers and screen capture fail at
	// once, as a cancelled chooser does, and the browser does not crash.
	mux.HandleFunc("/activate", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!doctype html><html><head><title>Just a moment...</title></head><body>
<script id="marker">window._cf_chl_opt={cType: 'managed'};</script>
<div class="main-content"><p>Checking</p><div><div><div style="width:300px;height:65px;background:#eee"></div></div></div></div>
<script>
const out = {};
const settle = (k, p) => Promise.resolve().then(p).then(v => { out[k] = 'resolved' + (Array.isArray(v) ? ' ' + v.length : '') },
  e => { out[k] = 'refused ' + (e && e.name) });
document.addEventListener('click', async () => {
  out.activation = navigator.userActivation.isActive;
  const t = document.createElement('textarea'); t.value = 'scarlett-live-exec-copy'; document.body.appendChild(t); t.select();
  out.exec_copy = document.execCommand('copy');
  await Promise.race([Promise.all([
    settle('clipboard_write', () => navigator.clipboard.writeText('scarlett-live-clipboard')),
    settle('clipboard_read', () => navigator.clipboard.readText()),
    settle('picker', () => window.showOpenFilePicker()),
    settle('bluetooth', () => navigator.bluetooth.requestDevice({acceptAllDevices: true})),
    settle('hid', () => navigator.hid.requestDevice({filters: []})),
    settle('usb', () => navigator.usb.requestDevice({filters: []})),
    settle('serial', () => navigator.serial.requestPort()),
    settle('display', () => navigator.mediaDevices.getDisplayMedia({video: true})),
  ]), new Promise(r => setTimeout(r, 5000))]);
  const a = document.createElement('a'); a.href = 'mailto:scarlett-live-click@example.invalid'; a.target = 'mailframe';
  const mf = document.createElement('iframe'); mf.name = 'mailframe'; document.body.appendChild(mf); document.body.appendChild(a); a.click();
  out.mail_window = window.open('mailto:scarlett-live-open@example.invalid') ? 'opened' : 'blocked';
  out.popup = window.open('/cookies') ? 'opened' : 'blocked';
  document.getElementById('marker').remove(); document.title = 'done';
  const el = document.createElement('div'); el.id = 'done'; el.textContent = JSON.stringify(out); document.body.appendChild(el);
}, {once: true});
</script></body></html>`)
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

	// External protocols open nothing: no handler app starts, every frame
	// navigation stays in the browser, a 3xx to mailto: fails the page.
	apps := handlerApps(t)
	if res = fetch(loopback+"/external", "load", "#done"); res.Outcome != "ok" || between(res.HTML, `<div id="done">`, `</div>`) != "4" {
		t.Fatalf("external-protocol page: outcome %s, frames kept in the browser %q of 4", res.Outcome, between(res.HTML, `<div id="done">`, `</div>`))
	}
	if res = fetch(loopback+"/to-mailto", "load", ""); res.Outcome == "ok" || res.HTML != "" {
		t.Fatalf("a document redirect to mailto: was followed: outcome %s", res.Outcome)
	}

	// A clicked page gets activation and still reaches nothing outside the
	// browser: the operator's clipboard is unchanged (compared by hash only).
	m.mu.Lock()
	warm := m.helper
	m.mu.Unlock()
	clipBefore := clipboardHash(t)
	res = fetch(loopback+"/activate", "load", "#done")
	var act struct {
		Activation     bool   `json:"activation"`
		ExecCopy       bool   `json:"exec_copy"`
		ClipboardWrite string `json:"clipboard_write"`
		ClipboardRead  string `json:"clipboard_read"`
		Picker         string `json:"picker"`
		Bluetooth      string `json:"bluetooth"`
		HID            string `json:"hid"`
		USB            string `json:"usb"`
		Serial         string `json:"serial"`
		Display        string `json:"display"`
	}
	if err := json.Unmarshal([]byte(between(res.HTML, `<div id="done">`, `</div>`)), &act); err != nil || !act.Activation {
		t.Fatalf("the solver did not click the interstitial-shaped page: %v %+v", err, act)
	}
	if !strings.HasPrefix(act.ClipboardWrite, "refused") || !strings.HasPrefix(act.ClipboardRead, "refused") || !strings.HasPrefix(act.Picker, "refused") {
		t.Fatalf("a gesture-gated API was granted: %+v", act)
	}
	// What a cancelled chooser returns: NotFoundError, an empty HID list,
	// NotAllowedError for screen capture.
	if act.Bluetooth != "refused NotFoundError" || act.HID != "resolved 0" || act.USB != "refused NotFoundError" ||
		act.Serial != "refused NotFoundError" || act.Display != "refused NotAllowedError" {
		t.Fatalf("a device chooser or screen capture did not fail at once: %+v", act)
	}
	if clipBefore != clipboardHash(t) {
		t.Fatal("a clicked page changed the operator's clipboard")
	}
	m.mu.Lock()
	same := m.helper == warm
	m.mu.Unlock()
	if !same {
		t.Fatal("the browser did not survive the clicked page")
	}
	checkNoHandlerApp(t, apps)

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

// clipboardHash is a digest of the operator's clipboard text on macOS ("" elsewhere);
// the text itself is never kept or logged.
func clipboardHash(t *testing.T) string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	out, err := exec.Command("/usr/bin/pbpaste").Output()
	if err != nil {
		t.Fatalf("pbpaste: %v", err)
	}
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:])
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
		"--disable-blink-features=AutomationControlled", "--deny-permission-prompts", "--disable-quic", "--disable-component-update", "--use-fake-device-for-media-stream",
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
		if a == "--no-sandbox" || a == "--force-webrtc-ip-handling-policy" || a == "--use-fake-ui-for-media-stream" {
			t.Fatalf("live argv has %s", a)
		}
	}
	// The browser runs on the profile the helper seeded, under node state.
	var profiles []string
	for _, a := range argv {
		if strings.Contains(a, "user-data-dir") {
			profiles = append(profiles, a)
		}
	}
	prefix := "--user-data-dir=" + filepath.Join(m.cfg.StateDir, "web-browser", "tmp", "scarlett-profile-")
	if len(profiles) != 1 || !strings.HasPrefix(profiles[0], prefix) || !slices.Equal(argv[len(argv)-3:], []string{profiles[0], "--remote-debugging-pipe", "--no-startup-window"}) {
		t.Fatalf("browser profile not the seeded one: %v", profiles)
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimPrefix(profiles[0], "--user-data-dir="), "Default", "Preferences"))
	var prefs struct {
		CustomHandlers struct {
			Enabled    bool `json:"enabled"`
			Registered []struct {
				Protocol  string `json:"protocol"`
				URL       string `json:"url"`
				Incognito bool   `json:"is_allowed_in_incognito"`
			} `json:"registered_protocol_handlers"`
		} `json:"custom_handlers"`
		Policy struct {
			URLBlocklist []string `json:"url_blocklist"`
		} `json:"policy"`
	}
	if err != nil || json.Unmarshal(raw, &prefs) != nil || !prefs.CustomHandlers.Enabled {
		t.Fatalf("seeded profile preferences unreadable: %v", err)
	}
	handled := map[string]bool{}
	for _, h := range prefs.CustomHandlers.Registered {
		handled[h.Protocol] = h.URL == "https://scarlett-blocked.invalid/?u=%s" && h.Incognito
	}
	if !handled["mailto"] || !handled["news"] {
		t.Fatalf("seeded protocol handlers missing: %+v", prefs.CustomHandlers.Registered)
	}
	for _, scheme := range []string{"mailto:*", "news:*", "snews:*"} {
		if !slices.Contains(prefs.Policy.URLBlocklist, scheme) {
			t.Fatalf("seeded URL blocklist lacks %s: %v", scheme, prefs.Policy.URLBlocklist)
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
