package worker

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// syntheticWebshare is an operator's Webshare account in tests: nothing here
// reaches Webshare.
func syntheticWebshare(t *testing.T, use string) *config.WebProxy {
	t.Helper()
	p, err := config.ParseWebProxy([]byte(`{"provider":"webshare","username":"synthetic0user","password":"synthetic-secret","country":"us","port":1080,"use":"` + use + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func syntheticHTTPProxy(t *testing.T, host string) *config.WebProxy {
	t.Helper()
	p, err := config.ParseWebProxy([]byte(`{"provider":"http","host":"` + host + `","port":3128,"username":"synthetic-user","password":"synthetic-secret","use":"all"}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// proxyAnswers are publicAnswers with the Webshare proxy host.
func proxyAnswers(extra map[string][]netip.Addr) map[string][]netip.Addr {
	answers := map[string][]netip.Addr{"p.webshare.io": addrs("104.16.0.10", "104.16.0.11")}
	for host, a := range publicAnswers {
		answers[host] = a
	}
	for host, a := range extra {
		answers[host] = a
	}
	return answers
}

// sessionUser is the username a hop's Proxy-Authorization signs in with.
func sessionUser(t *testing.T, authorization string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authorization, "Basic "))
	user, password, ok := strings.Cut(string(raw), ":")
	if err != nil || !ok || password != "synthetic-secret" {
		t.Fatalf("authorization %q", authorization)
	}
	return user
}

// runWebOn is runWeb with a worker the test built.
func runWebOn(t *testing.T, mode string, l coordinator.Lease, w Web) webRun {
	t.Helper()
	log := filepath.Join(t.TempDir(), "relay-web.log")
	t.Setenv("SCARLETT_FAKE_PROVER", mode)
	t.Setenv("SCARLETT_FAKE_WEB_LOG", log)
	if w.busyWait == nil {
		w.busyWait = func(int) time.Duration { return 10 * time.Millisecond }
	}
	report := w.Report(context.Background(), l)
	run := webRun{code: report.Code, report: report}
	raw, err := os.ReadFile(log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var in webHopInput
		if err := json.Unmarshal(line, &in); err != nil {
			t.Fatal(err)
		}
		run.inputs = append(run.inputs, in)
	}
	return run
}

// connectSeen is one CONNECT a fake proxy took.
type connectSeen struct{ target, authorization string }

// fakeConnectProxy is an HTTP CONNECT proxy on loopback that answers every
// CONNECT with status and, after a 200, tunnels it to origin whatever it
// named. status 0 never answers.
type fakeConnectProxy struct {
	addr string
	mu   sync.Mutex
	seen []connectSeen
}

func newFakeConnectProxy(t *testing.T, status int, reply string, origin string) *fakeConnectProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeConnectProxy{addr: listener.Addr().String()}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go p.serve(t, conn, status, reply, origin)
		}
	}()
	return p
}

func (p *fakeConnectProxy) serve(t *testing.T, conn net.Conn, status int, reply, origin string) {
	defer conn.Close()
	head := []byte{}
	one := make([]byte, 1)
	for !bytes.HasSuffix(head, []byte("\r\n\r\n")) {
		if _, err := conn.Read(one); err != nil {
			return
		}
		head = append(head, one[0])
	}
	seen := connectSeen{}
	for _, line := range strings.Split(string(head), "\r\n") {
		if target, ok := strings.CutPrefix(line, "CONNECT "); ok {
			seen.target, _, _ = strings.Cut(target, " ")
		}
		if value, ok := strings.CutPrefix(line, "Proxy-Authorization: "); ok {
			seen.authorization = value
		}
	}
	p.mu.Lock()
	p.seen = append(p.seen, seen)
	p.mu.Unlock()
	switch {
	case reply != "":
		io.WriteString(conn, reply)
		return
	case status == 0:
		time.Sleep(10 * time.Second)
		return
	}
	fmt.Fprintf(conn, "HTTP/1.1 %d Synthetic\r\n\r\n", status)
	if status != http.StatusOK {
		return
	}
	up, err := net.Dial("tcp", origin)
	if err != nil {
		return
	}
	defer up.Close()
	go io.Copy(up, conn)
	io.Copy(conn, up)
}

func (p *fakeConnectProxy) connects() []connectSeen {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]connectSeen(nil), p.seen...)
}

// exitEcho is the probe's host in tests: an https origin, trusted through
// roots, that answers body after delay, or never with a negative delay.
func exitEcho(t *testing.T, body string, delay time.Duration) (origin string, roots *x509.CertPool) {
	t.Helper()
	ended := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.URL.Path != "/" {
			http.Error(w, "unexpected probe", http.StatusBadRequest)
			return
		}
		if delay < 0 {
			<-ended
			return
		}
		time.Sleep(delay)
		io.WriteString(w, body)
	}))
	t.Cleanup(func() {
		close(ended)
		server.Close()
	})
	roots = x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return server.Listener.Addr().String(), roots
}

// probeWorker probes through proxy, whatever address the job's route
// checked: the probe's host is example.com, served by the local echo.
func probeWorker(c config.Config, answers map[string][]netip.Addr, proxy *fakeConnectProxy, roots *x509.CertPool) Web {
	r := &fakeResolver{answers: answers}
	return Web{Config: c, Resolver: r.resolve, Egress: staticEgress(), exitTarget: "example.com", exitRoots: roots,
		proxyDial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, proxy.addr)
		}}
}

func TestWebExitProbe(t *testing.T) {
	upstream := ProxyUpstream{Addr: netip.MustParseAddrPort("104.16.0.10:1080"), Authorization: "Basic c3ludGhldGlj"}
	probe := func(t *testing.T, w Web, limit time.Duration) (netip.Addr, string) {
		ctx, cancel := context.WithTimeout(context.Background(), limit)
		defer cancel()
		return w.probeExit(ctx, upstream)
	}
	t.Run("the exit through the session", func(t *testing.T) {
		origin, roots := exitEcho(t, "93.184.216.34\n", 0)
		proxy := newFakeConnectProxy(t, http.StatusOK, "", origin)
		exit, class := probe(t, probeWorker(webConfig(), publicAnswers, proxy, roots), 5*time.Second)
		if exit != netip.MustParseAddr("93.184.216.34") || class != "" {
			t.Fatal(exit, class)
		}
		// The probe's host was resolved and checked here, IPv4 only, and the
		// tunnel named the checked address with the job's session.
		if seen := proxy.connects(); len(seen) != 1 || seen[0] != (connectSeen{"93.184.215.14:443", "Basic c3ludGhldGlj"}) {
			t.Fatal(seen)
		}
	})
	for _, body := range []string{"10.0.0.1", "203.0.113.7", "100.64.0.1", "2606:2800:220:1::1", "not an address", "93.184.216.34" + strings.Repeat(" ", 60), ""} {
		t.Run("body "+strings.TrimSpace(body), func(t *testing.T) {
			origin, roots := exitEcho(t, body, 0)
			proxy := newFakeConnectProxy(t, http.StatusOK, "", origin)
			if exit, class := probe(t, probeWorker(webConfig(), publicAnswers, proxy, roots), 5*time.Second); exit.IsValid() || class != proxyExit {
				t.Fatal(exit, class)
			}
		})
	}
	t.Run("untrusted certificate", func(t *testing.T) {
		origin, _ := exitEcho(t, "93.184.216.34", 0)
		proxy := newFakeConnectProxy(t, http.StatusOK, "", origin)
		if exit, class := probe(t, probeWorker(webConfig(), publicAnswers, proxy, x509.NewCertPool()), 5*time.Second); exit.IsValid() || class != proxyExit {
			t.Fatal(exit, class)
		}
	})
	t.Run("slow answer", func(t *testing.T) {
		origin, roots := exitEcho(t, "", -1)
		proxy := newFakeConnectProxy(t, http.StatusOK, "", origin)
		started := time.Now()
		if exit, class := probe(t, probeWorker(webConfig(), publicAnswers, proxy, roots), 300*time.Millisecond); exit.IsValid() || class != proxyExit || time.Since(started) > 2*time.Second {
			t.Fatal(exit, class, time.Since(started))
		}
	})
	t.Run("the probe's host passes the guard", func(t *testing.T) {
		origin, roots := exitEcho(t, "93.184.216.34", 0)
		for name, answers := range map[string][]netip.Addr{"private": addrs("10.0.0.1"), "mixed": addrs("93.184.215.14", "127.0.0.1"), "IPv6 only": addrs("2606:2800:220:1::1"), "none": {}} {
			proxy := newFakeConnectProxy(t, http.StatusOK, "", origin)
			if exit, class := probe(t, probeWorker(webConfig(), map[string][]netip.Addr{"example.com": answers}, proxy, roots), 5*time.Second); exit.IsValid() || class != proxyUnreachable || len(proxy.connects()) != 0 {
				t.Fatal(name, exit, class)
			}
		}
	})
	t.Run("CONNECT replies", func(t *testing.T) {
		for _, tc := range []struct {
			status int
			reply  string
			class  string
		}{
			{http.StatusProxyAuthRequired, "", proxyAuth},
			{http.StatusPaymentRequired, "", proxyQuota},
			{http.StatusTooManyRequests, "", proxyBusy},
			{http.StatusForbidden, "", proxyRefused},
			{http.StatusBadGateway, "", proxyExit},
			{http.StatusGatewayTimeout, "", proxyExit},
			{0, "SSH-2.0-OpenSSH\r\n\r\n", proxyUnreachable},
			{0, "HTTP/1.1 200 OK\r\n\r\nunexpected", proxyExit},
			{0, "HTTP/1.1 2000 OK\r\n\r\n", proxyUnreachable},
			{0, "", proxyExit}, // never answers: the exit never did
		} {
			proxy := newFakeConnectProxy(t, tc.status, tc.reply, "")
			if exit, class := probe(t, probeWorker(webConfig(), publicAnswers, proxy, nil), 500*time.Millisecond); exit.IsValid() || class != tc.class {
				t.Errorf("%d %q: %s, want %s", tc.status, tc.reply, class, tc.class)
			}
		}
		closed, _ := net.Listen("tcp", "127.0.0.1:0")
		addr := closed.Addr().String()
		closed.Close()
		w := probeWorker(webConfig(), publicAnswers, &fakeConnectProxy{addr: addr}, nil)
		if _, class := probe(t, w, time.Second); class != proxyUnreachable {
			t.Fatal("closed proxy", class)
		}
	})
}

// A proxied relay job goes through the proxy's checked address on its own
// session, IPv4 only, and reports the exit its probe found.
func TestWebProxiedRelayJob(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	origin, roots := exitEcho(t, "93.184.216.34\n", 0)
	proxy := newFakeConnectProxy(t, http.StatusOK, "", origin)
	c := webConfig()
	c.WebEgressProxy = syntheticWebshare(t, "all")
	var outcomes []config.WebEgressOutcome
	c.WebEgressObserver = func(o config.WebEgressOutcome) { outcomes = append(outcomes, o) }
	l := webFixtureLease(t)
	run := runWebOn(t, "web-final", l, probeWorker(c, proxyAnswers(nil), proxy, roots))
	if run.code != "" || len(run.inputs) != 1 {
		t.Fatal(run.code, len(run.inputs))
	}
	in := run.inputs[0]
	user := sessionUser(t, in.Proxy.Authorization)
	session, ok := strings.CutPrefix(user, "synthetic0user-us-")
	if in.Proxy.Host != "104.16.0.10" || in.Proxy.Port != 1080 || in.IP != "93.184.215.14" || !ok || len(session) != 9 {
		t.Fatalf("hop input %+v %s", in, user)
	}
	// The probe went through the same session.
	if seen := proxy.connects(); len(seen) != 1 || seen[0].authorization != in.Proxy.Authorization {
		t.Fatal("probe session", seen)
	}
	if run.report.Egress != (coordinator.WebEgress{Via: "proxy", Exit: "93.184.216.34"}) || len(outcomes) != 1 || outcomes[0] != (config.WebEgressOutcome{Via: "proxy", Exit: netip.MustParseAddr("93.184.216.34")}) {
		t.Fatalf("%+v %+v", run.report, outcomes)
	}
	// The same lease maps to the same session; another attempt to another.
	again := runWebOn(t, "web-final", l, probeWorker(c, proxyAnswers(nil), proxy, roots))
	other := webFixtureLease(t)
	other.Attempt = "22222222-2222-4222-8222-000000000000"
	third := runWebOn(t, "web-final", other, probeWorker(c, proxyAnswers(nil), proxy, roots))
	if again.inputs[0].Proxy.Authorization != in.Proxy.Authorization || third.inputs[0].Proxy.Authorization == in.Proxy.Authorization {
		t.Fatal("sessions per attempt")
	}

	t.Run("the report waits at most two seconds for the probe", func(t *testing.T) {
		slowOrigin, slowRoots := exitEcho(t, "", -1)
		slow := newFakeConnectProxy(t, http.StatusOK, "", slowOrigin)
		w := probeWorker(c, proxyAnswers(nil), slow, slowRoots)
		if run := runWebOn(t, "web-final", l, w); run.code != "" || run.report.Egress != (coordinator.WebEgress{Via: "proxy"}) {
			t.Fatal(run.code, run.report.Egress)
		}
		// Once the job ends, the route waits the two seconds and no longer.
		route, ok := w.jobRoute(context.Background(), l)
		started := time.Now()
		if egress, _ := route.finish(""); !ok || egress != (coordinator.WebEgress{Via: "proxy"}) || time.Since(started) < webExitWait || time.Since(started) > webExitWait+time.Second {
			t.Fatal(egress, time.Since(started))
		}
	})
	t.Run("every hop keeps the session", func(t *testing.T) {
		answers := proxyAnswers(map[string][]netip.Addr{"www.example.com": addrs("93.184.215.20"), "cdn.example.net": addrs("151.101.65.57")})
		run := runWebOn(t, "web-chain", l, probeWorker(c, answers, proxy, roots))
		if run.code != "" || len(run.inputs) != 3 {
			t.Fatal(run.code, len(run.inputs))
		}
		for _, hop := range run.inputs {
			if hop.Proxy == nil || hop.Proxy.Authorization != in.Proxy.Authorization {
				t.Fatal("hop left its session", hop.Hop)
			}
		}
	})
	t.Run("proxied hops are IPv4 only", func(t *testing.T) {
		// A later hop host with only IPv6 answers ends the chain; the job is
		// proven by its first hop.
		run := runWebOn(t, "web-chain", l, probeWorker(c, proxyAnswers(nil), proxy, roots))
		if run.code != "" || len(run.inputs) != 1 {
			t.Fatal(run.code, len(run.inputs))
		}
		v6 := proxyAnswers(map[string][]netip.Addr{"example.com": addrs("2606:2800:21f:cb07:6820:80da:af6b:8b2c")})
		if run := runWebOn(t, "web-final", l, probeWorker(c, v6, proxy, roots)); run.code != "web_dns_failed" || len(run.inputs) != 0 || run.report.Egress.Via != "proxy" {
			t.Fatal("IPv6-only page host", run.code, len(run.inputs))
		}
		mixed := proxyAnswers(map[string][]netip.Addr{"example.com": addrs("93.184.215.14", "fd00::1")})
		if run := runWebOn(t, "web-final", l, probeWorker(c, mixed, proxy, roots)); run.code != "web_egress_denied" || len(run.inputs) != 0 {
			t.Fatal("a private IPv6 answer beside the IPv4 one", run.code)
		}
	})
	t.Run("a hop-0 exit failure rotates once", func(t *testing.T) {
		run := runWebOn(t, "web-proxy-exit-once", l, probeWorker(c, proxyAnswers(nil), proxy, roots))
		if run.code != "" || len(run.inputs) != 2 || run.inputs[0].Hop != 0 || run.inputs[1].Hop != 0 {
			t.Fatal(run.code, len(run.inputs))
		}
		first, second := run.inputs[0].Proxy, run.inputs[1].Proxy
		if first.Authorization != in.Proxy.Authorization || second.Authorization == first.Authorization || second.Host != first.Host || sessionUser(t, second.Authorization) == user {
			t.Fatal("rotation", first.Host, second.Host)
		}
		always := runWebOn(t, "web-class-proxy_exit", l, probeWorker(c, proxyAnswers(nil), proxy, roots))
		if always.code != "web_connect_failed" || len(always.inputs) != 2 {
			t.Fatal("rotated more than once", always.code, len(always.inputs))
		}
		// Only hop 0 rotates; a later exit failure leaves the job proven.
		answers := proxyAnswers(map[string][]netip.Addr{"www.example.com": addrs("93.184.215.20")})
		later := runWebOn(t, "web-later-fails", l, probeWorker(c, answers, proxy, roots))
		if later.code != "" || len(later.inputs) != 2 {
			t.Fatal(later.code, len(later.inputs))
		}
	})
	t.Run("proxy classes", func(t *testing.T) {
		for class, want := range map[string]string{proxyUnreachable: "web_proxy_failed", proxyAuth: "web_proxy_failed", proxyQuota: "web_proxy_failed", proxyBusy: "web_proxy_failed", proxyRefused: "web_proxy_refused", proxyExit: "web_connect_failed"} {
			outcomes = nil
			run := runWebOn(t, "web-class-"+class, l, probeWorker(c, proxyAnswers(nil), proxy, roots))
			restClass := ""
			if want == "web_proxy_failed" {
				restClass = class
			}
			if run.code != want || len(outcomes) != 1 || outcomes[0].ProxyClass != restClass || outcomes[0].Via != "proxy" || run.report.Egress.Via != "proxy" {
				t.Errorf("%s: %s %+v", class, run.code, outcomes)
			}
		}
	})
}

// The proxy's host is resolved once per job and checked; a proxy that fails
// its check fails the job, and nothing goes out from this node's network.
func TestWebProxyHostGuard(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	l := webFixtureLease(t)
	for name, answers := range map[string][]netip.Addr{"private": addrs("10.0.0.5"), "mixed": addrs("104.16.0.10", "192.168.1.1"), "loopback": addrs("127.0.0.1"), "none": {}} {
		c := webConfig()
		c.WebEgressProxy = syntheticWebshare(t, "all")
		var outcomes []config.WebEgressOutcome
		c.WebEgressObserver = func(o config.WebEgressOutcome) { outcomes = append(outcomes, o) }
		run := runWebOn(t, "web-final", l, Web{Config: c, Resolver: (&fakeResolver{answers: proxyAnswers(map[string][]netip.Addr{"p.webshare.io": answers})}).resolve, Egress: staticEgress()})
		if run.code != "web_proxy_failed" || len(run.inputs) != 0 || run.report.Egress != (coordinator.WebEgress{Via: "proxy"}) || len(outcomes) != 1 || outcomes[0].ProxyClass != proxyUnreachable {
			t.Errorf("%s: %s %d %+v", name, run.code, len(run.inputs), outcomes)
		}
	}
	// An http proxy may be on loopback or the LAN, never link-local.
	for host, want := range map[string]string{"127.0.0.1": "127.0.0.1", "proxy.lan": "192.168.1.2", "::1": "::1"} {
		c := webConfig()
		c.WebEgressProxy = syntheticHTTPProxy(t, host)
		run := runWebOn(t, "web-final", l, Web{Config: c, Resolver: (&fakeResolver{answers: proxyAnswers(map[string][]netip.Addr{"proxy.lan": addrs("192.168.1.2")})}).resolve, Egress: staticEgress()})
		if run.code != "" || len(run.inputs) != 1 || run.inputs[0].Proxy.Host != want || run.inputs[0].Proxy.Port != 3128 || sessionUser(t, run.inputs[0].Proxy.Authorization) != "synthetic-user" || run.report.Egress != (coordinator.WebEgress{Via: "proxy"}) {
			t.Errorf("http proxy %s: %s %+v", host, run.code, run.report)
		}
	}
	for host, answers := range map[string][]netip.Addr{"169.254.169.254": nil, "fe80::1": nil, "0.0.0.0": nil, "proxy.lan": addrs("192.168.1.2", "169.254.1.1"), "proxy6.lan": addrs("fe80::1")} {
		c := webConfig()
		c.WebEgressProxy = syntheticHTTPProxy(t, host)
		run := runWebOn(t, "web-final", l, Web{Config: c, Resolver: (&fakeResolver{answers: map[string][]netip.Addr{host: answers, "example.com": publicAnswers["example.com"]}}).resolve, Egress: staticEgress()})
		if run.code != "web_proxy_failed" || len(run.inputs) != 0 {
			t.Errorf("http proxy %s: %s", host, run.code)
		}
	}
}

// A "both" node sends a lease through its proxy only when the lease asks,
// and a direct node refuses a lease that asks.
func TestWebEgressModes(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	hinted := webFixtureLease(t)
	hinted.WebEgress = "proxy"
	both := webConfig()
	both.WebEgressProxy = syntheticWebshare(t, "limited_sites")
	w := Web{Config: both, Resolver: (&fakeResolver{answers: proxyAnswers(nil)}).resolve, Egress: staticEgress()}
	if both.WebEgress() != "both" || UsesProxy(both, webFixtureLease(t)) || !UsesProxy(both, hinted) {
		t.Fatal("both")
	}
	if run := runWebOn(t, "web-final", webFixtureLease(t), w); run.code != "" || run.inputs[0].Proxy != nil || run.report.Egress != (coordinator.WebEgress{Via: "direct"}) {
		t.Fatal("unhinted lease on a both node", run.code, run.report)
	}
	if run := runWebOn(t, "web-final", hinted, w); run.code != "" || run.inputs[0].Proxy == nil || run.report.Egress.Via != "proxy" {
		t.Fatal("hinted lease on a both node", run.code, run.report)
	}
	direct := webConfig()
	if direct.WebEgress() != "direct" || UsesProxy(direct, hinted) {
		t.Fatal("direct")
	}
	if _, _, code := validateWebLease(direct, hinted); code != "invalid_lease" {
		t.Fatal("hinted lease on a direct node", code)
	}
	if run := runWebOn(t, "web-final", hinted, Web{Config: direct, Resolver: (&fakeResolver{answers: publicAnswers}).resolve, Egress: staticEgress()}); run.code != "invalid_lease" || len(run.inputs) != 0 || run.report.Egress.Via != "direct" {
		t.Fatal(run.code)
	}
	offer := webOffer(t)
	offer.WebEgress = "proxy"
	if (Web{Config: direct}).StartPredial(context.Background(), offer) != nil {
		t.Fatal("a direct node pre-dialed a proxy offer")
	}
	bad := webFixtureLease(t)
	bad.WebEgress = "direct"
	if _, _, code := validateWebLease(both, bad); code != "invalid_lease" {
		t.Fatal("web_egress other than proxy", code)
	}
}

// The pre-dial of a proxied offer checks the proxy once and dials on the
// job's session, so hop 0 still takes it.
func TestWebProxiedPredialIsUsed(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	_, webLog, predialLog := useWebDaemon(t, "web-final")
	webDaemonEnabled.Store(false)
	c := webConfig()
	c.WebEgressProxy = syntheticWebshare(t, "limited_sites")
	r := &fakeResolver{answers: proxyAnswers(nil)}
	w := Web{Config: c, Resolver: r.resolve, Egress: staticEgress(), busyWait: func(int) time.Duration { return 10 * time.Millisecond }}
	offer := webOffer(t)
	offer.WebEgress = "proxy"
	p := w.StartPredial(context.Background(), offer)
	lines := eventually(t, predialLog, 1)
	var first webHopInput
	raw, _ := json.Marshal(lines[0]["input"])
	if json.Unmarshal(raw, &first) != nil || first.Proxy == nil || first.Proxy.Host != "104.16.0.10" || first.IP != "93.184.215.14" {
		t.Fatal("pre-dial input", lines[0])
	}
	accepted := webFixtureLease(t)
	accepted.WebEgress = "proxy"
	accepted.LeaseDeadline, accepted.SettlementDeadline = offer.LeaseDeadline, offer.SettlementDeadline
	// By the job the proxy's host answers otherwise; the job keeps the
	// address its pre-dial checked.
	r.mu.Lock()
	r.answers["p.webshare.io"] = addrs("104.16.0.11")
	r.mu.Unlock()
	if report := w.Report(p.Accepted(context.Background(), accepted), accepted); report.Code != "" || report.Egress.Via != "proxy" {
		t.Fatal(report)
	}
	p.Cancel()
	if lines := fakeLines(t, predialLog); len(lines) != 2 || lines[1]["event"] != "token" {
		t.Fatal("pre-dial events", lines)
	}
	if lines := fakeLines(t, webLog); len(lines) != 1 {
		t.Fatal("hops", lines)
	}
	r.mu.Lock()
	asked := strings.Join(r.asked, ",")
	r.mu.Unlock()
	if strings.Count(asked, "p.webshare.io") != 1 {
		t.Fatal("proxy resolved more than once for one job", asked)
	}
}

// The proxy reaches the helper, which needs it, and nothing else: no report,
// observer, formatted configuration or value repeats a credential, a session
// or the proxy's address.
func TestWebProxyStaysLocal(t *testing.T) {
	ResetRelayHaltForTests()
	c := webConfig()
	c.WebEgressProxy = syntheticWebshare(t, "all")
	var outcomes []config.WebEgressOutcome
	c.WebEgressObserver = func(o config.WebEgressOutcome) { outcomes = append(outcomes, o) }
	w := Web{Config: c, Resolver: (&fakeResolver{answers: proxyAnswers(nil)}).resolve, Egress: staticEgress()}
	// A rotated job, with everything this process prints captured.
	var run webRun
	output := captureOutput(t, func() { run = runWebOn(t, "web-proxy-exit-once", webFixtureLease(t), w) })
	if run.code != "" || len(run.inputs) != 2 || run.inputs[0].Proxy == nil {
		t.Fatal(run.code)
	}
	rotated := strings.TrimPrefix(sessionUser(t, run.inputs[1].Proxy.Authorization), "synthetic0user-us-")
	user := sessionUser(t, run.inputs[0].Proxy.Authorization)
	session := strings.TrimPrefix(user, "synthetic0user-us-")
	route, ok := w.jobRoute(context.Background(), webFixtureLease(t))
	if !ok {
		t.Fatal("route")
	}
	defer route.finish("")
	report, _ := json.Marshal(run.report)
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		text := fmt.Sprintf(format, c) + fmt.Sprintf(format, *c.WebEgressProxy) + fmt.Sprintf(format, c.WebEgressProxy) + fmt.Sprintf(format, *route.upstream()) + fmt.Sprintf(format, *route.hopProxy()) +
			fmt.Sprintf(format, c.WebEgressProxy.Session("j", "a", 0)) + fmt.Sprintf(format, run.report) + fmt.Sprintf(format, outcomes) + string(report) + output
		for _, secret := range []string{"synthetic-secret", "synthetic0user", session, rotated, "c3ludGhldGlj", "104.16.0.10", "p.webshare.io"} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s prints %s", format, secret)
			}
		}
	}
}

// proxy-test's probe: a fresh session, the proxy host checked as for a job.
func TestProbeWebProxy(t *testing.T) {
	origin, roots := exitEcho(t, "93.184.216.34", 0)
	proxy := newFakeConnectProxy(t, http.StatusOK, "", origin)
	p := syntheticWebshare(t, "limited_sites")
	w := probeWorker(webConfig(), proxyAnswers(nil), proxy, roots)
	exit, class := w.probeWebProxy(context.Background(), p)
	if exit != netip.MustParseAddr("93.184.216.34") || class != "" {
		t.Fatal(exit, class)
	}
	again, _ := w.probeWebProxy(context.Background(), p)
	seen := proxy.connects()
	if !again.IsValid() || len(seen) != 2 || seen[0].authorization == seen[1].authorization || !strings.HasPrefix(sessionUser(t, seen[0].authorization), "synthetic0user-us-") {
		t.Fatal("fresh sessions", seen)
	}
	refused := probeWorker(webConfig(), proxyAnswers(map[string][]netip.Addr{"p.webshare.io": addrs("10.0.0.1")}), proxy, roots)
	if _, class := refused.probeWebProxy(context.Background(), p); class != proxyUnreachable || len(proxy.connects()) != 2 {
		t.Fatal("private proxy host", class)
	}
	auth := probeWorker(webConfig(), proxyAnswers(nil), newFakeConnectProxy(t, http.StatusProxyAuthRequired, "", ""), roots)
	if _, class := auth.probeWebProxy(context.Background(), p); class != proxyAuth {
		t.Fatal(class)
	}
}

// A proxied browser job hands the browser tier its session, and its relay
// re-fetch leaves through the same one; a direct job hands over none.
func TestWebProxiedBrowserJob(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	c := browserConfig()
	c.WebEgressProxy = syntheticWebshare(t, "limited_sites")
	l := webBrowserFixtureLease(t)
	l.WebEgress = "proxy"
	browser := &fakeBrowser{status: readyStatus(), result: renderedPage(), html: renderedHTML, dir: t.TempDir()}
	run := runWebOn(t, "web-final", l, Web{Config: c, Resolver: (&fakeResolver{answers: proxyAnswers(nil)}).resolve, Egress: staticEgress(), Browser: browser})
	if run.code != "" || len(run.inputs) != 1 || len(browser.requests) != 1 || run.report.Egress.Via != "proxy" {
		t.Fatal(run.code, len(run.inputs), len(browser.requests))
	}
	upstream := browser.requests[0].Upstream
	if upstream == nil || upstream.Addr != netip.MustParseAddrPort("104.16.0.10:1080") || upstream.Authorization != run.inputs[0].Proxy.Authorization || run.inputs[0].Proxy.Host != "104.16.0.10" {
		t.Fatal("browser and re-fetch sessions differ")
	}
	if raw, _ := json.Marshal(browser.requests[0]); strings.Contains(string(raw), "104.16.0.10") || strings.Contains(string(raw), "Basic") {
		t.Fatal("the helper request carries the upstream", string(raw))
	}
	direct := &fakeBrowser{status: readyStatus(), result: renderedPage(), html: renderedHTML, dir: t.TempDir()}
	plain := webBrowserFixtureLease(t)
	if run := runWebOn(t, "web-final", plain, Web{Config: c, Resolver: (&fakeResolver{answers: proxyAnswers(nil)}).resolve, Egress: staticEgress(), Browser: direct}); run.code != "" || direct.requests[0].Upstream != nil || run.inputs[0].Proxy != nil || run.report.Egress.Via != "direct" {
		t.Fatal("direct browser job", run.code)
	}
	v6 := &fakeBrowser{status: readyStatus(), result: renderedPage(), html: renderedHTML, dir: t.TempDir()}
	answers := proxyAnswers(map[string][]netip.Addr{"example.com": addrs("2606:2800:21f:cb07:6820:80da:af6b:8b2c")})
	if run := runWebOn(t, "web-final", l, Web{Config: c, Resolver: (&fakeResolver{answers: answers}).resolve, Egress: staticEgress(), Browser: v6}); run.code != "web_dns_failed" || len(v6.requests) != 0 {
		t.Fatal("IPv6-only page through the proxy", run.code)
	}
}

// A main document the job's proxy would not tunnel fails with the proxy's
// class as a relay hop 0 would, and that class decides web's rest whatever
// the re-fetch ran into. A re-fetch that proves the page still serves it.
func TestWebProxiedBrowserPageTheProxyRefused(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	origin, roots := exitEcho(t, "93.184.216.34\n", 0)
	proxy := newFakeConnectProxy(t, http.StatusOK, "", origin)
	c := browserConfig()
	c.WebEgressProxy = syntheticWebshare(t, "all")
	var outcomes []config.WebEgressOutcome
	c.WebEgressObserver = func(o config.WebEgressOutcome) { outcomes = append(outcomes, o) }
	refused := func(class string) *fakeBrowser {
		return &fakeBrowser{status: readyStatus(), result: BrowserFetchResult{Outcome: "failed", Error: "navigation_failed", Challenge: "none", ProxyClass: class}, dir: t.TempDir()}
	}
	for _, tc := range []struct{ class, relay, code, rest string }{
		{proxyRefused, "web-class-proxy_refused", "web_proxy_refused", ""},
		{proxyAuth, "web-class-proxy_busy", "web_proxy_failed", proxyAuth},
		{proxyQuota, "web-fetch", "web_proxy_failed", proxyQuota},
		{proxyUnreachable, "web-fetch", "web_proxy_failed", proxyUnreachable},
		{proxyExit, "web-fetch", "web_connect_failed", ""},
		{proxyRefused, "web-final", "", ""},
		{"no_such_class", "web-fetch", "web_browser_failed", ""},
	} {
		outcomes = nil
		w := probeWorker(c, proxyAnswers(nil), proxy, roots)
		w.Browser = refused(tc.class)
		run := runWebOn(t, tc.relay, webBrowserFixtureLease(t), w)
		if run.code != tc.code || run.report.Egress.Via != "proxy" || len(outcomes) != 1 || outcomes[0].ProxyClass != tc.rest {
			t.Fatalf("%s then %s: %q %+v", tc.class, tc.relay, run.code, outcomes)
		}
	}
	// A direct page never takes a proxy class from the tier.
	w := Web{Config: browserConfig(), Resolver: (&fakeResolver{answers: proxyAnswers(nil)}).resolve, Egress: staticEgress(), Browser: refused(proxyRefused)}
	if run := runWebOn(t, "web-fetch", webBrowserFixtureLease(t), w); run.code != "web_browser_failed" || run.report.Egress.Via != "direct" {
		t.Fatal("direct page", run.code)
	}
}
