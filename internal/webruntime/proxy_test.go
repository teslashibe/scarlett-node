package webruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	publicV4 = netip.MustParseAddr("93.184.215.14")
	publicV6 = netip.MustParseAddr("2606:2800:21f:cb07:6820:80da:af6b:8b2c")
)

// testGuard allows only global unicast outside the core's denied ranges
// (a copy of the C.4 IPv4 list, for this package's own tests).
type testGuard struct{}

var testDenied = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
	"192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::1/128", "fc00::/7", "fe80::/10", "2001:db8::/32", "64:ff9b::/96", "ff00::/8"}

func (testGuard) Allowed(_ context.Context, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range testDenied {
		if netip.MustParsePrefix(p).Contains(a) {
			return false
		}
	}
	return a.IsGlobalUnicast()
}

type fakeNet struct {
	mu       sync.Mutex
	resolves map[string]int
	answers  func(host string, n int) []netip.Addr
	dials    []string
	target   string // where every dial really goes
}

func (f *fakeNet) resolve(_ context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resolves == nil {
		f.resolves = map[string]int{}
	}
	f.resolves[host]++
	if f.answers == nil {
		return []netip.Addr{publicV4}, nil
	}
	if a := f.answers(host, f.resolves[host]); a != nil {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func (f *fakeNet) dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dials = append(f.dials, address)
	target := f.target
	f.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

func (f *fakeNet) calls() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.resolves {
		n += c
	}
	return n, append([]string(nil), f.dials...)
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

func newTestProxy(t *testing.T, f *fakeNet, upstream *Upstream, tunnels int) (*egressProxy, *ProxyStats) {
	t.Helper()
	stats := &ProxyStats{}
	p, err := newEgressProxy(testGuard{}, f.resolve, upstream, "example.com", tunnels, stats)
	if err != nil {
		t.Fatal(err)
	}
	p.dial = f.dial
	t.Cleanup(p.Close)
	return p, stats
}

// connect sends CONNECT and returns the status and the open connection.
func connect(t *testing.T, proxy, target string) (int, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp4", strings.TrimPrefix(proxy, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		t.Fatalf("CONNECT %s: %v", target, err)
	}
	c.SetReadDeadline(time.Time{})
	return resp.StatusCode, c
}

// absolute sends one absolute-form request and returns the status.
func absolute(t *testing.T, proxy, rawURL string) (int, string) {
	t.Helper()
	c, err := net.Dial("tcp4", strings.TrimPrefix(proxy, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	u, _ := url.Parse(rawURL)
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic c2VjcmV0\r\nX-Keep: yes\r\n\r\n", rawURL, u.Host)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestProxyConnectsToCheckedPublicAddress(t *testing.T) {
	f := &fakeNet{target: echoServer(t)}
	p, stats := newTestProxy(t, f, nil, 48)
	status, c := connect(t, p.URL(), "example.com:443")
	defer c.Close()
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	fmt.Fprint(c, "ping")
	buf := make([]byte, 4)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("tunnel did not splice: %q %v", buf, err)
	}
	if n, dials := f.calls(); n != 1 || len(dials) != 1 || dials[0] != publicV4.String()+":443" {
		t.Fatalf("resolves %d dials %v", n, dials)
	}
	if stats.Allowed.Load() != 1 {
		t.Fatal("allowed counter")
	}
}

func TestProxyForwardsAbsoluteFormInOriginFormWithoutHopHeaders(t *testing.T) {
	var got *http.Request
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		w.Header().Set("Connection", "X-Drop")
		w.Header().Set("X-Drop", "1")
		fmt.Fprint(w, "origin body")
	}))
	defer origin.Close()
	f := &fakeNet{target: origin.Listener.Addr().String()}
	p, _ := newTestProxy(t, f, nil, 48)
	status, body := absolute(t, p.URL(), "http://example.com/path?q=1")
	if status != 200 || body != "origin body" {
		t.Fatalf("status %d body %q", status, body)
	}
	if got.RequestURI != "/path?q=1" || got.Host != "example.com" || got.Header.Get("X-Keep") != "yes" ||
		got.Header.Get("Proxy-Authorization") != "" || got.Header.Get("Proxy-Connection") != "" {
		t.Fatalf("forwarded request: %s host %s headers %v", got.RequestURI, got.Host, got.Header)
	}
	if _, dials := f.calls(); len(dials) != 1 || dials[0] != publicV4.String()+":80" {
		t.Fatalf("dials %v", dials)
	}
}

func TestProxyRefusesPrivateAndMixedAnswers(t *testing.T) {
	for _, private := range []string{"10.1.2.3", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.168.1.1", "100.64.0.1", "0.0.0.0",
		"224.0.0.251", "::1", "fe80::1", "fd00::1", "64:ff9b::a00:1"} {
		addr := netip.MustParseAddr(private)
		for name, answers := range map[string][]netip.Addr{"private": {addr}, "mixed": {publicV4, addr}, "mixed6": {publicV6, addr}} {
			t.Run(private+"/"+name, func(t *testing.T) {
				f := &fakeNet{target: echoServer(t), answers: func(string, int) []netip.Addr { return answers }}
				p, stats := newTestProxy(t, f, nil, 48)
				if status, c := connect(t, p.URL(), "example.com:443"); status != 403 {
					c.Close()
					t.Fatalf("CONNECT status %d", status)
				}
				if status, _ := absolute(t, p.URL(), "http://example.com/"); status != 403 {
					t.Fatalf("GET status %d", status)
				}
				if _, dials := f.calls(); len(dials) != 0 || stats.RefusedAddress.Load() != 2 {
					t.Fatalf("dials %v refused %d", dials, stats.RefusedAddress.Load())
				}
			})
		}
		t.Run(private+"/literal", func(t *testing.T) {
			f := &fakeNet{target: echoServer(t)}
			p, _ := newTestProxy(t, f, nil, 48)
			host := private
			if addr.Is6() {
				host = "[" + private + "]"
			}
			if status, c := connect(t, p.URL(), host+":443"); status != 403 {
				c.Close()
				t.Fatalf("CONNECT literal status %d", status)
			}
			if status, _ := absolute(t, p.URL(), "http://"+host+"/"); status != 403 {
				t.Fatalf("GET literal status %d", status)
			}
			if n, dials := f.calls(); n != 0 || len(dials) != 0 {
				t.Fatalf("a literal was resolved (%d) or dialed (%v)", n, dials)
			}
		})
	}
}

func TestProxyRefusesLANNamesBeforeAnyLookup(t *testing.T) {
	f := &fakeNet{target: echoServer(t)}
	p, stats := newTestProxy(t, f, nil, 48)
	names := []string{"printer.local", "intranet", "router.lan", "x.home.arpa", "a.localhost", "x.internal", "1.2.3", "localhost",
		"box.localdomain", "x.onion", "a.invalid", "a.test", "-bad.example.com", "UPPER..example", "ex_ample.com"}
	for _, name := range names {
		if status, c := connect(t, p.URL(), name+":443"); status != 403 {
			c.Close()
			t.Fatalf("CONNECT %s: %d", name, status)
		}
		if status, _ := absolute(t, p.URL(), "http://"+name+"/x.png"); status != 403 {
			t.Fatalf("GET %s: %d", name, status)
		}
	}
	if n, dials := f.calls(); n != 0 || len(dials) != 0 {
		t.Fatalf("refused names reached the resolver (%d) or a dial (%v)", n, dials)
	}
	if stats.RefusedName.Load() != uint64(2*len(names)) {
		t.Fatalf("refused-name counter %d", stats.RefusedName.Load())
	}
}

func TestProxyNeverReResolves(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer origin.Close()
	rebinding := func(host string, n int) []netip.Addr {
		if n == 1 {
			return []netip.Addr{publicV4}
		}
		return []netip.Addr{netip.MustParseAddr("192.168.1.1")}
	}
	for _, form := range []string{"connect", "absolute"} {
		t.Run(form, func(t *testing.T) {
			f := &fakeNet{target: origin.Listener.Addr().String(), answers: rebinding}
			p, _ := newTestProxy(t, f, nil, 48)
			if form == "connect" {
				status, c := connect(t, p.URL(), "rebind.example:443")
				c.Close()
				if status != 200 {
					t.Fatalf("status %d", status)
				}
			} else if status, _ := absolute(t, p.URL(), "http://rebind.example/"); status != 200 {
				t.Fatalf("status %d", status)
			}
			n, dials := f.calls()
			port := map[string]string{"connect": "443", "absolute": "80"}[form]
			if n != 1 || len(dials) != 1 || dials[0] != publicV4.String()+":"+port {
				t.Fatalf("resolves %d dials %v", n, dials)
			}
		})
	}
}

func TestProxyRefusesOtherPortsAndMethods(t *testing.T) {
	f := &fakeNet{target: echoServer(t)}
	p, stats := newTestProxy(t, f, nil, 48)
	for _, target := range []string{"example.com:80", "example.com:8443", "example.com:22", "example.com"} {
		if status, c := connect(t, p.URL(), target); status != 403 && status != 400 {
			c.Close()
			t.Fatalf("CONNECT %s: %d", target, status)
		}
	}
	for _, u := range []string{"http://example.com:8080/", "http://example.com:443/", "https://example.com/"} {
		if status, _ := absolute(t, p.URL(), u); status != 403 {
			t.Fatalf("GET %s: %d", u, status)
		}
	}
	c, _ := net.Dial("tcp4", strings.TrimPrefix(p.URL(), "http://"))
	fmt.Fprint(c, "TRACE http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	c.Close()
	if err != nil || resp.StatusCode != 405 {
		t.Fatalf("TRACE: %v", err)
	}
	if _, dials := f.calls(); len(dials) != 0 || stats.RefusedPort.Load() < 6 {
		t.Fatalf("dials %v refused ports %d", dials, stats.RefusedPort.Load())
	}
}

func TestProxyUsesUpstreamWithCheckedAddress(t *testing.T) {
	var mu sync.Mutex
	var heads []string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "via upstream") }))
	defer origin.Close()
	upstream, _ := net.Listen("tcp4", "127.0.0.1:0")
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				mu.Lock()
				heads = append(heads, req.Method+" "+req.RequestURI+" "+req.Header.Get("Proxy-Authorization"))
				mu.Unlock()
				o, err := net.Dial("tcp4", origin.Listener.Addr().String())
				if err != nil {
					return
				}
				defer o.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go io.Copy(o, br)
				io.Copy(c, o)
			}()
		}
	}()
	f := &fakeNet{}
	auth := "Basic dXNlcjpwYXNz"
	u := &Upstream{Addr: netip.MustParseAddrPort(upstream.Addr().String()), Authorization: auth}
	p, _ := newTestProxy(t, f, u, 48)
	p.dial = (&net.Dialer{}).DialContext // only the upstream is dialed
	status, c := connect(t, p.URL(), "example.com:443")
	c.Close()
	if status != 200 {
		t.Fatalf("CONNECT through upstream: %d", status)
	}
	if status, body := absolute(t, p.URL(), "http://example.com/"); status != 200 || body != "via upstream" {
		t.Fatalf("GET through upstream: %d %q", status, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(heads) != 2 || heads[0] != "CONNECT "+publicV4.String()+":443 "+auth || heads[1] != "CONNECT "+publicV4.String()+":80 "+auth {
		t.Fatalf("upstream saw %v", heads)
	}
}

// fakeUpstream is the operator's proxy: it records each CONNECT's target and
// Proxy-Authorization and answers with reply(n) for the n-th one (from 1),
// an echo tunnel after a 200. A reply of "" never answers.
type fakeUpstream struct {
	ln    net.Listener
	mu    sync.Mutex
	heads []string
	reply func(n int) string
}

func newFakeUpstream(t *testing.T, reply func(n int) string) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &fakeUpstream{ln: ln, reply: reply}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go u.serve(c)
		}
	}()
	return u
}

func (u *fakeUpstream) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	u.mu.Lock()
	u.heads = append(u.heads, req.Method+" "+req.RequestURI+" "+req.Header.Get("Proxy-Authorization"))
	answer := u.reply(len(u.heads))
	u.mu.Unlock()
	if answer == "" {
		io.Copy(io.Discard, br) // until the egress proxy gives up
		return
	}
	io.WriteString(c, answer)
	if strings.HasPrefix(answer, "HTTP/1.1 200 ") {
		io.Copy(c, br)
	}
}

func (u *fakeUpstream) seen() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.heads...)
}

func (u *fakeUpstream) upstream(auth string) *Upstream {
	return &Upstream{Addr: netip.MustParseAddrPort(u.ln.Addr().String()), Authorization: auth}
}

func statusReply(status int) func(int) string {
	return func(int) string {
		return "HTTP/1.1 " + strconv.Itoa(status) + " " + http.StatusText(status) + "\r\nContent-Length: 0\r\n\r\n"
	}
}

// A refused tunnel keeps the upstream's answer as a proxy class, the first
// one only, and the page still sees 502.
func TestProxyKeepsTheUpstreamRefusalClass(t *testing.T) {
	for status, class := range map[int]string{407: proxyAuth, 402: proxyQuota, 429: proxyBusy, 403: proxyRefused, 502: proxyExit, 500: proxyExit, 404: proxyExit} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			up := newFakeUpstream(t, statusReply(status))
			p, _ := newTestProxy(t, &fakeNet{}, up.upstream("Basic c3ludGhldGlj"), jobTunnels)
			p.dial = (&net.Dialer{}).DialContext
			if p.Failure() != "" {
				t.Fatal("a failure before any tunnel")
			}
			if got, c := connect(t, p.URL(), "example.com:443"); got != http.StatusBadGateway {
				c.Close()
				t.Fatalf("CONNECT: %d", got)
			}
			if got, _ := absolute(t, p.URL(), "http://example.com/"); got != http.StatusBadGateway {
				t.Fatalf("GET: %d", got)
			}
			if p.Failure() != class {
				t.Fatalf("class %q", p.Failure())
			}
		})
	}
	// The first failure stays: a 403 after a 407 is still proxy_auth.
	up := newFakeUpstream(t, func(n int) string {
		if n == 1 {
			return statusReply(407)(n)
		}
		return statusReply(403)(n)
	})
	p, _ := newTestProxy(t, &fakeNet{}, up.upstream("Basic c3ludGhldGlj"), jobTunnels)
	p.dial = (&net.Dialer{}).DialContext
	for range 2 {
		if _, c := connect(t, p.URL(), "example.com:443"); c != nil {
			c.Close()
		}
	}
	if p.Failure() != proxyAuth {
		t.Fatalf("class %q", p.Failure())
	}
}

// Only a tunnel to the page's own host records a class: a refused redirect
// target or third-party subresource is not the page's refusal.
func TestProxyKeepsOnlyThePageHostsClass(t *testing.T) {
	up := newFakeUpstream(t, statusReply(http.StatusForbidden))
	p, _ := newTestProxy(t, &fakeNet{}, up.upstream("Basic c3ludGhldGlj"), jobTunnels)
	p.dial = (&net.Dialer{}).DialContext
	for _, target := range []string{"cdn.example.net:443", "www.example.com:443", publicV4.String() + ":443"} {
		if got, c := connect(t, p.URL(), target); got != http.StatusBadGateway {
			c.Close()
			t.Fatalf("CONNECT %s: %d", target, got)
		}
	}
	if got, _ := absolute(t, p.URL(), "http://b.example.org/"); got != http.StatusBadGateway {
		t.Fatalf("GET: %d", got)
	}
	if p.Failure() != "" || len(up.seen()) != 4 {
		t.Fatalf("another host's refusal recorded %q", p.Failure())
	}
	// The page's host, as Chrome may spell it.
	if got, c := connect(t, p.URL(), "EXAMPLE.com.:443"); got != http.StatusBadGateway {
		c.Close()
		t.Fatalf("CONNECT: %d", got)
	}
	if p.Failure() != proxyRefused {
		t.Fatalf("class %q", p.Failure())
	}
	// The shared proxy has no page and no upstream.
	shared, err := newEgressProxy(testGuard{}, (&fakeNet{}).resolve, nil, "", jobTunnels, &ProxyStats{})
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Close()
	if shared.page != "" {
		t.Fatal("the shared proxy has a page")
	}
}

func TestProxyUpstreamThatIsNoProxy(t *testing.T) {
	// No TCP to the proxy at all.
	closed, _ := net.Listen("tcp4", "127.0.0.1:0")
	gone := netip.MustParseAddrPort(closed.Addr().String())
	closed.Close()
	p, _ := newTestProxy(t, &fakeNet{}, &Upstream{Addr: gone}, jobTunnels)
	p.dial = (&net.Dialer{}).DialContext
	if got, c := connect(t, p.URL(), "example.com:443"); got != http.StatusBadGateway {
		c.Close()
		t.Fatalf("CONNECT: %d", got)
	}
	if p.Failure() != proxyUnreachable {
		t.Fatalf("unreachable: %q", p.Failure())
	}
	// A reply that is not HTTP, and bytes after the 200 that cannot be the
	// target's.
	for name, answer := range map[string]string{"not-http": "SSH-2.0-OpenSSH\r\n\r\n", "early-bytes": "HTTP/1.1 200 OK\r\n\r\nhello"} {
		t.Run(name, func(t *testing.T) {
			up := newFakeUpstream(t, func(int) string { return answer })
			p, _ := newTestProxy(t, &fakeNet{}, up.upstream(""), jobTunnels)
			p.dial = (&net.Dialer{}).DialContext
			if got, c := connect(t, p.URL(), "example.com:443"); got != http.StatusBadGateway {
				c.Close()
				t.Fatalf("CONNECT: %d", got)
			}
			if p.Failure() != proxyUnreachable {
				t.Fatalf("class %q", p.Failure())
			}
			if heads := up.seen(); len(heads) != 1 || heads[0] != "CONNECT "+publicV4.String()+":443 " {
				t.Fatalf("upstream saw %v", heads)
			}
		})
	}
}

// A proxy that took the connection but never answered the CONNECT in time
// failed at its exit.
func TestProxyUpstreamThatNeverAnswers(t *testing.T) {
	up := newFakeUpstream(t, func(int) string { return "" })
	p, _ := newTestProxy(t, &fakeNet{}, up.upstream("Basic c3ludGhldGlj"), jobTunnels)
	p.dial = (&net.Dialer{}).DialContext
	p.dialLimit = 300 * time.Millisecond
	if got, c := connect(t, p.URL(), "example.com:443"); got != http.StatusBadGateway {
		c.Close()
		t.Fatalf("CONNECT: %d", got)
	}
	if p.Failure() != proxyExit {
		t.Fatalf("class %q", p.Failure())
	}
}

// Closing a page's proxy ends a CONNECT its upstream never answered at once,
// and records nothing: the page is over.
func TestProxyCloseEndsAnUnansweredTunnel(t *testing.T) {
	up := newFakeUpstream(t, func(int) string { return "" })
	p, err := newEgressProxy(testGuard{}, (&fakeNet{}).resolve, up.upstream("Basic c3ludGhldGlj"), "example.com", jobTunnels, &ProxyStats{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp4", strings.TrimPrefix(p.URL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	for deadline := time.Now().Add(5 * time.Second); len(up.seen()) == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the CONNECT never reached the upstream")
		}
	}
	started := time.Now()
	p.Close()
	if took := time.Since(started); took > 2*time.Second {
		t.Fatalf("Close waited %v for the upstream", took)
	}
	if p.Failure() != "" {
		t.Fatalf("a closed page recorded %q", p.Failure())
	}
	if _, err := net.DialTimeout("tcp4", strings.TrimPrefix(p.URL(), "http://"), time.Second); err == nil {
		t.Fatal("the closed proxy still accepts")
	}
}

// Through an upstream only IPv4 is dialled, as proxy exits are IPv4; every
// answer still passes the guard.
func TestProxyUpstreamIsIPv4Only(t *testing.T) {
	up := newFakeUpstream(t, statusReply(200))
	answers := map[string][]netip.Addr{"v6.example.com": {publicV6}, "both.example.com": {publicV6, publicV4}}
	f := &fakeNet{answers: func(host string, _ int) []netip.Addr { return answers[host] }}
	p, _ := newTestProxy(t, f, up.upstream("Basic c3ludGhldGlj"), jobTunnels)
	p.dial = (&net.Dialer{}).DialContext
	if got, c := connect(t, p.URL(), "v6.example.com:443"); got != http.StatusBadGateway {
		c.Close()
		t.Fatalf("IPv6-only host: %d", got)
	}
	if got, c := connect(t, p.URL(), "["+publicV6.String()+"]:443"); got != http.StatusBadGateway {
		c.Close()
		t.Fatalf("IPv6 literal: %d", got)
	}
	got, c := connect(t, p.URL(), "both.example.com:443")
	c.Close()
	if got != 200 {
		t.Fatalf("dual-stack host: %d", got)
	}
	if heads := up.seen(); len(heads) != 1 || heads[0] != "CONNECT "+publicV4.String()+":443 Basic c3ludGhldGlj" {
		t.Fatalf("upstream saw %v", heads)
	}
	if p.Failure() != "" {
		t.Fatalf("an unreachable IPv6 host is not the proxy's failure: %q", p.Failure())
	}
}

func TestUpstreamRulesAndRedaction(t *testing.T) {
	for addr, ok := range map[string]bool{"104.16.0.10:1080": true, "127.0.0.1:3128": true, "[2001:4860::1]:80": true, "10.0.0.2:3128": true,
		"169.254.169.254:80": false, "[fe80::1]:80": false, "0.0.0.0:80": false, "224.0.0.1:80": false, "255.255.255.255:80": false, "104.16.0.10:0": false} {
		u := Upstream{Addr: netip.MustParseAddrPort(addr), Authorization: "Basic c3ludGhldGlj"}
		if u.valid() != ok {
			t.Errorf("%s: %v", addr, !ok)
		}
		if _, err := newEgressProxy(testGuard{}, nil, &u, "example.com", jobTunnels, &ProxyStats{}); (err == nil) != ok {
			t.Errorf("%s: proxy %v", addr, err)
		}
	}
	for _, auth := range []string{"Basic a\r\nX-Injected: 1", "Basic \x7f", strings.Repeat("a", maxUpstreamAuthorization+1)} {
		if (Upstream{Addr: netip.MustParseAddrPort("104.16.0.10:1080"), Authorization: auth}).valid() {
			t.Errorf("authorization %q accepted", auth[:min(len(auth), 16)])
		}
	}
	if (Upstream{}).valid() {
		t.Error("an empty upstream")
	}
	u := &Upstream{Addr: netip.MustParseAddrPort("104.16.0.10:1080"), Authorization: "Basic synthetic-session-secret"}
	req := FetchRequest{URL: "https://example.com/", Wait: "load", TimeoutMS: 5000, Upstream: u}
	for _, out := range []string{fmt.Sprint(u), fmt.Sprintf("%v %+v %#v", *u, *u, *u), fmt.Sprintf("%v %+v %#v", req, req, req)} {
		if strings.Contains(out, "synthetic-session-secret") || strings.Contains(out, "104.16.0.10") {
			t.Fatalf("an upstream formats its values: %s", out)
		}
	}
	if raw, _ := json.Marshal(helperFetch{FetchRequest: req}); strings.Contains(string(raw), "synthetic") || strings.Contains(string(raw), "104.16") || strings.Contains(string(raw), "egress_proxy") {
		t.Fatalf("the helper request carries the upstream: %s", raw)
	}
	if req.validate() != nil {
		t.Fatal("a proxied request is invalid")
	}
	req.Upstream = &Upstream{Addr: netip.MustParseAddrPort("169.254.169.254:80")}
	if req.validate() == nil {
		t.Fatal("a link-local upstream passed")
	}
}

func TestProxyTunnelCap(t *testing.T) {
	f := &fakeNet{target: echoServer(t)}
	capacity := 1
	p, _ := newTestProxy(t, f, nil, 32*capacity+16)
	var open []net.Conn
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	for i := 0; i < 32*capacity+16; i++ {
		status, c := connect(t, p.URL(), "example.com:443")
		if status != 200 {
			t.Fatalf("tunnel %d refused: %d", i, status)
		}
		open = append(open, c)
	}
	if status, c := connect(t, p.URL(), "example.com:443"); status != 503 {
		c.Close()
		t.Fatalf("tunnel over the cap: %d", status)
	}
	open[0].Close()
	open = open[1:]
	deadline := time.Now().Add(5 * time.Second)
	for {
		status, c := connect(t, p.URL(), "example.com:443")
		if status == 200 {
			open = append(open, c)
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("a closed tunnel never freed its slot")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Over the cap, the 503 follows the request head. Answering first and closing
// with the head unread resets the connection, and on Windows the reset
// discards the 503 before the client reads it.
func TestProxyOverCapAnswersAfterTheHead(t *testing.T) {
	f := &fakeNet{target: echoServer(t)}
	p, _ := newTestProxy(t, f, nil, 1)
	_, held := connect(t, p.URL(), "example.com:443")
	defer held.Close()
	c, err := net.Dial("tcp4", strings.TrimPrefix(p.URL(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("answered before the request head: %d %v", n, err)
	}
	fmt.Fprintf(c, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("over-cap answer: %v", err)
	}
	if n, err := c.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("over-cap connection not closed cleanly: %d %v", n, err)
	}
}

func TestDenyListenerAnswers403WithoutNetworking(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	stats := &ProxyStats{}
	d, err := newDenyListener(stats)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if status, c := connect(t, d.URL(), "update.googleapis.com:443"); status != 403 {
		t.Fatalf("CONNECT: %d", status)
	} else {
		c.Close()
	}
	if status, _ := absolute(t, d.URL(), "http://clients2.google.com/time/1/current"); status != 403 {
		t.Fatalf("GET: %d", status)
	}
	if stats.BackgroundDenied.Load() != 2 {
		t.Fatalf("denied counter %d", stats.BackgroundDenied.Load())
	}
	if strings.Contains(buf.String(), "google") {
		t.Fatal("a host reached a log")
	}
}

func TestProxyHostRules(t *testing.T) {
	for host, ok := range map[string]bool{"example.com": true, "EXAMPLE.com.": true, "a-b.example.co.uk": true, "xn--bcher-kva.example": true,
		"example": false, "example.123": false, "a..b": false, "-a.com": false, "a-.com": false, "printer.local": false, "x.home.arpa": false,
		strings.Repeat("a", 64) + ".com": false, "a.b.lan": false, "ünicode.com": false} {
		if _, _, got := proxyHost(host); got != ok {
			t.Errorf("%q: got %v", host, got)
		}
	}
	if _, addr, ok := proxyHost("[2001:db8::1]"); !ok || addr != netip.MustParseAddr("2001:db8::1") {
		t.Fatal("IPv6 literal")
	}
	if _, _, ok := proxyHost("[fe80::1%en0]"); ok {
		t.Fatal("zoned literal accepted")
	}
}
