package webruntime

import (
	"bufio"
	"bytes"
	"context"
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

func newTestProxy(t *testing.T, f *fakeNet, upstream *url.URL, tunnels int) (*egressProxy, *ProxyStats) {
	t.Helper()
	stats := &ProxyStats{}
	p, err := newEgressProxy(testGuard{}, f.resolve, upstream, "", tunnels, stats)
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
	u := &url.URL{Scheme: "http", Host: upstream.Addr().String(), User: url.UserPassword("user", "pass")}
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
	auth := "Basic dXNlcjpwYXNz"
	if len(heads) != 2 || heads[0] != "CONNECT "+publicV4.String()+":443 "+auth || heads[1] != "CONNECT "+publicV4.String()+":80 "+auth {
		t.Fatalf("upstream saw %v", heads)
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
