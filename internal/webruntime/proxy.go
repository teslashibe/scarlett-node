package webruntime

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// EgressGuard decides which resolved addresses a page may reach. The node
// injects the core web egress guard (worker.WebEgress), which keeps every
// web hop on the public internet.
type EgressGuard interface {
	Allowed(ctx context.Context, addr netip.Addr) bool
}

// The ports a page may reach: 443 through CONNECT, 80 as absolute-form
// plain HTTP. Tests widen them to loopback fixture listeners.
var (
	connectPorts = map[string]bool{"443": true}
	forwardPorts = map[string]bool{"80": true}
)

// Reserved names that never reach the public internet (core §1), the name
// itself or any subdomain. They are refused before any DNS lookup, which also
// keeps .local (mDNS, the macOS Local Network trigger) off the LAN.
var reservedSuffixes = []string{"localhost", "local", "internal", "home.arpa", "lan", "localdomain", "onion", "invalid", "test"}

const (
	proxyHeadLimit    = 64 << 10
	proxyTunnelIdle   = 60 * time.Second
	proxyTunnelBytes  = 128 << 20
	proxyResolveLimit = 5 * time.Second
	proxyDialLimit    = 10 * time.Second
	denyHeadLimit     = 8 << 10
	denyReadLimit     = 5 * time.Second
)

// ProxyStats are the proxy's only output besides traffic: counters. Hosts
// are never recorded.
type ProxyStats struct {
	Allowed, RefusedName, RefusedAddress, RefusedPort, BackgroundDenied atomic.Uint64
}

// proxyHost applies the core §1.1 host rules to a page-chosen name: ASCII,
// 1–253 bytes, at least two labels of [a-z0-9-] (1–63 bytes, no leading or
// trailing '-'), a letter in the last label, and no reserved suffix. An IP
// literal is returned as an address instead and is never resolved.
func proxyHost(raw string) (string, netip.Addr, bool) {
	if addr, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")); err == nil {
		return "", addr, addr.Zone() == ""
	}
	host := strings.TrimSuffix(strings.ToLower(raw), ".")
	if host == "" || len(host) > 253 {
		return "", netip.Addr{}, false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", netip.Addr{}, false
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", netip.Addr{}, false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", netip.Addr{}, false
			}
		}
	}
	if !strings.ContainsFunc(labels[len(labels)-1], func(r rune) bool { return r >= 'a' && r <= 'z' }) {
		return "", netip.Addr{}, false
	}
	for _, suffix := range reservedSuffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return "", netip.Addr{}, false
		}
	}
	return host, netip.Addr{}, true
}

// egressProxy is the loopback HTTP proxy every per-job browser context uses.
type egressProxy struct {
	ln           net.Listener
	guard        EgressGuard
	resolve      func(ctx context.Context, host string) ([]netip.Addr, error)
	dial         func(ctx context.Context, network, address string) (net.Conn, error)
	upstream     *url.URL
	upstreamAuth string
	slots        chan struct{}
	stats        *ProxyStats
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.Mutex
	conns        map[net.Conn]struct{}
	wg           sync.WaitGroup
}

func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func newEgressProxy(guard EgressGuard, resolve func(context.Context, string) ([]netip.Addr, error), upstream *url.URL, upstreamAuth string, tunnels int, stats *ProxyStats) (*egressProxy, error) {
	if guard == nil {
		return nil, errors.New("egress guard required")
	}
	if resolve == nil {
		resolve = defaultResolver
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	dialer := &net.Dialer{Timeout: proxyDialLimit}
	p := &egressProxy{ln: ln, guard: guard, resolve: resolve, dial: dialer.DialContext, upstream: upstream, upstreamAuth: upstreamAuth,
		slots: make(chan struct{}, tunnels), stats: stats, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}}
	if upstream != nil && upstream.User != nil && upstreamAuth == "" {
		password, _ := upstream.User.Password()
		p.upstreamAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(upstream.User.Username()+":"+password))
	}
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

func (p *egressProxy) URL() string { return "http://" + p.ln.Addr().String() }

func (p *egressProxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		select {
		case p.slots <- struct{}{}:
		default:
			// Over the tunnel cap: Chrome retries the request.
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			conn.Close()
			continue
		}
		if !p.track(conn, true) {
			<-p.slots
			conn.Close()
			continue
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { <-p.slots }()
			defer p.track(conn, false)
			defer conn.Close()
			p.handle(conn)
		}()
	}
}

func (p *egressProxy) track(conn net.Conn, add bool) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if add {
		if p.ctx.Err() != nil {
			return false
		}
		p.conns[conn] = struct{}{}
	} else {
		delete(p.conns, conn)
	}
	return true
}

func (p *egressProxy) Close() {
	p.cancel()
	p.ln.Close()
	p.mu.Lock()
	for conn := range p.conns {
		conn.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
}

func reply(conn net.Conn, status int) {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "HTTP/1.1 "+strconv.Itoa(status)+" "+http.StatusText(status)+"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

var forwardMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true, "OPTIONS": true, "PATCH": true}

func (p *egressProxy) handle(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	limited := &io.LimitedReader{R: conn, N: proxyHeadLimit}
	br := bufio.NewReader(limited)
	req, err := http.ReadRequest(br)
	if err != nil {
		reply(conn, http.StatusBadRequest)
		return
	}
	limited.N = proxyTunnelBytes // the head was read; a request body may follow
	var hostport, port string
	switch {
	case req.Method == http.MethodConnect:
		hostport = req.RequestURI
		var host string
		if host, port, err = net.SplitHostPort(hostport); err != nil || !connectPorts[port] {
			p.stats.RefusedPort.Add(1)
			reply(conn, http.StatusForbidden)
			return
		}
		hostport = host
	case forwardMethods[req.Method] && req.URL.IsAbs() && req.URL.Scheme == "http" && req.URL.Host != "":
		if port = req.URL.Port(); port == "" {
			port = "80"
		}
		if !forwardPorts[port] {
			p.stats.RefusedPort.Add(1)
			reply(conn, http.StatusForbidden)
			return
		}
		hostport = req.URL.Hostname()
	case forwardMethods[req.Method]:
		p.stats.RefusedPort.Add(1)
		reply(conn, http.StatusForbidden)
		return
	default:
		reply(conn, http.StatusMethodNotAllowed)
		return
	}
	addr, status := p.check(hostport)
	if status != 0 {
		reply(conn, status)
		return
	}
	portNum, _ := strconv.Atoi(port)
	target := netip.AddrPortFrom(addr, uint16(portNum))
	p.stats.Allowed.Add(1)
	_ = conn.SetReadDeadline(time.Time{})
	if req.Method == http.MethodConnect {
		upstream, err := p.dialChecked(p.ctx, target)
		if err != nil {
			reply(conn, http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		// Bytes the client sent after the head belong to the tunnel.
		if n := br.Buffered(); n > 0 {
			early, _ := br.Peek(n)
			if _, err = upstream.Write(early); err != nil {
				return
			}
		}
		splice(conn, upstream)
		return
	}
	p.forward(conn, req, target)
}

// check resolves a page-chosen host under the rules: names first (no lookup
// for a refused name), then every address through the guard. It returns the
// address to dial: the first IPv4, else the first IPv6.
func (p *egressProxy) check(host string) (netip.Addr, int) {
	name, literal, ok := proxyHost(host)
	if !ok {
		p.stats.RefusedName.Add(1)
		return netip.Addr{}, http.StatusForbidden
	}
	addrs := []netip.Addr{literal}
	if name != "" {
		ctx, cancel := context.WithTimeout(p.ctx, proxyResolveLimit)
		resolved, err := p.resolve(ctx, name)
		cancel()
		if err != nil || len(resolved) == 0 {
			return netip.Addr{}, http.StatusBadGateway
		}
		addrs = resolved
	}
	var v4, v6 netip.Addr
	for _, a := range addrs {
		if !p.guard.Allowed(p.ctx, a) {
			p.stats.RefusedAddress.Add(1)
			return netip.Addr{}, http.StatusForbidden
		}
		a = a.Unmap()
		if a.Is4() && !v4.IsValid() {
			v4 = a
		} else if a.Is6() && !v6.IsValid() {
			v6 = a
		}
	}
	if v4.IsValid() {
		return v4, 0
	}
	if v6.IsValid() {
		return v6, 0
	}
	return netip.Addr{}, http.StatusForbidden
}

// dialChecked connects to exactly the checked address: directly, or as the
// CONNECT target of the configured upstream proxy, as the core relay does.
func (p *egressProxy) dialChecked(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, proxyDialLimit)
	defer cancel()
	if p.upstream == nil {
		return p.dial(ctx, "tcp", target.String())
	}
	conn, err := p.dial(ctx, "tcp", p.upstream.Host)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(proxyDialLimit))
	head := "CONNECT " + target.String() + " HTTP/1.1\r\nHost: " + target.String() + "\r\n"
	if p.upstreamAuth != "" {
		head += "Proxy-Authorization: " + p.upstreamAuth + "\r\n"
	}
	if _, err = io.WriteString(conn, head+"\r\n"); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK || br.Buffered() > 0 {
		conn.Close()
		return nil, errors.New("upstream proxy refused the tunnel")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func stripHop(h http.Header) {
	for _, field := range strings.Split(h.Get("Connection"), ",") {
		if field = strings.TrimSpace(field); field != "" {
			h.Del(field)
		}
	}
	for _, name := range hopHeaders {
		h.Del(name)
	}
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "proxy-") {
			delete(h, name)
		}
	}
}

// forward sends an absolute-form plain-HTTP request in origin form to the
// checked address (never re-resolving the name) and streams the response.
func (p *egressProxy) forward(conn net.Conn, req *http.Request, target netip.AddrPort) {
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	out := req.Clone(ctx)
	out.RequestURI = ""
	stripHop(out.Header)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 1 << 20,
		ResponseHeaderTimeout: proxyTunnelIdle,
		DialContext:           func(ctx context.Context, _, _ string) (net.Conn, error) { return p.dialChecked(ctx, target) }}
	defer transport.CloseIdleConnections()
	resp, err := transport.RoundTrip(out)
	if err != nil {
		reply(conn, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	stripHop(resp.Header)
	resp.Close = true
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, proxyTunnelBytes), resp.Body}
	_ = conn.SetWriteDeadline(time.Now().Add(proxyTunnelIdle))
	_ = resp.Write(&idleWriter{conn: conn})
}

type idleWriter struct{ conn net.Conn }

func (w *idleWriter) Write(b []byte) (int, error) {
	_ = w.conn.SetWriteDeadline(time.Now().Add(proxyTunnelIdle))
	return w.conn.Write(b)
}

// splice copies both ways until either side closes, a direction is idle for
// 60 s, or the tunnel has carried 128 MiB in total.
func splice(a, b net.Conn) {
	var total atomic.Int64
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32<<10)
		for {
			_ = src.SetReadDeadline(time.Now().Add(proxyTunnelIdle))
			n, err := src.Read(buf)
			if n > 0 {
				if total.Add(int64(n)) > proxyTunnelBytes {
					return
				}
				_ = dst.SetWriteDeadline(time.Now().Add(proxyTunnelIdle))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}

// denyListener is the browser-level proxy: Chrome's own update, time, GCM
// and account traffic gets 403 and goes nowhere. It never dials or resolves.
type denyListener struct {
	ln    net.Listener
	stats *ProxyStats
	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	shut  bool
}

func newDenyListener(stats *ProxyStats) (*denyListener, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d := &denyListener{ln: ln, stats: stats, conns: map[net.Conn]struct{}{}}
	d.wg.Add(1)
	go d.serve()
	return d, nil
}

func (d *denyListener) URL() string { return "http://" + d.ln.Addr().String() }

func (d *denyListener) serve() {
	defer d.wg.Done()
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			return
		}
		d.mu.Lock()
		if d.shut {
			d.mu.Unlock()
			conn.Close()
			continue
		}
		d.conns[conn] = struct{}{}
		d.mu.Unlock()
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			defer func() { d.mu.Lock(); delete(d.conns, conn); d.mu.Unlock(); conn.Close() }()
			_ = conn.SetReadDeadline(time.Now().Add(denyReadLimit))
			_, _ = http.ReadRequest(bufio.NewReader(io.LimitReader(conn, denyHeadLimit)))
			d.stats.BackgroundDenied.Add(1)
			reply(conn, http.StatusForbidden)
		}()
	}
}

func (d *denyListener) Close() {
	d.ln.Close()
	d.mu.Lock()
	d.shut = true
	for conn := range d.conns {
		conn.Close()
	}
	d.mu.Unlock()
	d.wg.Wait()
}
