package webruntime

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
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
	// Over-cap 503 answers in flight at once; past it a connection is closed
	// unanswered. Each lasts at most proxyRefuseLimit per direction.
	proxyRefusals    = 16
	proxyRefuseLimit = time.Second
	// jobTunnels caps one proxied page's own egress proxy.
	jobTunnels = 48
	// maxUpstreamAuthorization bounds a job's Proxy-Authorization, as the
	// prover does.
	maxUpstreamAuthorization = 4096
)

// Upstream is one proxied page's way out: the operator's proxy at the address
// the node checked, which nothing resolves again, and the job's
// Proxy-Authorization (empty for a proxy without credentials). String and
// GoString redact it.
type Upstream struct {
	Addr          netip.AddrPort
	Authorization string
}

func (Upstream) String() string   { return "web proxy upstream [redacted]" }
func (Upstream) GoString() string { return "webruntime.Upstream{}" }

// valid is the prover's proxy rule (prover/src/dial.rs): an IP literal that
// is not link-local, unspecified, multicast or broadcast, a port, and a
// Proxy-Authorization of printable ASCII up to 4096 bytes.
func (u Upstream) valid() bool {
	a := u.Addr.Addr().Unmap()
	if !a.IsValid() || a.Zone() != "" || u.Addr.Port() == 0 || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() ||
		a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || len(u.Authorization) > maxUpstreamAuthorization {
		return false
	}
	for i := 0; i < len(u.Authorization); i++ {
		if u.Authorization[i] < 0x20 || u.Authorization[i] > 0x7e {
			return false
		}
	}
	return true
}

// The proxy classes of an upstream tunnel that would not open, as the prover
// names them (prover/src/relay/node.rs proxy_class); the worker maps them to
// the job's code.
const (
	proxyUnreachable = "proxy_unreachable" // no TCP to the proxy, or no CONNECT reply as HTTP
	proxyAuth        = "proxy_auth"        // 407
	proxyQuota       = "proxy_quota"       // 402
	proxyBusy        = "proxy_busy"        // 429
	proxyRefused     = "proxy_refused"     // 403
	proxyExit        = "proxy_exit"        // 502 or any other status, or no reply in time
)

// upstreamClass is the proxy class of a CONNECT reply status other than 200.
func upstreamClass(status int) string {
	switch status {
	case http.StatusProxyAuthRequired:
		return proxyAuth
	case http.StatusPaymentRequired:
		return proxyQuota
	case http.StatusTooManyRequests:
		return proxyBusy
	case http.StatusForbidden:
		return proxyRefused
	}
	return proxyExit
}

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

// egressProxy is the loopback HTTP proxy a per-job browser context uses: the
// helper's shared one for direct pages, which has no upstream, or a proxied
// page's own, which reaches every checked address through that job's
// upstream.
type egressProxy struct {
	ln      net.Listener
	guard   EgressGuard
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
	// dialLimit bounds a dial, and through an upstream its CONNECT reply.
	dialLimit time.Duration
	upstream  *Upstream
	slots     chan struct{}
	refusals  chan struct{}
	stats     *ProxyStats
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	// failure is the proxy class of the first upstream tunnel to page that
	// would not open, under mu.
	failure string
	wg      sync.WaitGroup

	// page is a proxied page's own host: only a tunnel to it records a
	// failure, so a refused redirect target or third-party subresource is
	// never reported as the page's.
	page string
}

func defaultResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// newEgressProxy listens on a fresh loopback port. upstream is nil for the
// helper's shared proxy, else the one proxied page's way out, and page that
// page's host.
func newEgressProxy(guard EgressGuard, resolve func(context.Context, string) ([]netip.Addr, error), upstream *Upstream, page string, tunnels int, stats *ProxyStats) (*egressProxy, error) {
	if guard == nil {
		return nil, errors.New("egress guard required")
	}
	if upstream != nil && !upstream.valid() {
		return nil, errors.New("egress proxy upstream invalid")
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
	p := &egressProxy{ln: ln, guard: guard, resolve: resolve, dial: dialer.DialContext, dialLimit: proxyDialLimit, upstream: upstream, page: tunnelHost(page),
		slots: make(chan struct{}, tunnels), refusals: make(chan struct{}, proxyRefusals), stats: stats, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{}}
	p.wg.Add(1)
	go p.serve()
	return p, nil
}

func (p *egressProxy) URL() string { return "http://" + p.ln.Addr().String() }

// Failure is the proxy class of the first upstream tunnel to the page's own
// host that would not open, or "".
func (p *egressProxy) Failure() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failure
}

// tunnelHost is a host as the page's own is compared: lowercase, without a
// trailing dot or IPv6 brackets.
func tunnelHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")), ".")
}

func (p *egressProxy) upstreamFailed(class string) {
	p.mu.Lock()
	if p.failure == "" {
		p.failure = class
	}
	p.mu.Unlock()
}

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
			p.refuse(conn)
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

// refuse answers a connection over the tunnel cap with 503, which Chrome
// retries. The request head is read before the answer: closing a socket that
// still holds unread bytes resets the connection, and the reset can discard
// the 503 before the client reads it (Windows does). Answers run off the
// accept loop, at most proxyRefusals at once and each bounded by
// proxyRefuseLimit; past that a connection is closed unanswered.
func (p *egressProxy) refuse(conn net.Conn) {
	select {
	case p.refusals <- struct{}{}:
	default:
		conn.Close()
		return
	}
	if !p.track(conn, true) {
		<-p.refusals
		conn.Close()
		return
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() { <-p.refusals }()
		defer p.track(conn, false)
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(proxyRefuseLimit))
		_, _ = http.ReadRequest(bufio.NewReader(io.LimitReader(conn, proxyHeadLimit)))
		_ = conn.SetWriteDeadline(time.Now().Add(proxyRefuseLimit))
		_, _ = io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	}()
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
	p.retire()
	p.ln.Close()
	p.wg.Wait()
}

// retire ends the proxy's tunnels but keeps its port: every later connection
// is closed unanswered until Close. A page the helper never answered for may
// still be loading, and while the port stays bound no later page's proxy can
// take it and carry the stale page's connections on another job's session.
func (p *egressProxy) retire() {
	p.cancel()
	p.mu.Lock()
	for conn := range p.conns {
		conn.Close()
	}
	p.mu.Unlock()
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
	own := p.page != "" && tunnelHost(hostport) == p.page
	p.stats.Allowed.Add(1)
	_ = conn.SetReadDeadline(time.Time{})
	if req.Method == http.MethodConnect {
		upstream, err := p.dialChecked(p.ctx, target, own)
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
	p.forward(conn, req, target, own)
}

// check resolves a page-chosen host under the rules: names first (no lookup
// for a refused name), then every address through the guard. It returns the
// address to dial: the first IPv4, else the first IPv6. Through an upstream
// it is IPv4 only, as proxy exits are (the relay's proxied hops pick the
// same way): a host without an IPv4 answer gets 502.
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
	if v6.IsValid() && p.upstream != nil {
		return netip.Addr{}, http.StatusBadGateway
	}
	if v6.IsValid() {
		return v6, 0
	}
	return netip.Addr{}, http.StatusForbidden
}

// dialChecked connects to exactly the checked address: directly, or as the
// CONNECT target of the job's upstream at its checked address, as the core
// relay does. A tunnel to the page's own host (own) that the upstream would
// not open keeps its proxy class (Failure, the first one only); the page
// gets 502 either way. Closing the proxy ends a CONNECT the upstream has not
// answered.
func (p *egressProxy) dialChecked(ctx context.Context, target netip.AddrPort, own bool) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, p.dialLimit)
	defer cancel()
	if p.upstream == nil {
		return p.dial(ctx, "tcp", target.String())
	}
	class := ""
	conn, err := p.dial(ctx, "tcp", p.upstream.Addr.String())
	if err != nil {
		class = proxyUnreachable
	} else {
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		class = p.connect(ctx, conn, target)
		if !stop() && class == "" {
			// The dial limit passed, or the proxy closed, as the reply came.
			class = proxyExit
		}
		if class != "" {
			conn.Close()
		}
	}
	if class != "" {
		// A proxy that is closing records nothing: the page is done.
		if own && !errors.Is(ctx.Err(), context.Canceled) {
			p.upstreamFailed(class)
		}
		return nil, errors.New("upstream proxy refused the tunnel")
	}
	return conn, nil
}

// connect asks the upstream on conn for a tunnel to target and returns ""
// once it is open, else the proxy class (as the prover's dial.rs tells them
// apart).
func (p *egressProxy) connect(ctx context.Context, conn net.Conn, target netip.AddrPort) string {
	head := "CONNECT " + target.String() + " HTTP/1.1\r\nHost: " + target.String() + "\r\n"
	if p.upstream.Authorization != "" {
		head += "Proxy-Authorization: " + p.upstream.Authorization + "\r\n"
	}
	if _, err := io.WriteString(conn, head+"\r\n"); err != nil {
		return proxyUnreachable
	}
	br := bufio.NewReader(io.LimitReader(conn, proxyHeadLimit))
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	switch {
	case err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded):
		// The proxy took the connection but never answered: its exit.
		return proxyExit
	case err != nil:
		return proxyUnreachable
	case resp.StatusCode != http.StatusOK:
		return upstreamClass(resp.StatusCode)
	case br.Buffered() > 0:
		// The target speaks only after the browser's ClientHello.
		return proxyUnreachable
	}
	return ""
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
func (p *egressProxy) forward(conn net.Conn, req *http.Request, target netip.AddrPort, own bool) {
	ctx, cancel := context.WithCancel(p.ctx)
	defer cancel()
	out := req.Clone(ctx)
	out.RequestURI = ""
	stripHop(out.Header)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 1 << 20,
		ResponseHeaderTimeout: proxyTunnelIdle,
		DialContext:           func(ctx context.Context, _, _ string) (net.Conn, error) { return p.dialChecked(ctx, target, own) }}
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
