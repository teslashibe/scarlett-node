package worker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"sync"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// A web job leaves either from this node's own network or through the
// operator's proxy: on a node whose egress is "proxy" every job does, on a
// "both" node the jobs whose lease says web_egress "proxy". A proxied job
// never falls back to the node's own network when the proxy fails.
//
// The proxy's host is resolved once per job and checked like a target (an
// http proxy may be on loopback or the LAN, never link-local), and the
// helper and the browser tier dial the checked address, so no second DNS
// answer can redirect the proxy connection. A Webshare job uses its own
// sticky session, so every connection of the job leaves from one exit, and
// learns that exit with one probe through the session (webexit.go).

// UsesProxy reports whether lease l's page goes through this node's proxy.
func UsesProxy(c config.Config, l coordinator.Lease) bool {
	switch c.WebEgress() {
	case "proxy":
		return true
	case "both":
		return l.WebEgress == "proxy"
	}
	return false
}

// ProxyUpstream is one proxied web job's way out: the proxy's checked
// address, which nothing resolves again, and the job's Proxy-Authorization
// (empty for an http proxy without credentials). The browser tier's egress
// proxy tunnels the job's page through it. String and GoString redact it.
type ProxyUpstream struct {
	Addr          netip.AddrPort
	Authorization string
}

func (ProxyUpstream) String() string   { return "web proxy upstream [redacted]" }
func (ProxyUpstream) GoString() string { return "worker.ProxyUpstream{}" }

// The proxy classes of a failed tunnel (prover/src/relay/node.rs
// proxy_class) and what each does to the job and the node.
const (
	proxyUnreachable = "proxy_unreachable" // no TCP to the proxy, or no CONNECT reply as HTTP: web_proxy_failed
	proxyAuth        = "proxy_auth"        // 407: web_proxy_failed
	proxyQuota       = "proxy_quota"       // 402, the plan is out of bandwidth: web_proxy_failed
	proxyBusy        = "proxy_busy"        // 429: web_proxy_failed
	proxyRefused     = "proxy_refused"     // 403 for this target: web_proxy_refused
	proxyExit        = "proxy_exit"        // 502 or any other status, or no reply in time: web_connect_failed
)

// proxyClass is class when it names a proxy failure, else "".
func proxyClass(class string) string {
	switch class {
	case proxyUnreachable, proxyAuth, proxyQuota, proxyBusy, proxyRefused, proxyExit:
		return class
	}
	return ""
}

// ValidProxyClass reports whether class is one a proxied job can fail with.
func ValidProxyClass(class string) bool { return proxyClass(class) != "" }

// proxyCode is a proxy class's job code: web_proxy_failed when the proxy
// itself failed, web_proxy_refused when it refused the target and
// web_connect_failed when its exit failed; "" for any other class.
func proxyCode(class string) string {
	switch class {
	case proxyUnreachable, proxyAuth, proxyQuota, proxyBusy:
		return "web_proxy_failed"
	case proxyRefused:
		return "web_proxy_refused"
	case proxyExit:
		return "web_connect_failed"
	}
	return ""
}

// webRoute is one web job's egress: direct (proxy nil), or the operator's
// proxy on the job's session. For a sticky (Webshare) session it holds the
// exit probe, which a rotation restarts. Every method is nil-safe and safe
// for the relay and the browser phase at once.
type webRoute struct {
	w            Web
	proxy        *config.WebProxy
	job, attempt string
	// probeCtx parents every exit probe; it is the job's context before its
	// deadline, so a probe may finish while the report waits for it.
	probeCtx context.Context

	mu       sync.Mutex
	addr     netip.AddrPort
	rotation int
	session  config.ProxySession
	probe    *exitProbe
	// pinned keeps the session from rotating once a browser page used it.
	pinned bool
	// class is the proxy class hop 0 failed with, if any.
	class string
}

// proxied reports whether the route goes through the proxy.
func (r *webRoute) proxied() bool { return r != nil && r.proxy != nil }

// jobRoute builds lease l's route. A proxied route reuses the proxy address
// the job's pre-dial checked (so that hop 0 still matches it), else resolves
// and checks the proxy now; one whose proxy does not resolve or fails its
// check is refused, and the job fails web_proxy_failed. A sticky session's
// exit probe starts at once, beside the job.
func (w Web) jobRoute(ctx context.Context, l coordinator.Lease) (*webRoute, bool) {
	if !UsesProxy(w.Config, l) {
		return nil, true
	}
	r := &webRoute{w: w, proxy: w.Config.WebEgressProxy, job: l.JobID, attempt: l.Attempt, probeCtx: ctx}
	if p, _ := ctx.Value(webPredialKey{}).(*WebPredial); p != nil && p.job == l.JobID && p.attempt == l.Attempt {
		select {
		case <-p.started:
		case <-ctx.Done():
		}
		p.mu.Lock()
		r.addr = p.proxyAddr
		p.mu.Unlock()
	}
	if !r.addr.IsValid() {
		addr, ok := w.proxyAddress(ctx, r.proxy)
		if !ok {
			r.class = proxyUnreachable
			return r, false
		}
		r.addr = addr
	}
	r.session = r.proxy.Session(r.job, r.attempt, 0)
	if r.session.Sticky {
		r.probe = w.startExitProbe(r.probeCtx, r.upstreamLocked())
	}
	return r, true
}

// proxyAddress resolves and checks the proxy's host for one job. A Webshare
// host must resolve to public addresses only, as a target must; an http
// proxy may name loopback or LAN addresses (a local proxy in front of a
// cloud server) but never link-local, unspecified or multicast ones. Every
// answer must pass, and the first IPv4 one, else the first IPv6 one, is the
// address dialled.
func (w Web) proxyAddress(ctx context.Context, p *config.WebProxy) (netip.AddrPort, bool) {
	var addrs []netip.Addr
	if literal, err := netip.ParseAddr(p.Host); err == nil {
		addrs = []netip.Addr{literal}
	} else {
		lookupCtx, cancel := context.WithTimeout(ctx, webLookupLimit)
		addrs, err = w.resolver()(lookupCtx, p.Host)
		cancel()
		if err != nil {
			return netip.AddrPort{}, false
		}
	}
	var addr netip.Addr
	ok := false
	if p.Provider == config.ProxyWebshare {
		addr, ok = w.egress().pickWebAddr(ctx, addrs)
	} else {
		addr, ok = localProxyAddr(addrs)
	}
	if !ok || p.Port < 1 || p.Port > 65535 {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, uint16(p.Port)), true
}

// localProxyAddr checks an http proxy's answers: none link-local,
// unspecified, multicast or zoned. It returns the first IPv4 one, else the
// first IPv6 one.
func localProxyAddr(addrs []netip.Addr) (netip.Addr, bool) {
	var v4, v6 netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if !a.IsValid() || a.Zone() != "" || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return netip.Addr{}, false
		}
		if a.Is4() && !v4.IsValid() {
			v4 = a
		} else if a.Is6() && !v6.IsValid() {
			v6 = a
		}
	}
	if v4.IsValid() {
		return v4, true
	}
	return v6, v6.IsValid()
}

func (r *webRoute) upstreamLocked() ProxyUpstream {
	return ProxyUpstream{Addr: r.addr, Authorization: r.session.Authorization}
}

// upstream is the route's proxy for the browser tier, nil when direct.
func (r *webRoute) upstream() *ProxyUpstream {
	if !r.proxied() {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	u := r.upstreamLocked()
	return &u
}

// hopProxy is a hop's proxy input, nil when direct.
func (r *webRoute) hopProxy() *webProxyInput {
	if !r.proxied() {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return &webProxyInput{Host: r.addr.Addr().String(), Port: int(r.addr.Port()), Authorization: r.session.Authorization}
}

// rotate moves a sticky session to its one fresh session after an exit
// failure on hop 0, before any hop was verified (Webshare's advice after a
// failure), and restarts the exit probe on it. It reports whether it did.
// A pinned route never rotates.
func (r *webRoute) rotate() bool {
	if !r.proxied() {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.session.Sticky || r.rotation > 0 || r.pinned {
		return false
	}
	r.rotation = 1
	r.session = r.proxy.Session(r.job, r.attempt, r.rotation)
	r.probe.stop()
	r.probe = r.w.startExitProbe(r.probeCtx, r.upstreamLocked())
	return true
}

// pin keeps the route on its current session: a browser job's re-fetch
// reaches the site from the exit the page used (its cookies are bound to
// that address), and the report names that exit.
func (r *webRoute) pin() {
	if r.proxied() {
		r.mu.Lock()
		r.pinned = true
		r.mu.Unlock()
	}
}

// failed records the proxy class the job failed with: hop 0's, or the
// browser's main document's.
func (r *webRoute) failed(class string) {
	if r.proxied() && proxyClass(class) != "" {
		r.mu.Lock()
		r.class = class
		r.mu.Unlock()
	}
}

// finish ends the route once the job has its code: it waits at most
// webExitWait for the probe still running, and returns the report's egress
// and, for a job that failed web_proxy_failed, the proxy class behind it.
func (r *webRoute) finish(code string) (coordinator.WebEgress, string) {
	if !r.proxied() {
		return coordinator.WebEgress{Via: "direct"}, ""
	}
	r.mu.Lock()
	probe, class := r.probe, r.class
	r.mu.Unlock()
	egress := coordinator.WebEgress{Via: "proxy"}
	if exit, ok := probe.wait(webExitWait); ok {
		egress.Exit = exit.String()
	}
	probe.stop()
	if code != "web_proxy_failed" {
		class = ""
	}
	return egress, class
}

// exitOf is the probe's exit for local status, if it found one.
func exitOf(e coordinator.WebEgress) netip.Addr {
	addr, err := netip.ParseAddr(e.Exit)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

// proxyTestJob is the job a proxy test's fresh session is numbered from:
// random, and never a real job.
func proxyTestJob() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "proxy-test-" + hex.EncodeToString(b[:])
}
