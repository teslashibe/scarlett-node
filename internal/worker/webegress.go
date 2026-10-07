package worker

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// A web job dials whatever host a buyer names, from the operator's own network.
// The egress guard is what keeps that to the public internet: every address a
// hop host resolves to must pass, and the prover then dials exactly the checked
// address (directly, or as the CONNECT target of the local proxy), so a second
// DNS answer can never redirect the connection. Go is authoritative here; the
// prover's own address check is only a backstop.

var deniedWebIPv4 = prefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)

// Only global unicast IPv6 (2000::/3) is allowed, which already excludes
// ::/128, ::1, ::/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, fc00::/7,
// fe80::/10, fec0::/10 and ff00::/8. These are the special ranges inside it:
// Teredo, ORCHID and benchmarking (2001::/23), documentation (2001:db8::/32
// and 3fff::/20) and 6to4 (2002::/16).
var (
	allowedWebIPv6 = netip.MustParsePrefix("2000::/3")
	deniedWebIPv6  = prefixes("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20")
)

func prefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(values))
	for i, value := range values {
		out[i] = netip.MustParsePrefix(value)
	}
	return out
}

func inAny(addr netip.Addr, ranges []netip.Prefix) bool {
	for _, prefix := range ranges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

const (
	webNAT64Refresh = 10 * time.Minute
	webLocalRefresh = time.Minute
)

// WebEgress decides which resolved addresses a web hop may dial. Its NAT64
// prefixes (RFC 7050) and local interface addresses are refreshed in the
// background by Keep and loaded on first use otherwise.
type WebEgress struct {
	mu       sync.Mutex
	nat64    []netip.Prefix
	nat64At  time.Time
	local    map[netip.Addr]bool
	localAt  time.Time
	now      func() time.Time
	discover func(context.Context) ([]netip.Addr, error)
	addrs    func() ([]net.Addr, error)
}

// NewWebEgress is a guard reading this host's resolver and interfaces.
func NewWebEgress() *WebEgress {
	return &WebEgress{
		now: time.Now,
		discover: func(ctx context.Context) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip6", "ipv4only.arpa")
		},
		addrs: net.InterfaceAddrs,
	}
}

// NewWebEgressWith is a guard over fixed /96 NAT64 prefixes and local
// addresses that never consults this host's resolver or interfaces. Tests and
// local fixtures use it.
func NewWebEgressWith(nat64 []netip.Prefix, local []netip.Addr) *WebEgress {
	answers := []netip.Addr{}
	for _, prefix := range nat64 {
		if prefix.Bits() == 96 && prefix.Addr().Is6() {
			b := prefix.Masked().Addr().As16()
			b[12], b[13], b[14], b[15] = 192, 0, 0, 170
			answers = append(answers, netip.AddrFrom16(b))
		}
	}
	interfaces := []net.Addr{}
	for _, addr := range local {
		interfaces = append(interfaces, &net.IPAddr{IP: net.IP(addr.AsSlice())})
	}
	return &WebEgress{
		now:      time.Now,
		discover: func(context.Context) ([]netip.Addr, error) { return answers, nil },
		addrs:    func() ([]net.Addr, error) { return interfaces, nil },
	}
}

var defaultWebEgress = NewWebEgress()

// DefaultWebEgress is the node-wide guard every web hop uses; the browser
// tier's egress proxy checks its connections against the same one.
func DefaultWebEgress() *WebEgress { return defaultWebEgress }

// KeepWebEgressFresh refreshes the node-wide guard now and then on its own
// schedule until ctx ends, so a hop never waits on NAT64 discovery.
func KeepWebEgressFresh(ctx context.Context) {
	defaultWebEgress.Keep(ctx)
}

// Keep refreshes g at once and then as its entries age, until ctx ends.
func (g *WebEgress) Keep(ctx context.Context) {
	tick := time.NewTicker(webLocalRefresh)
	defer tick.Stop()
	for {
		g.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// refresh reloads what has aged out. A failed discovery keeps no prefix:
// NAT64 then reads as absent, which only ever denies more.
func (g *WebEgress) refresh(ctx context.Context) {
	g.mu.Lock()
	now := g.now()
	wantNAT64 := g.nat64At.IsZero() || now.Sub(g.nat64At) >= webNAT64Refresh
	wantLocal := g.localAt.IsZero() || now.Sub(g.localAt) >= webLocalRefresh
	discover, addrs := g.discover, g.addrs
	g.mu.Unlock()
	var nat64 []netip.Prefix
	if wantNAT64 && discover != nil {
		lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		found, err := discover(lookupCtx)
		cancel()
		if err == nil {
			nat64 = nat64Prefixes(found)
		}
	}
	var local map[netip.Addr]bool
	if wantLocal && addrs != nil {
		local = map[netip.Addr]bool{}
		if list, err := addrs(); err == nil {
			for _, a := range list {
				if prefix, err := netip.ParsePrefix(a.String()); err == nil {
					local[prefix.Addr().Unmap().WithZone("")] = true
				} else if addr, err := netip.ParseAddr(a.String()); err == nil {
					local[addr.Unmap().WithZone("")] = true
				}
			}
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if wantNAT64 {
		g.nat64, g.nat64At = nat64, now
	}
	if wantLocal {
		g.local, g.localAt = local, now
	}
}

// nat64Prefixes derives the /96 prefixes from the AAAA answers for
// ipv4only.arpa: each answer whose low 32 bits are one of that name's two
// well-known IPv4 addresses (192.0.0.170 and 192.0.0.171).
func nat64Prefixes(answers []netip.Addr) []netip.Prefix {
	out := []netip.Prefix{}
	for _, a := range answers {
		if !a.Is6() || a.Is4In6() {
			continue
		}
		b := a.As16()
		if b[12] != 192 || b[13] != 0 || b[14] != 0 || b[15] != 170 && b[15] != 171 {
			continue
		}
		prefix, err := a.WithZone("").Prefix(96)
		if err == nil && !inAny(prefix.Addr(), out) {
			out = append(out, prefix)
		}
	}
	return out
}

// Allowed reports whether a web hop may dial addr.
func (g *WebEgress) Allowed(ctx context.Context, addr netip.Addr) bool {
	g.refresh(ctx)
	g.mu.Lock()
	defer g.mu.Unlock()
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if g.local[addr] {
		return false
	}
	if addr.Is6() {
		for _, prefix := range g.nat64 {
			if prefix.Contains(addr) {
				b := addr.As16()
				embedded := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
				return !inAny(embedded, deniedWebIPv4) && !g.local[embedded]
			}
		}
		return allowedWebIPv6.Contains(addr) && !inAny(addr, deniedWebIPv6)
	}
	return addr.Is4() && !inAny(addr, deniedWebIPv4)
}

// pickWebAddr checks every resolved address and returns the one to dial: the
// first IPv4 address, else the first IPv6 address. Any denied address refuses
// the hop, so a host cannot mix a public answer with a private one.
func (g *WebEgress) pickWebAddr(ctx context.Context, addrs []netip.Addr) (netip.Addr, bool) {
	if len(addrs) == 0 {
		return netip.Addr{}, false
	}
	var v4, v6 netip.Addr
	for _, a := range addrs {
		if !g.Allowed(ctx, a) {
			return netip.Addr{}, false
		}
		a = a.Unmap()
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
