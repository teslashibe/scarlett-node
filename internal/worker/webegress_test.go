package worker

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func egressWith(nat64 []string, local []string) *WebEgress {
	return &WebEgress{
		now: time.Now,
		discover: func(context.Context) ([]netip.Addr, error) {
			return addrs(nat64...), nil
		},
		addrs: func() ([]net.Addr, error) {
			out := []net.Addr{}
			for _, l := range local {
				_, network, _ := net.ParseCIDR(l)
				ip, _, _ := net.ParseCIDR(l)
				out = append(out, &net.IPNet{IP: ip, Mask: network.Mask})
			}
			return out, nil
		},
	}
}

func TestWebEgressTable(t *testing.T) {
	// A network-specific NAT64 prefix inside 2000::/3, plus the well-known one,
	// both discovered from ipv4only.arpa; and one public address on a local
	// interface, as a cloud server has.
	g := egressWith([]string{"2a01:4f8:c0c:1::c000:aa", "2a01:4f8:c0c:1::c000:ab", "64:ff9b::c000:aa", "2001:db8:1::1"}, []string{"203.0.114.7/24", "2a02:6b8::5/64", "fe80::1/64"})
	denied := []string{
		// IPv4: one address in every denied range.
		"0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.254", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.255",
		"192.0.0.170", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1", "192.175.48.1",
		"198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		// IPv4-mapped IPv6 is judged as the IPv4 it carries.
		"::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
		// IPv6 outside global unicast.
		"::", "::1", "::a00:1", "64:ff9b:1::a00:1", "100::1", "fc00::1", "fd12:3456::1", "fe80::1", "fec0::1", "ff02::1",
		// Special ranges inside 2000::/3: Teredo, ORCHID, benchmarking, documentation, 6to4.
		"2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:10::1", "2001:2::1", "2001:db8::1", "2002:c0a8:101::1", "2002:5db8:d70e::1", "3fff::1",
		// NAT64: the discovered prefixes carry a private IPv4 address.
		"2a01:4f8:c0c:1::a00:1", "2a01:4f8:c0c:1::7f00:1", "64:ff9b::a00:1", "64:ff9b::c0a8:101",
		// Addresses on this host's own interfaces.
		"203.0.114.7", "::ffff:203.0.114.7", "2a02:6b8::5",
	}
	for _, a := range denied {
		if g.Allowed(context.Background(), netip.MustParseAddr(a)) {
			t.Errorf("%s allowed", a)
		}
	}
	allowed := []string{
		"93.184.215.14", "1.1.1.1", "8.8.8.8", "151.101.1.57", "100.128.0.1", "172.32.0.1", "192.0.1.1", "203.0.114.8",
		"::ffff:93.184.215.14",
		"2606:2800:21f:cb07:6820:80da:af6b:8b2c", "2a00:1450:4001::200e", "2001:200::1", "2a02:6b8::6",
		// NAT64 carrying a public IPv4 address, through a discovered prefix.
		"2a01:4f8:c0c:1::5db8:d70e", "64:ff9b::5db8:d70e",
	}
	for _, a := range allowed {
		if !g.Allowed(context.Background(), netip.MustParseAddr(a)) {
			t.Errorf("%s denied", a)
		}
	}
	// Scoped addresses, and the invalid zero address, never pass.
	for _, a := range []netip.Addr{netip.MustParseAddr("2606:2800:21f:cb07:6820:80da:af6b:8b2c%en0"), {}} {
		if g.Allowed(context.Background(), a) {
			t.Errorf("%v allowed", a)
		}
	}
	// The fixed guard behaves the same way.
	fixed := NewWebEgressWith([]netip.Prefix{netip.MustParsePrefix("2a01:4f8:c0c:1::/96")}, addrs("203.0.114.7"))
	for a, want := range map[string]bool{"2a01:4f8:c0c:1::a00:1": false, "2a01:4f8:c0c:1::5db8:d70e": true, "203.0.114.7": false, "93.184.215.14": true} {
		if fixed.Allowed(context.Background(), netip.MustParseAddr(a)) != want {
			t.Errorf("fixed guard: %s allowed != %v", a, want)
		}
	}
	// Without discovery the well-known NAT64 prefix stays outside 2000::/3.
	if egressWith(nil, nil).Allowed(context.Background(), netip.MustParseAddr("64:ff9b::5db8:d70e")) {
		t.Error("undiscovered NAT64 prefix allowed")
	}
}

func TestPickWebAddr(t *testing.T) {
	g := egressWith(nil, nil)
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"2606:4700::6810:84e5", "104.16.132.229"}, "104.16.132.229"},
		{[]string{"::ffff:104.16.132.229"}, "104.16.132.229"},
		{[]string{"2606:4700::6810:84e5", "2606:4700::6810:85e5"}, "2606:4700::6810:84e5"},
		{[]string{"104.16.132.229", "104.16.133.229"}, "104.16.132.229"},
		{[]string{"104.16.132.229", "10.0.0.1"}, ""},
		{[]string{"2606:4700::6810:84e5", "fd00::1"}, ""},
		{[]string{}, ""},
	} {
		got, ok := g.pickWebAddr(context.Background(), addrs(tc.in...))
		if tc.want == "" {
			if ok {
				t.Errorf("%v: picked %v", tc.in, got)
			}
			continue
		}
		if !ok || got.String() != tc.want {
			t.Errorf("%v: picked %v, want %s", tc.in, got, tc.want)
		}
	}
}

func TestNAT64Discovery(t *testing.T) {
	got := nat64Prefixes(addrs("64:ff9b::c000:aa", "64:ff9b::c000:ab", "2a01:4f8:c0c:1::c000:ab", "2001:db8::1", "::ffff:192.0.0.170", "192.0.0.170"))
	if len(got) != 2 || got[0].String() != "64:ff9b::/96" || got[1].String() != "2a01:4f8:c0c:1::/96" {
		t.Fatal(got)
	}
	// Discovery and interface reads refresh on their own schedules; a failed
	// discovery holds no prefix.
	now := time.Now()
	lookups, reads := 0, 0
	g := &WebEgress{
		now: func() time.Time { return now },
		discover: func(context.Context) ([]netip.Addr, error) {
			lookups++
			if lookups > 1 {
				return nil, errors.New("synthetic resolver failure")
			}
			return addrs("2a01:4f8:c0c:1::c000:aa"), nil
		},
		addrs: func() ([]net.Addr, error) { reads++; return nil, nil },
	}
	// Inside the discovered prefix this carries 10.0.0.1; outside any known
	// prefix it is an ordinary global address.
	nat64 := netip.MustParseAddr("2a01:4f8:c0c:1::a00:1")
	if g.Allowed(context.Background(), nat64) || lookups != 1 || reads != 1 {
		t.Fatal("first use did not load", lookups, reads)
	}
	now = now.Add(webLocalRefresh)
	if g.Allowed(context.Background(), nat64) || lookups != 1 || reads != 2 {
		t.Fatal("interfaces not refreshed each minute, or NAT64 rediscovered early", lookups, reads)
	}
	now = now.Add(webNAT64Refresh)
	if !g.Allowed(context.Background(), nat64) || lookups != 2 {
		t.Fatal("NAT64 not rediscovered after ten minutes", lookups)
	}
}
