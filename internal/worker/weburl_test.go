package worker

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The node shares api/web-vectors.json with the app and the verifier; it
// implements the strict rules only.
func TestCanonicalWebURLSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../api/web-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Version int `json:"version"`
		Strict  []struct {
			Input  string `json:"input"`
			Output string `json:"output"`
			Error  string `json:"error"`
		} `json:"strict"`
		Requests []struct {
			URL string `json:"url"`
		} `json:"requests"`
		Redirects []struct {
			Next string `json:"next"`
		} `json:"redirects"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil || vectors.Version != 2 || len(vectors.Strict) == 0 {
		t.Fatal("vectors unreadable", err)
	}
	for _, v := range vectors.Strict {
		got, host, err := canonicalWebURL(v.Input)
		if v.Error != "" {
			if err == nil || err.Error() != "web URL refused: "+v.Error {
				t.Errorf("%q: got %q %v, want error %s", v.Input, got, err, v.Error)
			}
			continue
		}
		if err != nil || got != v.Output || !strings.HasPrefix(got, "https://"+host+"/") {
			t.Errorf("%q: got %q host %q %v, want %q", v.Input, got, host, err, v.Output)
		}
		// Canonical output is a fixed point.
		if again, _, err := canonicalWebURL(got); err != nil || again != got {
			t.Errorf("%q not a fixed point", got)
		}
	}
	// Every URL the verifier may authorize as a next hop is canonical here too.
	for _, v := range vectors.Redirects {
		if v.Next == "" {
			continue
		}
		if got, _, err := canonicalWebURL(v.Next); err != nil || got != v.Next {
			t.Errorf("redirect target %q not canonical: %q %v", v.Next, got, err)
		}
	}
	for _, v := range vectors.Requests {
		if got, _, err := canonicalWebURL(v.URL); err != nil || got != v.URL {
			t.Errorf("request URL %q not canonical", v.URL)
		}
	}
}

func TestCanonicalWebURLRules(t *testing.T) {
	for _, tc := range []struct{ in, out, err string }{
		{in: "https://example.com/a/./b/../c", out: "https://example.com/a/c"},
		{in: "https://example.com/../../a", out: "https://example.com/a"},
		{in: "https://example.com/%7euser", out: "https://example.com/%7euser"},
		{in: "https://example.com/100%", out: "https://example.com/100%25"},
		{in: "https://example.com/%zz", out: "https://example.com/%25zz"},
		{in: "https://example.com/é", out: "https://example.com/%C3%A9"},
		{in: "https://example.com/?a=1&b=[2]", out: "https://example.com/?a=1&b=%5B2%5D"},
		{in: "https://example.com/?", out: "https://example.com/?"},
		{in: "https://example.com?q=a?b", out: "https://example.com/?q=a?b"},
		{in: "https://example.com#frag", out: "https://example.com/"},
		{in: "HTTPS://WWW.Example.COM.", out: "https://www.example.com/"},
		{in: "https://example.com:/x", out: "https://example.com/x"},
		{in: "https://a-b.example.co.uk/", out: "https://a-b.example.co.uk/"},
		{in: "https://example.com\\@evil.com/", err: "userinfo"},
		{in: "https://example.com/\x00", err: "invalid"},
		{in: "https://example.com/\x7f", err: "invalid"},
		{in: "https:example.com", err: "invalid"},
		{in: "//example.com/", err: "invalid"},
		{in: "http://example.com/", err: "scheme"},
		{in: "https://[2001:db8::1]/", err: "ip_literal"},
		{in: "https://0x7f000001/", err: "ip_literal"},
		{in: "https://example.0x1/", err: "ip_literal"},
		{in: "https://2130706433/", err: "ip_literal"},
		{in: "https://1.2.3.4.5/", err: "ip_literal"},
		{in: "https://example.com:8443/", err: "port"},
		{in: "https://localhost:8443/", err: "host"},
		{in: "https://printer.local/", err: "host"},
		{in: "https://a.internal/", err: "host"},
		{in: "https://router.home.arpa/", err: "host"},
		{in: "https://abc.onion/", err: "host"},
		{in: "https://site.test/", err: "host"},
		{in: "https://example.123/", err: "ip_literal"},
		{in: "https://exa_mple.com/", err: "host"},
		{in: "https://example-.com/", err: "host"},
		{in: "https://" + strings.Repeat("a", 64) + ".com/", err: "host"},
		{in: "https://x.com/", err: "x_host"},
		{in: "https://mobile.twitter.com/", err: "x_host"},
		{in: "https://notx.com/", out: "https://notx.com/"},
		{in: "https://example.com/" + strings.Repeat("a", 2048), err: "too_long"},
	} {
		got, _, err := canonicalWebURL(tc.in)
		if tc.err != "" {
			if err == nil || err.Error() != "web URL refused: "+tc.err {
				t.Errorf("%q: got %q %v, want %s", tc.in, got, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.out {
			t.Errorf("%q: got %q %v, want %q", tc.in, got, err, tc.out)
		}
	}
}
