package worker

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type browserVectors struct {
	Version               int         `json:"version"`
	BrowserDefaultHeaders []webHeader `json:"browser_default_headers"`
	BrowserRequests       []struct {
		URL          string      `json:"url"`
		Headers      []webHeader `json:"headers"`
		UserAgent    string      `json:"user_agent"`
		Cookie       string      `json:"cookie"`
		CookieSHA256 string      `json:"cookie_sha256"`
		Bytes        string      `json:"bytes"`
		SHA256       string      `json:"sha256"`
	} `json:"browser_requests"`
	Cookies struct {
		Valid   []string `json:"valid"`
		Invalid []string `json:"invalid"`
	} `json:"cookies"`
	CookieNames struct {
		Allowed []string `json:"allowed"`
		Refused []string `json:"refused"`
	} `json:"cookie_names"`
	UserAgents struct {
		Allowed []string `json:"allowed"`
		Refused []string `json:"refused"`
	} `json:"user_agents"`
	BrowserAuthorize []struct {
		Case    string `json:"case"`
		URL     string `json:"url"`
		Request string `json:"request"`
		Refused string `json:"refused"`
	} `json:"browser_authorize"`
}

func readBrowserVectors(t *testing.T) browserVectors {
	t.Helper()
	raw, err := os.ReadFile("../../api/web-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v browserVectors
	if err := json.Unmarshal(raw, &v); err != nil || v.Version != 2 {
		t.Fatal("vectors unreadable", err)
	}
	return v
}

// The node shares the cookie grammar and the clearance allowlist with the
// verifier through api/web-vectors.json; grammar and names are separate checks.
func TestCookieVectors(t *testing.T) {
	v := readBrowserVectors(t)
	if len(v.Cookies.Valid) == 0 || len(v.Cookies.Invalid) == 0 || len(v.CookieNames.Allowed) == 0 || len(v.CookieNames.Refused) == 0 {
		t.Fatal("empty cookie vectors")
	}
	for _, header := range v.Cookies.Valid {
		if !ValidCookie(header) {
			t.Errorf("valid cookie refused: %.60q", header)
		}
	}
	for _, header := range v.Cookies.Invalid {
		if ValidCookie(header) {
			t.Errorf("invalid cookie accepted: %.60q", header)
		}
	}
	for _, name := range v.CookieNames.Allowed {
		if !ClearanceCookie(name) {
			t.Errorf("clearance cookie refused: %q", name)
		}
	}
	for _, name := range v.CookieNames.Refused {
		if ClearanceCookie(name) {
			t.Errorf("cookie name accepted: %q", name)
		}
	}
	if !slicesEqualHeaders(v.BrowserDefaultHeaders, webBrowserHeaders) {
		t.Fatal("browser default headers differ from the vectors")
	}
	for _, r := range v.BrowserRequests {
		if !slicesEqualHeaders(r.Headers, webBrowserHeaders) || r.URL != "https://example.com/" || r.Cookie != "" && (!ValidCookie(r.Cookie) || SHA(r.Cookie) != r.CookieSHA256) {
			t.Fatalf("browser request vector %+v", r.URL)
		}
		// The node builds the same Cookie value from the browser's jar.
		if r.Cookie != "" {
			jar := []BrowserCookie{{Name: "cf_clearance", Value: "abc.DEF-123_456", Domain: ".example.com", Path: "/", Expires: -1}, {Name: "__cf_bm", Value: "x1y2", Domain: "example.com", Path: "/", Expires: -1}}
			if got := CookieHeader(jar, r.URL, time.Now()); got != r.Cookie {
				t.Fatalf("cookie header %q, want %q", got, r.Cookie)
			}
		}
	}
}

func slicesEqualHeaders(a, b []webHeader) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCookieHeaderSelection(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	future := float64(now.Add(time.Hour).Unix())
	past := float64(now.Add(-time.Second).Unix())
	cookie := func(name, value, domain, path string) BrowserCookie {
		return BrowserCookie{Name: name, Value: value, Domain: domain, Path: path, Expires: -1}
	}
	for _, tc := range []struct {
		name    string
		cookies []BrowserCookie
		url     string
		want    string
	}{
		{"nothing", nil, "https://example.com/", ""},
		{"not allowlisted", []BrowserCookie{cookie("session", "s3cr3t", ".example.com", "/"), cookie("sid", "1", "example.com", "/"), cookie("CF_CLEARANCE", "x", "example.com", "/")}, "https://example.com/", ""},
		{"allowlisted kept, others dropped", []BrowserCookie{cookie("session", "s3cr3t", ".example.com", "/"), cookie("cf_clearance", "a", ".example.com", "/"), cookie("_px3", "b", "example.com", "/")}, "https://example.com/", "cf_clearance=a; _px3=b"},
		{"domain cookie on a subdomain", []BrowserCookie{cookie("datadome", "d", ".example.com", "/")}, "https://www.example.com/a", "datadome=d"},
		{"host-only cookie on a subdomain", []BrowserCookie{cookie("datadome", "d", "example.com", "/")}, "https://www.example.com/a", ""},
		{"host-only cookie on its host", []BrowserCookie{cookie("datadome", "d", "www.example.com", "/")}, "https://www.example.com/a", "datadome=d"},
		{"other site", []BrowserCookie{cookie("datadome", "d", ".example.org", "/"), cookie("_abck", "a", "badexample.com", "/")}, "https://example.com/", ""},
		{"suffix is not a domain match", []BrowserCookie{cookie("_abck", "a", ".ample.com", "/")}, "https://example.com/", ""},
		{"path prefix", []BrowserCookie{cookie("bm_sz", "1", ".example.com", "/a"), cookie("bm_sv", "2", ".example.com", "/a/"), cookie("ak_bmsc", "3", ".example.com", "/ab")}, "https://example.com/a/b", "bm_sv=2; bm_sz=1"},
		{"path exact", []BrowserCookie{cookie("bm_sz", "1", ".example.com", "/a")}, "https://example.com/a?x=1", "bm_sz=1"},
		{"longer path first, then browser order", []BrowserCookie{cookie("_cfuvid", "1", ".example.com", "/"), cookie("__cf_bm", "2", ".example.com", "/x/y"), cookie("cf_clearance", "3", ".example.com", "/"), cookie("pxcts", "4", ".example.com", "/x")}, "https://example.com/x/y/z", "__cf_bm=2; pxcts=4; _cfuvid=1; cf_clearance=3"},
		{"secure over https", []BrowserCookie{{Name: "cf_clearance", Value: "s", Domain: ".example.com", Path: "/", Expires: -1, Secure: true}}, "https://example.com/", "cf_clearance=s"},
		{"secure never over http", []BrowserCookie{{Name: "cf_clearance", Value: "s", Domain: ".example.com", Path: "/", Expires: -1, Secure: true}}, "http://example.com/", ""},
		{"expiry", []BrowserCookie{{Name: "reese84", Value: "old", Domain: ".example.com", Path: "/", Expires: past}, {Name: "aws-waf-token", Value: "new", Domain: ".example.com", Path: "/", Expires: future}}, "https://example.com/", "aws-waf-token=new"},
		{"invalid value dropped", []BrowserCookie{cookie("cf_clearance", "a b", ".example.com", "/"), cookie("__cf_bm", "a;b", ".example.com", "/"), cookie("_cfuvid", "a\r\nX: y", ".example.com", "/"), cookie("datadome", `"q"`, ".example.com", "/")}, "https://example.com/", `datadome="q"`},
		{"prefix names", []BrowserCookie{cookie("incap_ses_1_2", "a", ".example.com", "/"), cookie("visid_incap_3", "b", ".example.com", "/"), cookie("nlbi_4", "c", ".example.com", "/"), cookie("_px", "d", ".example.com", "/"), cookie("incap_ses_", "e", ".example.com", "/")}, "https://example.com/", "incap_ses_1_2=a; visid_incap_3=b; nlbi_4=c"},
		{"uppercase host and domain", []BrowserCookie{cookie("cf_clearance", "a", ".Example.COM", "/")}, "https://example.com/", "cf_clearance=a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := CookieHeader(tc.cookies, tc.url, now)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
			if got != "" && !ValidCookie(got) {
				t.Fatal("result fails the grammar", got)
			}
		})
	}
}

func TestCookieHeaderCaps(t *testing.T) {
	jar := []BrowserCookie{}
	for i := range 60 {
		jar = append(jar, BrowserCookie{Name: fmt.Sprintf("_px%d", i), Value: "v", Domain: ".example.com", Path: "/", Expires: -1})
	}
	got := CookieHeader(jar, "https://example.com/", time.Now())
	if pairs := strings.Split(got, "; "); len(pairs) != 50 || pairs[0] != "_px0=v" || pairs[49] != "_px49=v" || !ValidCookie(got) {
		t.Fatalf("pair cap: %d pairs", len(pairs))
	}
	// A pair that would pass 4096 bytes is skipped; smaller ones still fit.
	big := []BrowserCookie{
		{Name: "cf_clearance", Value: strings.Repeat("a", 3000), Domain: ".example.com", Path: "/", Expires: -1},
		{Name: "datadome", Value: strings.Repeat("b", 1500), Domain: ".example.com", Path: "/", Expires: -1},
		{Name: "__cf_bm", Value: strings.Repeat("c", 1000), Domain: ".example.com", Path: "/", Expires: -1},
	}
	got = CookieHeader(big, "https://example.com/", time.Now())
	if len(got) > 4096 || !strings.HasPrefix(got, "cf_clearance=") || strings.Contains(got, "datadome") || !strings.Contains(got, "; __cf_bm=") || !ValidCookie(got) {
		t.Fatalf("byte cap: %d bytes", len(got))
	}
	exact := []BrowserCookie{{Name: "cf_clearance", Value: strings.Repeat("a", 4096-len("cf_clearance=")), Domain: ".example.com", Path: "/", Expires: -1}}
	if got = CookieHeader(exact, "https://example.com/", time.Now()); len(got) != 4096 {
		t.Fatal("a 4096-byte header must fit", len(got))
	}
	exact[0].Value += "a"
	if got = CookieHeader(exact, "https://example.com/", time.Now()); got != "" {
		t.Fatal("a 4097-byte header was built")
	}
}

func TestBrowserCookieNeverPrintsItsValue(t *testing.T) {
	c := BrowserCookie{Name: "cf_clearance", Value: "synthetic-secret-value", Domain: ".example.com", Path: "/"}
	h := webNodeHeaders{UserAgent: "ua", Cookie: "cf_clearance=synthetic-secret-value"}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		text := fmt.Sprintf(format, c) + fmt.Sprintf(format, []BrowserCookie{c}) + fmt.Sprintf(format, h) + fmt.Sprintf(format, &h)
		if strings.Contains(text, "synthetic-secret-value") {
			t.Fatalf("%s prints a cookie value", format)
		}
	}
}
