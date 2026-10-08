package worker

import (
	"net/url"
	"sort"
	"strings"
	"time"
)

// BrowserCookie is one cookie the browser context held when a browser fetch
// ended (Playwright's context.cookies()). Values reach Go only over loopback,
// live for one job and are never logged, stored or reported; at most the
// clearance cookies among them are sent on the proven re-fetch.
type BrowserCookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"` // Unix seconds; negative for a session cookie
	Secure   bool    `json:"secure"`
	HTTPOnly bool    `json:"http_only"`
}

// String and GoString keep cookie values out of any formatted output.
func (BrowserCookie) String() string   { return "browser cookie [redacted]" }
func (BrowserCookie) GoString() string { return "worker.BrowserCookie{}" }

const (
	maxCookieHeaderBytes = 4096
	maxCookiePairs       = 50
	maxCookieNameBytes   = 256
)

// clearanceCookieNames are the anti-bot clearance cookies the re-fetch may
// carry, matched exactly and case-sensitively (contract §1, the same list the
// verifier enforces): Cloudflare; DataDome; Akamai Bot Manager, including
// its sensor (sbsd) and SEC-CPT challenge cookies; HUMAN; Imperva; AWS WAF;
// and Kasada's mirror of its x-kpsdk-ct token.
var clearanceCookieNames = map[string]bool{
	"cf_clearance": true, "__cf_bm": true, "_cfuvid": true, "datadome": true,
	"_abck": true, "bm_sz": true, "ak_bmsc": true, "bm_sv": true, "bm_s": true, "bm_so": true, "bm_sc": true, "bm_lso": true, "bm_mi": true,
	"sbsd": true, "sbsd_o": true, "sec_cpt": true, "pxcts": true, "reese84": true, "___utmvc": true, "aws-waf-token": true,
	"KP_UIDz": true, "KP_UIDz-ssn": true, "tkrm_alpekz_s1.3": true, "tkrm_alpekz_s1.3-ssn": true,
}

// clearanceCookiePrefixes match only when at least one more byte follows.
var clearanceCookiePrefixes = []string{"_px", "incap_ses_", "visid_incap_", "nlbi_", "incap_sh_"}

// ClearanceCookie reports whether name is an anti-bot clearance cookie the
// verifier accepts on a browser job's re-fetch.
func ClearanceCookie(name string) bool {
	if !validCookieName(name) {
		return false
	}
	if clearanceCookieNames[name] {
		return true
	}
	for _, prefix := range clearanceCookiePrefixes {
		if len(name) > len(prefix) && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// ValidCookie applies the Cookie header grammar shared with the verifier:
// pair *("; " pair), 1-50 pairs and 1-4096 bytes, pair = name "=" value, name
// 1-256 RFC 9110 tchar, value cookie-octets, optionally in double quotes.
// Duplicate names are allowed. Names are checked apart, by ClearanceCookie.
func ValidCookie(header string) bool {
	if len(header) < 1 || len(header) > maxCookieHeaderBytes {
		return false
	}
	pairs := strings.Split(header, "; ")
	if len(pairs) > maxCookiePairs {
		return false
	}
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || !validCookieName(name) || !validCookieValue(value) {
			return false
		}
	}
	return true
}

func validCookieName(name string) bool {
	if len(name) < 1 || len(name) > maxCookieNameBytes {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || digit(c) || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// validCookieValue is *cookie-octet or DQUOTE *cookie-octet DQUOTE, where
// cookie-octet is %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E.
func validCookieValue(value string) bool {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == ',' || c == ';' || c == '\\' {
			return false
		}
	}
	return true
}

// CookieHeader builds the Cookie value for one re-fetch hop from the cookies
// the browser held: clearance-allowlisted names only, each matching the hop's
// host (host-only or domain cookie) and path, secure only over https, not
// expired, with a valid name and value. Longer paths come first, then the
// browser's order; the result is capped at 50 pairs and 4096 bytes. It is ""
// when nothing qualifies, and the hop then sends no Cookie line.
func CookieHeader(cookies []BrowserCookie, hopURL string, now time.Time) string {
	u, err := url.Parse(hopURL)
	if err != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	type candidate struct {
		pair string
		path int
	}
	matched := []candidate{}
	for _, c := range cookies {
		cookiePath := c.Path
		if cookiePath == "" {
			cookiePath = "/"
		}
		if !ClearanceCookie(c.Name) || !validCookieValue(c.Value) || c.Secure && u.Scheme != "https" || !cookieDomainMatch(host, c.Domain) || !cookiePathMatch(path, cookiePath) {
			continue
		}
		if c.Expires >= 0 && !time.UnixMilli(int64(c.Expires*1000)).After(now) {
			continue
		}
		matched = append(matched, candidate{c.Name + "=" + c.Value, len(cookiePath)})
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].path > matched[j].path })
	out := []string{}
	size := 0
	for _, m := range matched {
		if len(out) == maxCookiePairs {
			break
		}
		added := len(m.pair)
		if len(out) > 0 {
			added += 2
		}
		if size+added > maxCookieHeaderBytes {
			continue
		}
		out = append(out, m.pair)
		size += added
	}
	return strings.Join(out, "; ")
}

// cookieDomainMatch is RFC 6265 §5.1.3 over Playwright's cookie domains: a
// leading dot marks a domain cookie, which also matches subdomains; without
// it the cookie is host-only.
func cookieDomainMatch(host, domain string) bool {
	domain = strings.ToLower(domain)
	if trimmed, ok := strings.CutPrefix(domain, "."); ok {
		return trimmed != "" && (host == trimmed || strings.HasSuffix(host, "."+trimmed))
	}
	return domain != "" && host == domain
}

// cookiePathMatch is RFC 6265 §5.1.4.
func cookiePathMatch(requestPath, cookiePath string) bool {
	if requestPath == cookiePath {
		return true
	}
	if !strings.HasPrefix(requestPath, cookiePath) {
		return false
	}
	return strings.HasSuffix(cookiePath, "/") || requestPath[len(cookiePath)] == '/'
}
