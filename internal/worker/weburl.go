package worker

import (
	"strings"
)

// webURLError is one closed refusal reason of the strict canonical URL rules
// shared with the app and the verifier (api/web-vectors.json). It carries no
// part of the URL, so it is safe to log.
type webURLError string

func (e webURLError) Error() string { return "web URL refused: " + string(e) }

const (
	errWebURLInvalid   webURLError = "invalid"
	errWebURLScheme    webURLError = "scheme"
	errWebURLUserinfo  webURLError = "userinfo"
	errWebURLPort      webURLError = "port"
	errWebURLIPLiteral webURLError = "ip_literal"
	errWebURLHost      webURLError = "host"
	errWebURLXHost     webURLError = "x_host"
	errWebURLTooLong   webURLError = "too_long"
)

// maxWebURLBytes bounds a canonical web URL.
const maxWebURLBytes = 2048

// Reserved names that never reach the public internet, the name itself or any
// subdomain. Lookups for them are refused before any DNS query is made.
var webReservedSuffixes = []string{"localhost", "local", "internal", "home.arpa", "lan", "localdomain", "onion", "invalid", "test"}

// X is read through the x_read service only, never as a web page.
var webXHosts = []string{"x.com", "twitter.com"}

func webHostUnder(host string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// canonicalWebURL applies the strict rules of contract §1.1 and returns the
// canonical URL with its host. A URL is canonical iff the result equals it.
// Only https on port 443 to a public DNS name passes; IP literals, userinfo,
// reserved names and X hosts are refused.
func canonicalWebURL(raw string) (string, string, error) {
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return "", "", errWebURLInvalid
		}
	}
	colon := strings.IndexByte(raw, ':')
	if colon < 1 || !webScheme(raw[:colon]) || !strings.HasPrefix(raw[colon+1:], "//") {
		return "", "", errWebURLInvalid
	}
	if strings.ToLower(raw[:colon]) != "https" {
		return "", "", errWebURLScheme
	}
	rest := raw[colon+3:]
	end := len(rest)
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		end = i
	}
	authority, tail := rest[:end], rest[end:]
	if strings.Contains(authority, "@") {
		return "", "", errWebURLUserinfo
	}
	if strings.HasPrefix(authority, "[") {
		return "", "", errWebURLIPLiteral
	}
	port, hasPort := "", false
	if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		authority, port, hasPort = authority[:i], authority[i+1:], true
	}
	host, err := canonicalWebHost(authority)
	if err != nil {
		return "", "", err
	}
	if hasPort && port != "" && port != "443" {
		return "", "", errWebURLPort
	}
	if i := strings.IndexByte(tail, '#'); i >= 0 {
		tail = tail[:i]
	}
	path, query, hasQuery := tail, "", false
	if i := strings.IndexByte(tail, '?'); i >= 0 {
		path, query, hasQuery = tail[:i], tail[i+1:], true
	}
	if path == "" {
		path = "/"
	}
	path = removeDotSegments(percentEncode(path, false))
	if path == "" {
		path = "/"
	}
	out := "https://" + host + path
	if hasQuery {
		out += "?" + percentEncode(query, true)
	}
	if len(out) > maxWebURLBytes {
		return "", "", errWebURLTooLong
	}
	return out, host, nil
}

func webScheme(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if i == 0 && !letter || !letter && !(c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-') {
			return false
		}
	}
	return s != ""
}

func canonicalWebHost(host string) (string, error) {
	if strings.HasPrefix(host, "[") {
		return "", errWebURLIPLiteral
	}
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return "", errWebURLHost
		}
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	labels := strings.Split(host, ".")
	last := labels[len(labels)-1]
	if allBytes(last, digit) || strings.HasPrefix(last, "0x") || allBytes(host, func(c byte) bool { return digit(c) || c == '.' }) {
		return "", errWebURLIPLiteral
	}
	if len(host) < 1 || len(host) > 253 || len(labels) < 2 {
		return "", errWebURLHost
	}
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || !allBytes(label, func(c byte) bool { return c >= 'a' && c <= 'z' || digit(c) || c == '-' }) {
			return "", errWebURLHost
		}
	}
	if !strings.ContainsFunc(last, func(r rune) bool { return r >= 'a' && r <= 'z' }) || webHostUnder(host, webReservedSuffixes) {
		return "", errWebURLHost
	}
	if webHostUnder(host, webXHosts) {
		return "", errWebURLXHost
	}
	return host, nil
}

func digit(c byte) bool { return c >= '0' && c <= '9' }

// allBytes reports whether s is non-empty and every byte satisfies ok.
func allBytes(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return s != ""
}

func hexDigit(c byte) bool { return digit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// percentEncode keeps unreserved and sub-delimiter bytes, ':', '@', '/' (and
// '?' in a query), keeps an existing %XX escape as written and encodes every
// other byte, including a stray '%', as uppercase %XX.
func percentEncode(s string, query bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '%' && i+2 < len(s) && hexDigit(s[i+1]) && hexDigit(s[i+2]):
			b.WriteString(s[i : i+3])
			i += 2
		case c != '%' && (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || digit(c) || strings.IndexByte("-._~!$&'()*+,;=:@/", c) >= 0 || query && c == '?'):
			b.WriteByte(c)
		default:
			const upper = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(upper[c>>4])
			b.WriteByte(upper[c&15])
		}
	}
	return b.String()
}

// removeDotSegments is RFC 3986 §5.2.4.
func removeDotSegments(in string) string {
	out := ""
	popLast := func() {
		if i := strings.LastIndexByte(out, '/'); i >= 0 {
			out = out[:i]
		} else {
			out = ""
		}
	}
	for in != "" {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = "/" + in[3:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = "/" + in[4:]
			popLast()
		case in == "/..":
			in = "/"
			popLast()
		case in == "." || in == "..":
			in = ""
		default:
			j := strings.IndexByte(in[1:], '/')
			if j < 0 {
				out += in
				in = ""
			} else {
				out += in[:j+1]
				in = in[j+1:]
			}
		}
	}
	return out
}
