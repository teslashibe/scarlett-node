package config

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// The web egress proxy providers. Webshare is the operator's own Rotating
// Residential account, through which every job gets its own sticky session
// and so its own exit; http is any other HTTP CONNECT proxy, such as one in
// front of a cloud server, with one fixed sign-in for every job.
const (
	ProxyWebshare = "webshare"
	ProxyHTTP     = "http"
)

// The pages a proxy carries: only those whose lease asks for it (sites that
// limit this node's own network; heartbeat egress "both"), or every page
// ("proxy").
const (
	ProxyUseLimitedSites = "limited_sites"
	ProxyUseAll          = "all"
)

// The Webshare preset: its documented proxy host and ports for username and
// password sign-in, and the one country this release offers.
const (
	WebshareHost    = "p.webshare.io"
	WebshareCountry = "us"
)

// maxWebshareUsername bounds the base username Webshare issues, 1-32 letters
// and digits, to which each session adds -<country>-<session>.
const maxWebshareUsername = 32

// maxWebProxyBytes bounds the proxy file and the desktop start line.
const maxWebProxyBytes = 4096

// WebProxy is the operator's HTTP CONNECT proxy for web egress
// (SCARLETT_WEB_EGRESS_PROXY_FILE, or the desktop app's start line). Only
// non-intercepting CONNECT tunnels work: TLS runs end to end between the
// target and the verifier, so the proxy sees only ciphertext. Its address and
// credentials never leave this node; String and GoString redact all of it.
type WebProxy struct {
	// Provider is ProxyWebshare or ProxyHTTP.
	Provider string
	// Host is WebshareHost for Webshare, else the proxy's name or address.
	// The worker resolves and checks it for each job and dials the checked
	// address.
	Host string
	Port int
	// Username is Webshare's base username (each session extends it), or an
	// http proxy's fixed one. Password goes with it; an http proxy may have
	// neither.
	Username, Password string
	// Country is WebshareCountry for Webshare and empty for http.
	Country string
	// Use is ProxyUseLimitedSites or ProxyUseAll; an http proxy carries all.
	Use string
}

func (WebProxy) String() string   { return "web egress proxy [redacted]" }
func (WebProxy) GoString() string { return "config.WebProxy{}" }

// ProxySession is one job's way through the proxy: the host the worker
// resolves and checks before it dials the checked address, the port, and the
// Proxy-Authorization for this job. It is built for each job and never kept,
// logged or reported; String and GoString redact it.
type ProxySession struct {
	Host          string
	Port          int
	Authorization string
	// Sticky is set when the session has an exit of its own (Webshare): the
	// worker then probes that exit and may rotate to a fresh session once.
	Sticky bool
}

func (ProxySession) String() string   { return "web proxy session [redacted]" }
func (ProxySession) GoString() string { return "config.ProxySession{}" }

// proxySessionKey is made once per process and never stored: Webshare cannot
// link a session to a Scarlett job, and two nodes sharing one account never
// pick the same session.
var proxySessionKey = newProxySessionKey()

func newProxySessionKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("web proxy session key: " + err.Error())
	}
	return key
}

// Session is the job's session: for Webshare a sticky session of its own,
// numbered from the job, its attempt and rotation (0, or 1 after an exit
// failure), so that the same lease always maps to the same session and every
// connection of one job leaves from one exit; for http the proxy's fixed
// sign-in, the same for every job.
func (p *WebProxy) Session(job, attempt string, rotation int) ProxySession {
	if p == nil {
		return ProxySession{}
	}
	s := ProxySession{Host: p.Host, Port: p.Port}
	switch p.Provider {
	case ProxyWebshare:
		s.Sticky = true
		s.Authorization = basicAuthorization(p.Username+"-"+p.Country+"-"+proxySessionID(proxySessionKey, job, attempt, rotation), p.Password)
	case ProxyHTTP:
		if p.Username != "" {
			s.Authorization = basicAuthorization(p.Username, p.Password)
		}
	}
	return s
}

// proxySessionID is the 9-digit decimal session number for a job: the first
// eight bytes of HMAC-SHA256(key, "job/attempt/rotation"), brought into
// 100000000-999999999 so it never starts with a zero.
func proxySessionID(key []byte, job, attempt string, rotation int) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(job + "/" + attempt + "/" + strconv.Itoa(rotation)))
	n := binary.BigEndian.Uint64(mac.Sum(nil)[:8])
	return strconv.FormatUint(100_000_000+n%900_000_000, 10)
}

func basicAuthorization(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// ParseWebProxy reads one proxy object: SCARLETT_WEB_EGRESS_PROXY_FILE's
// content, or the web_egress_proxy of the desktop start line. Its keys are
// unique and known, its strings strings and its port an integer:
//
//	{"provider":"webshare","username":…,"password":…,"country":"us","port":80|1080|3128,"use":"limited_sites"|"all"}
//	{"provider":"http","host":…,"port":…,["username":…,"password":…,]"use":"all"}
//
// Errors never repeat the content, which holds credentials.
func ParseWebProxy(raw []byte) (*WebProxy, error) {
	invalid := errors.New("invalid web egress proxy")
	fields, ok := uniqueObject(raw)
	if !ok {
		return nil, invalid
	}
	p := &WebProxy{}
	texts := map[string]*string{"provider": &p.Provider, "host": &p.Host, "username": &p.Username, "password": &p.Password, "country": &p.Country, "use": &p.Use}
	for name, value := range fields {
		if name == "port" {
			if p.Port, ok = portValue(value); !ok {
				return nil, invalid
			}
			continue
		}
		target, known := texts[name]
		if !known {
			return nil, invalid
		}
		if *target, ok = stringValue(value); !ok {
			return nil, invalid
		}
	}
	switch p.Provider {
	case ProxyWebshare:
		_, named := fields["host"]
		if len(fields) != 6 || named {
			return nil, invalid
		}
		p.Host = WebshareHost
	case ProxyHTTP:
		_, user := fields["username"]
		_, password := fields["password"]
		_, country := fields["country"]
		if user != password || country || len(fields) != 4 && len(fields) != 6 {
			return nil, invalid
		}
	default:
		return nil, invalid
	}
	if !p.valid() {
		return nil, invalid
	}
	return p, nil
}

func (p WebProxy) valid() bool {
	switch p.Provider {
	case ProxyWebshare:
		return p.Host == WebshareHost && (p.Port == 80 || p.Port == 1080 || p.Port == 3128) && p.Country == WebshareCountry &&
			(p.Use == ProxyUseLimitedSites || p.Use == ProxyUseAll) && alnum(p.Username, maxWebshareUsername) && proxySecret(p.Password, false)
	case ProxyHTTP:
		return p.Port >= 1 && p.Port <= 65535 && validProxyHost(p.Host) && p.Country == "" && p.Use == ProxyUseAll &&
			(p.Username == "" && p.Password == "" || proxySecret(p.Username, true) && proxySecret(p.Password, false))
	}
	return false
}

// validProxyHost is an IP literal or a DNS name of letters, digits, hyphens
// and dots.
func validProxyHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func alnum(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z' || s[i] >= '0' && s[i] <= '9') {
			return false
		}
	}
	return true
}

// proxySecret is 1-128 printable ASCII bytes without spaces; a username may
// not hold the colon that ends it in Basic authorization.
func proxySecret(s string, username bool) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' || username && s[i] == ':' {
			return false
		}
	}
	return true
}

// ReadWebProxyFile reads SCARLETT_WEB_EGRESS_PROXY_FILE: an absolute path to
// a private regular file (mode 0600 on macOS and Linux) of at most 4 KiB
// holding one ParseWebProxy object. Errors name the variable, never the
// path's contents.
func ReadWebProxyFile(path string) (*WebProxy, error) {
	const env = "SCARLETT_WEB_EGRESS_PROXY_FILE"
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New(env + " must be a clean absolute path")
	}
	f, err := localfs.OpenPrivateInherited(path)
	if err != nil {
		return nil, errors.New(env + " must name a private regular file (mode 0600) readable by this user")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxWebProxyBytes+1))
	if err != nil || len(raw) > maxWebProxyBytes {
		return nil, errors.New(env + " is unreadable or larger than 4 KiB")
	}
	p, err := ParseWebProxy(bytes.TrimSpace(raw))
	if err != nil {
		return nil, errors.New("invalid " + env + "; it holds one JSON object with provider webshare or http")
	}
	return p, nil
}

// MaxDesktopStartLine bounds the desktop app's start line, without its
// newline.
const MaxDesktopStartLine = maxWebProxyBytes

// ParseDesktopStart reads the line the desktop app writes to `desktop run`
// before anything else, without its newline: {} or
// {"web_egress_proxy":{…}} holding a Webshare proxy. It returns that proxy,
// or nil for {}. Errors never repeat the line.
func ParseDesktopStart(line []byte) (*WebProxy, error) {
	invalid := errors.New("invalid desktop start line")
	if len(line) > MaxDesktopStartLine {
		return nil, invalid
	}
	fields, ok := uniqueObject(line)
	if !ok {
		return nil, invalid
	}
	if len(fields) == 0 {
		return nil, nil
	}
	raw, present := fields["web_egress_proxy"]
	if !present || len(fields) != 1 {
		return nil, invalid
	}
	p, err := ParseWebProxy(raw)
	if err != nil || p.Provider != ProxyWebshare {
		return nil, invalid
	}
	return p, nil
}

// UseDesktopProxy merges the start line's proxy into a loaded configuration.
// The desktop app never sets SCARLETT_WEB_EGRESS_PROXY_FILE, so a node given
// both refuses to start rather than pick one.
func (c *Config) UseDesktopProxy(p *WebProxy) error {
	if p == nil {
		return nil
	}
	if c.Executor != ExecutorServices {
		return errors.New("the desktop web egress proxy requires services executor")
	}
	if c.WebEgressProxy != nil {
		return errors.New("the desktop web egress proxy and SCARLETT_WEB_EGRESS_PROXY_FILE are both set")
	}
	c.WebEgressProxy = p
	return c.Validate()
}

// uniqueObject decodes one JSON object whose keys are unique, with nothing
// after it.
func uniqueObject(raw []byte) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(raw))
	if d.Decode(&fields) != nil || fields == nil || d.Decode(new(any)) != io.EOF {
		return nil, false
	}
	// A repeated key collapses in the map; count the keys as written.
	t := json.NewDecoder(bytes.NewReader(raw))
	if open, err := t.Token(); err != nil || open != json.Delim('{') {
		return nil, false
	}
	keys := 0
	for t.More() {
		var value json.RawMessage
		if _, err := t.Token(); err != nil || t.Decode(&value) != nil {
			return nil, false
		}
		keys++
	}
	return fields, keys == len(fields)
}

func stringValue(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// portValue is a JSON integer 1-65535 written without sign, fraction,
// exponent or leading zero.
func portValue(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 || len(raw) > 5 || raw[0] == '0' {
		return 0, false
	}
	for _, b := range raw {
		if b < '0' || b > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(string(raw))
	return n, err == nil && n >= 1 && n <= 65535
}
