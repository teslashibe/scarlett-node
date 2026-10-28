package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const syntheticWebshare = `{"provider":"webshare","username":"synthetic0user","password":"synthetic-secret","country":"us","port":1080,"use":"limited_sites"}`

func TestParseWebProxy(t *testing.T) {
	p, err := ParseWebProxy([]byte(syntheticWebshare))
	if err != nil || *p != (WebProxy{Provider: ProxyWebshare, Host: WebshareHost, Port: 1080, Username: "synthetic0user", Password: "synthetic-secret", Country: "us", Use: ProxyUseLimitedSites}) {
		t.Fatalf("webshare: %v %#v", err, p)
	}
	for raw, want := range map[string]WebProxy{
		`{"provider":"http","host":"127.0.0.1","port":3128,"username":"synthetic","password":"synthetic-secret","use":"all"}`: {Provider: ProxyHTTP, Host: "127.0.0.1", Port: 3128, Username: "synthetic", Password: "synthetic-secret", Use: ProxyUseAll},
		`{"provider":"http","host":"proxy.lan","port":8080,"use":"all"}`:                                                      {Provider: ProxyHTTP, Host: "proxy.lan", Port: 8080, Use: ProxyUseAll},
		`{"provider":"http","host":"::1","port":65535,"use":"all"}`:                                                           {Provider: ProxyHTTP, Host: "::1", Port: 65535, Use: ProxyUseAll},
		` {"use":"all","provider":"webshare","port":80,"country":"us","password":"p","username":"A1"} `:                       {Provider: ProxyWebshare, Host: WebshareHost, Port: 80, Username: "A1", Password: "p", Country: "us", Use: ProxyUseAll},
	} {
		p, err := ParseWebProxy([]byte(raw))
		if err != nil || *p != want {
			t.Errorf("%s: %v %#v", raw, err, p)
		}
	}
	replace := func(old, new string) string { return strings.Replace(syntheticWebshare, old, new, 1) }
	for _, raw := range []string{
		"", "null", "[]", "{}", syntheticWebshare + "{}", syntheticWebshare + "x",
		replace(`"use":"limited_sites"`, `"use":"limited_sites","use":"all"`),
		replace(`"use":"limited_sites"`, `"use":"limited_sites","extra":"synthetic-secret"`),
		replace(`,"use":"limited_sites"`, ``),
		replace(`"provider":"webshare"`, `"provider":"socks5"`),
		replace(`"username":"synthetic0user"`, `"username":"synthetic-user"`),
		replace(`"username":"synthetic0user"`, `"username":"`+strings.Repeat("a", 33)+`"`),
		replace(`"username":"synthetic0user"`, `"username":""`),
		replace(`"username":"synthetic0user"`, `"username":7`),
		replace(`"password":"synthetic-secret"`, `"password":""`),
		replace(`"password":"synthetic-secret"`, `"password":"synthetic secret"`),
		replace(`"password":"synthetic-secret"`, `"password":"synthetic\r\nsecret"`),
		replace(`"country":"us"`, `"country":"gb"`),
		replace(`"use":"limited_sites"`, `"use":"some"`),
		replace(`"port":1080`, `"port":8080`),
		replace(`"port":1080`, `"port":"1080"`),
		replace(`"port":1080`, `"port":1080.0`),
		replace(`"port":1080`, `"port":01080`),
		replace(`"port":1080`, `"port":-80`),
		replace(`"provider":"webshare"`, `"provider":"webshare","host":"p.webshare.io"`),
		`{"provider":"http","host":"127.0.0.1","port":3128,"use":"limited_sites"}`,
		`{"provider":"http","host":"127.0.0.1","port":0,"use":"all"}`,
		`{"provider":"http","host":"127.0.0.1","port":65536,"use":"all"}`,
		`{"provider":"http","host":"pro_xy.lan","port":3128,"use":"all"}`,
		`{"provider":"http","host":"","port":3128,"use":"all"}`,
		`{"provider":"http","host":"127.0.0.1","port":3128,"username":"synthetic","use":"all"}`,
		`{"provider":"http","host":"127.0.0.1","port":3128,"username":"syn:thetic","password":"p","use":"all"}`,
		`{"provider":"http","host":"127.0.0.1","port":3128,"country":"us","use":"all"}`,
	} {
		_, err := ParseWebProxy([]byte(raw))
		if err == nil {
			t.Errorf("%s accepted", raw)
		} else if strings.Contains(err.Error(), "synthetic") {
			t.Errorf("error repeats the content: %v", err)
		}
	}
}

func TestReadWebProxyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("proxy file permissions are checked through ACLs on Windows")
	}
	dir := t.TempDir()
	path := writeKey(t, dir, "proxy.json", syntheticWebshare+"\n", 0o600)
	if p, err := ReadWebProxyFile(path); err != nil || p.Username != "synthetic0user" {
		t.Fatal(err, p)
	}
	for name, path := range map[string]string{
		"group-readable": writeKey(t, dir, "open.json", syntheticWebshare, 0o640),
		"over 4 KiB":     writeKey(t, dir, "large.json", syntheticWebshare+strings.Repeat(" ", 4096), 0o600),
		"unknown field":  writeKey(t, dir, "field.json", strings.Replace(syntheticWebshare, `}`, `,"session":"synthetic"}`, 1), 0o600),
		"not JSON":       writeKey(t, dir, "text.json", "synthetic0user:synthetic-secret", 0o600),
		"relative":       "proxy.json",
		"unclean":        dir + "/./proxy.json",
		"missing":        filepath.Join(dir, "missing.json"),
		"directory":      dir,
	} {
		_, err := ReadWebProxyFile(path)
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "synthetic") || !strings.Contains(err.Error(), "SCARLETT_WEB_EGRESS_PROXY_FILE") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseDesktopStart(t *testing.T) {
	if p, err := ParseDesktopStart([]byte(`{}`)); p != nil || err != nil {
		t.Fatal("empty start line", p, err)
	}
	p, err := ParseDesktopStart([]byte(`{"web_egress_proxy":` + syntheticWebshare + `}`))
	if err != nil || p == nil || p.Provider != ProxyWebshare || p.Port != 1080 || p.Use != ProxyUseLimitedSites {
		t.Fatal("proxy start line", err, p)
	}
	for _, line := range []string{
		"", "null", "{} ", `{"web_egress_proxy":null}`, `{"web_egress_proxy":{}}`, `{"other":1}`,
		`{"web_egress_proxy":` + syntheticWebshare + `,"other":1}`,
		`{"web_egress_proxy":` + syntheticWebshare + `,"web_egress_proxy":` + syntheticWebshare + `}`,
		`{"web_egress_proxy":{"provider":"http","host":"127.0.0.1","port":3128,"use":"all"}}`,
		`{"web_egress_proxy":` + strings.Replace(syntheticWebshare, `"use"`, `"pad":"`+strings.Repeat("a", 4096)+`","use"`, 1) + `}`,
	} {
		_, err := ParseDesktopStart([]byte(line))
		if line == "{} " {
			// Surrounding spaces are the reader's business; the JSON is valid.
			if err != nil {
				t.Errorf("%q refused", line)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q accepted", line)
		} else if strings.Contains(err.Error(), "synthetic") {
			t.Errorf("error repeats the line: %v", err)
		}
	}

	c := Config{Executor: ExecutorServices, Services: []string{"web"}, WebConcurrency: 4, Profile: "p", Coordinator: "https://example.org", StateDir: filepath.Join(t.TempDir(), "state"), Verifier: "127.0.0.1:7047", Prover: "scarlett-prover", CodexConcurrency: 1, XConcurrency: 1, InferenceTimeout: 45e9, MaxInputBytes: 1, MaxOutputTokens: 1}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	merged := c
	if err := merged.UseDesktopProxy(p); err != nil || merged.WebEgressProxy != p || merged.WebEgress() != "both" {
		t.Fatal("merge", err)
	}
	if err := merged.UseDesktopProxy(p); err == nil {
		t.Fatal("start line proxy merged over a proxy file")
	}
	gateway := c
	gateway.Executor = ExecutorGateway
	if gateway.UseDesktopProxy(p) == nil {
		t.Fatal("start line proxy outside services mode")
	}
	if err := c.UseDesktopProxy(nil); err != nil || c.WebEgressProxy != nil || c.WebEgress() != "direct" {
		t.Fatal("empty start line changed the configuration")
	}
}

// One lease maps to one session; another attempt, rotation or process key
// to another. Sessions are 9 digits and never start with a zero.
func TestWebProxySession(t *testing.T) {
	p, err := ParseWebProxy([]byte(syntheticWebshare))
	if err != nil {
		t.Fatal(err)
	}
	user := func(s ProxySession) (string, string) {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s.Authorization, "Basic "))
		name, password, ok := strings.Cut(string(raw), ":")
		if err != nil || !ok || !strings.HasPrefix(s.Authorization, "Basic ") {
			t.Fatalf("authorization %q", s.Authorization)
		}
		return name, password
	}
	a := p.Session("job-a", "attempt-1", 0)
	if a.Host != WebshareHost || a.Port != 1080 || !a.Sticky || a != p.Session("job-a", "attempt-1", 0) {
		t.Fatal("session not deterministic", a.Host, a.Port, a.Sticky)
	}
	name, password := user(a)
	session, ok := strings.CutPrefix(name, "synthetic0user-us-")
	if !ok || len(session) != 9 || session[0] == '0' || strings.Trim(session, "0123456789") != "" || password != "synthetic-secret" {
		t.Fatalf("session username %q", name)
	}
	seen := map[string]bool{session: true}
	for _, other := range []ProxySession{p.Session("job-a", "attempt-2", 0), p.Session("job-a", "attempt-1", 1), p.Session("job-b", "attempt-1", 0)} {
		name, _ := user(other)
		if seen[name] {
			t.Fatal("two jobs share a session")
		}
		seen[name] = true
	}
	// Another process key gives another session for the same job.
	first, second := proxySessionID(newProxySessionKey(), "job-a", "attempt-1", 0), proxySessionID(newProxySessionKey(), "job-a", "attempt-1", 0)
	if first == second || len(first) != 9 || len(second) != 9 {
		t.Fatal("process keys", first, second)
	}
	for i := range 1000 {
		if id := proxySessionID(proxySessionKey, fmt.Sprint(i), "a", 0); len(id) != 9 || id[0] == '0' {
			t.Fatal("session id", id)
		}
	}
	// An http proxy has one fixed sign-in and no session.
	h, _ := ParseWebProxy([]byte(`{"provider":"http","host":"127.0.0.1","port":3128,"username":"synthetic","password":"synthetic-secret","use":"all"}`))
	if s := h.Session("job-a", "attempt-1", 0); s.Sticky || s != h.Session("job-b", "attempt-2", 1) || s.Authorization != "Basic c3ludGhldGljOnN5bnRoZXRpYy1zZWNyZXQ=" {
		t.Fatal("http session", s.Sticky)
	}
	open, _ := ParseWebProxy([]byte(`{"provider":"http","host":"127.0.0.1","port":3128,"use":"all"}`))
	if s := open.Session("job-a", "attempt-1", 0); s.Authorization != "" {
		t.Fatal("http proxy without credentials sent some")
	}
	// Nothing formats the credentials or a session.
	var nilProxy *WebProxy
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		text := fmt.Sprintf(format, p) + fmt.Sprintf(format, *p) + fmt.Sprintf(format, a) + fmt.Sprintf(format, Config{WebEgressProxy: p}) + fmt.Sprint(nilProxy.Session("j", "a", 0))
		for _, secret := range []string{"synthetic", "c3ludGhldGlj", session, WebshareHost} {
			if strings.Contains(text, secret) {
				t.Fatalf("%s prints %s: %s", format, secret, text)
			}
		}
	}
}

func TestMain(m *testing.M) {
	os.Unsetenv("SCARLETT_WEB_EGRESS_PROXY")
	os.Unsetenv("SCARLETT_WEB_EGRESS_PROXY_FILE")
	os.Exit(m.Run())
}
