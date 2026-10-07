package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
)

func TestOrigins(t *testing.T) {
	c := Config{Coordinator: "https://example.org", Executor: ExecutorGateway, Gateway: "http://127.0.0.1:8080", Profile: "p", StateDir: filepath.Join(t.TempDir(), "state"), InferenceTimeout: time.Second, MaxInputBytes: 1, MaxOutputTokens: 1}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://example.org", "http://127.0.0.1", "https://example.org/path", "https://user:secret@example.org"} {
		copy := c
		copy.Coordinator = bad
		if copy.Validate() == nil {
			t.Fatalf("accepted coordinator %s", bad)
		}
	}

	for _, ca := range []string{"relative.pem", filepath.Join(t.TempDir(), "synthetic-ca.pem")} {
		copy := c
		copy.CoordinatorCA = ca
		if (copy.Validate() == nil) != filepath.IsAbs(ca) {
			t.Fatal("coordinator CA path validation wrong")
		}
	}
	local := Config{Coordinator: "http://host.docker.internal:8091", Executor: ExecutorGateway, Gateway: "http://agent1-gateway:8088", Profile: "local-fixture", StateDir: filepath.Join(t.TempDir(), "state"), NodeID: "terra", Credential: "local-sim-terra-credential-not-a-wallet", LocalFixture: true, InferenceTimeout: time.Second, MaxInputBytes: 32, MaxOutputTokens: 128}
	if err := local.Validate(); err != nil {
		t.Fatalf("local Docker fixture rejected: %v", err)
	}
	local.Gateway = "http://agent2-gateway:8088"
	if err := local.Validate(); err != nil {
		t.Fatalf("luna on agent2 rejected: %v", err)
	}
	local.Gateway = "http://agent3-gateway:8088"
	if err := local.Validate(); err != nil {
		t.Fatalf("terra on agent3 rejected: %v", err)
	}
	local.Gateway = "http://agent4-gateway:8088"
	if err := local.Validate(); err != nil {
		t.Fatalf("sol on agent4 rejected: %v", err)
	}
	local.Gateway = "http://agent9-gateway:8088"
	if local.Validate() == nil {
		t.Fatal("accepted unknown Docker gateway")
	}
	local.Gateway = "http://agent2-gateway:8088"
	local.Credential = ""
	if local.Validate() == nil {
		t.Fatal("accepted local fixture without a node credential")
	}
	local.Credential = "local-sim-terra-credential-not-a-wallet"
	local.LocalFixture = false
	if local.Validate() == nil {
		t.Fatal("accepted plaintext Docker services outside local fixture")
	}
	local.LocalFixture = true
	local.Coordinator = "http://example.org:8091"
	if local.Validate() == nil {
		t.Fatal("accepted remote plaintext fixture coordinator")
	}
	c.Gateway = "http://example.org:8080"
	if c.Validate() == nil {
		t.Fatal("accepted remote plaintext gateway")
	}
}

func TestCodexTLSN(t *testing.T) {
	c := Config{Coordinator: "https://example.org", Executor: ExecutorCodexTLSN, Verifier: "127.0.0.1:7047", Prover: "scarlett-prover", Profile: "p", StateDir: filepath.Join(t.TempDir(), "state"), InferenceTimeout: time.Second, MaxInputBytes: 1, MaxOutputTokens: 1}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Verifier = "chatgpt.com"
	if c.Validate() == nil {
		t.Fatal("accepted verifier without a port")
	}
	c.Verifier = "127.0.0.1:7047"
	c.Executor = "other"
	if c.Validate() == nil {
		t.Fatal("accepted unknown executor")
	}
	local := Config{Coordinator: "http://host.docker.internal:8091", Executor: ExecutorCodexTLSN, Verifier: "verifier:7047", Prover: "scarlett-prover", Profile: "local-fixture", StateDir: filepath.Join(t.TempDir(), "state"), NodeID: "terra", Credential: "local-sim-terra-credential-not-a-wallet", LocalFixture: true, InferenceTimeout: time.Second, MaxInputBytes: 32, MaxOutputTokens: 128}
	if err := local.Validate(); err != nil {
		t.Fatalf("local TLSN fixture rejected: %v", err)
	}
	local.Verifier = "127.0.0.1:7047"
	if local.Validate() == nil {
		t.Fatal("accepted unpinned fixture verifier")
	}
}

func TestIndependentProvenServices(t *testing.T) {
	c := Config{Coordinator: "https://example.org", Executor: ExecutorServices, Services: []string{"x_read"}, XSession: filepath.Join(t.TempDir(), "synthetic-x.json"), Verifier: "127.0.0.1:7047", Prover: "scarlett-prover", Profile: "p", StateDir: filepath.Join(t.TempDir(), "state"), InferenceTimeout: time.Second, MaxInputBytes: 1024, MaxOutputTokens: 128, CodexConcurrency: 1, XConcurrency: 1}
	if e := c.Validate(); e != nil {
		t.Fatal("X-only requires unused gateway or Codex", e)
	}
	c.Services = []string{"codex", "x_read"}
	c.CodexHome = filepath.Join(t.TempDir(), "synthetic-codex")
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, services := range [][]string{nil, {"codex", "codex"}, {"x"}, {"unrestricted"}, {"codex", "x_read", "other"}} {
		bad := c
		bad.Services = services
		if bad.Validate() == nil {
			t.Fatal("accepted invalid services")
		}
	}
	for _, change := range []func(*Config){func(c *Config) { c.XSession = "relative" }, func(c *Config) { c.CodexHome = "" }, func(c *Config) { c.XConcurrency = 33 }, func(c *Config) { c.XAccountConcurrency = -1 }, func(c *Config) { c.XAccountConcurrency = 33 }, func(c *Config) { c.CodexConcurrency = 0 }, func(c *Config) { c.LocalFixture = true }, func(c *Config) { c.Verifier = "https://arbitrary/path" }} {
		bad := c
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("accepted unsafe service configuration")
		}
	}
}

func TestVerifierTLSConfiguration(t *testing.T) {
	c := Config{Coordinator: "https://example.org", Executor: ExecutorCodexTLSN, Verifier: "verifier.example.org:7047", Prover: "scarlett-prover", Profile: "standard", StateDir: filepath.Join(t.TempDir(), "state"), InferenceTimeout: time.Second, MaxInputBytes: 1024, MaxOutputTokens: 20}
	c.VerifierCA = filepath.Join(t.TempDir(), "public-test-ca.pem")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.VerifierCA = "relative.pem"
	if c.Validate() == nil {
		t.Fatal("relative verifier CA accepted")
	}
	c.VerifierCA = ""
	c.VerifierPlaintextFixture = true
	if c.Validate() == nil {
		t.Fatal("community plaintext verifier accepted")
	}
	c.LocalFixture = true
	c.Profile = "local-fixture"
	c.Coordinator = "http://host.docker.internal:8091"
	c.NodeID = "synthetic-node"
	c.Credential = "synthetic-local-credential-never-used-remotely"
	c.Verifier = "verifier:7047"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.VerifierCA = filepath.Join(t.TempDir(), "public-test-ca.pem")
	if c.Validate() == nil {
		t.Fatal("mixed fixture plaintext and CA accepted")
	}
}

// Relay is on unless the operator sets SCARLETT_X_RELAY=0; anything else,
// including the old opt-in value and an unset variable, leaves it on.
func TestKeyedRelayDefaultsOnWithExplicitOptOut(t *testing.T) {
	t.Setenv("SCARLETT_COORDINATOR", "https://example.org")
	t.Setenv("SCARLETT_PROFILE", "synthetic")
	t.Setenv("SCARLETT_EXECUTOR", ExecutorServices)
	t.Setenv("SCARLETT_SERVICES", "x_read")
	t.Setenv("SCARLETT_VERIFIER", "127.0.0.1:7047")
	t.Setenv("SCARLETT_PROVER", "scarlett-prover")
	t.Setenv("SCARLETT_X_SESSION", filepath.Join(t.TempDir(), "synthetic-x.json"))
	for _, tc := range []struct {
		value string
		set   bool
		relay bool
	}{{"", false, true}, {"1", true, true}, {"0", true, false}, {"false", true, false}, {"OFF", true, false}, {" no ", true, false}, {"yes", true, true}, {"", true, true}} {
		if tc.set {
			t.Setenv("SCARLETT_X_RELAY", tc.value)
		} else {
			os.Unsetenv("SCARLETT_X_RELAY")
		}
		c, err := Load()
		if err != nil {
			t.Fatalf("SCARLETT_X_RELAY=%q set=%v: %v", tc.value, tc.set, err)
		}
		if c.XRelay != tc.relay {
			t.Fatalf("SCARLETT_X_RELAY=%q set=%v: relay %v, want %v", tc.value, tc.set, c.XRelay, tc.relay)
		}
	}
}

func TestXPacingModeRequiresExplicitBoundedOptIn(t *testing.T) {
	t.Setenv("SCARLETT_COORDINATOR", "https://example.org")
	t.Setenv("SCARLETT_PROFILE", "synthetic")
	t.Setenv("SCARLETT_EXECUTOR", ExecutorServices)
	t.Setenv("SCARLETT_SERVICES", "x_read")
	t.Setenv("SCARLETT_VERIFIER", "127.0.0.1:7047")
	t.Setenv("SCARLETT_PROVER", "scarlett-prover")
	t.Setenv("SCARLETT_X_SESSION", filepath.Join(t.TempDir(), "synthetic-x.json"))
	for _, tc := range []struct{ value, want string }{{"", "conservative"}, {"conservative", "conservative"}, {" quota_budget ", "quota_budget"}, {"fast", ""}, {"QUOTA_BUDGET", ""}} {
		t.Setenv("SCARLETT_X_PACING_MODE", tc.value)
		c, err := Load()
		if tc.want == "" {
			if err == nil {
				t.Fatal("unreviewed pacing mode accepted", tc.value)
			}
			continue
		}
		if err != nil || c.XPacingMode != tc.want {
			t.Fatal("incorrect pacing policy", tc, c.XPacingMode, err)
		}
	}
}

// The warm X client's background refresh interval defaults to 30 minutes and
// takes 60 s to a day; anything else is a configuration error.
func TestXRefreshIntervalDefaultsAndBounds(t *testing.T) {
	t.Setenv("SCARLETT_COORDINATOR", "https://example.org")
	t.Setenv("SCARLETT_PROFILE", "synthetic")
	t.Setenv("SCARLETT_EXECUTOR", ExecutorServices)
	t.Setenv("SCARLETT_SERVICES", "x_read")
	t.Setenv("SCARLETT_VERIFIER", "127.0.0.1:7047")
	t.Setenv("SCARLETT_PROVER", "scarlett-prover")
	t.Setenv("SCARLETT_X_SESSION", filepath.Join(t.TempDir(), "synthetic-x.json"))
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{{"", 30 * time.Minute}, {"60", time.Minute}, {"1800", 30 * time.Minute}, {"86400", 24 * time.Hour}, {"59", 0}, {"86401", 0}, {"soon", 0}} {
		if tc.value == "" {
			os.Unsetenv("SCARLETT_X_REFRESH_SECONDS")
		} else {
			t.Setenv("SCARLETT_X_REFRESH_SECONDS", tc.value)
		}
		c, err := Load()
		if tc.want == 0 {
			if err == nil {
				t.Fatalf("SCARLETT_X_REFRESH_SECONDS=%q accepted", tc.value)
			}
			continue
		}
		if err != nil || c.XRefresh != tc.want {
			t.Fatalf("SCARLETT_X_REFRESH_SECONDS=%q: %v, refresh %v, want %v", tc.value, err, c.XRefresh, tc.want)
		}
	}
	// Outside services mode the field stays zero and the worker default applies.
	os.Unsetenv("SCARLETT_X_REFRESH_SECONDS")
	t.Setenv("SCARLETT_EXECUTOR", ExecutorGateway)
	t.Setenv("SCARLETT_GATEWAY", "http://127.0.0.1:8080")
	os.Unsetenv("SCARLETT_SERVICES")
	if c, err := Load(); err != nil || c.XRefresh != 0 {
		t.Fatal("refresh interval set outside services mode", err, c.XRefresh)
	}
}

func TestJournalCapacityEnvironment(t *testing.T) {
	t.Setenv("SCARLETT_COORDINATOR", "https://example.org")
	t.Setenv("SCARLETT_PROFILE", "synthetic")
	t.Setenv("SCARLETT_GATEWAY", "http://127.0.0.1:8080")
	t.Setenv("SCARLETT_JOURNAL_MAX_RECORDS", "4096")
	t.Setenv("SCARLETT_JOURNAL_MAX_RECORD_BYTES", "192000")
	t.Setenv("SCARLETT_JOURNAL_MAX_TOTAL_BYTES", "268435456")
	c, err := Load()
	if err != nil || c.JournalLimits.MaxRecords != 4096 || c.JournalLimits.MaxTerminalRecords != attempts.DefaultLimits().MaxTerminalRecords || c.JournalLimits.MaxTerminalBytes != attempts.DefaultLimits().MaxTerminalBytes {
		t.Fatal(c.JournalLimits, err)
	}
	t.Setenv("SCARLETT_JOURNAL_MAX_TERMINAL_RECORDS", "250000")
	t.Setenv("SCARLETT_JOURNAL_MAX_TERMINAL_BYTES", "536870912")
	if c, err = Load(); err != nil || c.JournalLimits.MaxTerminalRecords != 250000 || c.JournalLimits.MaxTerminalBytes != 536870912 {
		t.Fatal(c.JournalLimits, err)
	}
	for name, values := range map[string][]string{
		"SCARLETT_JOURNAL_MAX_RECORDS":          {"0", "1000001", "garbage", "-1"},
		"SCARLETT_JOURNAL_MAX_TERMINAL_RECORDS": {"0", "1000001", "garbage", "-1"},
		"SCARLETT_JOURNAL_MAX_TERMINAL_BYTES":   {"0", "191999", "17179869185", "garbage", "-1"},
	} {
		good := os.Getenv(name)
		for _, bad := range values {
			t.Setenv(name, bad)
			if _, err := Load(); err == nil {
				t.Fatal("invalid limit accepted", name, bad)
			}
		}
		t.Setenv(name, good)
	}
}

func TestManagedCodexRootIsExplicitServicesOptIn(t *testing.T) {
	c := Config{Prover: "scarlett-prover", Profile: "synthetic", Coordinator: "https://example.org", Executor: ExecutorServices, Services: []string{"codex"}, AccountsFile: filepath.Join(t.TempDir(), "accounts.json"), StateDir: filepath.Join(t.TempDir(), "state"), CodexConcurrency: 1, XConcurrency: 1, InferenceTimeout: time.Second, MaxInputBytes: 1, MaxOutputTokens: 1, Verifier: "example.org:7047"}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.CodexManagedRoot = filepath.Join(t.TempDir(), "managed")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"relative", c.CodexManagedRoot + string(filepath.Separator) + "..", c.CodexManagedRoot + "\n"} {
		copy := c
		copy.CodexManagedRoot = root
		if copy.Validate() == nil {
			t.Fatal("invalid managedroot accepted")
		}
	}
	c.Executor = ExecutorCodex
	if c.Validate() == nil {
		t.Fatal("managed renewal allowed outside services pool")
	}
}

func TestWebServiceConfiguration(t *testing.T) {
	t.Setenv("SCARLETT_COORDINATOR", "https://example.org")
	t.Setenv("SCARLETT_PROFILE", "synthetic")
	t.Setenv("SCARLETT_EXECUTOR", ExecutorServices)
	t.Setenv("SCARLETT_VERIFIER", "127.0.0.1:7047")
	t.Setenv("SCARLETT_PROVER", "scarlett-prover")
	t.Setenv("SCARLETT_X_SESSION", filepath.Join(t.TempDir(), "synthetic-x.json"))
	// Web alone needs no credential path at all.
	t.Setenv("SCARLETT_SERVICES", "web")
	c, err := Load()
	if err != nil || !c.Enabled("web") || c.Enabled("x_read") || c.WebConcurrency != 4 || c.WebEgressProxy != nil || c.WebEgress() != "direct" {
		t.Fatal("web-only node", err, c.WebConcurrency)
	}
	for services, ok := range map[string]bool{"codex,x_read,web": true, "x_read,web": true, "web,web": false, "web,browser": false, "codex,x_read,web,web": false, "": false} {
		t.Setenv("SCARLETT_SERVICES", services)
		if _, err := Load(); (err == nil) != ok {
			t.Errorf("SCARLETT_SERVICES=%q: %v", services, err)
		}
	}
	t.Setenv("SCARLETT_SERVICES", "web")
	for value, want := range map[string]int{"1": 1, "32": 32, "0": 0, "33": 0, "four": 0} {
		t.Setenv("SCARLETT_WEB_CONCURRENCY", value)
		c, err := Load()
		if want == 0 {
			if err == nil {
				t.Errorf("SCARLETT_WEB_CONCURRENCY=%q accepted", value)
			}
			continue
		}
		if err != nil || c.WebConcurrency != want {
			t.Errorf("SCARLETT_WEB_CONCURRENCY=%q: %v %d", value, err, c.WebConcurrency)
		}
	}
	os.Unsetenv("SCARLETT_WEB_CONCURRENCY")
	for _, tc := range []struct {
		raw, host, auth string
		port            int
	}{
		{"http://proxy.example:8080", "proxy.example", "", 8080},
		{"http://proxy.example:8080/", "proxy.example", "", 8080},
		{"http://127.0.0.1:3128", "127.0.0.1", "", 3128},
		{"http://[::1]:3128", "::1", "", 3128},
		{"http://user:p%40ss@proxy.example:8080", "proxy.example", "Basic dXNlcjpwQHNz", 8080},
		{"http://user@proxy.example:8080", "proxy.example", "Basic dXNlcjo=", 8080},
	} {
		t.Setenv("SCARLETT_WEB_EGRESS_PROXY", tc.raw)
		c, err := Load()
		if err != nil || c.WebEgressProxy == nil || c.WebEgressProxy.Host != tc.host || c.WebEgressProxy.Port != tc.port || c.WebEgressProxy.Authorization != tc.auth || c.WebEgress() != "proxy" {
			t.Errorf("%q: %v %+v", tc.raw, err, c.WebEgressProxy)
		}
	}
	for _, bad := range []string{"https://proxy.example:8080", "socks5://proxy.example:1080", "http://proxy.example", "http://proxy.example:0", "http://proxy.example:65536", "http://proxy.example:80a", "http://proxy.example:8080/path", "http://proxy.example:8080?x=1", "http://proxy.example:8080#f", "http://:secret@proxy.example:8080", "proxy.example:8080", "http://pro_xy.example:8080", "http://user:secret@:8080"} {
		t.Setenv("SCARLETT_WEB_EGRESS_PROXY", bad)
		_, err := Load()
		if err == nil {
			t.Errorf("%q accepted", bad)
			continue
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "proxy.example") {
			t.Errorf("error repeats the value: %v", err)
		}
	}
	// The proxy belongs to the services executor only.
	t.Setenv("SCARLETT_WEB_EGRESS_PROXY", "http://proxy.example:8080")
	t.Setenv("SCARLETT_EXECUTOR", ExecutorGateway)
	t.Setenv("SCARLETT_GATEWAY", "http://127.0.0.1:8080")
	os.Unsetenv("SCARLETT_SERVICES")
	if _, err := Load(); err == nil {
		t.Fatal("egress proxy accepted outside services mode")
	}
}

func TestWebBrowserConfiguration(t *testing.T) {
	if !WebBrowserDefault("darwin") || !WebBrowserDefault("linux") || WebBrowserDefault("windows") {
		t.Fatal("browser tier defaults: on for macOS and Linux, off for Windows")
	}
	for _, name := range []string{"SCARLETT_WEB_BROWSER", "SCARLETT_WEB_BROWSER_CONCURRENCY", "SCARLETT_WEB_BROWSER_IDLE_SECONDS", "SCARLETT_WEB_CONCURRENCY"} {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	load := func(goos string) (Config, error) {
		c := Config{Services: []string{"web"}}
		err := c.loadWebBrowser(goos)
		return c, err
	}
	for goos, want := range map[string]bool{"darwin": true, "linux": true, "windows": false} {
		c, err := load(goos)
		if err != nil || c.WebBrowser != want || c.WebBrowserConcurrency != 0 || c.WebBrowserIdle != 120*time.Second {
			t.Fatalf("%s default: %v %v", goos, c.WebBrowser, err)
		}
	}
	for value, want := range map[string]bool{"on": true, "ON": true, "1": true, "true": true, "off": false, "0": false, "false": false} {
		t.Setenv("SCARLETT_WEB_BROWSER", value)
		for _, goos := range []string{"darwin", "windows"} {
			if c, err := load(goos); err != nil || c.WebBrowser != want {
				t.Fatalf("SCARLETT_WEB_BROWSER=%q on %s: %v %v", value, goos, c.WebBrowser, err)
			}
		}
	}
	t.Setenv("SCARLETT_WEB_BROWSER", "maybe")
	if _, err := load("darwin"); err == nil {
		t.Fatal("SCARLETT_WEB_BROWSER=maybe accepted")
	}
	// The browser needs web: without it the tier is off.
	t.Setenv("SCARLETT_WEB_BROWSER", "on")
	if c := (Config{Services: []string{"x_read"}}); c.loadWebBrowser("darwin") != nil || c.WebBrowser {
		t.Fatal("browser on without web")
	}
	os.Unsetenv("SCARLETT_WEB_BROWSER")
	for value, want := range map[string]int{"1": 1, "4": 4, "0": -1, "5": -1, "two": -1} {
		t.Setenv("SCARLETT_WEB_BROWSER_CONCURRENCY", value)
		c, err := load("darwin")
		if (err == nil) != (want > 0) || want > 0 && c.WebBrowserConcurrency != want {
			t.Errorf("SCARLETT_WEB_BROWSER_CONCURRENCY=%q: %v %d", value, err, c.WebBrowserConcurrency)
		}
	}
	os.Unsetenv("SCARLETT_WEB_BROWSER_CONCURRENCY")
	for value, want := range map[string]time.Duration{"30": 30 * time.Second, "3600": time.Hour, "29": 0, "3601": 0, "x": 0} {
		t.Setenv("SCARLETT_WEB_BROWSER_IDLE_SECONDS", value)
		c, err := load("darwin")
		if (err == nil) != (want > 0) || want > 0 && c.WebBrowserIdle != want {
			t.Errorf("SCARLETT_WEB_BROWSER_IDLE_SECONDS=%q: %v %v", value, err, c.WebBrowserIdle)
		}
	}
	os.Unsetenv("SCARLETT_WEB_BROWSER_IDLE_SECONDS")

	// Through Load: on this host's default, never above web concurrency, and
	// only with the services executor.
	t.Setenv("SCARLETT_COORDINATOR", "https://example.org")
	t.Setenv("SCARLETT_PROFILE", "synthetic")
	t.Setenv("SCARLETT_EXECUTOR", ExecutorServices)
	t.Setenv("SCARLETT_VERIFIER", "127.0.0.1:7047")
	t.Setenv("SCARLETT_PROVER", "scarlett-prover")
	t.Setenv("SCARLETT_SERVICES", "web")
	c, err := Load()
	if err != nil || c.WebBrowser != WebBrowserDefault(runtime.GOOS) {
		t.Fatal("loaded browser default", err, c.WebBrowser)
	}
	t.Setenv("SCARLETT_WEB_BROWSER", "on")
	t.Setenv("SCARLETT_WEB_CONCURRENCY", "2")
	t.Setenv("SCARLETT_WEB_BROWSER_CONCURRENCY", "3")
	if _, err := Load(); err == nil {
		t.Fatal("browser concurrency above web concurrency accepted")
	}
	t.Setenv("SCARLETT_WEB_BROWSER_CONCURRENCY", "2")
	if c, err := Load(); err != nil || !c.WebBrowser || c.WebBrowserConcurrency != 2 {
		t.Fatal("browser concurrency at web concurrency", err)
	}
	t.Setenv("SCARLETT_WEB_BROWSER", "off")
	t.Setenv("SCARLETT_WEB_BROWSER_CONCURRENCY", "4")
	if c, err := Load(); err != nil || c.WebBrowser {
		t.Fatal("browser off ignores its concurrency", err)
	}
	t.Setenv("SCARLETT_EXECUTOR", ExecutorGateway)
	t.Setenv("SCARLETT_SERVICES", "")
	t.Setenv("SCARLETT_GATEWAY", "http://127.0.0.1:8088")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SCARLETT_WEB_BROWSER") {
		t.Fatal("browser settings accepted without the services executor", err)
	}
	os.Unsetenv("SCARLETT_WEB_BROWSER")
	os.Unsetenv("SCARLETT_WEB_BROWSER_CONCURRENCY")
	if _, err := Load(); err != nil {
		t.Fatal("gateway node", err)
	}
}
