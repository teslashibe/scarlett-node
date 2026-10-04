package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
	for _, change := range []func(*Config){func(c *Config) { c.XSession = "relative" }, func(c *Config) { c.CodexHome = "" }, func(c *Config) { c.XConcurrency = 33 }, func(c *Config) { c.CodexConcurrency = 0 }, func(c *Config) { c.LocalFixture = true }, func(c *Config) { c.Verifier = "https://arbitrary/path" }} {
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
	if err != nil || c.JournalLimits.MaxRecords != 4096 {
		t.Fatal(c.JournalLimits, err)
	}
	for _, bad := range []string{"0", "1000001", "garbage", "-1"} {
		t.Setenv("SCARLETT_JOURNAL_MAX_RECORDS", bad)
		if _, err := Load(); err == nil {
			t.Fatal("invalid limit accepted", bad)
		}
	}
}
