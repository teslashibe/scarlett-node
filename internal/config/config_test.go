package config

import (
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

	for _, ca := range []string{"relative.pem", "/tmp/synthetic-ca.pem"} {
		copy := c
		copy.CoordinatorCA = ca
		if (copy.Validate() == nil) != (ca == "/tmp/synthetic-ca.pem") {
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
	c := Config{Coordinator: "https://example.org", Executor: ExecutorServices, Services: []string{"x_read"}, XSession: "/tmp/synthetic-x.json", Verifier: "127.0.0.1:7047", Prover: "scarlett-prover", Profile: "p", StateDir: filepath.Join(t.TempDir(), "state"), InferenceTimeout: time.Second, MaxInputBytes: 1024, MaxOutputTokens: 128, CodexConcurrency: 1, XConcurrency: 1}
	if e := c.Validate(); e != nil {
		t.Fatal("X-only requires unused gateway or Codex", e)
	}
	c.Services = []string{"codex", "x_read"}
	c.CodexHome = "/tmp/synthetic-codex"
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
