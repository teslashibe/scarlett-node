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
