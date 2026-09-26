package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOrigins(t *testing.T) {
	c := Config{Coordinator: "https://example.org", Gateway: "http://127.0.0.1:8080", Model: "a", Profile: "p", StateDir: filepath.Join(t.TempDir(), "state"), InferenceTimeout: time.Second, MaxInputBytes: 1, MaxOutputTokens: 1}
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
	local := Config{Coordinator: "http://host.docker.internal:8091", Gateway: "http://agent1-gateway:8088", Model: "gpt-5.6-terra", Profile: "local-fixture", StateDir: filepath.Join(t.TempDir(), "state"), GatewayKey: "local-fixture-key-at-least-32-bytes-long", LocalFixture: true, InferenceTimeout: time.Second, MaxInputBytes: 32, MaxOutputTokens: 128}
	if err := local.Validate(); err != nil {
		t.Fatalf("local Docker fixture rejected: %v", err)
	}
	local.Gateway = "http://agent2-gateway:8088"
	if local.Validate() == nil {
		t.Fatal("accepted agent2 gateway for agent1 model")
	}
	local.Model = "gpt-5.6-sol"
	if err := local.Validate(); err != nil {
		t.Fatalf("agent2 fixture rejected: %v", err)
	}
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
