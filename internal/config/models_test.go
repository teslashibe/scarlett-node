package config

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestReviewedCodexModelContract(t *testing.T) {
	want := []string{"gpt-6.1-sol", "gpt-6-astra", "gpt-6-sol", "gpt-6-luna", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5"}
	before := time.Date(2026, 10, 13, 23, 59, 59, 0, time.UTC)
	if !reflect.DeepEqual(Models, want) || !reflect.DeepEqual(AvailableModelsAt(before), want) {
		t.Fatal("reviewed model inventory changed")
	}
	for _, model := range modelCatalog {
		if !slices.Contains(model.CodexEfforts, "low") || model.PaidEffort != "low" || model.PaidServiceTier != "default" {
			t.Fatalf("%s cannot serve the canonical paid request", model.ID)
		}
		if base, ok := Serves(model.ID); !ok || base != model.ID || !ExecutableAt(model.ID, before) {
			t.Fatalf("reviewed base %s was rejected", model.ID)
		}
	}
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	if ExecutableAt("gpt-5.5", at) || slices.Contains(AvailableModelsAt(at), "gpt-5.5") {
		t.Fatal("retired sign-in model advertised or accepted")
	}
	if base, ok := Serves("gpt-5.5"); !ok || base != "gpt-5.5" {
		t.Fatal("retirement removed historical result resolution")
	}
	for _, invalid := range []string{"gpt-6", "gpt-6-astra-high", "gpt-6.1-sol-fast", "gpt-6-luna-ultra", "gpt-5.5-high", "claude-opus-4-6", "hidden-internal"} {
		if _, ok := Serves(invalid); ok || ExecutableAt(invalid, before) {
			t.Fatalf("unreviewed execution identifier %q accepted", invalid)
		}
	}
	for _, id := range []string{"gpt-5.6-terra-fast-low", "gpt-5.6-sol-high"} {
		if !ExecutableAt(id, before) {
			t.Fatalf("legacy gateway compatibility removed: %s", id)
		}
	}
}

func TestHeartbeatFixtureMatchesReviewedInventory(t *testing.T) {
	raw, err := os.ReadFile("../../api/fixtures/heartbeat-services.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Services []struct {
			Kind   string   `json:"kind"`
			Models []string `json:"models"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Services) != 2 || fixture.Services[0].Kind != "codex" || !reflect.DeepEqual(fixture.Services[0].Models, Models) || len(fixture.Services[1].Models) != 0 {
		t.Fatal("wire fixture does not match Codex-only model contract")
	}
}
