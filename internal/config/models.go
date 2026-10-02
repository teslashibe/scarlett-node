package config

import (
	_ "embed"
	"encoding/json"
	"time"
)

//go:embed codex-model-catalog.json
var modelCatalogJSON []byte

type modelCapability struct {
	ID              string   `json:"id"`
	CodexEfforts    []string `json:"codexEfforts"`
	PaidEffort      string   `json:"paidEffort"`
	PaidServiceTier string   `json:"paidServiceTier"`
	SignInRetiresAt string   `json:"signInRetiresAt,omitempty"`
}

var modelCatalog = func() []modelCapability {
	var manifest struct {
		Models []modelCapability `json:"models"`
	}
	if err := json.Unmarshal(modelCatalogJSON, &manifest); err != nil {
		panic("invalid reviewed Codex model manifest")
	}
	return manifest.Models
}()

// These aliases are part of the existing gateway contract, not the paid proof
// contract. New model capabilities do not imply new gateway suffix support.
var legacyGatewayAliases = map[string]bool{
	"gpt-5.6-luna": true, "gpt-5.6-terra": true, "gpt-5.6-sol": true,
}

func modelIDs() []string {
	ids := make([]string, 0, len(modelCatalog))
	for _, model := range modelCatalog {
		ids = append(ids, model.ID)
	}
	return ids
}

// AvailableModelsAt returns reviewed bases eligible for new sign-in execution.
// It reports compatibility, never authenticated subscription entitlement.
func AvailableModelsAt(now time.Time) []string {
	ids := make([]string, 0, len(modelCatalog))
	for _, model := range modelCatalog {
		if model.SignInRetiresAt != "" {
			deadline, err := time.Parse(time.RFC3339, model.SignInRetiresAt)
			if err != nil || !now.Before(deadline) {
				continue
			}
		}
		ids = append(ids, model.ID)
	}
	return ids
}

// ExecutableAt rejects unknown bases/variants and retired sign-in models before
// provider execution. Historical model resolution uses Serves without this gate.
func ExecutableAt(id string, now time.Time) bool {
	base, ok := Serves(id)
	if !ok {
		return false
	}
	for _, available := range AvailableModelsAt(now) {
		if base == available {
			return true
		}
	}
	return false
}
