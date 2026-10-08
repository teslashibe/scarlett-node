package update

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// keys.go is generated from desktop/signing/identities.json; a pin can only
// change together with the reviewed identities file.
func TestReleasePinsMatchTheReviewedIdentities(t *testing.T) {
	raw, err := os.ReadFile("../../desktop/signing/identities.json")
	if err != nil {
		t.Fatal(err)
	}
	var identities struct {
		MacOS   struct{ SHA1, SHA256 string } `json:"macos"`
		Windows struct{ SHA256 string }       `json:"windows"`
		Updater struct {
			Minisign []struct {
				Role      string `json:"role"`
				KeyID     string `json:"keyId"`
				PublicKey string `json:"publicKey"`
			} `json:"minisign"`
		} `json:"updater"`
	}
	if err = json.Unmarshal(raw, &identities); err != nil {
		t.Fatal(err)
	}
	if identities.MacOS.SHA1 != releaseMacCertificateSHA1 || identities.MacOS.SHA256 != releaseMacCertificateSHA256 || identities.Windows.SHA256 != releaseWindowsCertificateSHA256 {
		t.Fatal("certificate pins differ from identities.json; run signing_identities.py go-pins --write")
	}
	var keys []string
	for _, k := range identities.Updater.Minisign {
		keys = append(keys, k.PublicKey)
		parsed, err := ParsePublicKey(k.PublicKey)
		if err != nil || parsed.KeyID() != k.KeyID {
			t.Fatalf("%s key %s does not match its key id", k.Role, k.KeyID)
		}
	}
	if !slices.Equal(keys, releaseMinisignKeys) {
		t.Fatal("updater keys differ from identities.json; run signing_identities.py go-pins --write")
	}
	trust, err := LoadTrust()
	if err != nil || trust.Rehearsal || len(trust.Keys) != len(keys) {
		t.Fatal("release trust did not load", err)
	}
}
