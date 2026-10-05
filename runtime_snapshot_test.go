package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestXRuntimeSnapshotMatchesReviewedSource(t *testing.T) {
	const root = "third_party/x-go"
	raw, err := os.ReadFile(filepath.Join(root, "UPSTREAM.json"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Module         string            `json:"module"`
		SourceRevision string            `json:"source_revision"`
		SHA256         map[string]string `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Module != "github.com/teslashibe/x-go" || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(metadata.SourceRevision) {
		t.Fatal("runtime snapshot requires an exact reviewed upstream commit")
	}
	files, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil || len(files) == 0 || len(files) != len(metadata.SHA256) {
		t.Fatal("runtime source inventory does not match provenance")
	}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		if metadata.SHA256[filepath.Base(file)] != hex.EncodeToString(sum[:]) {
			t.Fatalf("runtime source does not match reviewed provenance: %s", filepath.Base(file))
		}
	}
}
