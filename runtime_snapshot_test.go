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
	// Original upstream hashes remain intact; local changes must be explicitly
	// inventoried against the same pinned revision rather than posing as upstream.
	expected := make(map[string]string, len(metadata.SHA256))
	for name, sum := range metadata.SHA256 {
		expected[name] = sum
	}
	patchedRaw, err := os.ReadFile(filepath.Join(root, "PATCHED.json"))
	if err == nil {
		var patched struct {
			UpstreamRevision string            `json:"upstream_revision"`
			Scope            string            `json:"scope"`
			SHA256           map[string]string `json:"sha256"`
		}
		if json.Unmarshal(patchedRaw, &patched) != nil || patched.UpstreamRevision != metadata.SourceRevision || patched.Scope == "" || len(patched.SHA256) == 0 {
			t.Fatal("runtime patches require reviewed provenance against the pinned source")
		}
		for name, sum := range patched.SHA256 {
			if filepath.Base(name) != name || filepath.Ext(name) != ".go" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(sum) {
				t.Fatal("invalid patched runtime source inventory")
			}
			expected[name] = sum
		}
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil || len(files) == 0 || len(files) != len(expected) {
		t.Fatal("runtime source inventory does not match provenance")
	}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		if expected[filepath.Base(file)] != hex.EncodeToString(sum[:]) {
			t.Fatalf("runtime source does not match reviewed provenance: %s", filepath.Base(file))
		}
	}
}
