package worker

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// The public catalog describes requests actually emitted by the pinned runtime.
// xFixture's transports terminate locally and cannot dial X or any provider.
func TestPublicXRequestCatalogMatchesRuntime(t *testing.T) {
	raw, err := os.ReadFile("../../api/x-request-catalog.json")
	var catalog struct {
		Version         string           `json:"version"`
		PolicyReference string           `json:"policy_reference"`
		SourceModule    string           `json:"source_module"`
		SourceVersion   string           `json:"source_version"`
		Features        map[string]any   `json:"features"`
		Operations      map[string]xSpec `json:"operations"`
	}
	if err != nil || json.Unmarshal(raw, &catalog) != nil {
		t.Fatal("public X catalog unavailable", err)
	}
	if catalog.Version != coordinator.Version || catalog.PolicyReference != "x-public-v1" || catalog.SourceModule != "github.com/teslashibe/x-go" || catalog.SourceVersion != "v1.13.0" || len(catalog.Operations) != 4 {
		t.Fatal("public catalog contract drift")
	}
	for _, request := range []coordinator.XRequest{{Operation: "search", Query: "bitcoin", Count: 20, Pages: 1}, {Operation: "profile", Username: "fixture"}, {Operation: "post", PostID: "20"}, {Operation: "thread", PostID: "20"}} {
		t.Run(request.Operation, func(t *testing.T) {
			_, _, captured := xFixture(t, request)
			want, exists := catalog.Operations[request.Operation]
			if !exists {
				t.Fatal("missing public operation")
			}
			want.Features = catalog.Features
			// Use the runtime's integer-preserving decoder for exact comparison.
			expected, _ := json.Marshal(want)
			actual, _ := json.Marshal(captured.Exchanges[0])
			a, ea := uniqueJSON(actual)
			b, eb := uniqueJSON(expected)
			if ea != nil || eb != nil || !reflect.DeepEqual(a, b) {
				t.Fatal("public request catalog differs from native runtime")
			}
		})
	}
}
