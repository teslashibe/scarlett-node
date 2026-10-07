package coordinator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	yaml "go.yaml.in/yaml/v2"
)

// webPayloadA2 is the exact verifier payload of contract §A.2.
const webPayloadA2 = `{"type":"web.fetch","proof_mode":"relay","proof_policy":"web-relay-v1","url":"https://example.com/","max_redirects":5,"max_response_bytes":10485760,"headers":[{"name":"user-agent","value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"},{"name":"accept","value":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},{"name":"accept-language","value":"en-US,en;q=0.9"}]}`

func readLeaseFixture(t *testing.T, name string) Lease {
	t.Helper()
	raw, err := os.ReadFile("../../api/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var l Lease
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

// The web fixtures carry the A.2 payload byte for byte, and their digests are
// what the app computes: input over Go's encoding of web_request, request over
// the sorted-key canonical payload.
func TestWebLeaseFixturesBindTheExactPayload(t *testing.T) {
	for _, name := range []string{"lease-web-offer.json", "lease-web.json"} {
		l := readLeaseFixture(t, name)
		if l.ServiceType != "web" || l.WebRequest == nil || *l.WebRequest != (WebRequest{Operation: "scrape", URL: "https://example.com/"}) || !bytes.Equal(l.WebPayload, []byte(webPayloadA2)) {
			t.Fatalf("%s: unexpected web terms", name)
		}
		request, _ := json.Marshal(l.WebRequest)
		if sum := sha256.Sum256(request); hex.EncodeToString(sum[:]) != l.InputSHA256 || l.InputSHA256 != "7afc6139ad4118976d0b226e279ab1a668e2d73009b84043efefe4e98c89d0ab" {
			t.Fatalf("%s: input digest", name)
		}
		if l.RequestSHA256 != "71dba31576cd0825efd7ec112e1693f2274fd7e2d6b5fb55e0f903b435f053a1" || l.ModelID != "" || l.Prompt != "" || l.XRequest != nil || len(l.XPayload) != 0 || len(l.CodexPayload) != 0 {
			t.Fatalf("%s: unexpected shape", name)
		}
		if (name == "lease-web.json") != (l.VerifierToken != "") {
			t.Fatalf("%s: token placement", name)
		}
	}
}

func TestValidOfferAcceptsWeb(t *testing.T) {
	offer := readLeaseFixture(t, "lease-web-offer.json")
	now := time.Now()
	offer.LeaseDeadline = now.Add(118 * time.Second)
	offer.SettlementDeadline = offer.LeaseDeadline
	if err := ValidOffer(offer, now); err != nil {
		t.Fatal(err)
	}
	accepted := readLeaseFixture(t, "lease-web.json")
	accepted.LeaseDeadline, accepted.SettlementDeadline = offer.LeaseDeadline, offer.LeaseDeadline
	if ValidOffer(accepted, now) == nil {
		t.Fatal("offer carrying a verifier token accepted")
	}
	offer.ServiceType = "browser"
	if ValidOffer(offer, now) == nil {
		t.Fatal("unknown service accepted")
	}
}

// No schema validator ships with the node, so the spec's web additions are
// checked structurally: a typo in an enum would otherwise only surface in the app.
func TestOpenAPIDescribesWeb(t *testing.T) {
	raw, err := os.ReadFile("../../api/node-v1.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	get := func(v any, path ...any) any {
		for _, key := range path {
			switch k := key.(type) {
			case string:
				m, ok := v.(map[any]any)
				if !ok {
					t.Fatalf("not a map at %v", path)
				}
				v = m[k]
			case int:
				a, ok := v.([]any)
				if !ok || k >= len(a) {
					t.Fatalf("not a list at %v", path)
				}
				v = a[k]
			}
		}
		return v
	}
	strs := func(v any) []string {
		out := []string{}
		for _, item := range v.([]any) {
			out = append(out, item.(string))
		}
		return out
	}
	schemas := get(spec["components"], "schemas")
	if get(schemas, "Heartbeat", "properties", "capacity", "maximum") != 96 || get(schemas, "Heartbeat", "properties", "services", "maxItems") != 3 {
		t.Fatal("heartbeat limits")
	}
	if !slices.Equal(strs(get(schemas, "ServiceHealth", "properties", "kind", "enum")), []string{"codex", "x_read", "web"}) || !slices.Equal(strs(get(schemas, "ServiceHealth", "properties", "egress", "enum")), []string{"direct", "proxy"}) {
		t.Fatal("service kinds or egress")
	}
	if !slices.Contains(strs(get(schemas, "Lease", "properties", "service_type", "enum")), "web") || get(schemas, "Lease", "properties", "web_request", "$ref") != "#/components/schemas/WebRequest" || get(schemas, "Lease", "properties", "web_payload", "$ref") != "#/components/schemas/WebPayload" {
		t.Fatal("lease web fields")
	}
	branch := get(schemas, "Lease", "oneOf", 2)
	if !slices.Equal(strs(get(branch, "required")), []string{"service_type", "web_request", "web_payload"}) || !slices.Equal(strs(get(branch, "properties", "service_type", "enum")), []string{"web"}) || get(branch, "properties", "max_output_tokens", "maximum") != 0 {
		t.Fatal("lease web branch")
	}
	if get(schemas, "WebRequest", "additionalProperties") != false || !slices.Equal(strs(get(schemas, "WebRequest", "properties", "operation", "enum")), []string{"scrape"}) || get(schemas, "WebRequest", "properties", "url", "maxLength") != 2048 {
		t.Fatal("web request schema")
	}
	payload := get(schemas, "WebPayload")
	if get(payload, "additionalProperties") != false || len(strs(get(payload, "required"))) != 7 || get(payload, "properties", "max_redirects", "maximum") != 5 || get(payload, "properties", "max_response_bytes", "maximum") != 10485760 || get(payload, "properties", "headers", "maxItems") != 3 || !slices.Equal(strs(get(payload, "properties", "headers", "items", "properties", "name", "enum")), []string{"user-agent", "accept", "accept-language"}) {
		t.Fatal("web payload schema")
	}
	codes := strs(get(schemas, "Failure", "properties", "code", "enum"))
	for _, code := range []string{"web_egress_denied", "web_dns_failed", "web_connect_failed", "web_proxy_failed", "web_fetch_failed"} {
		if !slices.Contains(codes, code) {
			t.Fatal("missing failure code", code)
		}
	}
	// Every fixture field is a field the spec names.
	var heartbeat map[string]any
	fixture, _ := os.ReadFile("../../api/fixtures/heartbeat-web.json")
	if err := json.Unmarshal(fixture, &heartbeat); err != nil {
		t.Fatal(err)
	}
	properties := get(schemas, "ServiceHealth", "properties").(map[any]any)
	for _, service := range heartbeat["services"].([]any) {
		for field := range service.(map[string]any) {
			if properties[field] == nil {
				t.Fatal("heartbeat-web.json field outside the spec:", field)
			}
		}
	}
}
