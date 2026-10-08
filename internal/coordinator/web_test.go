package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
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

// webBrowserPayloadB2 is the exact web-browser-v1 verifier payload of
// contract §B.2.
const webBrowserPayloadB2 = `{"type":"web.fetch","proof_mode":"relay","proof_policy":"web-browser-v1","url":"https://example.com/","max_redirects":5,"max_response_bytes":10485760,"headers":[{"name":"accept","value":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},{"name":"accept-language","value":"en-US,en;q=0.9"}],"node_headers":["user-agent","cookie"]}`

func TestWebBrowserFixturesBindTheExactPayload(t *testing.T) {
	want := WebRequest{Operation: "scrape", URL: "https://example.com/", Mode: "browser", Browser: &WebBrowser{Wait: "networkidle", TimeoutMS: 30000, SolveChallenge: true}}
	for _, name := range []string{"lease-web-browser-offer.json", "lease-web-browser.json"} {
		l := readLeaseFixture(t, name)
		if l.ServiceType != "web" || l.WebRequest == nil || l.WebRequest.Browser == nil || l.WebRequest.Mode != want.Mode || *l.WebRequest.Browser != *want.Browser || !bytes.Equal(l.WebPayload, []byte(webBrowserPayloadB2)) || l.WebPrewarmBrowser {
			t.Fatalf("%s: unexpected browser terms", name)
		}
		request, _ := json.Marshal(l.WebRequest)
		if sum := sha256.Sum256(request); hex.EncodeToString(sum[:]) != l.InputSHA256 || l.InputSHA256 != "15907c5fbdfe9bda3af12efbcfbd1784f3651d13227899485b2a6bd974afca63" {
			t.Fatalf("%s: input digest", name)
		}
		if l.RequestSHA256 != "f24ba0094ed03be33c287a26997889217a0e6aebf62ca0b278f34dbecf0a175e" || (name == "lease-web-browser.json") != (l.VerifierToken == strings.Repeat("ab", 32)) {
			t.Fatalf("%s: request digest or token", name)
		}
	}
	// The pre-warm hint sits outside web_request: the hinted offer has the
	// plain relay offer's terms and digests.
	plain, hinted := readLeaseFixture(t, "lease-web-offer.json"), readLeaseFixture(t, "lease-web-prewarm-offer.json")
	if !hinted.WebPrewarmBrowser || hinted.InputSHA256 != plain.InputSHA256 || hinted.RequestSHA256 != plain.RequestSHA256 || !bytes.Equal(hinted.WebPayload, plain.WebPayload) {
		t.Fatal("pre-warm offer changed the job")
	}
	hinted.WebPrewarmBrowser = false
	a, _ := json.Marshal(plain)
	b, _ := json.Marshal(hinted)
	if !bytes.Equal(a, b) {
		t.Fatal("pre-warm offer differs beyond the hint")
	}
	// A relay lease marshals exactly as before the browser fields existed.
	relay, _ := json.Marshal(readLeaseFixture(t, "lease-web.json").WebRequest)
	if string(relay) != `{"operation":"scrape","url":"https://example.com/"}` {
		t.Fatal("relay web_request bytes changed", string(relay))
	}
	if code := readFailureCode(t, "failure-web-browser.json"); code != "web_browser_failed" {
		t.Fatal("browser failure fixture", code)
	}
	var heartbeat Heartbeat
	raw, _ := os.ReadFile("../../api/fixtures/heartbeat-web-browser.json")
	if err := json.Unmarshal(raw, &heartbeat); err != nil || heartbeat.Services[2].Browser == nil || *heartbeat.Services[2].Browser != (BrowserHealth{State: "ready", Capacity: 2, Version: "155.0.8059.39"}) || heartbeat.Services[2].Browser.Capacity > heartbeat.Services[2].Capacity {
		t.Fatal("browser heartbeat fixture", err)
	}
}

func readFailureCode(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile("../../api/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var f Failure
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Code
}

// The core web fixtures, which the app and verifier pin, keep their bytes.
func TestCoreWebFixturesUnchanged(t *testing.T) {
	for name, want := range map[string]string{
		"lease-web-offer.json": "c1d1fad1523f3491ff873eea205b94746c301e49c74391a0f5cbdaad4e42ba4d",
		"lease-web.json":       "b77e83335788b314ca405b860f9d1c8520d968d0d24ad865e2dedbfc642441ff",
		"heartbeat-web.json":   "b0c3866d9babd74be4a03d815f7320ba428d77b1431c8d525abcba72757b5a65",
		"failure-web.json":     "ede9d412a9524c44cae1a5cfc9dc9105407b3a360914f3d4aa100c27da56c8d8",
	} {
		raw, err := os.ReadFile("../../api/fixtures/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != want {
			t.Errorf("%s changed", name)
		}
	}
}

func TestValidOfferBrowserAndPrewarm(t *testing.T) {
	now := time.Now()
	read := func(name string) Lease {
		l := readLeaseFixture(t, name)
		l.LeaseDeadline = now.Add(118 * time.Second)
		l.SettlementDeadline = l.LeaseDeadline
		return l
	}
	for _, name := range []string{"lease-web-browser-offer.json", "lease-web-prewarm-offer.json"} {
		if err := ValidOffer(read(name), now); err != nil {
			t.Fatal(name, err)
		}
	}
	browser := read("lease-web-browser-offer.json")
	browser.WebPrewarmBrowser = true
	if ValidOffer(browser, now) == nil {
		t.Fatal("pre-warm hint accepted on a browser offer")
	}
	codex := retryOffer(time.Minute)
	codex.WebPrewarmBrowser = true
	if ValidOffer(codex, now) == nil {
		t.Fatal("pre-warm hint accepted on a non-web offer")
	}
}

// The coordinator decides the pre-warm hint per offer; acceptance compares
// the terms without it and keeps the offer's value.
func TestAcceptIgnoresThePrewarmHint(t *testing.T) {
	offer := readLeaseFixture(t, "lease-web-prewarm-offer.json")
	offer.LeaseDeadline = time.Now().Add(118 * time.Second).UTC().Truncate(time.Second)
	offer.SettlementDeadline = offer.LeaseDeadline
	for _, echo := range []bool{false, true} {
		reply := offer
		reply.WebPrewarmBrowser = echo
		client, _, _ := acceptRetryServer(t, reply, nil)
		got, err := client.Accept(context.Background(), offer)
		if err != nil || !got.WebPrewarmBrowser || got.VerifierToken == "" {
			t.Fatal("hinted acceptance", echo, err)
		}
	}
	// Any other difference is still refused.
	changed := offer
	changed.WebRequest = &WebRequest{Operation: "scrape", URL: "https://example.org/"}
	client, _, _ := acceptRetryServer(t, changed, nil)
	if _, err := client.Accept(context.Background(), offer); err == nil {
		t.Fatal("changed terms accepted")
	}
}

// The spec's browser additions are checked structurally, as the core ones are.
func TestOpenAPIDescribesTheBrowserTier(t *testing.T) {
	raw, err := os.ReadFile("../../api/node-v1.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec map[any]any
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	get := func(v any, path ...string) any {
		for _, key := range path {
			m, ok := v.(map[any]any)
			if !ok {
				t.Fatalf("not a map at %v", path)
			}
			v = m[key]
		}
		return v
	}
	strs := func(v any) []string {
		out := []string{}
		items, _ := v.([]any)
		for _, item := range items {
			out = append(out, item.(string))
		}
		return out
	}
	schemas := get(spec, "components", "schemas")
	if get(schemas, "ServiceHealth", "properties", "browser", "$ref") != "#/components/schemas/BrowserHealth" || !slices.Equal(strs(get(schemas, "BrowserHealth", "properties", "state", "enum")), []string{"ready", "unavailable"}) || get(schemas, "BrowserHealth", "properties", "capacity", "maximum") != 4 {
		t.Fatal("browser health")
	}
	reasons := strs(get(schemas, "BrowserHealth", "properties", "reason", "enum"))
	if !slices.Equal(reasons, []string{"disabled", "web_unavailable", "memory_low", "disk_low", "runtime_missing", "runtime_invalid", "browser_downloading", "browser_download_failed", "browser_invalid", "deps_missing", "sandbox_unavailable", "helper_failed"}) || slices.Contains(reasons, "launch_failed") {
		t.Fatal("browser reasons", reasons)
	}
	if get(schemas, "WebRequest", "properties", "browser", "$ref") != "#/components/schemas/WebBrowser" || !slices.Equal(strs(get(schemas, "WebRequest", "properties", "mode", "enum")), []string{"browser"}) || get(schemas, "WebBrowser", "properties", "timeout_ms", "maximum") != 45000 || get(schemas, "WebBrowser", "properties", "wait_ms", "maximum") != 15000 || get(schemas, "WebBrowser", "additionalProperties") != false {
		t.Fatal("web browser options")
	}
	if !slices.Equal(strs(get(schemas, "WebPayload", "properties", "proof_policy", "enum")), []string{"web-relay-v1", "web-browser-v1"}) || !slices.Equal(strs(get(schemas, "WebPayload", "properties", "node_headers", "items", "enum")), []string{"user-agent", "cookie"}) || get(schemas, "Lease", "properties", "web_prewarm_browser", "type") != "boolean" {
		t.Fatal("browser payload or hint")
	}
	codes := strs(get(schemas, "Failure", "properties", "code", "enum"))
	if !slices.Contains(codes, "web_browser_unavailable") || !slices.Contains(codes, "web_browser_failed") {
		t.Fatal("browser failure codes")
	}
	path := get(spec, "paths", "/api/node/v1/jobs/{job_id}/browser-result", "post")
	if get(path, "requestBody", "content", "application/json", "schema", "$ref") != "#/components/schemas/BrowserResult" || get(path, "responses", "409") == nil || get(path, "responses", "415") == nil {
		t.Fatal("browser-result path")
	}
	// Every fixture field is one the spec names.
	fields := func(name string) map[string]any {
		raw, _ := os.ReadFile("../../api/fixtures/" + name)
		var v map[string]any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	within := func(v map[string]any, schema string) {
		properties := get(schemas, schema, "properties").(map[any]any)
		for field := range v {
			if properties[field] == nil {
				t.Fatalf("%s field outside the spec: %s", schema, field)
			}
		}
		for _, required := range strs(get(schemas, schema, "required")) {
			if _, ok := v[required]; !ok {
				t.Fatalf("%s misses required %s", schema, required)
			}
		}
	}
	result := fields("browser-result.json")
	within(result, "BrowserResult")
	if len(strs(get(schemas, "BrowserResult", "required"))) != len(result) {
		t.Fatal("browser result fixture leaves a field out")
	}
	web := fields("heartbeat-web-browser.json")["services"].([]any)[2].(map[string]any)
	within(web, "ServiceHealth")
	within(web["browser"].(map[string]any), "BrowserHealth")
	lease := fields("lease-web-browser.json")
	within(lease, "Lease")
	within(lease["web_request"].(map[string]any), "WebRequest")
	within(lease["web_request"].(map[string]any)["browser"].(map[string]any), "WebBrowser")
	within(lease["web_payload"].(map[string]any), "WebPayload")
	within(fields("lease-web-prewarm-offer.json"), "Lease")
}
