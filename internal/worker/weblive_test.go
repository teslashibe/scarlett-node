package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// TestWebLive fetches one real page through the real helper and a running
// verifier, with the system resolver and the node-wide egress guard. It is
// opt-in and reaches the public internet:
//
//	SCARLETT_VERIFIER_TLS_CERT=/absolute/server.pem SCARLETT_VERIFIER_TLS_KEY=/absolute/private-key.pem \
//	SCARLETT_VERIFIER_KEY=... scarlett-prover verifier
//	SCARLETT_TEST_WEB_LIVE=1 SCARLETT_TEST_WEB_VERIFIER=127.0.0.1:7047 SCARLETT_VERIFIER_API=http://127.0.0.1:7070 \
//	SCARLETT_VERIFIER_KEY=... SCARLETT_PROVER=path/to/scarlett-prover [SCARLETT_VERIFIER_CA_FILE=/absolute/ca.pem] \
//	[SCARLETT_TEST_WEB_URL=https://example.com/] [SCARLETT_WEB_EGRESS_PROXY=http://...] \
//	go test -run TestWebLive -v ./internal/worker
func TestWebLive(t *testing.T) {
	if os.Getenv("SCARLETT_TEST_WEB_LIVE") != "1" {
		t.Skip("SCARLETT_TEST_WEB_LIVE is not 1")
	}
	env := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			t.Fatalf("%s is not set", k)
		}
		return v
	}
	verifier, api, key, prover := env("SCARLETT_TEST_WEB_VERIFIER"), env("SCARLETT_VERIFIER_API"), env("SCARLETT_VERIFIER_KEY"), env("SCARLETT_PROVER")
	target := os.Getenv("SCARLETT_TEST_WEB_URL")
	if target == "" {
		target = "https://example.com/"
	}
	if canonical, _, err := canonicalWebURL(target); err != nil || canonical != target {
		t.Fatalf("SCARLETT_TEST_WEB_URL is not canonical: %v", err)
	}
	c := webConfig()
	c.Prover, c.Verifier, c.VerifierCA = prover, verifier, os.Getenv("SCARLETT_VERIFIER_CA_FILE")
	if raw := os.Getenv("SCARLETT_WEB_EGRESS_PROXY"); raw != "" {
		proxy, err := config.ParseWebProxy(raw)
		if err != nil {
			t.Fatal(err)
		}
		c.WebEgressProxy = proxy
	}
	payload, _ := json.Marshal(map[string]any{"type": "web.fetch", "proof_mode": "relay", "proof_policy": webRelayPolicy, "url": target, "max_redirects": 5, "max_response_bytes": maxWebResponseBytes, "headers": []webHeader{
		{"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
		{"accept-language", "en-US,en;q=0.9"},
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	jobID := fmt.Sprintf("weblive-%d", time.Now().UnixNano())
	deadline := time.Now().Add(118 * time.Second)
	var created struct{ Token string }
	webVerifierAPI(t, ctx, http.MethodPost, api+"/v1/sessions", key, map[string]any{"job_id": jobID, "attempt": "1", "fence": "f1", "expires_at_ms": deadline.UnixMilli(), "payload": json.RawMessage(payload)}, &created)
	request := coordinator.WebRequest{Operation: "scrape", URL: target}
	encoded, _ := json.Marshal(request)
	l := coordinator.Lease{Version: coordinator.Version, ServiceType: "web", JobID: jobID, SignedJobID: strings.Repeat("a", 64), Profile: c.Profile, InputSHA256: SHA(string(encoded)), Attempt: "1", Fence: "f1", LeaseDeadline: deadline, SettlementDeadline: deadline, WebRequest: &request, WebPayload: payload, VerifierToken: created.Token, AcceptanceRequired: true}
	started := time.Now()
	if code := (Web{Config: c}).Run(ctx, l); code != "" {
		t.Fatalf("live web job failed: %s", code)
	}
	t.Logf("node wall %s", time.Since(started).Round(time.Millisecond))
	var status struct {
		Status string `json:"status"`
		Hops   []struct {
			URL        string `json:"url"`
			StatusCode int    `json:"status_code"`
			BodyBytes  int    `json:"body_bytes"`
		} `json:"hops"`
		Rejections []string `json:"rejections"`
	}
	webVerifierAPI(t, ctx, http.MethodGet, api+"/v1/sessions/"+jobID+"/1", key, nil, &status)
	if status.Status != "web_read" || len(status.Hops) == 0 || status.Hops[0].URL != target {
		t.Fatalf("verifier holds %+v", status)
	}
	for _, hop := range status.Hops {
		t.Logf("hop %s HTTP %d, %d body bytes", hop.URL, hop.StatusCode, hop.BodyBytes)
	}
}

func webVerifierAPI(t *testing.T, ctx context.Context, method, url, key string, in, out any) {
	t.Helper()
	var body io.Reader
	if in != nil {
		data, _ := json.Marshal(in)
		body = bytes.NewReader(data)
	}
	req, _ := http.NewRequestWithContext(ctx, method, url, body)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("verifier API: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode/100 != 2 || json.Unmarshal(data, out) != nil {
		t.Fatalf("verifier API %s %s: HTTP %d", method, url, resp.StatusCode)
	}
}
