package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
// verifier, with the system resolver and the node-wide egress guard, then
// reads the verifier's body file for the page, checks it against the receipt
// and releases it. It is opt-in and reaches the public internet:
//
//	SCARLETT_VERIFIER_TLS_CERT=/absolute/server.pem SCARLETT_VERIFIER_TLS_KEY=/absolute/private-key.pem \
//	SCARLETT_VERIFIER_KEY=... SCARLETT_VERIFIER_STATE_DIR=/absolute/state scarlett-prover verifier
//	SCARLETT_TEST_WEB_LIVE=1 SCARLETT_TEST_WEB_VERIFIER=127.0.0.1:7047 SCARLETT_VERIFIER_API=http://127.0.0.1:7070 \
//	SCARLETT_VERIFIER_KEY=... SCARLETT_PROVER=path/to/scarlett-prover [SCARLETT_VERIFIER_CA_FILE=/absolute/ca.pem] \
//	[SCARLETT_TEST_WEB_URL=https://example.com/] [SCARLETT_WEB_EGRESS_PROXY=http://...] \
//	[SCARLETT_TEST_WEB_PLAINTEXT=1] [SCARLETT_TEST_WEB_EXPECT=page_too_large] \
//	go test -run TestWebLive -v ./internal/worker
//
// SCARLETT_TEST_WEB_PLAINTEXT=1 talks to a loopback verifier started with
// SCARLETT_VERIFIER_PLAINTEXT_FIXTURE=1 (no TLS files). SCARLETT_TEST_WEB_EXPECT
// names the failure code the job must end with instead of proven.
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
	c.VerifierPlaintextFixture = os.Getenv("SCARLETT_TEST_WEB_PLAINTEXT") == "1"
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
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	jobID := fmt.Sprintf("weblive-%d", time.Now().UnixNano())
	// A web job's deadline: its creation second plus 298 s.
	deadline := time.Now().Add(298 * time.Second)
	var created struct{ Token string }
	webVerifierAPI(t, ctx, http.MethodPost, api+"/v1/sessions", key, map[string]any{"job_id": jobID, "attempt": "1", "fence": "f1", "expires_at_ms": deadline.UnixMilli(), "payload": json.RawMessage(payload)}, &created)
	request := coordinator.WebRequest{Operation: "scrape", URL: target}
	encoded, _ := json.Marshal(request)
	l := coordinator.Lease{Version: coordinator.Version, ServiceType: "web", JobID: jobID, SignedJobID: strings.Repeat("a", 64), Profile: c.Profile, InputSHA256: SHA(string(encoded)), Attempt: "1", Fence: "f1", LeaseDeadline: deadline, SettlementDeadline: deadline, WebRequest: &request, WebPayload: payload, VerifierToken: created.Token, AcceptanceRequired: true}
	started := time.Now()
	report := (Web{Config: c}).Report(ctx, l)
	t.Logf("node wall %s, report %+v", time.Since(started).Round(time.Millisecond), report)
	var status struct {
		Status string `json:"status"`
		Hops   []struct {
			URL           string `json:"url"`
			StatusCode    int    `json:"status_code"`
			BodyStored    bool   `json:"body_stored"`
			BodyBytes     int64  `json:"body_bytes"`
			BodySHA256    string `json:"body_sha256"`
			ReceivedBytes int64  `json:"received_bytes"`
			Framing       string `json:"framing"`
			DurationMS    int64  `json:"duration_ms"`
		} `json:"hops"`
		Rejections []string        `json:"rejections"`
		Rejection  json.RawMessage `json:"rejection"`
	}
	webVerifierAPI(t, ctx, http.MethodGet, api+"/v1/sessions/"+jobID+"/1", key, nil, &status)
	if expect := os.Getenv("SCARLETT_TEST_WEB_EXPECT"); expect != "" {
		if report.Code != expect || len(status.Rejections) != 1 || status.Rejections[0] != expect {
			t.Fatalf("want %s, got report %+v and verifier rejections %v", expect, report, status.Rejections)
		}
		t.Logf("verifier rejection %s", status.Rejection)
		return
	}
	if report.Code != "" {
		t.Fatalf("live web job failed: %+v (verifier rejection %s)", report, status.Rejection)
	}
	if status.Status != "web_read" || len(status.Hops) == 0 || status.Hops[0].URL != target {
		t.Fatalf("verifier holds %+v", status)
	}
	for _, hop := range status.Hops {
		t.Logf("hop %s HTTP %d, %d body bytes (%d received, %s) in %d ms, stored %v", hop.URL, hop.StatusCode, hop.BodyBytes, hop.ReceivedBytes, hop.Framing, hop.DurationMS, hop.BodyStored)
	}
	final := status.Hops[len(status.Hops)-1]
	if !final.BodyStored {
		t.Fatal("the final hop stored no body")
	}
	// The page body, streamed from the verifier's file, matches the receipt.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, api+"/v1/sessions/"+jobID+"/1/body", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || n != final.BodyBytes || hex.EncodeToString(h.Sum(nil)) != final.BodySHA256 || resp.Header.Get("X-Body-SHA256") != final.BodySHA256 {
		t.Fatalf("body: HTTP %d, %d bytes, %v", resp.StatusCode, n, err)
	}
	t.Logf("body %d bytes, sha256 %s matches the receipt", n, final.BodySHA256)
	if os.Getenv("SCARLETT_TEST_WEB_KEEP") == "1" {
		return
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodDelete, api+"/v1/sessions/"+jobID+"/1/body", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	if resp, err = http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("release: %v %v", resp, err)
	}
	resp.Body.Close()
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
