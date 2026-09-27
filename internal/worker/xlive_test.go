//go:build xlive

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

	x "github.com/teslashibe/x-go"
)

// TestXLive runs x-go's read surface through XTransport against a running
// verifier with a real X session, and checks that the verifier's copy of every
// response is exactly what x-go parsed. It spends the session's X quota and
// never calls a write method.
//
//	SCARLETT_VERIFIER_KEY=... scarlett-prover verifier
//	SCARLETT_X_SESSION=path/to/session.json SCARLETT_PROVER=path/to/scarlett-prover \
//	SCARLETT_VERIFIER=127.0.0.1:7047 SCARLETT_VERIFIER_API=http://127.0.0.1:7070 SCARLETT_VERIFIER_KEY=... \
//	go test -tags xlive -run TestXLive -v ./internal/worker
func TestXLive(t *testing.T) {
	env := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			t.Skipf("%s is not set", k)
		}
		return v
	}
	sessionPath, prover, verifierAddr, api, key := env("SCARLETT_X_SESSION"), env("SCARLETT_PROVER"), env("SCARLETT_VERIFIER"), env("SCARLETT_VERIFIER_API"), env("SCARLETT_VERIFIER_KEY")
	var session x.Session
	data, err := os.ReadFile(sessionPath)
	if err != nil || json.Unmarshal(data, &session) != nil {
		t.Fatal("X session file is unreadable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	jobID := fmt.Sprintf("xlive-%d", time.Now().UnixNano())
	var created struct{ Token string }
	verifierAPI(t, ctx, http.MethodPost, api+"/v1/sessions", key, map[string]any{
		"job_id": jobID, "attempt": "1", "ttl_seconds": 600,
		"payload": map[string]any{"type": "x.read", "max_exchanges": 30, "operations": []string{
			"Viewer", "UserByRestId", "UserByScreenName", "UserTweets", "TweetResultByRestId", "TweetDetail", "SearchTimeline", "Followers",
		}},
	}, &created)

	rec := &recorder{t: t, next: XTransport{Prover: prover, Verifier: verifierAddr, Token: created.Token}}
	c, err := session.NewClient(ctx, x.WithHTTPClient(&http.Client{Timeout: 5 * time.Minute, Transport: rec}))
	if err != nil {
		t.Fatalf("x-go client: %v", err)
	}
	tweet, err := c.GetTweet(ctx, "20")
	if err != nil || tweet.Text != "just setting up my twttr" {
		t.Fatalf("GetTweet: %v %+v", err, tweet)
	}
	jack, err := c.GetProfile(ctx, "jack")
	if err != nil || jack.ID == "" {
		t.Fatalf("GetProfile: %v", err)
	}
	reads := []struct {
		name string
		run  func() error
	}{
		{"GetTweetDetail", func() error { _, err := c.GetTweetDetail(ctx, "20"); return err }},
		{"UserTweets", func() error { _, err := c.UserTweets(ctx, jack.ID, 20); return err }},
		{"SearchTweets", func() error { _, err := c.SearchTweets(ctx, "bitcoin", 20); return err }},
		{"GetFollowers", func() error { _, err := c.GetFollowers(ctx, jack.ID, 20); return err }},
	}
	for _, r := range reads {
		if err := r.run(); err != nil {
			t.Errorf("%s: %v", r.name, err)
		}
	}

	var status struct {
		Status    string
		Exchanges []struct {
			Operation     string `json:"operation"`
			HTTPStatus    int    `json:"http_status"`
			Body          string `json:"body"`
			SentBytes     int    `json:"sent_bytes"`
			ReceivedBytes int    `json:"received_bytes"`
			DurationMS    int    `json:"duration_ms"`
		}
		Rejections []string
	}
	verifierAPI(t, ctx, http.MethodGet, api+"/v1/sessions/"+jobID+"/1", key, nil, &status)
	if len(status.Rejections) > 0 {
		t.Errorf("verifier rejected exchanges: %v", status.Rejections)
	}
	if len(status.Exchanges) != len(rec.bodies) {
		t.Fatalf("verifier recorded %d exchanges, x-go received %d", len(status.Exchanges), len(rec.bodies))
	}
	for i, e := range status.Exchanges {
		if e.Operation != rec.ops[i] || e.Body != rec.bodies[i] {
			t.Errorf("exchange %d: verifier has %s (%d bytes), x-go parsed %s (%d bytes)", i, e.Operation, len(e.Body), rec.ops[i], len(rec.bodies[i]))
		}
		t.Logf("%-20s HTTP %d  sent %5d B  received %6d B  body %7d B  verifier %5d ms  node %6d ms", e.Operation, e.HTTPStatus, e.SentBytes, e.ReceivedBytes, len(e.Body), e.DurationMS, rec.took[i].Milliseconds())
	}
}

// recorder keeps the proven response bodies x-go receives, in order.
type recorder struct {
	t           *testing.T
	next        http.RoundTripper
	ops, bodies []string
	took        []time.Duration
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := r.next.RoundTrip(req)
	if err != nil {
		r.t.Logf("%s failed after %s: %v", req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:], time.Since(start).Round(time.Millisecond), err)
	}
	if err != nil || req.URL.Host != "x.com" || !strings.HasPrefix(req.URL.Path, "/i/api/") {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	r.ops = append(r.ops, req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:])
	r.bodies = append(r.bodies, string(body))
	r.took = append(r.took, time.Since(start))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

func verifierAPI(t *testing.T, ctx context.Context, method, url, key string, in, out any) {
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
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 || json.Unmarshal(data, out) != nil {
		t.Fatalf("verifier API %s %s: %d %s", method, url, resp.StatusCode, data)
	}
}
