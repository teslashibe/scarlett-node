//go:build xperf

package worker

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// This observer preserves all provider responses and quota headers. It records
// only fixed phase labels, timings, sizes and numeric quota observations; it
// never records URLs, identities, bodies, cookies or transaction values.
type buyerXPerfBootstrap struct {
	base    http.RoundTripper
	started time.Time
	mu      sync.Mutex
	records []*buyerXPerfBootstrapRecord
}

type buyerXPerfBootstrapRecord struct {
	Phase         string  `json:"phase"`
	StartedMS     int64   `json:"started_ms"`
	HeadersMS     int64   `json:"headers_ms"`
	FinishedMS    int64   `json:"finished_ms"`
	BodyBytes     int64   `json:"body_bytes"`
	HTTPStatus    int     `json:"http_status"`
	Failed        bool    `json:"failed"`
	RateLimit     *uint64 `json:"rate_limit_limit,omitempty"`
	RateRemaining *uint64 `json:"rate_limit_remaining,omitempty"`
	RateReset     *uint64 `json:"rate_limit_reset_epoch_seconds,omitempty"`
}

func (b *buyerXPerfBootstrap) RoundTrip(req *http.Request) (*http.Response, error) {
	phase := "other"
	if req.URL.Host == "x.com" {
		switch {
		case strings.HasSuffix(req.URL.Path, "/Viewer"):
			phase = "auth_viewer"
		case strings.HasSuffix(req.URL.Path, "/UserByRestId"):
			phase = "auth_profile"
		case !strings.HasPrefix(req.URL.Path, "/i/api/"):
			phase = "transaction_home"
		}
	} else if req.URL.Host == "abs.twimg.com" {
		phase = "transaction_js"
	}
	record := &buyerXPerfBootstrapRecord{Phase: phase, StartedMS: time.Since(b.started).Milliseconds()}
	b.mu.Lock()
	b.records = append(b.records, record)
	b.mu.Unlock()
	resp, err := b.base.RoundTrip(req)
	b.mu.Lock()
	record.HeadersMS = time.Since(b.started).Milliseconds()
	if err != nil {
		record.Failed = true
		record.FinishedMS = record.HeadersMS
	} else {
		record.HTTPStatus = resp.StatusCode
		record.RateLimit = xperfNumericHeader(resp.Header, "X-Rate-Limit-Limit")
		record.RateRemaining = xperfNumericHeader(resp.Header, "X-Rate-Limit-Remaining")
		record.RateReset = xperfNumericHeader(resp.Header, "X-Rate-Limit-Reset")
		resp.Body = &buyerXPerfBootstrapBody{ReadCloser: resp.Body, owner: b, record: record}
	}
	b.mu.Unlock()
	return resp, err
}

type buyerXPerfBootstrapBody struct {
	io.ReadCloser
	owner  *buyerXPerfBootstrap
	record *buyerXPerfBootstrapRecord
}

func (b *buyerXPerfBootstrapBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.owner.mu.Lock()
	b.record.BodyBytes += int64(n)
	if err != nil && err != io.EOF {
		b.record.Failed = true
	}
	b.owner.mu.Unlock()
	return n, err
}

func (b *buyerXPerfBootstrapBody) Close() error {
	err := b.ReadCloser.Close()
	b.owner.mu.Lock()
	b.record.FinishedMS = time.Since(b.owner.started).Milliseconds()
	if err != nil {
		b.record.Failed = true
	}
	b.owner.mu.Unlock()
	return err
}

func (b *buyerXPerfBootstrap) report(proofStarted time.Duration) map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	var occupied int64
	for _, r := range b.records {
		if r.FinishedMS >= r.StartedMS {
			occupied += r.FinishedMS - r.StartedMS
		}
	}
	return map[string]any{"proof_started_ms": proofStarted.Milliseconds(), "http_and_body_ms": occupied, "non_http_before_proof_ms": max(int64(0), proofStarted.Milliseconds()-occupied), "non_http_includes_pacing_and_client_processing": true, "requests": b.records}
}

func TestBuyerXPerfBootstrapPrivacy(t *testing.T) {
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"X-Rate-Limit-Limit": {"50"}, "X-Rate-Limit-Remaining": {"49"}, "X-Rate-Limit-Reset": {"1700000100"}, "Set-Cookie": {"private-cookie"}}, Body: io.NopCloser(strings.NewReader("private-body")), Request: req}, nil
	})
	observer := &buyerXPerfBootstrap{base: base, started: time.Now()}
	req, _ := http.NewRequest("GET", "https://x.com/i/api/graphql/private-query/Viewer?variables=private-identity", nil)
	resp, err := observer.RoundTrip(req)
	if err != nil || resp.Header.Get("Set-Cookie") != "private-cookie" {
		t.Fatal("observer changed provider response")
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "private-body" {
		t.Fatal("observer changed provider body")
	}
	raw, _ := json.Marshal(observer.report(time.Since(observer.started)))
	if strings.Contains(string(raw), "private-") || !strings.Contains(string(raw), `"phase":"auth_viewer"`) || !strings.Contains(string(raw), `"rate_limit_remaining":49`) || !strings.Contains(string(raw), `"body_bytes":12`) {
		t.Fatal("bootstrap report lost numeric observations or exposed private data")
	}
}
