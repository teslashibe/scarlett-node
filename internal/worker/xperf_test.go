//go:build xperf

package worker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	x "github.com/teslashibe/x-go"
	"golang.org/x/sys/unix"
)

// This harness is experimental and deliberately independent of XTransport's
// production defaults. Credentials enter only through private local files.
type xperfConfig struct {
	session, prover, verifier, ca, api, key, output string
	mode, headers, workload                         string
	samples, maxRecv, sentRecords, recvRecords      int
	prepareHoldMS                                   int
	responseReady                                   bool
}

func xperfConfiguration() (xperfConfig, error) {
	c := xperfConfig{session: os.Getenv("SCARLETT_X_SESSION"), prover: os.Getenv("SCARLETT_PROVER"), verifier: os.Getenv("SCARLETT_VERIFIER"), ca: os.Getenv("SCARLETT_VERIFIER_CA_FILE"), api: os.Getenv("SCARLETT_VERIFIER_API"), output: os.Getenv("SCARLETT_XPERF_OUTPUT"), mode: os.Getenv("SCARLETT_XPERF_MODE"), headers: os.Getenv("SCARLETT_XPERF_HEADERS"), workload: os.Getenv("SCARLETT_XPERF_WORKLOAD")}
	if c.mode == "" {
		c.mode = "mpc"
	}
	if c.headers == "" {
		c.headers = "normal"
	}
	if c.workload == "" {
		c.workload = "search"
	}
	if c.mode != "mpc" && c.mode != "proxy" || c.headers != "normal" && c.headers != "minimal" || !xperfWorkloadAllowed(c.workload) {
		return c, errors.New("invalid_variant")
	}
	var err error
	for _, p := range []struct {
		name          string
		out           *int
		def, min, max int
	}{
		{"SCARLETT_XPERF_SAMPLES", &c.samples, 1, 1, 100},
		{"SCARLETT_XPERF_MAX_RECV", &c.maxRecv, 0, 0, 256 << 10},
		{"SCARLETT_XPERF_SENT_RECORDS", &c.sentRecords, 0, 0, 32},
		{"SCARLETT_XPERF_RECV_RECORDS", &c.recvRecords, 0, 0, 32},
		{"SCARLETT_XPERF_PREPARE_HOLD_MS", &c.prepareHoldMS, 0, 0, 30000},
	} {
		*p.out = p.def
		if value := os.Getenv(p.name); value != "" {
			*p.out, err = strconv.Atoi(value)
		}
		if err != nil || *p.out < p.min || *p.out > p.max {
			return c, errors.New("invalid_variant")
		}
	}
	if c.sentRecords != 0 && c.sentRecords < 3 || c.recvRecords != 0 && c.recvRecords < 3 {
		return c, errors.New("invalid_record_allocation")
	}
	if v := os.Getenv("SCARLETT_XPERF_RESPONSE_READY"); v != "" && v != "0" && v != "1" {
		return c, errors.New("invalid_variant")
	}
	c.responseReady = os.Getenv("SCARLETT_XPERF_RESPONSE_READY") == "1"
	if c.mode == "proxy" && (c.sentRecords != 0 || c.recvRecords != 0 || c.prepareHoldMS != 0) {
		return c, errors.New("mpc_option_on_proxy")
	}
	if c.session == "" || c.prover == "" || c.verifier == "" || c.api == "" || c.output == "" {
		return c, errors.New("missing_configuration")
	}
	u, err := url.Parse(c.api)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return c, errors.New("unsafe_control_origin")
	}
	c.api = strings.TrimRight(c.api, "/")
	key, err := xperfPrivateRead(os.Getenv("SCARLETT_VERIFIER_KEY_FILE"), 4096)
	if err != nil {
		return c, errors.New("invalid_private_key_file")
	}
	c.key = strings.TrimSpace(string(key))
	if c.key == "" || strings.ContainsAny(c.key, "\r\n") {
		return c, errors.New("invalid_private_key_file")
	}
	if err := xperfPrivateDirectory(c.output); err != nil {
		return c, err
	}
	return c, nil
}

func xperfWorkloadAllowed(v string) bool {
	return v == "search" || v == "empty" || v == "profile" || v == "post" || v == "pagination"
}

func xperfPrivateDirectory(path string) error {
	i, err := os.Lstat(path)
	if err != nil || !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return errors.New("output_directory_must_be_private")
	}
	return nil
}

func xperfPrivateRead(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("private_file_unavailable")
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 || i.Size() > max {
		return nil, errors.New("private_file_unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, errors.New("private_file_unavailable")
	}
	return b, nil
}

// The captured request remains private. Only its typed, credential-free
// GraphQL specification is sent to the verifier's authenticated control API.
type xperfCapture struct {
	bootstrap  bool
	base       http.RoundTripper
	request    *http.Request
	replaySpec *xSpec
	replayBody []byte
}

var errXPerfCaptured = errors.New("xperf_request_captured")

func (c *xperfCapture) RoundTrip(r *http.Request) (*http.Response, error) {
	if c.bootstrap {
		b := xBoundTransport{bootstrap: true, base: c.base}
		return b.RoundTrip(r)
	}
	s, err := xperfSpec(r)
	if err != nil {
		return nil, err
	}
	if c.replaySpec != nil {
		if !reflect.DeepEqual(s, *c.replaySpec) {
			return nil, errors.New("parser_request_mismatch")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(c.replayBody)), Request: r}, nil
	}
	c.request = r.Clone(r.Context())
	c.request.Header = r.Header.Clone()
	return nil, errXPerfCaptured
}

func xperfSpec(r *http.Request) (xSpec, error) {
	var s xSpec
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "x.com" || r.URL.User != nil || r.URL.Fragment != "" {
		return s, errors.New("request_policy")
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/i/api/graphql/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/i/api/graphql/") || len(parts) != 2 || !validID(parts[0], 64) {
		return s, errors.New("request_policy")
	}
	s.QueryID, s.Operation = parts[0], parts[1]
	if s.Operation != "SearchTimeline" && s.Operation != "UserByScreenName" && s.Operation != "TweetResultByRestId" {
		return s, errors.New("request_policy")
	}
	q := r.URL.Query()
	for k, v := range q {
		if len(v) != 1 || k != "variables" && k != "features" && k != "fieldToggles" {
			return s, errors.New("request_policy")
		}
	}
	for _, p := range []struct {
		name     string
		out      *map[string]any
		optional bool
	}{{"variables", &s.Variables, false}, {"features", &s.Features, false}, {"fieldToggles", &s.FieldToggles, true}} {
		if q.Get(p.name) == "" && p.optional {
			continue
		}
		v, err := uniqueJSON([]byte(q.Get(p.name)))
		var ok bool
		*p.out, ok = v.(map[string]any)
		if err != nil || !ok {
			return s, errors.New("request_policy")
		}
	}
	return s, nil
}

type xperfParsed struct {
	items  int
	cursor string
}

func xperfRead(ctx context.Context, c *x.Client, workload, cursor string) (xperfParsed, error) {
	switch workload {
	case "profile":
		u, err := c.GetProfile(ctx, "jack")
		if err == nil && (u.ID != "12" || !strings.EqualFold(u.ScreenName, "jack")) {
			return xperfParsed{}, errors.New("profile_identity_mismatch")
		}
		if err != nil {
			return xperfParsed{}, err
		}
		return xperfParsed{items: 1}, nil
	case "post":
		p, err := c.GetTweet(ctx, "20")
		if err == nil && p.ID != "20" {
			return xperfParsed{}, errors.New("post_identity_mismatch")
		}
		if err != nil {
			return xperfParsed{}, err
		}
		return xperfParsed{items: 1}, nil
	default:
		query := "solana"
		if workload == "empty" {
			query = "scarlettcanarynevermatch7fbea4519fd1484185d772aef090fe29"
		}
		p, err := c.SearchTweetsPage(ctx, query, 20, cursor, x.WithSearchType(x.SearchLatest))
		if err != nil {
			return xperfParsed{}, err
		}
		if workload == "empty" && len(p.Tweets) != 0 {
			return xperfParsed{}, errors.New("empty_fixture_not_empty")
		}
		return xperfParsed{items: len(p.Tweets), cursor: p.NextCursor}, nil
	}
}

func xperfPlan(ctx context.Context, client *x.Client, capture *xperfCapture, workload string) ([]xSpec, *http.Request, error) {
	capture.request, capture.replaySpec = nil, nil
	_, _ = xperfRead(ctx, client, workload, "")
	if capture.request == nil {
		return nil, nil, errors.New("request_capture_failed")
	}
	s, err := xperfSpec(capture.request)
	if err != nil {
		return nil, nil, err
	}
	specs := []xSpec{s}
	if workload == "pagination" {
		second := s
		second.Variables = make(map[string]any, len(s.Variables))
		for k, v := range s.Variables {
			second.Variables[k] = v
		}
		zero := 0
		second.CursorFrom = &zero
		specs = append(specs, second)
	}
	return specs, capture.request, nil
}

func xperfPayload(specs []xSpec, mode string) map[string]any {
	p := map[string]any{"type": "x.read", "exchanges": specs, "max_attempts": len(specs)}
	if mode == "proxy" {
		p["proof_mode"], p["proof_policy"] = "proxy", "x-proxy-experimental-v1"
	}
	return p
}

func xperfProverInput(c xperfConfig, token string, req *http.Request) ([]byte, int, error) {
	r := req.Clone(req.Context())
	r.Header = req.Header.Clone()
	r.Close = true
	r.Header.Set("Accept-Encoding", "gzip")
	if c.headers == "minimal" {
		for _, h := range []string{"Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Accept-Language", "X-Twitter-Client-Language", "Referer"} {
			r.Header.Del(h)
		}
	}
	var raw bytes.Buffer
	if err := r.Write(&raw); err != nil {
		return nil, 0, errors.New("request_serialization")
	}
	p := map[string]any{"verifier": c.verifier, "token": token, "request": base64.StdEncoding.EncodeToString(raw.Bytes()), "proof_mode": c.mode}
	if c.ca != "" {
		p["verifier_ca_file"] = c.ca
	}
	if c.maxRecv != 0 {
		p["max_recv"] = c.maxRecv
	}
	if c.sentRecords != 0 {
		p["max_sent_records"] = c.sentRecords
	}
	if c.recvRecords != 0 {
		p["max_recv_records_online"] = c.recvRecords
	}
	if c.prepareHoldMS != 0 {
		p["prepare_hold_ms"] = c.prepareHoldMS
	}
	if c.responseReady {
		p["response_ready_event"] = true
	}
	b, err := json.Marshal(p)
	return b, raw.Len(), err
}

type xperfSummary struct {
	Status             string            `json:"status"`
	Mode               string            `json:"proof_mode"`
	Response           string            `json:"response"`
	SentBytes          uint64            `json:"sent_bytes"`
	ReceivedBytes      uint64            `json:"received_bytes"`
	DurationMS         uint64            `json:"duration_ms"`
	ExecutionMS        *uint64           `json:"execution_ms"`
	VerifierSent       *uint64           `json:"verifier_sent_bytes"`
	VerifierReceived   *uint64           `json:"verifier_received_bytes"`
	TransportLayer     string            `json:"verifier_transport_layer"`
	TransportSaturated bool              `json:"verifier_bytes_saturated"`
	Timings            map[string]uint64 `json:"timings_ms"`
}

type xperfObserved struct {
	spec                             xSpec
	bodyHash                         [32]byte
	bodyBytes, items, httpStatus     int
	summary                          xperfSummary
	helperMS                         int64
	userCPUSeconds, systemCPUSeconds float64
	peakRSSBytes                     int64
	provisionalMS                    *uint64
}

func xperfProve(ctx context.Context, c xperfConfig, token string, req *http.Request, diagnostic string) (xperfObserved, []byte, error) {
	var o xperfObserved
	input, _, err := xperfProverInput(c, token, req)
	if err != nil {
		return o, nil, err
	}
	o.spec, err = xperfSpec(req)
	if err != nil {
		return o, nil, err
	}
	cmd := exec.CommandContext(ctx, c.prover, "prove-x")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = 4<<20, 16384
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	started := time.Now()
	err = cmd.Run()
	o.helperMS = time.Since(started).Milliseconds()
	if state := cmd.ProcessState; state != nil {
		o.userCPUSeconds, o.systemCPUSeconds = state.UserTime().Seconds(), state.SystemTime().Seconds()
		if ru, ok := state.SysUsage().(*syscall.Rusage); ok {
			o.peakRSSBytes = ru.Maxrss
			if runtime.GOOS != "darwin" {
				o.peakRSSBytes *= 1024
			}
		}
	}
	if len(stderr.Bytes()) > 0 {
		f, e := os.OpenFile(diagnostic, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
		if e != nil {
			return o, nil, errors.New("private_diagnostic_write_failed")
		}
		_, e = f.Write(stderr.Bytes())
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return o, nil, errors.New("private_diagnostic_write_failed")
		}
		o.provisionalMS = xperfProvisional(stderr.Bytes())
	}
	if err != nil {
		return o, nil, errors.New("helper_failed")
	}
	if json.Unmarshal(stdout.Bytes(), &o.summary) != nil || o.summary.Status != "proof_sent" || o.summary.Mode != c.mode {
		return o, nil, errors.New("helper_summary_invalid")
	}
	raw, err := base64.StdEncoding.DecodeString(o.summary.Response)
	if err != nil {
		return o, nil, errors.New("helper_response_invalid")
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req)
	if err != nil {
		return o, nil, errors.New("helper_response_invalid")
	}
	defer resp.Body.Close()
	o.httpStatus = resp.StatusCode
	var reader io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		z, err := gzip.NewReader(resp.Body)
		if err != nil {
			return o, nil, errors.New("helper_response_invalid")
		}
		defer z.Close()
		reader = z
	}
	body, err := io.ReadAll(io.LimitReader(reader, (8<<20)+1))
	if err != nil || len(body) > 8<<20 {
		return o, nil, errors.New("helper_response_invalid")
	}
	o.bodyHash, o.bodyBytes = sha256.Sum256(body), len(body)
	if resp.StatusCode == 429 {
		return o, nil, errors.New("provider_rate_limited")
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return o, nil, errors.New("provider_auth_failed")
	}
	if resp.StatusCode != 200 {
		return o, nil, errors.New("provider_http_failed")
	}
	return o, body, nil
}

func xperfProvisional(raw []byte) *uint64 {
	for _, line := range bytes.Split(raw, []byte("\n")) {
		var v struct {
			Phase   string  `json:"phase"`
			Elapsed *uint64 `json:"elapsed_ms"`
		}
		if json.Unmarshal(line, &v) == nil && v.Phase == "response_ready" && v.Elapsed != nil && *v.Elapsed <= 600000 {
			return v.Elapsed
		}
	}
	return nil
}

type xperfReceipt struct {
	Status     string   `json:"status"`
	Mode       string   `json:"proof_mode"`
	Policy     string   `json:"proof_policy"`
	JobID      string   `json:"job_id"`
	Attempt    string   `json:"attempt"`
	Fence      string   `json:"fence"`
	ExpiresMS  int64    `json:"expires_at_ms"`
	RequestSHA string   `json:"request_sha256"`
	Complete   bool     `json:"complete"`
	Pending    []int    `json:"pending"`
	Remaining  int      `json:"remaining_attempts"`
	Rejections []string `json:"rejections"`
	Exchanges  []struct {
		Index         int            `json:"index"`
		Fulfilled     bool           `json:"fulfilled"`
		Operation     string         `json:"operation"`
		QueryID       string         `json:"query_id"`
		Variables     map[string]any `json:"variables"`
		Features      map[string]any `json:"features"`
		FieldToggles  map[string]any `json:"field_toggles"`
		HTTPStatus    int            `json:"http_status"`
		Body          string         `json:"body"`
		SentBytes     uint64         `json:"sent_bytes"`
		ReceivedBytes uint64         `json:"received_bytes"`
		DurationMS    uint64         `json:"duration_ms"`
	} `json:"exchanges"`
}

type xperfBinding struct {
	job, fence, requestSHA string
	expiresMS              int64
}

func xperfRegistration(job string, specs []xSpec, mode string, now time.Time) (map[string]any, xperfBinding, error) {
	payload := xperfPayload(specs, mode)
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, xperfBinding{}, errors.New("control_request_invalid")
	}
	// The verifier hashes serde_json::Value, whose object keys are ordered.
	// Convert nested Go structs to maps before reproducing that canonical JSON.
	var canonical any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&canonical) != nil {
		return nil, xperfBinding{}, errors.New("control_request_invalid")
	}
	raw, err = json.Marshal(canonical)
	if err != nil {
		return nil, xperfBinding{}, errors.New("control_request_invalid")
	}
	hash := sha256.Sum256(raw)
	b := xperfBinding{job: job, fence: "fence-" + job, requestSHA: hex.EncodeToString(hash[:]), expiresMS: now.Add(300 * time.Second).UnixMilli()}
	return map[string]any{"job_id": job, "attempt": "1", "fence": b.fence, "expires_at_ms": b.expiresMS, "payload": payload}, b, nil
}

func xperfCheckBinding(r xperfReceipt, b xperfBinding) error {
	if r.JobID != b.job || r.Attempt != "1" || r.Fence != b.fence || r.ExpiresMS != b.expiresMS || r.RequestSHA != b.requestSHA {
		return errors.New("receipt_binding_mismatch")
	}
	return nil
}

func xperfCheckReceipt(r xperfReceipt, observations []xperfObserved, mode string) error {
	if mode == "proxy" && (r.Mode != "proxy" || r.Policy != "x-proxy-experimental-v1") || mode == "mpc" && (r.Mode != "" && r.Mode != "mpc" || r.Policy != "") {
		return errors.New("receipt_proof_mode_mismatch")
	}
	if r.Status != "x_read" || !r.Complete || len(r.Pending) != 0 || r.Remaining != 0 || len(r.Rejections) != 0 || len(r.Exchanges) != len(observations) || len(observations) == 0 {
		return errors.New("receipt_incomplete_or_rejected")
	}
	for i, e := range r.Exchanges {
		o := observations[i]
		s := xSpec{Operation: e.Operation, QueryID: e.QueryID, Variables: e.Variables, Features: e.Features, FieldToggles: e.FieldToggles}
		if e.Index != i || !e.Fulfilled || e.HTTPStatus != 200 || o.httpStatus != 200 || !reflect.DeepEqual(s, o.spec) || sha256.Sum256([]byte(e.Body)) != o.bodyHash || e.SentBytes != o.summary.SentBytes || e.ReceivedBytes != o.summary.ReceivedBytes {
			return errors.New("receipt_mismatch")
		}
	}
	return nil
}

func xperfAPI(ctx context.Context, client *http.Client, c xperfConfig, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return errors.New("control_request_invalid")
		}
		body = bytes.NewReader(b)
	}
	r, err := http.NewRequestWithContext(ctx, method, c.api+path, body)
	if err != nil {
		return errors.New("control_request_invalid")
	}
	r.Header.Set("Authorization", "Bearer "+c.key)
	r.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(r)
	if err != nil {
		return errors.New("control_unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New("control_rejected")
	}
	d := json.NewDecoder(io.LimitReader(resp.Body, 16<<20))
	d.UseNumber()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("control_response_invalid")
	}
	return nil
}

func xperfWait(ctx context.Context, client *http.Client, c xperfConfig, job string, attempted int) (xperfReceipt, error) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		var r xperfReceipt
		err := xperfAPI(ctx, client, c, http.MethodGet, "/v1/sessions/"+job+"/1", nil, &r)
		if err != nil {
			return r, err
		}
		if r.Status != "x_read" || len(r.Exchanges)+len(r.Rejections) >= attempted || time.Now().After(deadline) {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return r, errors.New("receipt_timeout")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Metrics contain fixed labels and numbers only. Raw provider identifiers,
// request data, response data, control tokens and diagnostic text cannot enter.
type xperfMetric struct {
	Schema             int               `json:"schema"`
	Sample             int               `json:"sample"`
	Mode               string            `json:"mode"`
	Headers            string            `json:"headers"`
	Workload           string            `json:"workload"`
	Status             string            `json:"status"`
	Verified           bool              `json:"verified"`
	StartNS            int64             `json:"start_unix_ns"`
	FinishNS           int64             `json:"finish_unix_ns"`
	DurationMS         int64             `json:"duration_ms"`
	ReceiptWaitMS      int64             `json:"receipt_wait_ms"`
	Exchanges          int               `json:"exchanges"`
	Items              int               `json:"items"`
	MaxRecv            int               `json:"max_recv"`
	SentRecords        int               `json:"max_sent_records"`
	RecvRecords        int               `json:"max_recv_records_online"`
	PrepareHoldMS      int               `json:"prepare_hold_ms"`
	VerifierSent       uint64            `json:"verifier_sent_bytes"`
	VerifierReceived   uint64            `json:"verifier_received_bytes"`
	TransportComplete  bool              `json:"verifier_telemetry_complete"`
	TranscriptSent     uint64            `json:"transcript_sent_bytes"`
	TranscriptReceived uint64            `json:"transcript_received_bytes"`
	BodyBytes          int               `json:"decoded_body_bytes"`
	HelperMS           int64             `json:"helper_wall_ms"`
	ExecutionMS        *uint64           `json:"helper_execution_ms,omitempty"`
	ProvisionalMS      *uint64           `json:"response_ready_ms,omitempty"`
	UserCPUSeconds     float64           `json:"helper_user_cpu_seconds"`
	SystemCPUSeconds   float64           `json:"helper_system_cpu_seconds"`
	PeakRSSBytes       int64             `json:"helper_peak_rss_bytes"`
	Timings            map[string]uint64 `json:"timings_ms"`
}

func xperfMeasurement(c xperfConfig, sample int, started time.Time, observations []xperfObserved, receiptMS int64, failure string) xperfMetric {
	now := time.Now()
	m := xperfMetric{Schema: 1, Sample: sample, Mode: c.mode, Headers: c.headers, Workload: c.workload, Status: "verified", Verified: failure == "", StartNS: started.UnixNano(), FinishNS: now.UnixNano(), DurationMS: now.Sub(started).Milliseconds(), ReceiptWaitMS: receiptMS, Exchanges: len(observations), MaxRecv: c.maxRecv, SentRecords: c.sentRecords, RecvRecords: c.recvRecords, PrepareHoldMS: c.prepareHoldMS, TransportComplete: len(observations) > 0, Timings: map[string]uint64{}}
	if failure != "" {
		m.Status = xperfFailureLabel(failure)
	}
	for _, o := range observations {
		s := o.summary
		if s.Status != "proof_sent" || s.Mode != c.mode || s.VerifierSent == nil || s.VerifierReceived == nil || s.TransportLayer != "tcp_payload" || s.TransportSaturated || s.VerifierSent != nil && *s.VerifierSent > 1<<40 || s.VerifierReceived != nil && *s.VerifierReceived > 1<<40 {
			m.TransportComplete = false
		} else {
			m.VerifierSent += *s.VerifierSent
			m.VerifierReceived += *s.VerifierReceived
		}
		m.TranscriptSent += s.SentBytes
		m.TranscriptReceived += s.ReceivedBytes
		m.BodyBytes += o.bodyBytes
		m.Items += o.items
		m.HelperMS += o.helperMS
		m.UserCPUSeconds += o.userCPUSeconds
		m.SystemCPUSeconds += o.systemCPUSeconds
		if o.peakRSSBytes > m.PeakRSSBytes {
			m.PeakRSSBytes = o.peakRSSBytes
		}
		if s.ExecutionMS != nil {
			if m.ExecutionMS == nil {
				m.ExecutionMS = new(uint64)
			}
			*m.ExecutionMS += *s.ExecutionMS
		}
		if len(observations) == 1 {
			m.ProvisionalMS = o.provisionalMS
		}
		for _, phase := range []string{"control_connect", "commit", "request_write", "response_read", "tls_finish", "prove", "finalize", "total"} {
			if n, ok := s.Timings[phase]; ok && n <= 600000 {
				m.Timings[phase] += n
			}
		}
	}
	return m
}

func xperfFailureLabel(failure string) string {
	switch failure {
	case "bootstrap_failed", "request_capture_failed", "request_policy", "request_serialization", "random_source_failed", "control_request_invalid", "control_unavailable", "control_rejected", "control_response_invalid", "control_token_invalid", "private_diagnostic_write_failed", "helper_failed", "helper_summary_invalid", "helper_response_invalid", "provider_rate_limited", "provider_auth_failed", "provider_http_failed", "typed_result_parse_failed", "pagination_cursor_missing_or_stuck", "receipt_timeout", "receipt_incomplete_or_rejected", "receipt_mismatch", "receipt_proof_mode_mismatch", "receipt_binding_mismatch":
		return failure
	default:
		return "experiment_failed"
	}
}

func TestXPerformance(t *testing.T) {
	if os.Getenv("SCARLETT_XPERF") != "1" {
		t.Skip("real-provider experiments require SCARLETT_XPERF=1")
	}
	c, err := xperfConfiguration()
	if err != nil {
		t.Fatal(err.Error())
	}
	session, err := readXSession(c.session)
	if err != nil {
		t.Fatal("private_session_invalid")
	}
	metrics, err := os.OpenFile(filepath.Join(c.output, "metrics.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal("metrics_file_must_be_new")
	}
	defer metrics.Close()
	enc := json.NewEncoder(metrics)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.samples)*6*time.Minute+2*time.Minute)
	defer cancel()
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	defer base.CloseIdleConnections()
	control := &http.Client{Transport: base, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	capture := &xperfCapture{bootstrap: true, base: base}
	client, err := session.NewClient(ctx, x.WithHTTPClient(&http.Client{Timeout: 2 * time.Minute, Transport: capture}), x.WithRetry(1, time.Millisecond), x.WithMinRequestGap(0))
	if err != nil {
		_ = enc.Encode(xperfMeasurement(c, 0, time.Now(), nil, 0, "bootstrap_failed"))
		_ = metrics.Sync()
		t.Fatal("bootstrap_failed; no proof was attempted")
	}
	capture.bootstrap = false
	for sample := 1; sample <= c.samples; sample++ {
		started := time.Now()
		observations, receiptMS, failure := xperfSample(ctx, c, sample, control, client, capture)
		if err := enc.Encode(xperfMeasurement(c, sample, started, observations, receiptMS, failure)); err != nil {
			t.Fatal("metrics_write_failed")
		}
		if err := metrics.Sync(); err != nil {
			t.Fatal("metrics_write_failed")
		}
		if failure != "" {
			t.Fatal(failure + "; stopped without retrying provider work")
		}
	}
}

func xperfSample(parent context.Context, c xperfConfig, sample int, control *http.Client, client *x.Client, capture *xperfCapture) ([]xperfObserved, int64, string) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	specs, request, err := xperfPlan(ctx, client, capture, c.workload)
	if err != nil {
		return nil, 0, err.Error()
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, 0, "random_source_failed"
	}
	job := "xperf-" + hex.EncodeToString(random[:])
	registration, binding, err := xperfRegistration(job, specs, c.mode, time.Now())
	if err != nil {
		return nil, 0, err.Error()
	}
	var created struct {
		Token string `json:"token"`
	}
	if err := xperfAPI(ctx, control, c, http.MethodPost, "/v1/sessions", registration, &created); err != nil {
		return nil, 0, err.Error()
	}
	if len(created.Token) != 64 || !isHex(created.Token) {
		return nil, 0, "control_token_invalid"
	}
	observations := make([]xperfObserved, 0, len(specs))
	failure, cursor := "", ""
	for i := range specs {
		if i > 0 {
			capture.replaySpec, capture.request = nil, nil
			_, _ = xperfRead(ctx, client, c.workload, cursor)
			if capture.request == nil {
				failure = "request_capture_failed"
				break
			}
			request = capture.request
		}
		o, body, err := xperfProve(ctx, c, created.Token, request, filepath.Join(c.output, fmt.Sprintf("sample-%03d-exchange-%d.stderr", sample, i)))
		observations = append(observations, o)
		if err != nil {
			failure = err.Error()
			break
		}
		capture.replaySpec, capture.replayBody = &o.spec, body
		parsed, err := xperfRead(ctx, client, c.workload, cursor)
		capture.replaySpec, capture.replayBody = nil, nil
		if err != nil {
			failure = "typed_result_parse_failed"
			break
		}
		observations[len(observations)-1].items = parsed.items
		if i < len(specs)-1 && (parsed.cursor == "" || parsed.cursor == cursor) {
			failure = "pagination_cursor_missing_or_stuck"
			break
		}
		cursor = parsed.cursor
	}
	started := time.Now()
	r, err := xperfWait(ctx, control, c, job, len(observations))
	receiptMS := time.Since(started).Milliseconds()
	if failure == "" {
		if err != nil {
			failure = err.Error()
		} else if err := xperfCheckBinding(r, binding); err != nil {
			failure = err.Error()
		} else if err := xperfCheckReceipt(r, observations, c.mode); err != nil {
			failure = err.Error()
		}
	}
	return observations, receiptMS, failure
}

func TestXPerfCaptureAndVariantInput(t *testing.T) {
	r := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/SearchTimeline?variables=%7B%22rawQuery%22%3A%22solana%22%2C%22count%22%3A20%7D&features=%7B%22enabled%22%3Atrue%7D")
	r.Header.Set("Cookie", "auth_token=PRIVATECOOKIE; ct0=PRIVATECSRF")
	r.Header.Set("X-Csrf-Token", "PRIVATECSRF")
	r.Header.Set("Authorization", "Bearer PRIVATEBEARER")
	r.Header.Set("Sec-Fetch-Dest", "empty")
	capture := &xperfCapture{}
	if _, err := capture.RoundTrip(r); !errors.Is(err, errXPerfCaptured) {
		t.Fatal("offline capture failed")
	}
	spec, err := xperfSpec(capture.request)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(xperfPayload([]xSpec{spec}, "mpc"))
	if strings.Contains(string(payload), "PRIVATE") || strings.Contains(string(payload), "proof_mode") {
		t.Fatal("payload leaked credentials or experimental fields")
	}
	payload, _ = json.Marshal(xperfPayload([]xSpec{spec}, "proxy"))
	if !strings.Contains(string(payload), `"proof_policy":"x-proxy-experimental-v1"`) {
		t.Fatal("proxy policy is not server-bound")
	}
	input, _, err := xperfProverInput(xperfConfig{mode: "mpc", headers: "minimal", verifier: "verifier:7047", sentRecords: 3, recvRecords: 3, prepareHoldMS: 10, responseReady: true}, strings.Repeat("ab", 32), r)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(input, &p)
	raw, _ := base64.StdEncoding.DecodeString(p["request"].(string))
	if bytes.Contains(raw, []byte("Sec-Fetch-Dest")) || !bytes.Contains(raw, []byte("PRIVATECOOKIE")) || !bytes.Contains(raw, []byte("Connection: close")) || !bytes.Contains(raw, []byte("Accept-Encoding: gzip")) || p["max_sent_records"] != float64(3) || p["max_recv_records_online"] != float64(3) || p["response_ready_event"] != true {
		t.Fatal("candidate changed required transport or credentials")
	}
	if r.Header.Get("Sec-Fetch-Dest") == "" || r.Close {
		t.Fatal("candidate mutated original request")
	}
}

func TestXPerfRejectsIncompleteAndAlteredReceipts(t *testing.T) {
	spec := xSpec{Operation: "SearchTimeline", QueryID: "q", Variables: map[string]any{"count": json.Number("20")}, Features: map[string]any{}}
	o := xperfObserved{spec: spec, bodyHash: sha256.Sum256([]byte(`{"data":{}}`)), httpStatus: 200, summary: xperfSummary{SentBytes: 20, ReceivedBytes: 30}}
	raw := `{"status":"x_read","complete":true,"pending":[],"remaining_attempts":0,"rejections":[],"exchanges":[{"index":0,"fulfilled":true,"operation":"SearchTimeline","query_id":"q","variables":{"count":20},"features":{},"http_status":200,"body":"{\"data\":{}}","sent_bytes":20,"received_bytes":30}]}`
	decode := func() xperfReceipt {
		var r xperfReceipt
		d := json.NewDecoder(strings.NewReader(raw))
		d.UseNumber()
		if err := d.Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if err := xperfCheckReceipt(decode(), []xperfObserved{o}, "mpc"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*xperfReceipt){
		func(r *xperfReceipt) { r.Complete = false }, func(r *xperfReceipt) { r.Pending = []int{0} }, func(r *xperfReceipt) { r.Remaining = 1 }, func(r *xperfReceipt) { r.Rejections = []string{"PRIVATE_DIAGNOSTIC"} },
		func(r *xperfReceipt) { r.Exchanges[0].Fulfilled = false }, func(r *xperfReceipt) { r.Exchanges[0].Body += " " }, func(r *xperfReceipt) { r.Exchanges[0].Variables["count"] = json.Number("21") }, func(r *xperfReceipt) { r.Exchanges[0].ReceivedBytes++ }, func(r *xperfReceipt) { r.Exchanges[0].Index = 1 },
	} {
		r := decode()
		mutate(&r)
		if xperfCheckReceipt(r, []xperfObserved{o}, "mpc") == nil {
			t.Fatal("invalid receipt counted verified")
		}
	}
	proxy := decode()
	if xperfCheckReceipt(proxy, []xperfObserved{o}, "proxy") == nil {
		t.Fatal("MPC receipt counted as proxy proof")
	}
	proxy.Mode, proxy.Policy = "proxy", "x-proxy-experimental-v1"
	if xperfCheckReceipt(proxy, []xperfObserved{o}, "proxy") != nil {
		t.Fatal("valid experimental receipt rejected")
	}
	if xperfCheckReceipt(proxy, []xperfObserved{o}, "mpc") == nil {
		t.Fatal("proxy receipt counted as MPC proof")
	}
}

func TestXPerfMetricsCannotCarryProviderContent(t *testing.T) {
	n := uint64(100)
	o := xperfObserved{summary: xperfSummary{Status: "proof_sent", Response: "PRIVATE_RESPONSE", Mode: "mpc", VerifierSent: &n, VerifierReceived: &n, TransportLayer: "tcp_payload", Timings: map[string]uint64{"PRIVATE_PHASE": 1, "prove": 10}}, bodyBytes: 8}
	m := xperfMeasurement(xperfConfig{mode: "mpc", headers: "normal", workload: "search"}, 1, time.Now(), []xperfObserved{o}, 1, "")
	raw, err := json.Marshal(m)
	if err != nil || strings.Contains(string(raw), "PRIVATE") || !m.TransportComplete {
		t.Fatal("metrics leaked provider data or lost telemetry")
	}
	o.summary.VerifierReceived = nil
	if xperfMeasurement(xperfConfig{}, 1, time.Now(), []xperfObserved{o}, 0, "").TransportComplete {
		t.Fatal("missing counter became zero-byte evidence")
	}
	if xperfProvisional([]byte(`{"phase":"SECRET","elapsed_ms":4}`)) != nil {
		t.Fatal("untrusted phase escaped whitelist")
	}
	if xperfFailureLabel("PRIVATE_COOKIE") != "experiment_failed" {
		t.Fatal("untrusted failure text escaped whitelist")
	}
}

func TestXPerfPrivateFileAndDirectory(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("SECRET"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := xperfPrivateRead(path, 10); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := xperfPrivateRead(filepath.Join(dir, "link"), 10); err == nil {
		t.Fatal("symlink accepted")
	}
	_ = os.Chmod(path, 0644)
	if _, err := xperfPrivateRead(path, 10); err == nil {
		t.Fatal("public key file accepted")
	}
	_ = os.Chmod(dir, 0755)
	if xperfPrivateDirectory(dir) == nil {
		t.Fatal("public run directory accepted")
	}
}

func TestXPerfDurableRegistrationFenceAndExpiry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	spec := xSpec{Operation: "SearchTimeline", QueryID: "q", Variables: map[string]any{"count": json.Number("20")}, Features: map[string]any{}}
	registration, binding, err := xperfRegistration("xperf-synthetic", []xSpec{spec}, "mpc", now)
	if err != nil {
		t.Fatal(err)
	}
	if registration["expires_at_ms"] != int64(1700000300000) || registration["fence"] != "fence-xperf-synthetic" || registration["attempt"] != "1" {
		t.Fatal("durable registration missing bounded synthetic fence/expiry")
	}
	canonical := `{"exchanges":[{"features":{},"operation":"SearchTimeline","query_id":"q","variables":{"count":20}}],"max_attempts":1,"type":"x.read"}`
	hash := sha256.Sum256([]byte(canonical))
	if binding.requestSHA != hex.EncodeToString(hash[:]) {
		t.Fatal("payload hash does not match verifier canonical JSON")
	}
	r := xperfReceipt{JobID: binding.job, Attempt: "1", Fence: binding.fence, ExpiresMS: binding.expiresMS, RequestSHA: binding.requestSHA}
	if xperfCheckBinding(r, binding) != nil {
		t.Fatal("valid binding rejected")
	}
	r.ExpiresMS++
	if xperfCheckBinding(r, binding) == nil {
		t.Fatal("altered expiry accepted")
	}
}
