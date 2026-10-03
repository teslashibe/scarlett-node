//go:build xperf

package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const codexperfModel = "gpt-6.1-sol"
const codexperfPrompt = "Reply exactly scarlettperf"
const codexperfOutput = "scarlettperf"

type codexperfConfig struct {
	control       xperfConfig
	serverName    string
	closeStrategy string
	samples       int
}

func codexperfConfiguration() (codexperfConfig, error) {
	c := codexperfConfig{control: xperfConfig{prover: os.Getenv("SCARLETT_PROVER"), verifier: os.Getenv("SCARLETT_VERIFIER"), ca: os.Getenv("SCARLETT_VERIFIER_CA_FILE"), api: os.Getenv("SCARLETT_VERIFIER_API"), output: os.Getenv("SCARLETT_CODEXPERF_OUTPUT")}, serverName: os.Getenv("SCARLETT_VERIFIER_SERVER_NAME"), samples: 1}
	var err error
	c.closeStrategy, err = codexperfCloseStrategy(os.Getenv("SCARLETT_CODEXPERF_CLOSE_STRATEGY"))
	if err != nil {
		return c, err
	}
	if v := os.Getenv("SCARLETT_CODEXPERF_SAMPLES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 30 {
			return c, errors.New("invalid_sample_count")
		}
		c.samples = n
	}
	if c.control.prover == "" || c.control.verifier == "" || c.control.api == "" || c.control.output == "" {
		return c, errors.New("missing_configuration")
	}
	if os.Getenv("SCARLETT_PROVER_CHEAT") != "" {
		return c, errors.New("adversarial_helper_mode_enabled")
	}
	u, err := url.Parse(c.control.api)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return c, errors.New("unsafe_control_origin")
	}
	c.control.api = strings.TrimRight(c.control.api, "/")
	key, err := xperfPrivateRead(os.Getenv("SCARLETT_VERIFIER_KEY_FILE"), 4096)
	if err != nil {
		return c, errors.New("invalid_private_key_file")
	}
	c.control.key = strings.TrimSpace(string(key))
	if c.control.key == "" || strings.ContainsAny(c.control.key, "\r\n") {
		return c, errors.New("invalid_private_key_file")
	}
	if err := xperfPrivateDirectory(c.control.output); err != nil {
		return c, err
	}
	return c, nil
}

func codexperfPayload() map[string]any {
	return map[string]any{
		"type": "response.create", "model": codexperfModel,
		"instructions": "You are a helpful assistant.",
		"input":        []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": codexperfPrompt}}}},
		"stream":       true, "store": false,
		"reasoning": map[string]any{"effort": "low"}, "text": map[string]any{"verbosity": "low"},
	}
}

func codexperfRegistration(job string, now time.Time) (map[string]any, xperfBinding) {
	payload := codexperfPayload()
	raw, _ := json.Marshal(payload) // Maps at every level match serde_json's ordered objects.
	hash := sha256.Sum256(raw)
	b := xperfBinding{job: job, fence: "fence-" + job, requestSHA: hex.EncodeToString(hash[:]), expiresMS: now.Add(300 * time.Second).UnixMilli()}
	return map[string]any{"job_id": job, "attempt": "1", "fence": b.fence, "expires_at_ms": b.expiresMS, "payload": payload}, b
}

func codexperfProverInput(c codexperfConfig, token string) ([]byte, error) {
	p := map[string]any{"verifier": c.control.verifier, "token": token, "payload": codexperfPayload()}
	strategy, err := codexperfCloseStrategy(c.closeStrategy)
	if err != nil {
		return nil, err
	}
	p["close_strategy"] = strategy
	if c.control.ca != "" {
		p["verifier_ca_file"] = c.control.ca
	}
	if c.serverName != "" {
		p["verifier_server_name"] = c.serverName
	}
	return json.Marshal(p)
}

type codexperfSummary struct {
	xperfSummary
	CodexMS       *uint64 `json:"codex_ms"`
	CloseStrategy string  `json:"close_strategy"`
}

func codexperfCloseStrategy(v string) (string, error) {
	if v == "" {
		return "normal", nil
	}
	if v != "normal" && v != "tls_after_completed" {
		return "", errors.New("invalid_close_strategy")
	}
	return v, nil
}

func codexperfCheckCloseStrategy(requested, reported string) error {
	strategy, err := codexperfCloseStrategy(requested)
	if err != nil {
		return err
	}
	// Prior baseline helpers omitted this field and implemented only normal.
	if reported == "" && strategy == "normal" {
		return nil
	}
	if reported != strategy {
		return errors.New("helper_close_strategy_mismatch")
	}
	return nil
}

type codexperfObserved struct {
	summary                          codexperfSummary
	helperMS                         int64
	userCPUSeconds, systemCPUSeconds float64
	peakRSSBytes                     int64
}

func codexperfProve(ctx context.Context, c codexperfConfig, token, diagnostic string) (codexperfObserved, error) {
	var o codexperfObserved
	input, err := codexperfProverInput(c, token)
	if err != nil {
		return o, errors.New("control_request_invalid")
	}
	cmd := exec.CommandContext(ctx, c.control.prover, "prove")
	// The native helper owns login loading. The harness never opens auth.json.
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = 16384, 16384
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
			return o, errors.New("private_diagnostic_write_failed")
		}
		_, e = f.Write(stderr.Bytes())
		closeErr := f.Close()
		if e != nil || closeErr != nil {
			return o, errors.New("private_diagnostic_write_failed")
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return o, errors.New("helper_timeout")
		}
		return o, errors.New(codexperfProviderFailure(stderr.Bytes()))
	}
	if json.Unmarshal(stdout.Bytes(), &o.summary) != nil || o.summary.Status != "proof_sent" || o.summary.Mode != "proxy" || o.summary.CodexMS == nil || *o.summary.CodexMS > 300000 || o.summary.DurationMS == 0 || o.summary.DurationMS > 300000 || o.summary.SentBytes > 1<<40 || o.summary.ReceivedBytes > 1<<40 {
		return o, errors.New("helper_summary_invalid")
	}
	if err := codexperfCheckCloseStrategy(c.closeStrategy, o.summary.CloseStrategy); err != nil {
		return o, err
	}
	for _, phase := range codexperfPhases {
		if n, ok := o.summary.Timings[phase]; !ok || n > 300000 {
			return o, errors.New("helper_timings_invalid")
		}
	}
	return o, nil
}

func codexperfProviderFailure(raw []byte) string {
	for _, p := range []struct{ marker, label string }{
		{"Codex provider error: rate_limited", "provider_rate_limited"},
		{"Codex provider error: unauthenticated", "provider_auth_failed"},
		{"Codex provider error: model_unavailable", "provider_model_unavailable"},
		{"Codex provider error: unsupported_request", "provider_unsupported_request"},
	} {
		if bytes.Contains(raw, []byte(p.marker)) {
			return p.label
		}
	}
	return "helper_failed"
}

var codexperfPhases = []string{"control_connect", "commit", "websocket_handshake", "response_read", "tls_finish", "prove", "finalize", "total"}

type codexperfReceipt struct {
	xperfReceipt
	Model         string  `json:"model"`
	Output        string  `json:"output"`
	InputTokens   *uint64 `json:"input_tokens"`
	CachedTokens  *uint64 `json:"cached_input_tokens"`
	OutputTokens  *uint64 `json:"output_tokens"`
	DurationMS    uint64  `json:"duration_ms"`
	SentBytes     *uint64 `json:"sent_bytes"`
	ReceivedBytes *uint64 `json:"received_bytes"`
}

func codexperfCheckReceipt(r codexperfReceipt, b xperfBinding, s codexperfSummary) error {
	if err := xperfCheckBinding(r.xperfReceipt, b); err != nil {
		return err
	}
	if r.Status != "accepted" {
		return errors.New("receipt_not_accepted")
	}
	if r.Mode != "" && r.Mode != "proxy" || r.Policy != "" {
		return errors.New("receipt_proof_mode_mismatch")
	}
	if r.Model != codexperfModel {
		return errors.New("receipt_model_mismatch")
	}
	if r.Output != codexperfOutput {
		return errors.New("receipt_output_mismatch")
	}
	if r.InputTokens == nil || r.OutputTokens == nil || *r.InputTokens > 1000000000 || *r.OutputTokens > 1000000000 || r.CachedTokens != nil && *r.CachedTokens > *r.InputTokens {
		return errors.New("receipt_usage_invalid")
	}
	// Authenticated receipt counters are optional in the current server schema.
	// Never equate supplier telemetry with independently verified transcript sizes.
	if (r.SentBytes == nil) != (r.ReceivedBytes == nil) || r.SentBytes != nil && (*r.SentBytes != s.SentBytes || *r.ReceivedBytes != s.ReceivedBytes) {
		return errors.New("receipt_transcript_mismatch")
	}
	return nil
}

func codexperfWait(ctx context.Context, client *http.Client, c codexperfConfig, job string) (codexperfReceipt, error) {
	deadline := time.Now().Add(15 * time.Second)
	for {
		var r codexperfReceipt
		if err := xperfAPI(ctx, client, c.control, http.MethodGet, "/v1/sessions/"+job+"/1", nil, &r); err != nil {
			return r, err
		}
		if r.Status != "pending" && r.Status != "running" || time.Now().After(deadline) {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return r, errors.New("receipt_timeout")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type codexperfMetric struct {
	Schema             int               `json:"schema"`
	Sample             int               `json:"sample"`
	Mode               string            `json:"mode"`
	CloseStrategy      string            `json:"close_strategy"`
	Workload           string            `json:"workload"`
	Reasoning          string            `json:"reasoning"`
	ServiceTierOmitted bool              `json:"service_tier_omitted"`
	Status             string            `json:"status"`
	Verified           bool              `json:"verified"`
	ModelMatches       bool              `json:"model_matches"`
	OutputMatches      bool              `json:"output_matches"`
	StartNS            int64             `json:"start_unix_ns"`
	FinishNS           int64             `json:"finish_unix_ns"`
	DurationMS         int64             `json:"duration_ms"`
	ReceiptWaitMS      int64             `json:"receipt_wait_ms"`
	ReceiptDurationMS  uint64            `json:"receipt_duration_ms"`
	InputTokens        *uint64           `json:"input_tokens,omitempty"`
	CachedTokens       *uint64           `json:"cached_input_tokens,omitempty"`
	CachedReported     bool              `json:"cached_input_tokens_reported"`
	OutputTokens       *uint64           `json:"output_tokens,omitempty"`
	VerifierSent       uint64            `json:"verifier_sent_bytes"`
	VerifierReceived   uint64            `json:"verifier_received_bytes"`
	TransportComplete  bool              `json:"verifier_telemetry_complete"`
	TranscriptSent     uint64            `json:"transcript_sent_bytes"`
	TranscriptReceived uint64            `json:"transcript_received_bytes"`
	TranscriptVerified bool              `json:"transcript_counters_verified_by_receipt"`
	CodexMS            *uint64           `json:"codex_ms,omitempty"`
	HelperMS           int64             `json:"helper_wall_ms"`
	UserCPUSeconds     float64           `json:"helper_user_cpu_seconds"`
	SystemCPUSeconds   float64           `json:"helper_system_cpu_seconds"`
	PeakRSSBytes       int64             `json:"helper_peak_rss_bytes"`
	Timings            map[string]uint64 `json:"timings_ms"`
}

func codexperfMeasurement(sample int, started time.Time, o codexperfObserved, r codexperfReceipt, receiptMS int64, failure, closeStrategy string) codexperfMetric {
	now := time.Now()
	m := codexperfMetric{Schema: 1, Sample: sample, Mode: "proxy", Workload: "codex_trivial", Reasoning: "low", ServiceTierOmitted: true, Status: "verified", Verified: failure == "", StartNS: started.UnixNano(), FinishNS: now.UnixNano(), DurationMS: now.Sub(started).Milliseconds(), ReceiptWaitMS: receiptMS, HelperMS: o.helperMS, UserCPUSeconds: o.userCPUSeconds, SystemCPUSeconds: o.systemCPUSeconds, PeakRSSBytes: o.peakRSSBytes, Timings: make(map[string]uint64)}
	m.CloseStrategy, _ = codexperfCloseStrategy(closeStrategy)
	if m.CloseStrategy == "" {
		m.CloseStrategy, m.Status, m.Verified = "normal", "invalid_close_strategy", false
	}
	if failure != "" {
		m.Status = codexperfFailureLabel(failure)
	}
	if m.Verified {
		m.ModelMatches, m.OutputMatches = true, true
		m.InputTokens, m.CachedTokens, m.OutputTokens = r.InputTokens, r.CachedTokens, r.OutputTokens
		m.CachedReported, m.ReceiptDurationMS = r.CachedTokens != nil, r.DurationMS
		m.TranscriptVerified = r.SentBytes != nil && r.ReceivedBytes != nil
	}
	s := o.summary
	if s.Status == "proof_sent" && s.Mode == "proxy" && s.VerifierSent != nil && s.VerifierReceived != nil && s.TransportLayer == "tcp_payload" && !s.TransportSaturated && *s.VerifierSent <= 1<<40 && *s.VerifierReceived <= 1<<40 {
		m.TransportComplete, m.VerifierSent, m.VerifierReceived = true, *s.VerifierSent, *s.VerifierReceived
	}
	if s.SentBytes <= 1<<40 && s.ReceivedBytes <= 1<<40 {
		m.TranscriptSent, m.TranscriptReceived = s.SentBytes, s.ReceivedBytes
	}
	if s.CodexMS != nil && *s.CodexMS <= 300000 {
		m.CodexMS = s.CodexMS
	}
	for _, phase := range codexperfPhases {
		if n, ok := s.Timings[phase]; ok && n <= 300000 {
			m.Timings[phase] = n
		}
	}
	return m
}

func codexperfFailureLabel(failure string) string {
	switch failure {
	case "control_request_invalid", "random_source_failed", "control_unavailable", "control_rejected", "control_response_invalid", "control_token_invalid", "private_diagnostic_write_failed", "helper_timeout", "helper_failed", "helper_summary_invalid", "helper_timings_invalid", "helper_close_strategy_mismatch", "invalid_close_strategy", "provider_rate_limited", "provider_auth_failed", "provider_model_unavailable", "provider_unsupported_request", "receipt_timeout", "receipt_binding_mismatch", "receipt_not_accepted", "receipt_proof_mode_mismatch", "receipt_model_mismatch", "receipt_output_mismatch", "receipt_usage_invalid", "receipt_transcript_mismatch":
		return failure
	default:
		return "experiment_failed"
	}
}

func TestCodexPerformance(t *testing.T) {
	if os.Getenv("SCARLETT_CODEXPERF") != "1" {
		t.Skip("real-provider experiments require SCARLETT_CODEXPERF=1")
	}
	c, err := codexperfConfiguration()
	if err != nil {
		t.Fatal(err.Error())
	}
	metrics, err := os.OpenFile(filepath.Join(c.control.output, "metrics.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal("metrics_file_must_be_new")
	}
	defer metrics.Close()
	enc := json.NewEncoder(metrics)
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	defer base.CloseIdleConnections()
	control := &http.Client{Transport: base, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.samples)*6*time.Minute)
	defer cancel()
	for sample := 1; sample <= c.samples; sample++ {
		started := time.Now()
		o, r, receiptMS, failure := codexperfSample(ctx, c, sample, control)
		if err := enc.Encode(codexperfMeasurement(sample, started, o, r, receiptMS, failure, c.closeStrategy)); err != nil {
			t.Fatal("metrics_write_failed")
		}
		if err := metrics.Sync(); err != nil {
			t.Fatal("metrics_write_failed")
		}
		if failure != "" {
			t.Fatal(codexperfFailureLabel(failure) + "; stopped without retrying provider work")
		}
	}
}

func codexperfSample(parent context.Context, c codexperfConfig, sample int, control *http.Client) (codexperfObserved, codexperfReceipt, int64, string) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	var empty codexperfObserved
	var receipt codexperfReceipt
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return empty, receipt, 0, "random_source_failed"
	}
	job := "codexperf-" + hex.EncodeToString(random[:])
	registration, binding := codexperfRegistration(job, time.Now())
	var created struct {
		Token string `json:"token"`
	}
	if err := xperfAPI(ctx, control, c.control, http.MethodPost, "/v1/sessions", registration, &created); err != nil {
		return empty, receipt, 0, err.Error()
	}
	if len(created.Token) != 64 || !isHex(created.Token) {
		return empty, receipt, 0, "control_token_invalid"
	}
	o, proofErr := codexperfProve(ctx, c, created.Token, filepath.Join(c.control.output, "sample-"+strconv.Itoa(sample)+".stderr"))
	started := time.Now()
	receipt, receiptErr := codexperfWait(ctx, control, c, job)
	receiptMS := time.Since(started).Milliseconds()
	if proofErr != nil {
		return o, receipt, receiptMS, proofErr.Error()
	}
	if receiptErr != nil {
		return o, receipt, receiptMS, receiptErr.Error()
	}
	if err := codexperfCheckReceipt(receipt, binding, o.summary); err != nil {
		return o, receipt, receiptMS, err.Error()
	}
	return o, receipt, receiptMS, ""
}

func TestCodexPerfPayloadBindingAndNativeInput(t *testing.T) {
	now := time.Unix(1700000000, 0)
	registration, binding := codexperfRegistration("codexperf-synthetic", now)
	if registration["expires_at_ms"] != int64(1700000300000) || registration["fence"] != "fence-codexperf-synthetic" || registration["attempt"] != "1" {
		t.Fatal("registration lacks bounded synthetic binding")
	}
	payload := codexperfPayload()
	if len(payload) != 8 || payload["model"] != codexperfModel || payload["reasoning"].(map[string]any)["effort"] != "low" {
		t.Fatal("workload changed")
	}
	if _, ok := payload["service_tier"]; ok {
		t.Fatal("normal speed unexpectedly requests a tier")
	}
	if _, ok := payload["tools"]; ok {
		t.Fatal("benchmark enabled tools")
	}
	raw, _ := json.Marshal(payload)
	hash := sha256.Sum256(raw)
	if binding.requestSHA != hex.EncodeToString(hash[:]) {
		t.Fatal("payload binding mismatch")
	}
	input, err := codexperfProverInput(codexperfConfig{control: xperfConfig{verifier: "verifier:7047", ca: "private-ca.pem"}, serverName: "verifier.example"}, strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if json.Unmarshal(input, &v) != nil || v["verifier_ca_file"] != "private-ca.pem" || v["verifier_server_name"] != "verifier.example" {
		t.Fatal("native TLS input incomplete")
	}
	if bytes.Contains(input, []byte("auth.json")) || bytes.Contains(input, []byte("access_token")) {
		t.Fatal("harness read or serialized native login")
	}
}

func TestCodexPerfRejectsInvalidReceiptsAndUnknownUsage(t *testing.T) {
	_, binding := codexperfRegistration("codexperf-synthetic", time.Unix(1700000000, 0))
	one, two := uint64(1), uint64(2)
	makeReceipt := func() codexperfReceipt {
		return codexperfReceipt{xperfReceipt: xperfReceipt{Status: "accepted", JobID: binding.job, Attempt: "1", Fence: binding.fence, ExpiresMS: binding.expiresMS, RequestSHA: binding.requestSHA}, Model: codexperfModel, Output: codexperfOutput, InputTokens: &two, OutputTokens: &one}
	}
	if err := codexperfCheckReceipt(makeReceipt(), binding, codexperfSummary{}); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*codexperfReceipt){
		func(r *codexperfReceipt) { r.Status = "running" }, func(r *codexperfReceipt) { r.Status = "rejected" }, func(r *codexperfReceipt) { r.Fence = "wrong" }, func(r *codexperfReceipt) { r.RequestSHA = "wrong" },
		func(r *codexperfReceipt) { r.Model = "PRIVATE_MODEL" }, func(r *codexperfReceipt) { r.Output = "PRIVATE_OUTPUT" }, func(r *codexperfReceipt) { r.InputTokens = nil }, func(r *codexperfReceipt) { r.OutputTokens = nil },
		func(r *codexperfReceipt) { r.CachedTokens = &two; r.InputTokens = &one }, func(r *codexperfReceipt) { r.Mode = "mpc" }, func(r *codexperfReceipt) { r.SentBytes = &one; r.ReceivedBytes = &two },
	} {
		r := makeReceipt()
		mutate(&r)
		if codexperfCheckReceipt(r, binding, codexperfSummary{}) == nil {
			t.Fatal("invalid receipt counted verified")
		}
	}
	r := makeReceipt()
	m := codexperfMeasurement(1, time.Now(), codexperfObserved{}, r, 0, "", "normal")
	if m.CachedReported || m.CachedTokens != nil || m.TranscriptVerified {
		t.Fatal("missing cached usage or receipt counters became zero/verified evidence")
	}
}

func TestCodexPerfSanitizedMetricsAndErrorClassification(t *testing.T) {
	n := uint64(200)
	o := codexperfObserved{summary: codexperfSummary{xperfSummary: xperfSummary{Status: "proof_sent", Mode: "proxy", VerifierSent: &n, VerifierReceived: &n, TransportLayer: "tcp_payload", Response: "PRIVATE_RESPONSE", Timings: map[string]uint64{"PRIVATE_PHASE": 1, "prove": 10}}}}
	r := codexperfReceipt{Output: "PRIVATE_OUTPUT", Model: "PRIVATE_MODEL"}
	raw, _ := json.Marshal(codexperfMeasurement(1, time.Now(), o, r, 0, "PRIVATE_ERROR", "normal"))
	if bytes.Contains(raw, []byte("PRIVATE")) {
		t.Fatal("private provider content leaked into metrics")
	}
	if codexperfProviderFailure([]byte("Codex provider error: rate_limited PRIVATE_ACCOUNT")) != "provider_rate_limited" || codexperfProviderFailure([]byte("PRIVATE_ACCOUNT")) != "helper_failed" {
		t.Fatal("provider error escaped finite classification")
	}
	o.summary.VerifierReceived = nil
	if codexperfMeasurement(1, time.Now(), o, r, 0, "helper_failed", "normal").TransportComplete {
		t.Fatal("missing transport counter became measured zero")
	}
}

func TestCodexPerfCloseStrategyConfigAndSummaryBinding(t *testing.T) {
	for _, pair := range [][2]string{{"", ""}, {"normal", ""}, {"normal", "normal"}, {"tls_after_completed", "tls_after_completed"}} {
		if codexperfCheckCloseStrategy(pair[0], pair[1]) != nil {
			t.Fatal("supported strategy or old normal baseline rejected")
		}
	}
	for _, pair := range [][2]string{{"tls_after_completed", ""}, {"tls_after_completed", "normal"}, {"normal", "tls_after_completed"}, {"normal", "PRIVATE_STRATEGY"}, {"PRIVATE_STRATEGY", "PRIVATE_STRATEGY"}} {
		if codexperfCheckCloseStrategy(pair[0], pair[1]) == nil {
			t.Fatal("mismatched shutdown strategy accepted")
		}
	}
	input, err := codexperfProverInput(codexperfConfig{closeStrategy: "tls_after_completed"}, strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if json.Unmarshal(input, &v) != nil || v["close_strategy"] != "tls_after_completed" {
		t.Fatal("candidate strategy not sent to native helper")
	}
	metric := codexperfMeasurement(1, time.Now(), codexperfObserved{}, codexperfReceipt{}, 0, "helper_failed", "tls_after_completed")
	if metric.CloseStrategy != "tls_after_completed" {
		t.Fatal("failed candidate mixed into normal baseline")
	}
	t.Setenv("SCARLETT_CODEXPERF_CLOSE_STRATEGY", "PRIVATE_STRATEGY")
	if _, err := codexperfConfiguration(); err == nil || err.Error() != "invalid_close_strategy" {
		t.Fatal("invalid config accepted or leaked")
	}
}

func TestCodexPerfReceiptDecoderKeepsCachedUsageUnknown(t *testing.T) {
	for _, raw := range []string{`{"status":"accepted","input_tokens":2,"output_tokens":1}`, `{"status":"accepted","input_tokens":2,"cached_input_tokens":null,"output_tokens":1}`} {
		var r codexperfReceipt
		if json.NewDecoder(strings.NewReader(raw)).Decode(&r) != nil || r.Status != "accepted" || r.InputTokens == nil || r.OutputTokens == nil || r.CachedTokens != nil {
			t.Fatal("receipt field decoding invented cached usage")
		}
	}
	var r codexperfReceipt
	if json.NewDecoder(strings.NewReader(`{"input_tokens":-1}`)).Decode(&r) == nil {
		t.Fatal("negative provider token usage accepted")
	}
}
