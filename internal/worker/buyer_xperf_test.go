//go:build xperf

package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// The application supplies an exact funded node-v1 acceptance through a private
// local file. This bridge runs the existing X worker; it never imports the app,
// constructs a replacement plan, registers a second job or retries provider work.
type buyerXPerfArgs struct {
	LeaseFile          string `json:"lease_file"`
	Output             string `json:"output"`
	ProvisionalAPI     string `json:"provisional_api,omitempty"`
	ProvisionalKeyFile string `json:"provisional_key_file,omitempty"`
	Reuse              bool   `json:"reuse,omitempty"`
	MaxRecv            int    `json:"max_recv,omitempty"`
}

func TestBuyerBoundXPerformance(t *testing.T) {
	if os.Getenv("SCARLETT_BUYER_XPERF") != "1" {
		t.Skip("live buyer X experiment not enabled")
	}
	args := buyerXPerfArgs{LeaseFile: os.Getenv("SCARLETT_BUYER_X_LEASE_FILE"), Output: os.Getenv("SCARLETT_BUYER_X_OUTPUT"), ProvisionalAPI: os.Getenv("SCARLETT_BUYER_PROVISIONAL_API"), ProvisionalKeyFile: os.Getenv("SCARLETT_BUYER_PROVISIONAL_KEY_FILE")}
	if value := os.Getenv("SCARLETT_BUYER_X_MAX_RECV"); value != "" {
		var err error
		args.MaxRecv, err = strconv.Atoi(value)
		if err != nil {
			t.Fatal("invalid experimental receive allocation")
		}
	}
	if err := runBuyerXPerf(args, nil); err != nil {
		t.Fatal(err)
	}
}

// This tagged experiment keeps client metadata in one process. Private parent
// pipes carry only local paths; each command owns a fresh exact funded lease.
func TestBuyerContinuousXPerformance(t *testing.T) {
	if os.Getenv("SCARLETT_BUYER_X_CONTINUOUS") != "1" {
		t.Skip("continuous buyer X experiment not enabled")
	}
	pool := newXPerfClientPool(time.Hour)
	encoder := json.NewEncoder(os.Stdout)
	if encoder.Encode(map[string]any{"phase": "buyer_bridge_ready"}) != nil {
		t.Fatal("private bridge pipe unavailable")
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 16384)
	for scanner.Scan() {
		var args buyerXPerfArgs
		if decodeBuyerXPerf(scanner.Bytes(), &args) != nil {
			t.Fatal("invalid private bridge command")
		}
		err := runBuyerXPerf(args, pool)
		if encoder.Encode(map[string]any{"phase": "buyer_bridge_done", "ok": err == nil}) != nil {
			t.Fatal("private bridge reply unavailable")
		}
		if err != nil {
			t.Fatal(err)
		} // No retry after uncertain provider work.
	}
	if scanner.Err() != nil {
		t.Fatal("private bridge command exceeded its bound")
	}
}

func runBuyerXPerf(args buyerXPerfArgs, pool *xPerfClientPool) error {
	c := xperfConfig{session: os.Getenv("SCARLETT_X_SESSION"), prover: os.Getenv("SCARLETT_PROVER"), verifier: os.Getenv("SCARLETT_VERIFIER"), ca: os.Getenv("SCARLETT_VERIFIER_CA_FILE"), mode: "mpc", headers: "minimal", maxRecv: 32768, sentRecords: 3, recvRecords: 3, responseReady: true}
	switch args.MaxRecv {
	case 0:
	case 32768, 65536, 262144:
		c.maxRecv = args.MaxRecv
	default:
		return errors.New("unsupported experimental receive allocation")
	}
	host, _, err := net.SplitHostPort(c.verifier)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || !filepath.IsAbs(c.prover) || !filepath.IsAbs(c.ca) {
		return errors.New("explicit native helper and authenticated loopback verifier required")
	}
	raw, err := xperfPrivateRead(args.LeaseFile, 144<<10)
	var accepted coordinator.LeaseAcceptance
	if err != nil || decodeBuyerXPerf(raw, &accepted) != nil || accepted.Version != coordinator.Version || accepted.State != "leased" || accepted.FundingAuthority != "production_receipt" || !accepted.Lease.AcceptanceRequired {
		return errors.New("private funded acceptance invalid")
	}
	l := accepted.Lease
	local := config.Config{Profile: os.Getenv("SCARLETT_PROFILE"), XSession: c.session, Prover: c.prover, Verifier: c.verifier, VerifierCA: c.ca, MaxInputBytes: 32768, InferenceTimeout: 90 * time.Second}
	plan, deadline, failure := validateXLease(local, l)
	if failure != "" || l.RequestSHA256 == "" || len(plan.Exchanges) < 1 || len(plan.Exchanges) > 2 {
		return errors.New("buyer experiment requires one or two exact valid leased reads")
	}
	if args.ProvisionalAPI != "" && len(plan.Exchanges) != 1 {
		return errors.New("provisional experiment requires one independent read")
	}
	dir := args.Output
	if xperfPrivateDirectory(dir) != nil {
		return errors.New("private experiment directory required")
	}
	transport := &buyerXPerfTransport{config: c, lease: l, output: dir, maxExchanges: len(plan.Exchanges)}
	if origin := args.ProvisionalAPI; origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "http" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/experimental/provisional" {
			return errors.New("provisional destination must be the local experimental endpoint")
		}
		key, err := xperfPrivateRead(args.ProvisionalKeyFile, 4096)
		if err != nil || len(strings.TrimSpace(string(key))) < 16 {
			return errors.New("private provisional callback key required")
		}
		transport.provisionalOrigin, transport.provisionalKey = origin, strings.TrimSpace(string(key))
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	defer base.CloseIdleConnections()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	started := time.Now()
	bootstrap := &buyerXPerfBootstrap{base: base, started: started}
	transport.started = started
	worker := X{Config: local, Base: bootstrap, Proof: transport}
	if args.Reuse {
		if pool == nil {
			return errors.New("reusable client pool unavailable")
		}
		worker.clientFactory = pool.factory(local.Profile)
	}
	if failure := worker.Run(ctx, l); failure != "" {
		// Persist only bounded diagnostics before the parent cleans temporary
		// credential/lease files. The failed attempt is never replayed.
		_ = writeBuyerXPerfFailure(dir, failure, started, bootstrap, transport)
		return errors.New("bound X worker failed; uncertain provider work was not retried")
	}
	if len(transport.observed) != len(plan.Exchanges) {
		return errors.New("bound worker did not prove the exact exchange count")
	}
	report, err := buyerXPerfReport(args.Reuse, started, bootstrap, transport)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "node-report.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("report must be new")
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(report); err != nil {
		return errors.New("report write failed")
	}

	return nil
}

func buyerXPerfReport(reuse bool, started time.Time, bootstrap *buyerXPerfBootstrap, transport *buyerXPerfTransport) (map[string]any, error) {
	if len(transport.observed) == 0 {
		return nil, errors.New("no helper observations")
	}
	var helperMS, peakRSS int64
	var sent, received, transcriptSent, transcriptReceived uint64
	var userCPU, systemCPU float64
	resourcesComplete := true
	timings := map[string]uint64{}
	for _, o := range transport.observed {
		s := o.summary
		if s.VerifierSent == nil || s.VerifierReceived == nil || s.TransportLayer != "tcp_payload" || s.TransportSaturated {
			return nil, errors.New("helper traffic telemetry incomplete")
		}
		helperMS += o.helperMS
		resourcesComplete = resourcesComplete && o.resourceMetrics
		peakRSS = max(peakRSS, o.peakRSSBytes)
		userCPU += o.userCPUSeconds
		systemCPU += o.systemCPUSeconds
		sent += *s.VerifierSent
		received += *s.VerifierReceived
		transcriptSent += s.SentBytes
		transcriptReceived += s.ReceivedBytes
		for _, phase := range []string{"control_connect", "commit", "request_write", "response_read", "tls_finish", "prove", "finalize", "total"} {
			timings[phase] += s.Timings[phase]
		}
	}
	last := transport.observed[len(transport.observed)-1]
	return map[string]any{
		"schema": 1, "service": "x_read", "mode": "mpc", "headers": "minimal",
		"max_recv": transport.config.maxRecv, "max_sent_records": transport.config.sentRecords, "max_recv_records_online": transport.config.recvRecords,
		"proven_exchanges": len(transport.observed), "proof_connections": len(transport.observed),
		"worker_ms": time.Since(started).Milliseconds(), "helper_ms": helperMS,
		"response_ready_ms": transport.observed[0].provisionalMS, "provisional_callback": transport.provisionalOrigin != "",
		"verifier_tcp_payload_bytes": sent + received, "verifier_sent_tcp_payload_bytes": sent, "verifier_received_tcp_payload_bytes": received,
		"transcript_sent_bytes": transcriptSent, "transcript_received_bytes": transcriptReceived,
		"helper_peak_rss_bytes": peakRSS, "helper_user_cpu_seconds": userCPU, "helper_system_cpu_seconds": systemCPU,
		"helper_resource_metrics_complete": resourcesComplete, "helper_timings_ms": timings,
		"final_proof_sent": true, "provider_work_not_retried": true, "bootstrap": bootstrap.report(transport.proofStarted),
		"client_reuse_enabled": reuse, "quota_limit": last.rateLimit, "quota_remaining": last.rateRemaining, "quota_reset": last.rateReset,
	}, nil
}
func decodeBuyerXPerf(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("invalid private experiment JSON")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("invalid private experiment JSON")
	}
	return nil
}

type buyerXPerfTransport struct {
	config                            xperfConfig
	lease                             coordinator.Lease
	output                            string
	provisionalOrigin, provisionalKey string
	observed                          []xperfObserved
	started                           time.Time
	proofStarted                      time.Duration
	helperFailure                     string
	maxExchanges                      int
}

func (t *buyerXPerfTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(t.observed) >= t.maxExchanges {
		return nil, errors.New("experiment provider invocation already consumed")
	}
	if len(t.observed) == 0 {
		t.proofStarted = time.Since(t.started)
	}
	input, _, err := xperfProverInput(t.config, t.lease.VerifierToken, req)
	if err != nil {
		return nil, err
	}
	var o xperfObserved
	if t.provisionalOrigin == "" {
		o, err = xperfExecute(req.Context(), t.config, input, filepath.Join(t.output, "helper-"+strconv.Itoa(len(t.observed))+".stderr"))
	} else {
		o, err = t.executeProvisional(req.Context(), input)
	}
	t.observed = append(t.observed, o) // A failed call also spends the experiment attempt.
	if err != nil {
		t.helperFailure = o.helperFailure
		if t.helperFailure == "" {
			t.helperFailure = "native_execution_failed"
		}
		return nil, err
	}
	o, body, err := xperfDecodeResponse(o, req, o.summary.Response)
	t.observed[len(t.observed)-1] = o
	if err != nil {
		t.helperFailure = "native_response_invalid"
		return nil, err
	}
	headers := make(http.Header)
	for name, value := range map[string]*uint64{"X-Rate-Limit-Limit": o.rateLimit, "X-Rate-Limit-Remaining": o.rateRemaining, "X-Rate-Limit-Reset": o.rateReset} {
		if value != nil {
			headers.Set(name, strconv.FormatUint(*value, 10))
		}
	}
	return &http.Response{StatusCode: 200, Header: headers, Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
}

func writeBuyerXPerfFailure(dir, code string, started time.Time, bootstrap *buyerXPerfBootstrap, transport *buyerXPerfTransport) error {
	switch code {
	case "expired", "auth_required", "x_rate_limited", "invalid_lease", "x_incomplete", "x_request_failed":
	default:
		code = "worker_failed"
	}
	report := map[string]any{"schema": 1, "status": "failed", "failure": code, "service": "x_read", "mode": "mpc", "worker_ms": time.Since(started).Milliseconds(), "proof_invocations": len(transport.observed), "helper_failure": transport.helperFailure, "provider_work_not_retried": true, "bootstrap": bootstrap.report(transport.proofStarted)}
	report["failure_phase"] = "before_proof_invocation"
	if len(transport.observed) > 0 {
		o := transport.observed[len(transport.observed)-1]
		report["exchange_index"] = len(transport.observed) - 1
		report["helper_ms"], report["response_ready_ms"], report["provider_http_status"] = o.helperMS, o.provisionalMS, o.httpStatus
		report["last_native_phase"], report["last_native_phase_ms"] = o.nativePhase, o.nativePhaseMS
		report["failure_phase"] = "before_response_ready"
		if o.provisionalMS != nil {
			report["failure_phase"] = "after_response_ready"
		}
	}
	f, err := os.OpenFile(filepath.Join(dir, "node-failure.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(report)
}

func TestBuyerXPerfFailureReportPrivacy(t *testing.T) {
	dir := t.TempDir()
	started := time.Now()
	transport := &buyerXPerfTransport{lease: coordinator.Lease{JobID: "PRIVATE_JOB", VerifierToken: "PRIVATE_TOKEN"}, helperFailure: "native_execution_failed", observed: []xperfObserved{{helperMS: 90_000}}}
	if err := writeBuyerXPerfFailure(dir, "PRIVATE_ERROR", started, &buyerXPerfBootstrap{started: started}, transport); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "node-failure.json"))
	if err != nil || strings.Contains(string(raw), "PRIVATE") || !bytes.Contains(raw, []byte(`"failure":"worker_failed"`)) || !bytes.Contains(raw, []byte(`"helper_ms":90000`)) {
		t.Fatal("failure report leaked private data or lost bounded diagnostics")
	}
}

func TestBuyerXPerfMultiPageReportConservesTelemetryAndPrivacy(t *testing.T) {
	started := time.Now()
	sent, received, remaining := uint64(3), uint64(7), uint64(48)
	o := xperfObserved{helperMS: 5, peakRSSBytes: 11, userCPUSeconds: 1, summary: xperfSummary{Response: "PRIVATE_BODY", SentBytes: 2, ReceivedBytes: 4, VerifierSent: &sent, VerifierReceived: &received, TransportLayer: "tcp_payload", Timings: map[string]uint64{"commit": 3, "PRIVATE_PHASE": 99}}}
	transport := &buyerXPerfTransport{config: xperfConfig{maxRecv: 32768, sentRecords: 3, recvRecords: 3}, observed: []xperfObserved{o, o}, started: started, maxExchanges: 2}
	transport.observed[1].rateRemaining = &remaining
	report, err := buyerXPerfReport(true, started, &buyerXPerfBootstrap{started: started}, transport)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(report)
	if strings.Contains(string(raw), "PRIVATE") || report["proven_exchanges"] != 2 || report["verifier_tcp_payload_bytes"] != uint64(20) || report["helper_ms"] != int64(10) || report["helper_peak_rss_bytes"] != int64(11) || report["quota_remaining"] != &remaining || report["helper_timings_ms"].(map[string]uint64)["commit"] != 6 {
		t.Fatal("multi-page observations leaked private data or failed conservation")
	}
	transport.observed[1].summary.TransportSaturated = true
	if _, err := buyerXPerfReport(true, started, &buyerXPerfBootstrap{started: started}, transport); err == nil {
		t.Fatal("incomplete transport telemetry accepted")
	}
	request, _ := http.NewRequest(http.MethodGet, "https://x.com/i/api/graphql/synthetic/SearchTimeline", nil)
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("third provider invocation was accepted")
	}
}

func TestBuyerXPerfSuccessiveResponsesKeepDistinctPageTelemetry(t *testing.T) {
	dir := t.TempDir()
	started := time.Now()
	transport := &buyerXPerfTransport{config: xperfConfig{mode: "mpc", headers: "minimal", verifier: "127.0.0.1:1"}, lease: coordinator.Lease{VerifierToken: strings.Repeat("ab", 32)}, output: dir, started: started, maxExchanges: 2}
	for page := 1; page <= 2; page++ {
		body := `{"page":` + strconv.Itoa(page) + `}`
		remaining := 50 - page
		raw := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nX-Rate-Limit-Limit: 50\r\nX-Rate-Limit-Remaining: " + strconv.Itoa(remaining) + "\r\nX-Rate-Limit-Reset: 1700000100\r\n\r\n" + body
		sent, received := uint64(page*100), uint64(page*10)
		summary, err := json.Marshal(xperfSummary{Status: "proof_sent", Mode: "mpc", Response: base64.StdEncoding.EncodeToString([]byte(raw)), VerifierSent: &sent, VerifierReceived: &received, TransportLayer: "tcp_payload", Timings: map[string]uint64{"prove": uint64(page)}})
		if err != nil {
			t.Fatal(err)
		}
		// Synthetic executables consume no credentials and open no network sockets.
		helper := filepath.Join(dir, "fixture-helper-"+strconv.Itoa(page))
		if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s\\n' '"+string(summary)+"'\n"), 0700); err != nil {
			t.Fatal(err)
		}
		transport.config.prover = helper
		req := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/SearchTimeline?variables=%7B%22count%22%3A20%7D&features=%7B%7D")
		response, err := transport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || string(decoded) != body || response.Header.Get("X-Rate-Limit-Remaining") != strconv.Itoa(remaining) {
			t.Fatal("page response or quota changed")
		}
	}
	for index, observation := range transport.observed {
		if observation.httpStatus != 200 || observation.rateRemaining == nil || *observation.rateRemaining != uint64(49-index) || observation.summary.VerifierSent == nil || *observation.summary.VerifierSent != uint64((index+1)*100) {
			t.Fatal("one page replaced another page's decoded telemetry")
		}
	}
	report, err := buyerXPerfReport(true, started, &buyerXPerfBootstrap{started: started}, transport)
	if err != nil || report["verifier_tcp_payload_bytes"] != uint64(330) || report["helper_timings_ms"].(map[string]uint64)["prove"] != 3 || report["quota_remaining"] != transport.observed[1].rateRemaining {
		t.Fatal("distinct page telemetry was not conserved")
	}
}

type buyerXPerfProvisional struct {
	Phase      string `json:"phase"`
	State      string `json:"state"`
	Verified   *bool  `json:"verified"`
	Settled    *bool  `json:"settled"`
	HTTPStatus int    `json:"http_status"`
	Body       string `json:"body"`
	ElapsedMS  uint64 `json:"elapsed_ms"`
}

func (t *buyerXPerfTransport) executeProvisional(ctx context.Context, input []byte) (o xperfObserved, resultErr error) {
	var params map[string]any
	if json.Unmarshal(input, &params) != nil {
		return o, errors.New("invalid helper input")
	}
	params["provisional_response"] = true
	input, _ = json.Marshal(params)
	command := exec.CommandContext(ctx, t.config.prover, "prove-x")
	command.Stdin = bytes.NewReader(input)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return o, errors.New("private helper pipe unavailable")
	}
	var stderr limitedBuffer
	stderr.max = 16384
	command.Stderr = &stderr
	started := time.Now()
	if command.Start() != nil {
		return o, errors.New("native helper unavailable")
	}
	finished := false
	defer func() {
		if !finished {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		o.helperMS = time.Since(started).Milliseconds()
		xperfResourceUsage(&o, command.ProcessState)
		o.nativePhase, o.nativePhaseMS = xperfLastNativePhase(stderr.Bytes())
		if o.provisionalMS == nil {
			o.provisionalMS = xperfProvisional(stderr.Bytes())
		}
		if resultErr != nil && o.helperFailure == "" {
			o.helperFailure = xperfHelperFailure(ctx, stderr.Bytes())
		}
		if len(stderr.Bytes()) != 0 {
			if err := os.WriteFile(filepath.Join(t.output, "helper.stderr"), stderr.Bytes(), 0600); err != nil && resultErr == nil {
				o.helperFailure = "private_diagnostic_write_failed"
				resultErr = errors.New("private helper diagnostic write failed")
			}
		}
	}()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), (8<<20)+65536)
	provisional, final := false, false
	for scanner.Scan() {
		var marker struct {
			Phase string `json:"phase"`
		}
		if json.Unmarshal(scanner.Bytes(), &marker) != nil || final {
			return o, errors.New("private helper stream invalid")
		}
		if marker.Phase == "response_provisional" {
			var event buyerXPerfProvisional
			if provisional || decodeBuyerXPerf(scanner.Bytes(), &event) != nil || event.State != "unverified" || event.Verified == nil || *event.Verified || event.Settled == nil || *event.Settled || event.HTTPStatus != 200 || len(event.Body) > 8<<20 || !json.Valid([]byte(event.Body)) {
				return o, errors.New("provisional helper event invalid")
			}
			provisional = true
			o.provisionalMS = &event.ElapsedMS
			body, _ := json.Marshal(map[string]any{"job_id": t.lease.JobID, "attempt": t.lease.Attempt, "fence": t.lease.Fence, "request_sha256": t.lease.RequestSHA256, "expires_at_ms": t.lease.LeaseDeadline.UnixMilli(), "state": "unverified", "verified": false, "settled": false, "body": event.Body})
			r, _ := http.NewRequestWithContext(ctx, http.MethodPost, t.provisionalOrigin, bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+t.provisionalKey)
			r.Header.Set("Content-Type", "application/json")
			base := http.DefaultTransport.(*http.Transport).Clone()
			base.Proxy = nil
			client := &http.Client{Transport: base, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			response, err := client.Do(r)
			base.CloseIdleConnections()
			if err != nil {
				o.helperFailure = "provisional_callback_failed"
				return o, errors.New("provisional callback failed")
			}
			response.Body.Close()
			if response.StatusCode != 202 {
				o.helperFailure = "provisional_callback_rejected"
				return o, errors.New("provisional callback rejected")
			}
		} else {
			if marker.Phase != "" || json.Unmarshal(scanner.Bytes(), &o.summary) != nil || o.summary.Status != "proof_sent" || o.summary.Mode != "mpc" {
				return o, errors.New("native final summary invalid")
			}
			final = true
		}
	}
	if scanner.Err() != nil {
		return o, errors.New("private helper stream exceeded its bound")
	}
	err = command.Wait()
	finished = true
	if err != nil || scanner.Err() != nil || !provisional || !final {
		o.helperFailure = xperfHelperFailure(ctx, stderr.Bytes())
		return o, errors.New("provisional helper failed; provider work was not retried")
	}
	return o, nil
}

func TestBuyerXPerfRejectedPreviewRetainsProgressAndStopsHelper(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusConflict)
	}))
	defer server.Close()
	event, err := json.Marshal(buyerXPerfProvisional{Phase: "response_provisional", State: "unverified", Verified: new(bool), Settled: new(bool), HTTPStatus: 200, Body: `{"data":{"synthetic":{}}}`, ElapsedMS: 11})
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "fixture-helper")
	content := "#!/bin/sh\nprintf '%s\\n' '{\"phase\":\"response_read_started\",\"elapsed_ms\":7}' >&2\nprintf '%s\\n' '" + string(event) + "'\nexec sleep 30\n"
	if err := os.WriteFile(helper, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
	transport := &buyerXPerfTransport{config: xperfConfig{prover: helper}, output: dir, provisionalOrigin: server.URL, provisionalKey: "synthetic-private-key"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	observation, err := transport.executeProvisional(ctx, []byte(`{}`))
	if err == nil || calls.Load() != 1 || ctx.Err() != nil || observation.helperFailure != "provisional_callback_rejected" || observation.nativePhase != "response_read_started" || observation.nativePhaseMS == nil || *observation.nativePhaseMS != 7 || observation.provisionalMS == nil || *observation.provisionalMS != 11 || !observation.resourceMetrics {
		t.Fatal("rejected preview lost progress, kept the helper running or replayed its callback")
	}
}
