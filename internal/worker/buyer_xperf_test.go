//go:build xperf

package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
}

func TestBuyerBoundXPerformance(t *testing.T) {
	if os.Getenv("SCARLETT_BUYER_XPERF") != "1" {
		t.Skip("live buyer X experiment not enabled")
	}
	args := buyerXPerfArgs{LeaseFile: os.Getenv("SCARLETT_BUYER_X_LEASE_FILE"), Output: os.Getenv("SCARLETT_BUYER_X_OUTPUT"), ProvisionalAPI: os.Getenv("SCARLETT_BUYER_PROVISIONAL_API"), ProvisionalKeyFile: os.Getenv("SCARLETT_BUYER_PROVISIONAL_KEY_FILE")}
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
	if failure != "" || l.RequestSHA256 == "" || len(plan.Exchanges) != 1 {
		return errors.New("buyer experiment requires one exact valid leased read")
	}
	dir := args.Output
	if xperfPrivateDirectory(dir) != nil {
		return errors.New("private experiment directory required")
	}
	transport := &buyerXPerfTransport{config: c, lease: l, output: dir}
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
	if len(transport.observed) != 1 {
		return errors.New("bound worker did not prove exactly one exchange")
	}
	o := transport.observed[0]
	if o.summary.VerifierSent == nil || o.summary.VerifierReceived == nil || o.summary.TransportLayer != "tcp_payload" || o.summary.TransportSaturated {
		return errors.New("helper traffic telemetry incomplete")
	}
	f, err := os.OpenFile(filepath.Join(dir, "node-report.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("report must be new")
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(map[string]any{"schema": 1, "service": "x_read", "mode": "mpc", "headers": "minimal", "max_recv": 32768, "max_sent_records": 3, "max_recv_records_online": 3, "proven_exchanges": 1, "worker_ms": time.Since(started).Milliseconds(), "helper_ms": o.helperMS, "response_ready_ms": o.provisionalMS, "provisional_callback": transport.provisionalOrigin != "", "verifier_tcp_payload_bytes": *o.summary.VerifierSent + *o.summary.VerifierReceived, "final_proof_sent": true, "provider_work_not_retried": true, "bootstrap": bootstrap.report(transport.proofStarted), "client_reuse_enabled": args.Reuse, "quota_limit": o.rateLimit, "quota_remaining": o.rateRemaining, "quota_reset": o.rateReset}); err != nil {
		return errors.New("report write failed")
	}

	return nil
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
}

func (t *buyerXPerfTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(t.observed) != 0 {
		return nil, errors.New("experiment provider invocation already consumed")
	}
	t.proofStarted = time.Since(t.started)
	input, _, err := xperfProverInput(t.config, t.lease.VerifierToken, req)
	if err != nil {
		return nil, err
	}
	var o xperfObserved
	if t.provisionalOrigin == "" {
		o, err = xperfExecute(req.Context(), t.config, input, filepath.Join(t.output, "helper.stderr"))
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
	t.observed[0] = o
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
	if len(transport.observed) == 1 {
		o := transport.observed[0]
		report["helper_ms"], report["response_ready_ms"], report["provider_http_status"] = o.helperMS, o.provisionalMS, o.httpStatus
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

type buyerXPerfProvisional struct {
	Phase      string `json:"phase"`
	State      string `json:"state"`
	Verified   *bool  `json:"verified"`
	Settled    *bool  `json:"settled"`
	HTTPStatus int    `json:"http_status"`
	Body       string `json:"body"`
	ElapsedMS  uint64 `json:"elapsed_ms"`
}

func (t *buyerXPerfTransport) executeProvisional(ctx context.Context, input []byte) (xperfObserved, error) {
	var o xperfObserved
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
				return o, errors.New("provisional callback failed")
			}
			response.Body.Close()
			if response.StatusCode != 202 {
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
	o.helperMS = time.Since(started).Milliseconds()
	if len(stderr.Bytes()) != 0 {
		if err := os.WriteFile(filepath.Join(t.output, "helper.stderr"), stderr.Bytes(), 0600); err != nil {
			return o, errors.New("private helper diagnostic write failed")
		}
	}
	if err != nil || scanner.Err() != nil || !provisional || !final {
		o.helperFailure = xperfHelperFailure(ctx, stderr.Bytes())
		return o, errors.New("provisional helper failed; provider work was not retried")
	}
	return o, nil
}
