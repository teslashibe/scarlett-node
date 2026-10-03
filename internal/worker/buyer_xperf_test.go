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
	"strings"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// The application supplies an exact funded node-v1 acceptance through a private
// local file. This bridge runs the existing X worker; it never imports the app,
// constructs a replacement plan, registers a second job or retries provider work.
func TestBuyerBoundXPerformance(t *testing.T) {
	if os.Getenv("SCARLETT_BUYER_XPERF") != "1" {
		t.Skip("live buyer X experiment not enabled")
	}
	c := xperfConfig{session: os.Getenv("SCARLETT_X_SESSION"), prover: os.Getenv("SCARLETT_PROVER"), verifier: os.Getenv("SCARLETT_VERIFIER"), ca: os.Getenv("SCARLETT_VERIFIER_CA_FILE"), mode: "mpc", headers: "minimal", maxRecv: 32768, sentRecords: 3, recvRecords: 3, responseReady: true}
	host, _, err := net.SplitHostPort(c.verifier)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || !filepath.IsAbs(c.prover) || !filepath.IsAbs(c.ca) {
		t.Fatal("explicit native helper and authenticated loopback verifier required")
	}
	raw, err := xperfPrivateRead(os.Getenv("SCARLETT_BUYER_X_LEASE_FILE"), 144<<10)
	var accepted coordinator.LeaseAcceptance
	if err != nil || decodeBuyerXPerf(raw, &accepted) != nil || accepted.Version != coordinator.Version || accepted.State != "leased" || accepted.FundingAuthority != "production_receipt" || !accepted.Lease.AcceptanceRequired {
		t.Fatal("private funded acceptance invalid")
	}
	l := accepted.Lease
	local := config.Config{Profile: os.Getenv("SCARLETT_PROFILE"), XSession: c.session, Prover: c.prover, Verifier: c.verifier, VerifierCA: c.ca, MaxInputBytes: 32768, InferenceTimeout: 90 * time.Second}
	plan, deadline, failure := validateXLease(local, l)
	if failure != "" || l.RequestSHA256 == "" || len(plan.Exchanges) != 1 {
		t.Fatal("buyer experiment requires one exact valid leased read")
	}
	dir := os.Getenv("SCARLETT_BUYER_X_OUTPUT")
	if xperfPrivateDirectory(dir) != nil {
		t.Fatal("private experiment directory required")
	}
	transport := &buyerXPerfTransport{config: c, lease: l, output: dir}
	if origin := os.Getenv("SCARLETT_BUYER_PROVISIONAL_API"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "http" || net.ParseIP(u.Hostname()) == nil || !net.ParseIP(u.Hostname()).IsLoopback() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/experimental/provisional" {
			t.Fatal("provisional destination must be the local experimental endpoint")
		}
		key, err := xperfPrivateRead(os.Getenv("SCARLETT_BUYER_PROVISIONAL_KEY_FILE"), 4096)
		if err != nil || len(strings.TrimSpace(string(key))) < 16 {
			t.Fatal("private provisional callback key required")
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
	if failure := (X{Config: local, Base: bootstrap, Proof: transport}).Run(ctx, l); failure != "" {
		t.Fatal("bound X worker failed; uncertain provider work was not retried", failure)
	}
	if len(transport.observed) != 1 {
		t.Fatal("bound worker did not prove exactly one exchange")
	}
	o := transport.observed[0]
	if o.summary.VerifierSent == nil || o.summary.VerifierReceived == nil || o.summary.TransportLayer != "tcp_payload" || o.summary.TransportSaturated {
		t.Fatal("helper traffic telemetry incomplete")
	}
	f, err := os.OpenFile(filepath.Join(dir, "node-report.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("report must be new")
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(map[string]any{"schema": 1, "service": "x_read", "mode": "mpc", "headers": "minimal", "max_recv": 32768, "max_sent_records": 3, "max_recv_records_online": 3, "proven_exchanges": 1, "worker_ms": time.Since(started).Milliseconds(), "helper_ms": o.helperMS, "response_ready_ms": o.provisionalMS, "provisional_callback": transport.provisionalOrigin != "", "verifier_tcp_payload_bytes": *o.summary.VerifierSent + *o.summary.VerifierReceived, "final_proof_sent": true, "provider_work_not_retried": true, "bootstrap": bootstrap.report(transport.proofStarted)}); err != nil {
		t.Fatal("report write failed")
	}
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
		return nil, err
	}
	o, body, err := xperfDecodeResponse(o, req, o.summary.Response)
	t.observed[0] = o
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: req}, nil
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
		return o, errors.New("provisional helper failed; provider work was not retried")
	}
	return o, nil
}
