package worker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
	"github.com/teslashibe/scarlett-node/internal/process"
	"io"
	"net/http"
	"os/exec"
	"strings"
)

// XTransport is an http.RoundTripper for an x-go client. It proves each x.com
// GraphQL GET with `scarlett-prover prove-x`: the node's own connection reaches
// X over MPC-TLS and the verifier keeps its own copy of the response. With
// Relay set it runs `scarlett-prover relay-x` instead: the node still opens
// the connection to X, but the verifier is the TLS client and the node adds
// only its session values. Other x.com API calls, including writes, are
// refused. Everything else, such as transaction-ID bootstrap pages, goes
// through Base unproven.
type XTransport struct {
	Prover           string
	Verifier         string
	VerifierCA       string
	PlaintextFixture bool
	Token            string
	Relay            bool
	Base             http.RoundTripper
}

var errUnprovenXCall = errors.New("only X GraphQL reads can be proven")

func (t XTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "x.com" || !strings.HasPrefix(req.URL.Path, "/i/api/") {
		base := t.Base
		if base == nil {
			base = http.DefaultTransport
		}
		return base.RoundTrip(req)
	}
	if req.URL.Scheme != "https" || req.Method != http.MethodGet || !strings.HasPrefix(req.URL.Path, "/i/api/graphql/") {
		return nil, fmt.Errorf("%w: %s %s", errUnprovenXCall, req.Method, req.URL.Path)
	}
	r := req.Clone(req.Context())
	r.Close = true
	r.Header.Set("Accept-Encoding", "gzip")
	exchange := xExchange(req.Context())
	if exchange == 0 {
		exchange = 1
	}
	endEncode := diagnostics.Start(req.Context(), "request_encode", exchange)
	var raw bytes.Buffer
	if err := r.Write(&raw); err != nil {
		endEncode("error")
		return nil, err
	}
	input, err := json.Marshal(struct {
		Verifier         string `json:"verifier"`
		VerifierCA       string `json:"verifier_ca_file,omitempty"`
		PlaintextFixture bool   `json:"plaintext_fixture,omitempty"`
		Token            string `json:"token"`
		Request          string `json:"request"`
	}{t.Verifier, t.VerifierCA, t.PlaintextFixture, t.Token, base64.StdEncoding.EncodeToString(raw.Bytes())})
	endEncode(diagnosticOutcome(req.Context(), err))
	if err != nil {
		return nil, err
	}
	command := "prove-x"
	if t.Relay {
		command = "relay-x"
	}
	cmd := exec.CommandContext(req.Context(), t.Prover, command)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = 4<<20, 16<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	observe, err := beginProofObservation(req.Context())
	if err != nil {
		return nil, errors.New("proof traffic journal unavailable")
	}
	helperOK := false
	defer func() { observe(stdout.Bytes(), helperOK) }()
	endHelper := diagnostics.Start(req.Context(), "helper_wall", exchange)
	err = process.Run(cmd)
	endHelper(diagnosticOutcome(req.Context(), err))
	detail := helperStderr(req.Context(), exchange, stderr.String())
	if err != nil {
		return nil, fmt.Errorf("prover: %v: %s", err, detail)
	}
	helperOK = true
	helperDiagnostics(req.Context(), exchange, stdout.Bytes())
	endDecode := diagnostics.Start(req.Context(), "helper_stdout_decode", exchange)
	resp, err := readXHelperResponse(req, stdout.Bytes())
	endDecode(diagnosticOutcome(req.Context(), err))
	return resp, err
}

func readXHelperResponse(req *http.Request, raw []byte) (*http.Response, error) {
	var summary struct {
		Status   string `json:"status"`
		Response string `json:"response"`
	}
	if json.Unmarshal(raw, &summary) != nil || summary.Status != "proof_sent" {
		return nil, errors.New("prover: unexpected output")
	}
	body, err := base64.StdEncoding.DecodeString(summary.Response)
	if err != nil {
		return nil, fmt.Errorf("prover: response is not base64: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(body)), req)
	if err != nil {
		return nil, fmt.Errorf("prover: %v", err)
	}
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("prover: %v", err)
		}
		resp.Body = struct {
			io.Reader
			io.Closer
		}{zr, resp.Body}
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		resp.Uncompressed = true
	}
	return resp, nil
}
