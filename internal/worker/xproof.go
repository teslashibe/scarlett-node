package worker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/teslashibe/scarlett-node/internal/process"
	"io"
	"net/http"
	"os/exec"
	"strings"
)

// XTransport is an http.RoundTripper for an x-go client. It proves each x.com
// GraphQL GET with `scarlett-prover prove-x`: the node's own connection reaches
// X over MPC-TLS and the verifier keeps its own copy of the response. Other
// x.com API calls, including writes, are refused. Everything else, such as
// transaction-ID bootstrap pages, goes through Base unproven.
type XTransport struct {
	Prover           string
	Verifier         string
	VerifierCA       string
	PlaintextFixture bool
	Token            string
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
	var raw bytes.Buffer
	if err := r.Write(&raw); err != nil {
		return nil, err
	}
	input, err := json.Marshal(struct {
		Verifier         string `json:"verifier"`
		VerifierCA       string `json:"verifier_ca_file,omitempty"`
		PlaintextFixture bool   `json:"plaintext_fixture,omitempty"`
		Token            string `json:"token"`
		Request          string `json:"request"`
	}{t.Verifier, t.VerifierCA, t.PlaintextFixture, t.Token, base64.StdEncoding.EncodeToString(raw.Bytes())})
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(req.Context(), t.Prover, "prove-x")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = 4<<20, 4096
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := process.Run(cmd); err != nil {
		return nil, fmt.Errorf("prover: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	var summary struct {
		Status   string `json:"status"`
		Response string `json:"response"`
	}
	if json.Unmarshal(stdout.Bytes(), &summary) != nil || summary.Status != "proof_sent" {
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
