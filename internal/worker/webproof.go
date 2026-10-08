package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/teslashibe/scarlett-node/internal/diagnostics"
	"github.com/teslashibe/scarlett-node/internal/process"
)

var netResolver = net.DefaultResolver

// webHopInput is the stdin of `scarlett-prover relay-web` for one hop. The
// helper dials IP (or asks the proxy to CONNECT to it), never a hostname, and
// uses URL only for SNI, certificate checks and the request line.
type webHopInput struct {
	Verifier         string          `json:"verifier"`
	VerifierCA       string          `json:"verifier_ca_file,omitempty"`
	PlaintextFixture bool            `json:"plaintext_fixture,omitempty"`
	Token            string          `json:"token"`
	Hop              int             `json:"hop"`
	URL              string          `json:"url"`
	IP               string          `json:"ip"`
	Port             int             `json:"port"`
	Proxy            *webProxyInput  `json:"proxy,omitempty"`
	Payload          json.RawMessage `json:"payload"`
	TimeoutMS        int64           `json:"timeout_ms"`
	// NodeHeaders is present exactly for web-browser-v1 jobs.
	NodeHeaders *webNodeHeaders `json:"node_headers,omitempty"`
}

// webNodeHeaders are the request header values a browser job's re-fetch hop
// supplies: the browser's pinned User-Agent and, when any clearance cookie
// matches the hop, a Cookie value. They go to the helper's stdin only.
type webNodeHeaders struct {
	UserAgent string `json:"user_agent"`
	Cookie    string `json:"cookie,omitempty"`
}

// String and GoString keep the cookie out of any formatted output.
func (webNodeHeaders) String() string   { return "web node headers [redacted]" }
func (webNodeHeaders) GoString() string { return "worker.webNodeHeaders{}" }

type webProxyInput struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Authorization string `json:"authorization,omitempty"`
}

// The helper's one stderr classification line on failure. Anything else is a
// failed fetch.
const webErrorPrefix = "SCARLETT_WEB_ERROR="

// Bounds on what a helper may print. A summary carries counters and the next
// URL only, never page content.
const (
	maxWebStdout = 64 << 10
	maxWebStderr = 16 << 10
)

// prove runs one relay session to addr and reads its summary.
func (w Web) prove(ctx context.Context, plan webPlan, token string, hop int, url string, addr netip.Addr, headers *webNodeHeaders) webHopOutcome {
	c := w.Config
	deadline, ok := ctx.Deadline()
	budget := min(webHopLimit, time.Until(deadline))
	if !ok || budget < time.Second {
		return webHopOutcome{code: "expired"}
	}
	exchange := hop + 1
	endEncode := diagnostics.Start(ctx, "request_encode", exchange)
	in := webHopInput{Verifier: c.Verifier, VerifierCA: c.VerifierCA, PlaintextFixture: c.VerifierPlaintextFixture, Token: token, Hop: hop, URL: url, IP: addr.String(), Port: 443, Payload: plan.raw, TimeoutMS: budget.Milliseconds(), NodeHeaders: headers}
	if p := c.WebEgressProxy; p != nil {
		in.Proxy = &webProxyInput{Host: p.Host, Port: p.Port, Authorization: p.Authorization}
	}
	input, err := json.Marshal(in)
	endEncode(diagnosticOutcome(ctx, err))
	if err != nil {
		return webHopOutcome{code: "prover_error"}
	}
	// The helper bounds itself by timeout_ms; the extra second lets it say why
	// before it is killed. The job deadline still caps both.
	hopCtx, cancel := context.WithTimeout(ctx, budget+time.Second)
	defer cancel()
	cmd := exec.CommandContext(hopCtx, c.Prover, "relay-web")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = maxWebStdout, maxWebStderr
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	observe, err := beginProofObservation(ctx)
	if err != nil {
		return webHopOutcome{code: "prover_error"}
	}
	helperOK := false
	defer func() { observe(stdout.Bytes(), helperOK) }()
	endHelper := diagnostics.Start(ctx, "helper_wall", exchange)
	err = process.Run(cmd)
	endHelper(diagnosticOutcome(ctx, err))
	helperStderr(ctx, exchange, stderr.String())
	if err != nil {
		return webHopOutcome{code: webHelperFailure(ctx, hopCtx, err, stderr.String())}
	}
	helperOK = true
	helperDiagnostics(ctx, exchange, stdout.Bytes())
	endDecode := diagnostics.Start(ctx, "helper_stdout_decode", exchange)
	outcome, err := parseWebSummary(stdout.Bytes(), stdout.dropped, hop, url, plan.MaxRedirects)
	endDecode(diagnosticOutcome(ctx, err))
	if err != nil {
		return webHopOutcome{code: "web_fetch_failed"}
	}
	return outcome
}

// webHelperFailure classifies a failed helper run. Caught verifier misuse
// halts relay node-wide first, as for X: the request is already out, and the
// node must not be used that way again.
func webHelperFailure(ctx, hopCtx context.Context, err error, stderr string) string {
	if strings.Contains(stderr, relayMisuseMarker) {
		HaltRelay(relayMisuseMarker)
		return "relay_misuse"
	}
	if ctx.Err() != nil {
		return "expired"
	}
	var exit *exec.ExitError
	if hopCtx.Err() == nil && !errors.As(err, &exit) {
		// The helper never ran.
		return "prover_error"
	}
	switch webErrorClass(stderr) {
	case "connect_failed":
		return "web_connect_failed"
	case "proxy_failed":
		return "web_proxy_failed"
	}
	return "web_fetch_failed"
}

func webErrorClass(stderr string) string {
	class := ""
	for _, line := range strings.Split(stderr, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), webErrorPrefix); ok {
			if class != "" {
				return "" // More than one classification is no classification.
			}
			class = value
		}
	}
	return class
}

// parseWebSummary reads the helper's one success line: the hop it proved, the
// verified status, and whether the verifier authorized a next hop. Unique keys
// and integer numbers only, as for every proof summary.
func parseWebSummary(raw []byte, truncated bool, hop int, url string, maxRedirects int) (webHopOutcome, error) {
	if truncated {
		return webHopOutcome{}, errWebSummary
	}
	v, err := proofSummaryJSON(raw)
	if err != nil || v["status"] != "proof_sent" || v["hop"] != json.Number(strconv.Itoa(hop)) {
		return webHopOutcome{}, errWebSummary
	}
	if got, present := v["url"]; present && got != url {
		return webHopOutcome{}, errWebSummary
	}
	status, err := strconv.Atoi(string(jsonNumber(v["status_code"])))
	final, isBool := v["final"].(bool)
	// The verifier records any final (non-1xx) three-digit status, such as 999.
	if err != nil || status < 200 || status > 999 || !isBool {
		return webHopOutcome{}, errWebSummary
	}
	next, hasNext := v["next_url"]
	if final {
		if hasNext {
			return webHopOutcome{}, errWebSummary
		}
		return webHopOutcome{final: true}, nil
	}
	nextURL, isString := next.(string)
	if !hasNext || !isString || hop >= maxRedirects || status != 301 && status != 302 && status != 303 && status != 307 && status != 308 {
		return webHopOutcome{}, errWebSummary
	}
	if canonical, _, err := canonicalWebURL(nextURL); err != nil || canonical != nextURL {
		return webHopOutcome{}, errWebSummary
	}
	return webHopOutcome{next: nextURL}, nil
}

func jsonNumber(v any) json.Number {
	n, _ := v.(json.Number)
	return n
}
