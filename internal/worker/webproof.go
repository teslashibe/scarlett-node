package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
	"github.com/teslashibe/scarlett-node/internal/process"
)

var netResolver = net.DefaultResolver

// webHopInput is the stdin of `scarlett-prover relay-web` for one hop. The
// helper dials IP (or asks the proxy, at its own checked address, to CONNECT
// to it), never a hostname, and uses URL only for SNI, certificate checks
// and the request line.
type webHopInput struct {
	Verifier         string `json:"verifier"`
	VerifierCA       string `json:"verifier_ca_file,omitempty"`
	PlaintextFixture bool   `json:"plaintext_fixture,omitempty"`
	// Token is empty only before the accept, with Predial (one-shot) or on
	// the daemon: the helper then waits for it.
	Token     string          `json:"token,omitempty"`
	Predial   bool            `json:"predial,omitempty"`
	Hop       int             `json:"hop"`
	URL       string          `json:"url"`
	IP        string          `json:"ip"`
	Port      int             `json:"port"`
	Proxy     *webProxyInput  `json:"proxy,omitempty"`
	Payload   json.RawMessage `json:"payload"`
	TimeoutMS int64           `json:"timeout_ms"`
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

// webProxyInput is a proxied hop's proxy: its checked address as an IP
// literal, and the job's Proxy-Authorization. It goes to the helper's stdin
// only; String and GoString redact it.
type webProxyInput struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Authorization string `json:"authorization,omitempty"`
}

func (webProxyInput) String() string   { return "web proxy input [redacted]" }
func (webProxyInput) GoString() string { return "worker.webProxyInput{}" }

// The helper's one stderr classification line on failure. Anything else is a
// failed fetch.
const webErrorPrefix = "SCARLETT_WEB_ERROR="

// webHelperGrace is how long past a hop's timeout_ms the node waits for its
// helper: the daemon answers within a second of it whatever happens to the
// hop, so a daemon that has not answered by then is broken.
const webHelperGrace = 3 * time.Second

// errWebHelperOverran is the cause of a hop context that ran out on its own
// (not because the job's context ended).
var errWebHelperOverran = errors.New("web helper overran its hop time")

// Bounds on what a helper may print. A summary carries counters and the next
// URL only, never page content.
const (
	maxWebStdout = 64 << 10
	maxWebStderr = 16 << 10
)

// prove runs one relay session to addr, through route's proxy when it has
// one, and reads its summary: on the helper hop 0 started before the accept
// (E1), else on the web daemon, else as a one-shot relay-web helper. One
// proof observation covers the hop whichever way it runs, begun before its
// token can go out.
func (w Web) prove(ctx context.Context, plan webPlan, token string, hop int, url string, addr netip.Addr, headers *webNodeHeaders, route *webRoute) webHopOutcome {
	c := w.Config
	deadline, ok := ctx.Deadline()
	budget := min(w.hopLimit(), time.Until(deadline))
	if !ok || budget < time.Second {
		return webHopOutcome{code: "expired"}
	}
	exchange := hop + 1
	endEncode := diagnostics.Start(ctx, "request_encode", exchange)
	in := webHopInput{Verifier: c.Verifier, VerifierCA: c.VerifierCA, PlaintextFixture: c.VerifierPlaintextFixture, Token: token, Hop: hop, URL: url, IP: addr.String(), Port: 443, Proxy: route.hopProxy(), Payload: plan.raw, TimeoutMS: budget.Milliseconds(), NodeHeaders: headers}
	input, err := json.Marshal(in)
	endEncode(diagnosticOutcome(ctx, err))
	if err != nil {
		return webHopOutcome{code: "prover_error"}
	}
	// The helper bounds itself by timeout_ms; the grace lets it say why
	// before it is killed, or the daemon answer. The job deadline still caps
	// both. Only this context's own expiry says the helper overran.
	hopCtx, cancel := context.WithTimeoutCause(ctx, budget+webHelperGrace, errWebHelperOverran)
	defer cancel()
	observe, err := beginProofObservation(ctx)
	if err != nil {
		return webHopOutcome{code: "prover_error"}
	}
	var result webHelperResult
	defer func() { observe(result.summary(), result.err == nil) }()
	endHelper := diagnostics.Start(ctx, "helper_wall", exchange)
	result = w.runHelper(ctx, hopCtx, in, input)
	endHelper(diagnosticOutcome(ctx, result.err))
	return result.outcome(ctx, hopCtx, exchange, hop, url, plan.MaxRedirects)
}

// runHelper runs the hop's helper the fastest way available. A pre-dialed
// helper that cannot take this hop, or a daemon that died before it
// announced the token, sent nothing; the hop then runs the next way.
// Every hop counts busy for the warm pool's size once: a pre-dialed hop 0
// keeps the mark its pre-dial took, any other hop takes its own.
func (w Web) runHelper(ctx, hopCtx context.Context, in webHopInput, input []byte) webHelperResult {
	if p := takeWebPredial(ctx, in); p != nil {
		if result, ok := p.finish(hopCtx, in.Token); ok {
			return result
		}
		daemonDetail("pre-dial of job %s ended before its token", p.job)
	}
	defer webHopBusy(w.Config)()
	if d := daemonFor(w.Config); d != nil {
		if result, ok := d.run(hopCtx, in); ok {
			return result
		}
	}
	daemonDetail("hop %d runs one-shot", in.Hop)
	return runRelayWeb(hopCtx, w.Config.Prover, input)
}

// webHelperResult is how a hop's helper ended: a one-shot process's output,
// or the daemon's reply.
type webHelperResult struct {
	stdout  []byte
	dropped bool
	stderr  string
	// err is set when the helper failed or never ran.
	err error
	// fromDaemon: class, cause and diagnostics come from its error reply.
	fromDaemon  bool
	class       string
	cause       string
	diagnostics json.RawMessage
}

func (r webHelperResult) summary() []byte {
	if r.err != nil {
		return nil
	}
	return r.stdout
}

// outcome classifies the result: caught verifier misuse halts relay
// node-wide first, and an unopened session counts toward a relay rest, as
// for X.
func (r webHelperResult) outcome(ctx, hopCtx context.Context, exchange, hop int, url string, maxRedirects int) webHopOutcome {
	if r.fromDaemon {
		if r.err != nil {
			if len(r.diagnostics) > 0 {
				diagnostics.AddHelper(ctx, exchange, r.diagnostics)
			}
			return webFailure(ctx, r.cause, r.class)
		}
	} else {
		helperStderr(ctx, exchange, r.stderr)
		if r.err != nil {
			return webHelperFailure(ctx, hopCtx, r.err, r.stderr)
		}
	}
	helperDiagnostics(ctx, exchange, r.stdout)
	endDecode := diagnostics.Start(ctx, "helper_stdout_decode", exchange)
	outcome, err := parseWebSummary(r.stdout, r.dropped, hop, url, maxRedirects)
	endDecode(diagnosticOutcome(ctx, err))
	if err != nil {
		return webHopOutcome{code: "web_fetch_failed"}
	}
	return outcome
}

// runRelayWeb runs a one-shot `relay-web` with its whole input.
func runRelayWeb(hopCtx context.Context, prover string, input []byte) webHelperResult {
	cmd := exec.CommandContext(hopCtx, prover, "relay-web")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = maxWebStdout, maxWebStderr
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := process.Run(cmd)
	return webHelperResult{stdout: stdout.Bytes(), dropped: stdout.dropped, stderr: stderr.String(), err: err}
}

// webHelperFailure classifies a failed helper run. Caught verifier misuse
// halts relay node-wide first, as for X: the request is already out, and the
// node must not be used that way again.
func webHelperFailure(ctx, hopCtx context.Context, err error, stderr string) webHopOutcome {
	if code, ok := webRelayVerdict(stderr); ok {
		return webHopOutcome{code: code}
	}
	if ctx.Err() != nil {
		return webHopOutcome{code: "expired"}
	}
	var exit *exec.ExitError
	if hopCtx.Err() == nil && !errors.As(err, &exit) {
		// The helper never ran.
		return webHopOutcome{code: "prover_error"}
	}
	return webFailure(ctx, "", webErrorClass(stderr))
}

// webFailure is a failed hop's outcome: its code and, for a proxy class,
// that class too.
func webFailure(ctx context.Context, cause, class string) webHopOutcome {
	code := webFailureCode(ctx, cause, class)
	switch code {
	case "web_proxy_failed", "web_proxy_refused", "web_connect_failed":
		return webHopOutcome{code: code, proxyClass: proxyClass(class)}
	}
	return webHopOutcome{code: code}
}

// webRelayVerdict reads what the helper said about the verifier's handling
// of the request record. Misuse halts relay node-wide. A session that ended
// before the verifier opened the record counts toward a relay rest and is
// execution_uncertain: the coordinator builds the page from the verifier's
// receipt when that holds it, and otherwise fails the job as the node's,
// for the buyer to retry.
func webRelayVerdict(cause string) (string, bool) {
	switch misuse, unopened := relayVerdict(cause); {
	case misuse:
		HaltRelay(relayMisuseMarker)
		return "relay_misuse", true
	case unopened:
		noteRelayUnopened()
		return "execution_uncertain", true
	}
	return "", false
}

// webFailureCode maps a helper's failure class to the hop's code; a cause
// carrying the relay misuse or unopened text is read first. The proxy
// itself failing is web_proxy_failed, the proxy refusing the target (403)
// web_proxy_refused, and its exit failing web_connect_failed, as a direct
// connection that failed.
func webFailureCode(ctx context.Context, cause, class string) string {
	if code, ok := webRelayVerdict(cause); ok {
		return code
	}
	if ctx.Err() != nil {
		return "expired"
	}
	if code := proxyCode(class); code != "" {
		return code
	}
	switch class {
	case "connect_failed":
		return "web_connect_failed"
	case "verifier_busy":
		// Repeated by hop within its budget; never a job code.
		return "verifier_busy"
	case "page_too_large":
		return "page_too_large"
	}
	return "web_fetch_failed"
}

// WebPredial is hop 0 of a relay web offer whose helper starts before the
// node accepts it (design E1): it dials the verifier, or takes a warm
// connection on the daemon, while the accept is in flight, and gets the
// token only at hop 0, after the accepted lease passed the web worker's
// own checks. Until then nothing is sent but the connection's TCP, TLS and
// PING, and nothing reaches the target. Every method is nil-safe.
type WebPredial struct {
	job, attempt, fence string
	started             chan struct{}
	stop                context.CancelFunc
	idle                func()

	mu  sync.Mutex
	in  webHopInput
	run predialRun
	// proxyAddr is the proxy address the pre-dial checked for a proxied
	// offer; the job's route takes it, so hop 0 matches the pre-dial.
	proxyAddr netip.AddrPort
	used      bool
}

// predialRun is the helper of a pre-dialed hop: on the daemon, or a
// one-shot relay-web.
type predialRun interface {
	// finish sends the token and returns the hop's result; ok is false when
	// the helper had gone before the token was sent.
	finish(hopCtx context.Context, token string) (webHelperResult, bool)
	// cancel ends it unsent.
	cancel()
}

type webPredialKey struct{}

// StartPredial starts hop 0 of a relay web offer before the node accepts
// it: nil unless this node serves the offer as a relay page. It resolves
// and checks the target as hop 0 will, and for a proxied offer the proxy
// too, then starts the helper without a token on the job's session.
func (w Web) StartPredial(ctx context.Context, l coordinator.Lease) *WebPredial {
	c := w.Config
	if c.Executor != config.ExecutorServices || !c.Enabled("web") || l.ServiceType != "web" || !l.AcceptanceRequired || l.VerifierToken != "" || l.WebRequest == nil || l.WebRequest.Mode != "" || RelayPaused() || l.WebEgress != "" && c.WebEgressProxy == nil {
		return nil
	}
	plan, ok := decodeWebPlan(l.WebPayload)
	if !ok || plan.ProofPolicy != webRelayPolicy || plan.URL != l.WebRequest.URL || !webURLAllowed(plan.URL) {
		return nil
	}
	deadline := l.LeaseDeadline
	if l.SettlementDeadline.Before(deadline) {
		deadline = l.SettlementDeadline
	}
	deadline = deadline.Add(-webReportMargin)
	if time.Until(deadline) < 2*time.Second {
		return nil
	}
	ctx, stop := context.WithDeadline(ctx, deadline.Add(time.Second))
	p := &WebPredial{job: l.JobID, attempt: l.Attempt, fence: l.Fence, started: make(chan struct{}), stop: stop, idle: webHopBusy(c)}
	go p.start(ctx, w, plan, deadline, UsesProxy(c, l))
	return p
}

func (p *WebPredial) start(ctx context.Context, w Web, plan webPlan, deadline time.Time, proxied bool) {
	defer close(p.started)
	c := w.Config
	canonical, host, err := canonicalWebURL(plan.URL)
	if err != nil || canonical != plan.URL {
		return
	}
	// The job's route is hop 0's: the checked proxy address and the job's
	// session at rotation 0, exactly as the job will build them.
	var route *webRoute
	if proxied {
		addr, ok := w.proxyAddress(ctx, c.WebEgressProxy)
		if !ok {
			return
		}
		p.mu.Lock()
		p.proxyAddr = addr
		p.mu.Unlock()
		route = &webRoute{proxy: c.WebEgressProxy, addr: addr, session: c.WebEgressProxy.Session(p.job, p.attempt, 0)}
	}
	lookupCtx, cancel := context.WithTimeout(ctx, webLookupLimit)
	addrs, err := w.resolver()(lookupCtx, host)
	cancel()
	if err != nil || len(addrs) == 0 {
		return
	}
	addr, code := pickHopAddr(ctx, w.egress(), addrs, proxied)
	budget := min(w.hopLimit(), time.Until(deadline))
	if code != "" || budget < time.Second {
		return
	}
	in := webHopInput{Verifier: c.Verifier, VerifierCA: c.VerifierCA, PlaintextFixture: c.VerifierPlaintextFixture, Hop: 0, URL: plan.URL, IP: addr.String(), Port: 443, Proxy: route.hopProxy(), Payload: plan.raw, TimeoutMS: budget.Milliseconds()}
	var run predialRun
	if d := daemonFor(c); d != nil {
		if h, err := d.startHop(in); err == nil {
			run = &daemonPredial{d: d, h: h}
			daemonDetail("hop %s: pre-dial of job %s", h.id, p.job)
		}
	}
	if run == nil {
		if oneShot := startOneShotPredial(ctx, c.Prover, in); oneShot != nil {
			run = oneShot
			daemonDetail("pre-dial of job %s runs one-shot", p.job)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used {
		// Cancelled while it started.
		if run != nil {
			run.cancel()
		}
		return
	}
	p.in, p.run = in, run
}

// Accepted hands the accepted lease's hop 0 to the predial; the web worker
// finds it in the returned context. A lease that is not the offer's ends it.
func (p *WebPredial) Accepted(ctx context.Context, l coordinator.Lease) context.Context {
	if p == nil {
		return ctx
	}
	if l.JobID != p.job || l.Attempt != p.attempt || l.Fence != p.fence {
		p.Cancel()
		return ctx
	}
	return context.WithValue(ctx, webPredialKey{}, p)
}

// Cancel ends a predial no hop took, such as one whose accept failed: its
// helper sends no token and reaches no target. Idempotent.
func (p *WebPredial) Cancel() {
	if p == nil {
		return
	}
	p.mu.Lock()
	already := p.used
	p.used = true
	run := p.run
	p.mu.Unlock()
	if already {
		return
	}
	if run != nil {
		run.cancel()
	}
	p.idle()
	time.AfterFunc(5*time.Second, p.stop)
}

// takeWebPredial returns the predial for this hop, once: hop 0 of the
// accepted lease, to the address it checked, with no node headers. One
// started for anything else is ended unsent.
func takeWebPredial(ctx context.Context, in webHopInput) *WebPredial {
	p, _ := ctx.Value(webPredialKey{}).(*WebPredial)
	if p == nil {
		return nil
	}
	select {
	case <-p.started:
	case <-ctx.Done():
		p.Cancel()
		return nil
	}
	p.mu.Lock()
	usable := !p.used && p.run != nil && in.Hop == 0 && in.NodeHeaders == nil && sameHop(p.in, in)
	if usable {
		p.used = true
	}
	if webDaemonVerbose {
		daemonDetail("pre-dial of job %s for hop %d: usable %v (started %v, same hop %v)", p.job, in.Hop, usable, p.run != nil, in.Hop == 0 && sameHop(p.in, in))
	}
	p.mu.Unlock()
	if !usable {
		p.Cancel()
		return nil
	}
	return p
}

// sameHop: the started hop is this one in all but its token and budget.
func sameHop(started, hop webHopInput) bool {
	started.Token, started.TimeoutMS, hop.TimeoutMS = hop.Token, 0, 0
	a, errA := json.Marshal(started)
	b, errB := json.Marshal(hop)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

// finish sends the token and returns the hop's result.
func (p *WebPredial) finish(hopCtx context.Context, token string) (webHelperResult, bool) {
	defer p.idle()
	// The helper has ended by now; this ends what is left of its context.
	defer p.stop()
	return p.run.finish(hopCtx, token)
}

type daemonPredial struct {
	d *webDaemon
	h *daemonHop
}

func (r *daemonPredial) finish(hopCtx context.Context, token string) (webHelperResult, bool) {
	if r.d.token(r.h, token) != nil {
		// Never sent: the hop runs another way.
		r.d.forget(r.h.id)
		return webHelperResult{}, false
	}
	return daemonResult(r.d.wait(hopCtx, r.h))
}

func (r *daemonPredial) cancel() {
	r.d.cancel(r.h)
}

// oneShotPredial is a `relay-web` started with `"predial": true`: it dials
// the verifier and reads the token from its next stdin line.
type oneShotPredial struct {
	stdin  io.WriteCloser
	exited chan struct{}
	err    error
	kill   context.CancelFunc
	stdout limitedBuffer
	stderr limitedBuffer
}

func startOneShotPredial(ctx context.Context, prover string, in webHopInput) *oneShotPredial {
	in.Predial = true
	line, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	ctx, kill := context.WithCancel(ctx)
	o := &oneShotPredial{exited: make(chan struct{}), kill: kill}
	o.stdout.max, o.stderr.max = maxWebStdout, maxWebStderr
	cmd := exec.CommandContext(ctx, prover, "relay-web")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		kill()
		return nil
	}
	o.stdin = stdin
	cmd.Stdout, cmd.Stderr = &o.stdout, &o.stderr
	go func() {
		o.err = process.Run(cmd)
		close(o.exited)
	}()
	if _, err := stdin.Write(append(line, '\n')); err != nil {
		o.cancel()
		return nil
	}
	return o
}

func (o *oneShotPredial) finish(hopCtx context.Context, token string) (webHelperResult, bool) {
	select {
	case <-o.exited:
		// It ended before its token: nothing was sent.
		return webHelperResult{}, false
	default:
	}
	line, _ := json.Marshal(struct {
		Token string `json:"token"`
	}{token})
	if _, err := o.stdin.Write(append(line, '\n')); err != nil {
		o.cancel()
		return webHelperResult{}, false
	}
	o.stdin.Close()
	select {
	case <-o.exited:
	case <-hopCtx.Done():
		o.kill()
		<-o.exited
	}
	return webHelperResult{stdout: o.stdout.Bytes(), dropped: o.stdout.dropped, stderr: o.stderr.String(), err: o.err}, true
}

// cancel closes stdin: the helper ends unsent, and is killed if it lingers.
func (o *oneShotPredial) cancel() {
	o.stdin.Close()
	go func() {
		select {
		case <-o.exited:
		case <-time.After(5 * time.Second):
			o.kill()
		}
	}()
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
