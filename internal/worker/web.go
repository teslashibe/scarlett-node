package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
)

// Web serves web leases: one public https page per job, fetched from this
// node's own address while the operator's verifier is the TLS client. The
// node never sees the page; it resolves each hop host, checks every address
// against the egress guard and has the helper open the connection to the
// checked address only. Resolver and Egress replace the system resolver and
// the node-wide guard in tests.
//
// A browser job (web_request.mode "browser") first renders the page in the
// node's hidden browser (Browser), uploads that copy to the coordinator
// (Upload) and re-fetches the page through the same verified relay, sending
// the browser's User-Agent and only its anti-bot clearance cookies.
type Web struct {
	Config   config.Config
	Resolver func(ctx context.Context, host string) ([]netip.Addr, error)
	Egress   *WebEgress
	// Browser is the browser tier; nil when this node has none.
	Browser BrowserTier
	// Upload sends a browser result's gzip body before report; nil never stores one.
	Upload func(ctx context.Context, jobID string, gzipBody []byte, report time.Time) error
}

// The web proof policies: keyed relay with no hidden bits, so the verifier
// holds every session key. web-browser-v1 adds two node-supplied request
// headers, the browser's pinned User-Agent and its clearance cookies, which
// the verifier checks against the same pins and allowlist.
const (
	webRelayPolicy   = "web-relay-v1"
	webBrowserPolicy = "web-browser-v1"
)

const (
	maxWebRedirects     = 5
	maxWebResponseBytes = 10 << 20
	maxWebHeaderValue   = 512
	maxWebPayloadBytes  = 65536
	// webReportMargin is the part of a web lease kept for after the last hop:
	// the journal writes, the proven report and the coordinator's verifier read.
	webReportMargin = 10 * time.Second
	// webHopLimit bounds one relay session, as the verifier does.
	webHopLimit = 30 * time.Second
	// webLookupLimit bounds one hop's DNS lookup.
	webLookupLimit = 5 * time.Second
)

// webHeaderOrder is the allowlist of buyer-visible request headers, in the
// only order they may appear.
var webHeaderOrder = []string{"user-agent", "accept", "accept-language"}

// webBrowserHeaders are the only headers a web-browser-v1 payload carries,
// exactly and in this order; the User-Agent is the node's.
var webBrowserHeaders = []webHeader{
	{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
	{"accept-language", "en-US,en;q=0.9"},
}

// webNodeHeaderNames is the exact node_headers list of web-browser-v1.
var webNodeHeaderNames = []string{"user-agent", "cookie"}

type webHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type webPlan struct {
	Type             string      `json:"type"`
	ProofMode        string      `json:"proof_mode"`
	ProofPolicy      string      `json:"proof_policy"`
	URL              string      `json:"url"`
	MaxRedirects     int         `json:"max_redirects"`
	MaxResponseBytes int         `json:"max_response_bytes"`
	Headers          []webHeader `json:"headers"`
	NodeHeaders      []string    `json:"node_headers,omitempty"`
	// raw is the exact lease payload, handed to the helper unchanged.
	raw json.RawMessage
}

// WebOfferServable reports whether this node could serve a web offer: its
// proof mode and policy, and for a browser offer a ready browser tier. A
// halted relay serves no web: web has no MPC mode to fall back to, and a
// browser job's re-fetch is relay too. A servable browser offer, or a relay
// offer carrying the pre-warm hint while the browser is ready, starts the
// browser in the background while the node accepts. The service pool has
// already reserved the browser slot; this checks only readiness.
func WebOfferServable(c config.Config, l coordinator.Lease, browser BrowserTier) bool {
	var plan struct {
		ProofMode   string `json:"proof_mode"`
		ProofPolicy string `json:"proof_policy"`
	}
	if len(l.WebPayload) == 0 || len(l.WebPayload) > maxWebPayloadBytes || json.Unmarshal(l.WebPayload, &plan) != nil || l.WebRequest == nil || plan.ProofMode != "relay" || RelayHalted() {
		return false
	}
	ready := c.WebBrowser && browser != nil && browser.Status().Ready
	switch {
	case l.WebRequest.Mode == "" && plan.ProofPolicy == webRelayPolicy:
		if l.WebPrewarmBrowser && ready {
			go browser.Prewarm()
		}
		return true
	case l.WebRequest.Mode == "browser" && plan.ProofPolicy == webBrowserPolicy && !l.WebPrewarmBrowser && ready:
		go browser.Prewarm()
		return true
	}
	return false
}

// decodeWebPlan applies the verifier's web.fetch rules to the exact payload:
// unique keys, integers only, every field present and no unknown field. The
// URL is checked apart, by webURLAllowed.
func decodeWebPlan(raw []byte) (webPlan, bool) {
	var plan webPlan
	if len(raw) == 0 || len(raw) > maxWebPayloadBytes {
		return plan, false
	}
	value, err := uniqueJSON(raw)
	fields, ok := value.(map[string]any)
	if err != nil || !ok || len(fields) != 7 && len(fields) != 8 {
		return plan, false
	}
	if _, present := fields["node_headers"]; present != (len(fields) == 8) {
		return plan, false
	}
	if _, ok := fields["headers"].([]any); !ok {
		return plan, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&plan) != nil || d.Decode(new(any)) != io.EOF {
		return plan, false
	}
	for _, header := range fields["headers"].([]any) {
		if h, ok := header.(map[string]any); !ok || len(h) != 2 {
			return plan, false
		}
	}
	if plan.Type != "web.fetch" || plan.ProofMode != "relay" || plan.MaxRedirects < 0 || plan.MaxRedirects > maxWebRedirects || plan.MaxResponseBytes < 1 || plan.MaxResponseBytes > maxWebResponseBytes || len(plan.Headers) > len(webHeaderOrder) {
		return plan, false
	}
	switch plan.ProofPolicy {
	case webRelayPolicy:
		if len(fields) != 7 {
			return plan, false
		}
	case webBrowserPolicy:
		// Exactly the two default headers, the node's two headers, and the
		// app's fixed limits.
		if len(fields) != 8 || !slices.Equal(plan.Headers, webBrowserHeaders) || !slices.Equal(plan.NodeHeaders, webNodeHeaderNames) || plan.MaxRedirects != maxWebRedirects || plan.MaxResponseBytes != maxWebResponseBytes {
			return plan, false
		}
	default:
		return plan, false
	}
	next := 0
	for _, h := range plan.Headers {
		at := -1
		for i := next; i < len(webHeaderOrder); i++ {
			if webHeaderOrder[i] == h.Name {
				at = i
			}
		}
		if at < 0 || !webHeaderValue(h.Value) {
			return plan, false
		}
		next = at + 1
	}
	if len(plan.URL) > maxWebURLBytes || !strings.HasPrefix(plan.URL, "https://") {
		return plan, false
	}
	plan.raw = raw
	return plan, true
}

// webURLAllowed reports whether url is canonical under the shared strict
// rules, which also refuse IP literals, reserved names and X hosts.
func webURLAllowed(url string) bool {
	canonical, _, err := canonicalWebURL(url)
	return err == nil && canonical == url
}

// webHeaderValue is 1-512 printable ASCII bytes without surrounding spaces.
func webHeaderValue(v string) bool {
	if len(v) < 1 || len(v) > maxWebHeaderValue || v[0] == ' ' || v[len(v)-1] == ' ' {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}

func validateWebLease(c config.Config, l coordinator.Lease) (webPlan, time.Time, string) {
	var plan webPlan
	request, err := json.Marshal(l.WebRequest)
	if err != nil || l.WebRequest == nil || l.WebRequest.Operation != "scrape" || l.ServiceType != "web" || l.Version != coordinator.Version || l.JobID == "" || l.SignedJobID == "" || l.Attempt == "" || l.Fence == "" || l.Profile != c.Profile || SHA(string(request)) != l.InputSHA256 || len(request) > c.MaxInputBytes || l.ModelID != "" || l.Prompt != "" || l.MaxInputTokens != 0 || l.MaxOutputTokens != 0 || len(l.CodexPayload) != 0 || l.XRequest != nil || len(l.XPayload) != 0 || len(l.VerifierToken) != 64 || !isHex(l.VerifierToken) {
		return plan, time.Time{}, "invalid_lease"
	}
	plan, ok := decodeWebPlan(l.WebPayload)
	if !ok || plan.URL != l.WebRequest.URL || RelayHalted() {
		return plan, time.Time{}, "invalid_lease"
	}
	// Mode, policy, browser options and node headers go together, and the
	// pre-warm hint belongs to relay jobs only.
	browser := l.WebRequest.Mode == "browser"
	if l.WebRequest.Mode != "" && !browser || browser != (plan.ProofPolicy == webBrowserPolicy) || browser != (l.WebRequest.Browser != nil) || browser && l.WebPrewarmBrowser || browser && !validWebBrowser(*l.WebRequest.Browser) {
		return plan, time.Time{}, "invalid_lease"
	}
	// Well-formed terms for a page this node will not fetch: the buyer learns
	// the URL is not allowed rather than that the node failed.
	if !webURLAllowed(plan.URL) {
		return plan, time.Time{}, "web_egress_denied"
	}
	now := time.Now()
	deadline := l.LeaseDeadline
	if !deadline.After(now) || !l.SettlementDeadline.After(now) {
		return plan, time.Time{}, "expired"
	}
	if l.SettlementDeadline.Before(deadline) {
		deadline = l.SettlementDeadline
	}
	deadline = deadline.Add(-webReportMargin)
	if !deadline.After(now) {
		return plan, time.Time{}, "expired"
	}
	return plan, deadline, ""
}

// validWebBrowser applies the browser option bounds of contract §1.
func validWebBrowser(b coordinator.WebBrowser) bool {
	if b.Wait != "load" && b.Wait != "networkidle" || b.WaitMS < 0 || b.WaitMS > 15000 || b.TimeoutMS < 5000 || b.TimeoutMS > 45000 || len(b.WaitSelector) > 256 {
		return false
	}
	for i := 0; i < len(b.WaitSelector); i++ {
		if b.WaitSelector[i] < 0x20 || b.WaitSelector[i] > 0x7e {
			return false
		}
	}
	return true
}

// Run fetches the lease's page, following redirects only as the verifier
// authorizes them, and returns "" once at least the first hop was proven.
// The verifier holds every verified hop; the coordinator reads them there.
// A browser job is run by runBrowser.
func (w Web) Run(ctx context.Context, l coordinator.Lease) string {
	plan, deadline, code := validateWebLease(w.Config, l)
	if code != "" {
		return code
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if l.WebRequest.Mode == "browser" {
		return w.runBrowser(ctx, l, plan, deadline)
	}
	code, _ = w.relay(ctx, plan, l.VerifierToken, nil)
	return code
}

func (w Web) egress() *WebEgress {
	if w.Egress == nil {
		return defaultWebEgress
	}
	return w.Egress
}

func (w Web) resolver() func(context.Context, string) ([]netip.Addr, error) {
	if w.Resolver == nil {
		return func(ctx context.Context, host string) ([]netip.Addr, error) {
			return netResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	return w.Resolver
}

// relay runs the hop loop and returns the job's code and how many hops the
// verifier holds. One verified hop already makes the job: a later hop failing
// for any reason but relay misuse still reports proven. nodeHeaders, set for
// browser jobs, gives each hop's node-supplied User-Agent and Cookie.
func (w Web) relay(ctx context.Context, plan webPlan, token string, nodeHeaders func(hopURL string) *webNodeHeaders) (string, int) {
	resolve, egress := w.resolver(), w.egress()
	target := plan.URL
	for hop := 0; hop <= plan.MaxRedirects; hop++ {
		hopCtx := withXExchange(ctx, hop+1)
		end := diagnostics.Start(hopCtx, "page_wall", hop+1)
		var headers *webNodeHeaders
		if nodeHeaders != nil {
			headers = nodeHeaders(target)
		}
		outcome := w.hop(hopCtx, plan, token, hop, target, resolve, egress, headers)
		end(webDiagnosticOutcome(hopCtx, outcome.code))
		if outcome.code != "" {
			if hop > 0 && outcome.code != "relay_misuse" {
				return "", hop
			}
			return outcome.code, hop
		}
		if outcome.final {
			return "", hop + 1
		}
		target = outcome.next
	}
	// The verifier marks the last allowed hop final; a helper that says
	// otherwise is not trusted for anything more.
	return "", plan.MaxRedirects + 1
}

func webDiagnosticOutcome(ctx context.Context, code string) string {
	if ctx.Err() != nil {
		return "cancelled"
	}
	if code == "" {
		return "success"
	}
	return code
}

type webHopOutcome struct {
	code  string
	final bool
	next  string
}

// hop runs one relay session for target, the job URL or the previous hop's
// verified redirect. Its failure codes describe this hop; Run decides what a
// failure after a verified hop means for the job.
func (w Web) hop(ctx context.Context, plan webPlan, token string, hop int, target string, resolve func(context.Context, string) ([]netip.Addr, error), egress *WebEgress, headers *webNodeHeaders) webHopOutcome {
	if ctx.Err() != nil {
		return webHopOutcome{code: "expired"}
	}
	canonical, host, err := canonicalWebURL(target)
	if err != nil || canonical != target {
		return webHopOutcome{code: "web_egress_denied"}
	}
	lookupCtx, cancel := context.WithTimeout(ctx, webLookupLimit)
	addrs, err := resolve(lookupCtx, host)
	cancel()
	if ctx.Err() != nil {
		return webHopOutcome{code: "expired"}
	}
	if err != nil || len(addrs) == 0 {
		return webHopOutcome{code: "web_dns_failed"}
	}
	addr, ok := egress.pickWebAddr(ctx, addrs)
	if !ok {
		return webHopOutcome{code: "web_egress_denied"}
	}
	return w.prove(ctx, plan, token, hop, canonical, addr, headers)
}

var errWebSummary = errors.New("unexpected relay-web summary")
