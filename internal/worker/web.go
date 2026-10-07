package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
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
type Web struct {
	Config   config.Config
	Resolver func(ctx context.Context, host string) ([]netip.Addr, error)
	Egress   *WebEgress
}

// webRelayPolicy is the only web proof policy this node knows: keyed relay
// with no hidden bits, so the verifier holds every session key.
const webRelayPolicy = "web-relay-v1"

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
	// raw is the exact lease payload, handed to the helper unchanged.
	raw json.RawMessage
}

// WebOfferServable reports whether this node could serve a web offer's proof
// mode, from the payload the offer carries. A halted relay serves no web: web
// has no MPC mode to fall back to.
func WebOfferServable(c config.Config, payload json.RawMessage) bool {
	var plan struct {
		ProofMode   string `json:"proof_mode"`
		ProofPolicy string `json:"proof_policy"`
	}
	if len(payload) == 0 || len(payload) > maxWebPayloadBytes || json.Unmarshal(payload, &plan) != nil {
		return false
	}
	return plan.ProofMode == "relay" && plan.ProofPolicy == webRelayPolicy && !RelayHalted()
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
	if err != nil || !ok || len(fields) != 7 {
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
	if plan.Type != "web.fetch" || plan.ProofMode != "relay" || plan.ProofPolicy != webRelayPolicy || plan.MaxRedirects < 0 || plan.MaxRedirects > maxWebRedirects || plan.MaxResponseBytes < 1 || plan.MaxResponseBytes > maxWebResponseBytes || len(plan.Headers) > len(webHeaderOrder) {
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

// Run fetches the lease's page, following redirects only as the verifier
// authorizes them, and returns "" once at least the first hop was proven.
// The verifier holds every verified hop; the coordinator reads them there.
func (w Web) Run(ctx context.Context, l coordinator.Lease) string {
	plan, deadline, code := validateWebLease(w.Config, l)
	if code != "" {
		return code
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	egress := w.Egress
	if egress == nil {
		egress = defaultWebEgress
	}
	resolve := w.Resolver
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return netResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	target := plan.URL
	for hop := 0; hop <= plan.MaxRedirects; hop++ {
		hopCtx := withXExchange(ctx, hop+1)
		end := diagnostics.Start(hopCtx, "page_wall", hop+1)
		outcome := w.hop(hopCtx, plan, l.VerifierToken, hop, target, resolve, egress)
		end(webDiagnosticOutcome(hopCtx, outcome.code))
		if outcome.code != "" {
			// One verified hop already makes the job: the verifier keeps it.
			if hop > 0 && outcome.code != "relay_misuse" {
				return ""
			}
			return outcome.code
		}
		if outcome.final {
			return ""
		}
		target = outcome.next
	}
	// The verifier marks the last allowed hop final; a helper that says
	// otherwise is not trusted for anything more.
	return ""
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
func (w Web) hop(ctx context.Context, plan webPlan, token string, hop int, target string, resolve func(context.Context, string) ([]netip.Addr, error), egress *WebEgress) webHopOutcome {
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
	return w.prove(ctx, plan, token, hop, canonical, addr)
}

var errWebSummary = errors.New("unexpected relay-web summary")
