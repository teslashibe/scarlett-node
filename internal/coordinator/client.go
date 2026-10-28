package coordinator

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version is the node-coordinator protocol in every body. The routes keep
// their /api/node/v1 prefix. A coordinator answers a heartbeat in an older
// protocol with 426 update_required.
const Version = "node-v2"

// A lease repeats its bounded prompt in the exact 64 KiB verifier request.
// Leave room for that duplication and the acceptance/identity envelope.
const maxReplyBytes = 144 << 10

// A heartbeat answer carries up to MaxLeasesPerReply leases.
const maxHeartbeatReplyBytes = MaxLeasesPerReply*maxReplyBytes + 8<<10

type PairReply struct {
	Version        string `json:"version"`
	NodeID         string `json:"node_id"`
	SupplierPubkey string `json:"supplier_pubkey"`
	Credential     string `json:"credential"`
}
type Lease struct {
	Version            string    `json:"version"`
	ServiceType        string    `json:"service_type,omitempty"`
	JobID              string    `json:"job_id"`
	SignedJobID        string    `json:"signed_job_id"`
	Profile            string    `json:"profile"`
	ModelID            string    `json:"model_id"`
	Prompt             string    `json:"prompt"`
	MaxInputTokens     int       `json:"max_input_tokens"`
	MaxOutputTokens    int       `json:"max_output_tokens"`
	InputSHA256        string    `json:"input_sha256"`
	Attempt            string    `json:"attempt"`
	Fence              string    `json:"fence"`
	LeaseDeadline      time.Time `json:"lease_deadline"`
	SettlementDeadline time.Time `json:"settlement_deadline"`
	// Set for proven Codex jobs: the exact request to send and a single-use
	// token for the verifier configured locally in SCARLETT_VERIFIER.
	CodexPayload  json.RawMessage `json:"codex_payload,omitempty"`
	VerifierToken string          `json:"verifier_token,omitempty"`
	XRequest      *XRequest       `json:"x_request,omitempty"`
	XPayload      json.RawMessage `json:"x_payload,omitempty"`
	// Set for web jobs: the canonical page to fetch and the exact verifier
	// web.fetch payload that binds it.
	WebRequest *WebRequest     `json:"web_request,omitempty"`
	WebPayload json.RawMessage `json:"web_payload,omitempty"`
	// WebPrewarmBrowser asks the node to start its browser while it runs a
	// relay web job, because the page's domain has met bot protection before
	// and the coordinator may escalate. Relay web offers only; it is outside
	// web_request, so it never changes the job or its digests.
	WebPrewarmBrowser bool `json:"web_prewarm_browser,omitempty"`
	// WebEgress "proxy" sends a web job through the node's proxy, because the
	// page's domain recently limited a node's own network. Only a node whose
	// heartbeat egress is "both" or "proxy" is sent it, and like the pre-warm
	// hint it is outside web_request, never part of the job or its digests.
	WebEgress string `json:"web_egress,omitempty"`
	// Community offers grant no provider permission before funded acceptance.
	AcceptanceRequired bool   `json:"acceptance_required,omitempty"`
	RequestSHA256      string `json:"request_sha256,omitempty"`
}

// MaxXSearchPages is the most pages one x_read search may ask for: one
// verifier exchange and one attempt each, every page after the first
// following the cursor the verifier recorded for the page before it. Nodes
// before 0.1.16 accepted at most three; the coordinator sends more only to
// nodes that report 0.1.16 or later.
const MaxXSearchPages = 10

// XRequest is bounded public read work; no URLs, headers or credentials come
// from the coordinator. Pagination must be pinned separately in XPayload.
type XRequest struct {
	Operation string `json:"operation"`
	Query     string `json:"query,omitempty"`
	Username  string `json:"username,omitempty"`
	PostID    string `json:"post_id,omitempty"`
	Count     int    `json:"count,omitempty"`
	Pages     int    `json:"pages,omitempty"`
}

// WebRequest is one public https page. The URL is canonical (api/web-vectors.json);
// redirects are followed only as the verifier authorizes them. Mode is absent
// for a relay job, so relay leases keep their exact bytes and digests;
// "browser" renders the page in the node's hidden browser first, and Browser
// is present exactly then.
type WebRequest struct {
	Operation string      `json:"operation"`
	URL       string      `json:"url"`
	Mode      string      `json:"mode,omitempty"`
	Browser   *WebBrowser `json:"browser,omitempty"`
}

// WebBrowser is the browser phase of a browser web job. Every field is bound
// into input_sha256 with the rest of web_request.
type WebBrowser struct {
	Wait           string `json:"wait"`                    // "load" or "networkidle"
	WaitMS         int    `json:"wait_ms"`                 // 0-15000 extra settle time
	WaitSelector   string `json:"wait_selector,omitempty"` // 1-256 printable ASCII bytes
	TimeoutMS      int    `json:"timeout_ms"`              // 5000-45000 for the browser phase
	BlockResources bool   `json:"block_resources"`
	SolveChallenge bool   `json:"solve_challenge"`
}

// ActiveLease is an already acquired coordinator lease occupying local work.
// The coordinator only deduplicates references that match its live owned lease.
// Other or absent references remain conservatively additive to reported work.
type ActiveLease struct {
	JobID   string `json:"job_id"`
	Attempt string `json:"attempt"`
	Fence   string `json:"fence"`
}

func (l ActiveLease) Valid() bool {
	return canonicalUUID(l.JobID) && canonicalUUID(l.Attempt) && canonicalUUID(l.Fence)
}

type ServiceHealth struct {
	Kind          string        `json:"kind"`
	State         string        `json:"state"`
	Capacity      int           `json:"capacity"`
	InFlight      int           `json:"in_flight"`
	LastErrorCode string        `json:"last_error_code,omitempty"`
	ActiveLeases  []ActiveLease `json:"active_leases,omitempty"`
	// Optional aggregate readiness, never identities or provider quota budgets.
	ConfiguredCapacity    *int                    `json:"configured_capacity,omitempty"`
	RunnableCapacity      *int                    `json:"runnable_capacity,omitempty"`
	ActiveAccounts        *int                    `json:"active_accounts,omitempty"`
	ReadyAccounts         *int                    `json:"ready_accounts,omitempty"`
	CoolingAccounts       *int                    `json:"cooling_accounts,omitempty"`
	NextReadyAt           *time.Time              `json:"next_ready_at,omitempty"`
	OperationAvailability []OperationAvailability `json:"operation_availability,omitempty"`
	// Local execution limits, not provider authorization or proven readiness.
	MaxInputBytes   int      `json:"max_input_bytes,omitempty"`
	MaxOutputTokens int      `json:"max_output_tokens,omitempty"`
	Models          []string `json:"models,omitempty"`
	// Proof modes this node serves for the kind beyond the default. Absent
	// means MPC-TLS only, which is what every node before this field serves.
	ProofModes []string `json:"proof_modes,omitempty"`
	// Egress is how an enabled web service reaches targets: "direct" (its
	// own network), "both" (its own network, and the operator's proxy for
	// leases with web_egress "proxy") or "proxy" (every page through the
	// proxy). Node-reported, not verified.
	Egress string `json:"egress,omitempty"`
	// Browser is the browser tier inside an enabled web entry, and absent
	// everywhere else. Its capacity is part of the web capacity, never added.
	Browser *BrowserHealth `json:"browser,omitempty"`
}

// BrowserHealth is the readiness of the node's hidden browser for web jobs in
// browser mode. Ready means the runtime and browser were verified and a launch
// probe passed, not that a browser is running now.
type BrowserHealth struct {
	State    string `json:"state"`             // "ready" or "unavailable"
	Reason   string `json:"reason,omitempty"`  // present exactly when unavailable
	Capacity int    `json:"capacity"`          // 1-4 when ready, 0 when unavailable
	InFlight int    `json:"in_flight"`         // 0-Capacity
	Version  string `json:"version,omitempty"` // Chrome for Testing version, when ready
	// KillBytes is the browser tree size above which the node kills its
	// browser, when ready: max(recycle + 1.5 GiB, physical memory / 4).
	KillBytes int64 `json:"kill_bytes,omitempty"`
	// Solvers names the operator's captcha-solver providers (capmonster,
	// capsolver, 2captcha) the browser may use now: present only when ready,
	// configured and under the operator's daily spend cap. Never keys.
	Solvers []string `json:"solvers,omitempty"`
}

// Per-operation lanes overlap and must never be added together. Admission
// applies the exact immutable job operation and the configured physical ceiling.
type OperationAvailability struct {
	Operation        string     `json:"operation"`
	RunnableCapacity int        `json:"runnable_capacity"`
	NextReadyAt      *time.Time `json:"next_ready_at,omitempty"`
}

// Proven tells the coordinator a proof was sent; it reads the answer from the verifier.
type Proven struct {
	Version string `json:"version"`
	Attempt string `json:"attempt"`
	Fence   string `json:"fence"`
	// Egress is required in a web job's report and absent from any other.
	Egress *WebEgress `json:"egress,omitempty"`
}

// WebEgress is how a web job left the node: Via "direct" (its own network)
// or "proxy", and for a proxied job the proxy's public IPv4 exit when the
// node's probe through the job's session found it. The coordinator keys
// cooldowns by it. Node-reported, not verified; a direct job never names an
// address.
type WebEgress struct {
	Via  string `json:"via"`
	Exit string `json:"exit,omitempty"`
}
type Result struct {
	Version         string `json:"version"`
	JobID           string `json:"job_id"`
	Attempt         string `json:"attempt"`
	Fence           string `json:"fence"`
	InputSHA256     string `json:"input_sha256"`
	OutputSHA256    string `json:"output_sha256"`
	Output          string `json:"output"`
	ResolvedModelID string `json:"resolved_model_id"`
	InputTokens     int    `json:"input_tokens"`
	// CachedInputTokens is the reported cached subset of InputTokens; nil when not reported.
	CachedInputTokens *int   `json:"cached_input_tokens,omitempty"`
	OutputTokens      int    `json:"output_tokens"`
	DurationMS        int64  `json:"duration_ms"` // Diagnostic only; never reward latency.
	UsageAvailable    bool   `json:"usage_available"`
	UsageSource       string `json:"usage_source"`
	ExecutionMode     string `json:"execution_mode"`
}
type Failure struct {
	Version string `json:"version"`
	Attempt string `json:"attempt"`
	Fence   string `json:"fence"`
	Code    string `json:"code"`
	// Stage ("wire" or "dom") and ObservedBytes (a lower bound) are set
	// exactly when Code is page_too_large.
	Stage         string `json:"stage,omitempty"`
	ObservedBytes int64  `json:"observed_bytes,omitempty"`
	// Egress is required in a web job's report and absent from any other.
	Egress *WebEgress `json:"egress,omitempty"`
}
type Heartbeat struct {
	Version  string          `json:"version"`
	NodeID   string          `json:"node_id"`
	Profile  string          `json:"profile"`
	State    string          `json:"state"`
	Bid      int64           `json:"bid"`
	Capacity int             `json:"capacity"`
	Services []ServiceHealth `json:"services,omitempty"`
	// WaitSeconds asks the coordinator to hold the heartbeat open for up to
	// this long while it has nothing to offer, answering the moment a job for
	// this node is funded. The coordinator clamps it to [0, 20]; the node sends
	// HeartbeatWaitSeconds.
	WaitSeconds int `json:"wait_seconds"`
	// OffersSeen acknowledges every offer in the answers the node received
	// since its previous heartbeat request started, at most MaxOffersSeen and
	// each once, recorded the moment an answer is decoded and before the node
	// judges the offer. The coordinator sends an offer again when a later
	// heartbeat does not acknowledge it. Required, and [] when empty; Poll
	// fills it.
	OffersSeen []OfferRef `json:"offers_seen"`
}

// HeartbeatWaitSeconds is the hold the node asks for. The coordinator treats a
// node as stale 30 seconds after its last heartbeat, so the hold plus a round
// trip must stay well inside that.
const HeartbeatWaitSeconds = 20

// HeartbeatHoldJitter is how much longer than HeartbeatWaitSeconds the
// coordinator may hold a full-length heartbeat: it spreads such holds by up to
// two seconds either way.
const HeartbeatHoldJitter = 2 * time.Second

// HeartbeatGrace is how much longer than the longest hold a heartbeat may take
// before the node gives up on it: transport, queueing and the coordinator's
// own work on the reply. A heartbeat stuck on a connection that died quietly
// fails at 22 + 3 seconds; the HTTP/2 health check usually finds the dead
// connection first.
const HeartbeatGrace = 3 * time.Second

type Challenge struct {
	Version   string    `json:"version"`
	Nonce     string    `json:"nonce"`
	ExpiresAt time.Time `json:"expires_at"`
}

type ChallengeEcho struct {
	Version string `json:"version"`
	NodeID  string `json:"node_id"`
	Nonce   string `json:"nonce"`
}

type HeartbeatReply struct {
	// Leases are the offers in this answer: up to MaxLeasesPerReply, and no
	// more than the free slots the heartbeat advertised.
	Leases []Lease `json:"leases"`
	// Node is the coordinator's dispatch health for this node.
	Node      *NodeHealth `json:"node,omitempty"`
	Challenge *Challenge  `json:"challenge,omitempty"`
	// Unreadable names the offers in this answer that did not decode as a
	// lease. They are acknowledged like the others, and the node rejects them
	// as invalid_offer instead of leaving them to expire. Never part of the
	// body.
	Unreadable []OfferAttempt `json:"-"`
	// RetryAfter is the reply's Retry-After header, clamped, or zero when it
	// has none. A coordinator that is shutting down answers a held heartbeat
	// at once with no lease and a short Retry-After. Never part of the body.
	RetryAfter time.Duration `json:"-"`
}

// NodeHealth is how the coordinator sees this node take its offers.
// MissedStreak counts the offers in a row that the node neither accepted nor
// acknowledged in time. While SuspectUntil (RFC 3339, null when not suspect)
// is ahead, the coordinator sends the node no realtime work and at most one
// background job. Any acceptance resets both.
type NodeHealth struct {
	MissedStreak int        `json:"missed_streak"`
	SuspectUntil *time.Time `json:"suspect_until"`
}

// ErrHeartbeatRejected is a heartbeat the coordinator refused as invalid (400)
// or too large (413). Resending the same report cannot succeed, so the node
// logs it and backs off; it never resends a reduced shape.
var ErrHeartbeatRejected = errors.New("coordinator rejected the heartbeat")

// ErrInvalidResponse is a coordinator answer the node could not read: too
// large, or not the JSON the route promises.
var ErrInvalidResponse = errors.New("invalid coordinator response")

// A Retry-After from the coordinator is clamped to [MinRetryAfter,
// MaxRetryAfter] before the node waits on it.
const (
	MinRetryAfter = time.Second
	MaxRetryAfter = 60 * time.Second
)

// ErrorReply is the coordinator's JSON error body. The node reads only the
// code, and only to decide whether a request is worth repeating.
type ErrorReply struct {
	Error ErrorDetail `json:"error"`
}
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// StatusError is a coordinator answer outside 2xx. Code is the error code of
// its JSON body, empty when the body has none; RetryAfter is its clamped
// Retry-After header, zero when it has none.
type StatusError struct {
	Status     int
	Code       string
	RetryAfter time.Duration
}

func (e *StatusError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("coordinator HTTP %d %s", e.Status, e.Code)
	}
	return fmt.Sprintf("coordinator HTTP %d", e.Status)
}

// maxErrorBytes bounds the error body read for its code.
const maxErrorBytes = 4 << 10

// statusError reads a non-2xx answer. The code reaches logs, so only a short
// lowercase machine code is kept.
func statusError(resp *http.Response) error {
	e := &StatusError{Status: resp.StatusCode, RetryAfter: retryAfter(resp.Header, time.Now())}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes+1))
	var reply ErrorReply
	if err == nil && len(data) <= maxErrorBytes && json.Unmarshal(data, &reply) == nil && errorCode(reply.Error.Code) {
		e.Code = reply.Error.Code
	}
	return e
}

func errorCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// retryAfter reads a Retry-After header, in seconds or as an HTTP date, and
// clamps it to [MinRetryAfter, MaxRetryAfter]. It returns zero when the header
// is absent or unreadable.
func retryAfter(header http.Header, now time.Time) time.Duration {
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	var wait time.Duration
	seconds, err := strconv.ParseUint(value, 10, 64)
	switch {
	case err == nil:
		wait = time.Duration(min(seconds, uint64(MaxRetryAfter/time.Second))) * time.Second
	case errors.Is(err, strconv.ErrRange):
		wait = MaxRetryAfter
	default:
		at, err := http.ParseTime(value)
		if err != nil {
			return 0
		}
		wait = at.Sub(now)
	}
	return min(max(wait, MinRetryAfter), MaxRetryAfter)
}

// RetryAfterWait is how long to wait on a clamped Retry-After: the value plus
// a random share of up to half of it again, so nodes the coordinator asked to
// wait the same time do not all come back at once.
func RetryAfterWait(retryAfter time.Duration) time.Duration {
	if retryAfter <= 0 {
		return 0
	}
	return retryAfter + rand.N(retryAfter/2+1)
}

// Poll echoes an app-issued challenge before returning any lease to inference.
// The app owns single-use validation and RTT timing; the node supplies no duration.
// The heartbeat is a long poll: it may legitimately stay open for the hold the
// node asked for, so it runs under its own deadline of the longest hold plus
// HeartbeatGrace rather than the client's 10-second timeout, and ctx
// cancellation aborts it.
//
// Poll sets h.OffersSeen from the offers recorded since the last heartbeat,
// and records the offers of a decoded answer before it returns or checks
// anything else. A heartbeat that is not answered 200 hands its
// acknowledgements to the next one.
func (c *Client) Poll(ctx context.Context, h Heartbeat) (HeartbeatReply, error) {
	if c.seen == nil {
		c.seen = &offersSeen{}
	}
	h.OffersSeen = c.seen.take()
	var wire struct {
		Leases    []json.RawMessage `json:"leases"`
		Node      *NodeHealth       `json:"node"`
		Challenge *Challenge        `json:"challenge"`
	}
	pollCtx, cancel := context.WithTimeout(ctx, c.heartbeatTimeout(h.WaitSeconds))
	defer cancel()
	status, header, err := c.post(pollCtx, "/api/node/v1/heartbeat", h, &wire, true)
	if status != http.StatusOK {
		c.seen.restore(h.OffersSeen)
	}
	if status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge {
		return HeartbeatReply{}, fmt.Errorf("%w: %w", ErrHeartbeatRejected, err)
	}
	if err != nil {
		return HeartbeatReply{}, err
	}
	if status != http.StatusOK {
		return HeartbeatReply{}, fmt.Errorf("%w: heartbeat status %d", ErrInvalidResponse, status)
	}
	reply := HeartbeatReply{Leases: []Lease{}, Node: wire.Node, Challenge: wire.Challenge, RetryAfter: retryAfter(header, time.Now())}
	refs := make([]OfferRef, 0, len(wire.Leases))
	for _, raw := range wire.Leases {
		var id struct {
			JobID   string `json:"job_id"`
			Attempt string `json:"attempt"`
			Fence   string `json:"fence"`
		}
		_ = json.Unmarshal(raw, &id)
		refs = append(refs, OfferRef{JobID: id.JobID, Attempt: id.Attempt})
		var l Lease
		if json.Unmarshal(raw, &l) != nil {
			reply.Unreadable = append(reply.Unreadable, OfferAttempt{JobID: id.JobID, Attempt: id.Attempt, Fence: id.Fence})
			continue
		}
		reply.Leases = append(reply.Leases, l)
	}
	c.seen.record(refs...)
	if reply.Challenge == nil {
		return reply, nil
	}
	challenge := reply.Challenge
	origin, err := url.Parse(c.Origin)
	if err != nil || !c.allowEcho(origin) || h.NodeID == "" || h.Version != Version {
		return HeartbeatReply{}, errors.New("challenge echo is not allowed for this coordinator")
	}
	nonce, err := hex.DecodeString(challenge.Nonce)
	if err != nil || len(nonce) != 32 || hex.EncodeToString(nonce) != challenge.Nonce || challenge.Version != Version || !challenge.ExpiresAt.After(time.Now()) {
		return HeartbeatReply{}, errors.New("invalid or expired challenge")
	}
	echoCtx, cancel := context.WithDeadline(ctx, challenge.ExpiresAt)
	defer cancel()
	status, err = c.Post(echoCtx, "/api/node/v1/challenge/echo", ChallengeEcho{Version: Version, NodeID: h.NodeID, Nonce: challenge.Nonce}, nil)
	if err != nil {
		return HeartbeatReply{}, err
	}
	if status != http.StatusNoContent {
		return HeartbeatReply{}, errors.New("unexpected challenge echo status")
	}
	return reply, nil
}

type Client struct {
	Origin              string
	Credential          string
	EchoUnqualifiedHTTP bool
	HTTP                *http.Client
	// heartbeatGrace overrides HeartbeatGrace; tests shorten it.
	heartbeatGrace time.Duration
	// retryWait overrides RetryAfterWait for acceptance retries; tests shorten it.
	retryWait func(retryAfter time.Duration) time.Duration
	// uploadBackoff overrides browserUploadBackoff and uploadRetryBudget
	// browserUploadRetryBudget; tests shorten them.
	uploadBackoff     []time.Duration
	uploadRetryBudget time.Duration
	// release holds the coordinator's last release notice; see Release.
	release *releaseState
	// seen holds the offers the next heartbeat acknowledges.
	seen *offersSeen
	// stats counts connections, round trips and calls; see Stats.
	stats *clientStats
}

// heartbeatTimeout is the deadline of one heartbeat: the hold the node asked
// for, with the coordinator's jitter on a full-length hold, plus the grace for
// transport and the coordinator's reply.
func (c *Client) heartbeatTimeout(waitSeconds int) time.Duration {
	grace := HeartbeatGrace
	if c.heartbeatGrace > 0 {
		grace = c.heartbeatGrace
	}
	hold := time.Duration(max(waitSeconds, 0)) * time.Second
	if waitSeconds >= HeartbeatWaitSeconds {
		hold += HeartbeatHoldJitter
	}
	return hold + grace
}

func (c *Client) allowEcho(origin *url.URL) bool {
	if c == nil || origin == nil || c.Credential == "" {
		return false
	}
	host := origin.Hostname()
	switch {
	case origin.Scheme == "https":
		return true
	case origin.Scheme == "http" && c.EchoUnqualifiedHTTP:
		return true
	case origin.Scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1"):
		return true
	default:
		return false
	}
}

// New returns a client for one coordinator with its own transport: the
// default transport's settings plus HTTP/2 health checks, never shared with
// provider or verifier traffic.
func New(origin, credential string) *Client {
	return newClient(origin, credential, nil)
}

func newClient(origin, credential string, tlsConfig *tls.Config) *Client {
	return &Client{Origin: origin, Credential: credential, release: &releaseState{}, seen: &offersSeen{}, stats: &clientStats{},
		HTTP: &http.Client{Timeout: 10 * time.Second, Transport: newCoordinatorTransport(tlsConfig), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Post sends one report under the client's 10-second timeout. An answer
// outside 2xx is a *StatusError.
func (c *Client) Post(ctx context.Context, path string, body any, out any) (int, error) {
	status, _, err := c.post(ctx, path, body, out, false)
	return status, err
}

// post is Post, or with longPoll the same request bounded only by ctx: the
// client's timeout would cut a heartbeat hold short, and the answer may carry
// MaxLeasesPerReply leases. It also returns the response headers, which carry
// Retry-After. A request that gets no HTTP answer fails with a
// *TransportError.
func (c *Client) post(ctx context.Context, path string, body any, out any, longPoll bool) (int, http.Header, error) {
	var raw []byte
	var err error
	if exact, ok := body.(json.RawMessage); ok {
		if !json.Valid(exact) {
			return 0, nil, errors.New("invalid coordinator report")
		}
		raw = exact // preserve the journal's submission hash, including whitespace
	} else {
		raw, err = json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
	}
	if len(raw) > 131072 {
		return 0, nil, errors.New("request too large")
	}
	req, err := http.NewRequestWithContext(c.traced(ctx, longPoll), http.MethodPost, c.Origin+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(NodeVersionHeader, NodeRelease)
	if c.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.Credential)
	}
	client := c.HTTP
	limit := int64(maxReplyBytes)
	if longPoll {
		// Same transport and TLS roots; only the overall timeout is lifted.
		unbounded := *c.HTTP
		unbounded.Timeout = 0
		client = &unbounded
		limit = maxHeartbeatReplyBytes
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, transportError(err)
	}
	defer resp.Body.Close()
	c.observeRelease(resp.Header)
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, resp.Header, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, resp.Header, statusError(resp)
	}
	if out != nil {
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return resp.StatusCode, resp.Header, transportError(err)
		}
		if int64(len(data)) > limit {
			return resp.StatusCode, resp.Header, fmt.Errorf("%w: too large", ErrInvalidResponse)
		}
		if err = json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, resp.Header, ErrInvalidResponse
		}
	}
	return resp.StatusCode, resp.Header, nil
}
func JobPath(id, kind string) (string, error) {
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "/\\?&# \t\n\r") {
		return "", errors.New("invalid job ID")
	}
	return "/api/node/v1/jobs/" + url.PathEscape(id) + "/" + kind, nil
}
