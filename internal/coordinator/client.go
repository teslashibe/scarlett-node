package coordinator

import (
	"bytes"
	"context"
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

	"github.com/google/uuid"
)

const Version = "node-v1"

// A lease repeats its bounded prompt in the exact 64 KiB verifier request.
// Leave room for that duplication and the acceptance/identity envelope.
const maxReplyBytes = 144 << 10

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
	// Community offers grant no provider permission before funded acceptance.
	AcceptanceRequired bool   `json:"acceptance_required,omitempty"`
	RequestSHA256      string `json:"request_sha256,omitempty"`
}

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
// redirects are followed only as the verifier authorizes them.
type WebRequest struct {
	Operation string `json:"operation"`
	URL       string `json:"url"`
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
	for _, value := range []string{l.JobID, l.Attempt, l.Fence} {
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != value {
			return false
		}
	}
	return true
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
	// Egress is how an enabled web service reaches targets: "direct" or
	// "proxy" (a local HTTP CONNECT proxy). Node-reported, not verified.
	Egress string `json:"egress,omitempty"`
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
}

// HeartbeatWaitSeconds is the hold the node asks for. The coordinator treats a
// node as stale 30 seconds after its last heartbeat, so the hold plus a round
// trip must stay well inside that.
const HeartbeatWaitSeconds = 20

// HeartbeatGrace is how much longer than the requested hold a heartbeat may
// take before the node gives up on it: transport, queueing and the
// coordinator's own work on the reply.
const HeartbeatGrace = 10 * time.Second

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
	Lease     *Lease     `json:"lease"`
	Challenge *Challenge `json:"challenge,omitempty"`
	// RetryAfter is the reply's Retry-After header, clamped, or zero when it
	// has none. A coordinator that is shutting down answers a held heartbeat
	// at once with no lease and a short Retry-After. Never part of the body.
	RetryAfter time.Duration `json:"-"`
}

// ErrHeartbeatRejected is a heartbeat the coordinator refused as invalid (400)
// or too large (413). Resending the same report cannot succeed, so the node
// logs it and backs off; it never resends a reduced shape.
var ErrHeartbeatRejected = errors.New("coordinator rejected the heartbeat")

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
// node asked for, so it runs under its own deadline of wait plus HeartbeatGrace
// rather than the client's 10-second timeout, and ctx cancellation aborts it.
func (c *Client) Poll(ctx context.Context, h Heartbeat) (HeartbeatReply, error) {
	var reply HeartbeatReply
	pollCtx, cancel := context.WithTimeout(ctx, c.heartbeatTimeout(h.WaitSeconds))
	defer cancel()
	status, header, err := c.post(pollCtx, "/api/node/v1/heartbeat", h, &reply, true)
	if status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge {
		return HeartbeatReply{}, fmt.Errorf("%w: %w", ErrHeartbeatRejected, err)
	}
	if err != nil {
		return HeartbeatReply{}, err
	}
	if status != http.StatusOK {
		return HeartbeatReply{}, errors.New("unexpected heartbeat status")
	}
	reply.RetryAfter = retryAfter(header, time.Now())
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
	// release holds the coordinator's last release notice; see Release.
	release *releaseState
}

// heartbeatTimeout is the deadline of one heartbeat: the hold the node asked
// for plus the grace for transport and the coordinator's reply.
func (c *Client) heartbeatTimeout(waitSeconds int) time.Duration {
	grace := HeartbeatGrace
	if c.heartbeatGrace > 0 {
		grace = c.heartbeatGrace
	}
	return time.Duration(max(waitSeconds, 0))*time.Second + grace
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

func New(origin, credential string) *Client {
	return &Client{Origin: origin, Credential: credential, release: &releaseState{}, HTTP: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Post sends one report under the client's 10-second timeout. An answer
// outside 2xx is a *StatusError.
func (c *Client) Post(ctx context.Context, path string, body any, out any) (int, error) {
	status, _, err := c.post(ctx, path, body, out, false)
	return status, err
}

// post is Post, or with longPoll the same request bounded only by ctx: the
// client's timeout would cut a heartbeat hold short. It also returns the
// response headers, which carry Retry-After.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Origin+path, bytes.NewReader(raw))
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
	if longPoll {
		// Same transport and TLS roots; only the overall timeout is lifted.
		unbounded := *c.HTTP
		unbounded.Timeout = 0
		client = &unbounded
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, errors.New("coordinator unavailable")
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
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes+1))
		if err != nil || len(data) > maxReplyBytes {
			return resp.StatusCode, resp.Header, errors.New("coordinator response too large")
		}
		if err = json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, resp.Header, errors.New("invalid coordinator response")
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
