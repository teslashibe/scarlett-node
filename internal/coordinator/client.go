package coordinator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	// Local execution limits, not provider authorization or proven readiness.
	MaxInputBytes   int      `json:"max_input_bytes,omitempty"`
	MaxOutputTokens int      `json:"max_output_tokens,omitempty"`
	Models          []string `json:"models,omitempty"`
	// Proof modes this node serves for the kind beyond the default. Absent
	// means MPC-TLS only, which is what every node before this field serves.
	ProofModes []string `json:"proof_modes,omitempty"`
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
}

// ErrHeartbeatRejected is a heartbeat the coordinator refused as invalid. A
// coordinator older than a heartbeat field rejects the whole report, so the
// caller may retry with the fields that coordinator knows.
var ErrHeartbeatRejected = errors.New("coordinator rejected the heartbeat")

// WithoutProofModes returns a copy of the services with proof_modes removed,
// and whether anything was removed: the heartbeat a coordinator that predates
// the field accepts.
func WithoutProofModes(services []ServiceHealth) ([]ServiceHealth, bool) {
	out := make([]ServiceHealth, len(services))
	removed := false
	for i, s := range services {
		if s.ProofModes != nil {
			removed = true
			s.ProofModes = nil
		}
		out[i] = s
	}
	return out, removed
}

// WithoutExtensions returns the conservative heartbeat understood by older
// coordinators. A rollback retains additive occupancy and MPC-TLS execution.
func WithoutExtensions(services []ServiceHealth) ([]ServiceHealth, bool) {
	out, removed := WithoutProofModes(services)
	for i := range out {
		if out[i].ActiveLeases != nil {
			removed = true
			out[i].ActiveLeases = nil
		}
	}
	return out, removed
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
	status, err := c.post(pollCtx, "/api/node/v1/heartbeat", h, &reply, true)
	if status == http.StatusBadRequest {
		return HeartbeatReply{}, ErrHeartbeatRejected
	}
	if err != nil {
		return HeartbeatReply{}, err
	}
	if status != http.StatusOK {
		return HeartbeatReply{}, errors.New("unexpected heartbeat status")
	}
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
	return &Client{Origin: origin, Credential: credential, HTTP: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Post sends one report under the client's 10-second timeout.
func (c *Client) Post(ctx context.Context, path string, body any, out any) (int, error) {
	return c.post(ctx, path, body, out, false)
}

// post is Post, or with longPoll the same request bounded only by ctx: the
// client's timeout would cut a heartbeat hold short.
func (c *Client) post(ctx context.Context, path string, body any, out any, longPoll bool) (int, error) {
	var raw []byte
	var err error
	if exact, ok := body.(json.RawMessage); ok {
		if !json.Valid(exact) {
			return 0, errors.New("invalid coordinator report")
		}
		raw = exact // preserve the journal's submission hash, including whitespace
	} else {
		raw, err = json.Marshal(body)
		if err != nil {
			return 0, err
		}
	}
	if len(raw) > 131072 {
		return 0, errors.New("request too large")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Origin+path, bytes.NewReader(raw))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
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
		return 0, errors.New("coordinator unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("coordinator HTTP %d", resp.StatusCode)
	}
	if out != nil {
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes+1))
		if err != nil || len(data) > maxReplyBytes {
			return resp.StatusCode, errors.New("coordinator response too large")
		}
		if err = json.Unmarshal(data, out); err != nil {
			return resp.StatusCode, errors.New("invalid coordinator response")
		}
	}
	return resp.StatusCode, nil
}
func JobPath(id, kind string) (string, error) {
	if id == "" || len(id) > 128 || strings.ContainsAny(id, "/\\?&# \t\n\r") {
		return "", errors.New("invalid job ID")
	}
	return "/api/node/v1/jobs/" + url.PathEscape(id) + "/" + kind, nil
}
