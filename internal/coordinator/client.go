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
)

const Version = "node-v1"

type PairReply struct {
	Version        string `json:"version"`
	NodeID         string `json:"node_id"`
	SupplierPubkey string `json:"supplier_pubkey"`
	Credential     string `json:"credential"`
}
type Lease struct {
	Version            string    `json:"version"`
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
	OutputTokens    int    `json:"output_tokens"`
	DurationMS      int64  `json:"duration_ms"` // Diagnostic only; never reward latency.
	UsageAvailable  bool   `json:"usage_available"`
	UsageSource     string `json:"usage_source"`
	ExecutionMode   string `json:"execution_mode"`
}
type Failure struct {
	Version string `json:"version"`
	Attempt string `json:"attempt"`
	Fence   string `json:"fence"`
	Code    string `json:"code"`
}
type Heartbeat struct {
	Version string `json:"version"`
	NodeID  string `json:"node_id"`
	Profile string `json:"profile"`
	ModelID string `json:"model_id"`
	State   string `json:"state"`
}

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

// Poll echoes an app-issued challenge before returning any lease to inference.
// The app owns single-use validation and RTT timing; the node supplies no duration.
func (c *Client) Poll(ctx context.Context, h Heartbeat) (HeartbeatReply, error) {
	var reply HeartbeatReply
	status, err := c.Post(ctx, "/api/node/v1/heartbeat", h, &reply)
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
func (c *Client) Post(ctx context.Context, path string, body any, out any) (int, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, err
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
	resp, err := c.HTTP.Do(req)
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
		data, err := io.ReadAll(io.LimitReader(resp.Body, 131073))
		if err != nil || len(data) > 131072 {
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
