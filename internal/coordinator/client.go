package coordinator

import (
	"bytes"
	"context"
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
	DurationMS      int64  `json:"duration_ms"`
	UsageAvailable  bool   `json:"usage_available"`
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

type Client struct {
	Origin     string
	Credential string
	HTTP       *http.Client
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
