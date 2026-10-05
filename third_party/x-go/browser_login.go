package x

// This adapter follows social-login v0.2.20's bounded v1 wire contract, with
// interactive_x capability negotiation for retained-browser X continuation.
// It intentionally has no dependency on the private social-login Go module.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrBrowserService          = errors.New("x: browser login service unavailable")
	ErrBrowserProxy            = errors.New("x: browser login proxy failed")
	ErrBrowserProtocol         = errors.New("x: invalid browser login response")
	ErrBrowserChallengeExpired = errors.New("x: browser login challenge expired")
	ErrBrowserOwnerMismatch    = errors.New("x: browser login operation binding mismatch")
)

// BrowserLoginConfig selects the v1 protocol explicitly. Login's SidecarURL
// remains the separate legacy protocol; no automatic fallback is performed.
// HTTPClient is copied, with redirects disabled and a bounded request timeout.
type BrowserLoginConfig struct {
	URL         string
	BearerToken string
	HTTPClient  *http.Client
}

func (BrowserLoginConfig) String() string         { return "x.BrowserLoginConfig{redacted}" }
func (v BrowserLoginConfig) GoString() string     { return v.String() }
func (v BrowserLoginConfig) LogValue() slog.Value { return slog.StringValue(v.String()) }

// BrowserLogin owns no credentials or persisted profiles. The caller supplies
// opaque operation identity and persists only an independently verified Session.
type BrowserLogin struct {
	endpoint *url.URL
	bearer   string
	hc       *http.Client
}

func (*BrowserLogin) String() string         { return "x.BrowserLogin{redacted}" }
func (v *BrowserLogin) GoString() string     { return v.String() }
func (v *BrowserLogin) LogValue() slog.Value { return slog.StringValue(v.String()) }

func NewBrowserLogin(config BrowserLoginConfig) (*BrowserLogin, error) {
	u, err := url.Parse(config.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, browserError("invalid_request", 0, 0)
	}
	hc := http.Client{Timeout: 180 * time.Second}
	if config.HTTPClient != nil {
		hc = *config.HTTPClient
	}
	if hc.Timeout <= 0 || hc.Timeout > 240*time.Second {
		hc.Timeout = 240 * time.Second
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Cookie jars are not part of this bearer-authenticated local protocol.
	hc.Jar = nil
	return &BrowserLogin{endpoint: u, bearer: config.BearerToken, hc: &hc}, nil
}

// BrowserLoginBudget bounds one request. Zero explicitly forbids work; no
// default password/browser allowance is added. DeadlineAt is mandatory and is
// capped by the caller context, the transport timeout, and four minutes.
type BrowserLoginBudget struct {
	DeadlineAt            time.Time `json:"deadline_at"`
	MaxBrowserAttempts    int       `json:"max_browser_attempts"`
	MaxCredentialAttempts int       `json:"max_credential_attempts"`
	MaxSolverAttempts     int       `json:"max_solver_attempts"`
}

// BrowserLoginOperation must remain unchanged throughout a login operation.
// Identity values are caller-owned opaque strings, not product database IDs.
// A proxy requires an opaque ProxyLease. Credentials never belong here.
type BrowserLoginOperation struct {
	ProfileKey     string             `json:"profile_key"`
	OperationOwner string             `json:"operation_owner"`
	ConnectionID   string             `json:"connection_id"`
	Generation     string             `json:"generation"`
	Revision       string             `json:"revision"`
	RecoveryClaim  string             `json:"recovery_claim"`
	ProxyURL       string             `json:"proxy_url,omitempty"`
	ProxyLease     string             `json:"proxy_lease,omitempty"`
	Budget         BrowserLoginBudget `json:"budget"`
}

func (BrowserLoginOperation) String() string         { return "x.BrowserLoginOperation{redacted}" }
func (v BrowserLoginOperation) GoString() string     { return v.String() }
func (v BrowserLoginOperation) LogValue() slog.Value { return slog.StringValue(v.String()) }

type BrowserLoginRequest struct {
	Username, Password string
	Operation          BrowserLoginOperation
}

func (BrowserLoginRequest) String() string         { return "x.BrowserLoginRequest{redacted}" }
func (v BrowserLoginRequest) GoString() string     { return v.String() }
func (v BrowserLoginRequest) LogValue() slog.Value { return slog.StringValue(v.String()) }

// BrowserLoginChallenge is safe presentation metadata. Treat ID as an opaque
// reference; the original operation binding is additionally required to resume.
// Never interpolate it into logs or URLs.
type BrowserLoginChallenge struct {
	ID                string    `json:"id"`
	Method            string    `json:"method"`
	MaskedDestination string    `json:"masked_destination,omitempty"`
	ExpiresAt         time.Time `json:"expires_at"`
}

func (BrowserLoginChallenge) String() string         { return "x.BrowserLoginChallenge{redacted}" }
func (v BrowserLoginChallenge) GoString() string     { return v.String() }
func (v BrowserLoginChallenge) LogValue() slog.Value { return slog.StringValue(v.String()) }

type BrowserLoginAttempts struct {
	Browser    int  `json:"browser"`
	Credential int  `json:"credential"`
	Solver     int  `json:"solver"`
	Complete   bool `json:"complete"`
}

// BrowserLoginResult contains either a candidate session or a pending
// challenge. Session cookies alone do not prove login: call Session.NewClient
// and check Viewer identity before replacing saved credentials.
type BrowserLoginResult struct {
	Session    *Session
	Challenge  *BrowserLoginChallenge
	Attempts   BrowserLoginAttempts
	DeadlineAt time.Time
}

func (BrowserLoginResult) String() string         { return "x.BrowserLoginResult{redacted}" }
func (v BrowserLoginResult) GoString() string     { return v.String() }
func (v BrowserLoginResult) LogValue() slog.Value { return slog.StringValue(v.String()) }

// BrowserLoginError contains only allowlisted classifications and HTTP status,
// never provider messages, response bodies, request URLs or transport text.
type BrowserLoginError struct {
	Kind       string
	StatusCode int
	RetryAfter time.Duration
}

func (e *BrowserLoginError) Error() string {
	return fmt.Sprintf("x: browser login %s (HTTP %d)", safeBrowserKind(e.Kind), e.StatusCode)
}
func (e *BrowserLoginError) String() string       { return e.Error() }
func (e *BrowserLoginError) GoString() string     { return e.Error() }
func (e *BrowserLoginError) LogValue() slog.Value { return slog.StringValue(e.Error()) }
func (e *BrowserLoginError) Unwrap() error {
	switch safeBrowserKind(e.Kind) {
	case "unauthorized":
		return ErrUnauthorized
	case "rate_limited":
		return ErrRateLimited
	case "challenge":
		return ErrChallenge
	case "challenge_expired":
		return ErrBrowserChallengeExpired
	case "owner_mismatch":
		return ErrBrowserOwnerMismatch
	case "proxy":
		return ErrBrowserProxy
	case "service":
		return ErrBrowserService
	case "invalid_request":
		return ErrInvalidParams
	case "protocol":
		return ErrBrowserProtocol
	default:
		return ErrRequestFailed
	}
}
func safeBrowserKind(kind string) string {
	switch kind {
	case "unauthorized", "rate_limited", "challenge", "challenge_expired", "owner_mismatch", "proxy", "service", "invalid_request", "protocol", "transport":
		return kind
	}
	return "protocol"
}
func browserError(kind string, status int, wait time.Duration) error {
	return &BrowserLoginError{Kind: kind, StatusCode: status, RetryAfter: wait}
}

func (b *BrowserLogin) Start(ctx context.Context, request BrowserLoginRequest) (*BrowserLoginResult, error) {
	if strings.TrimSpace(request.Username) == "" || request.Password == "" {
		return nil, browserError("invalid_request", 0, 0)
	}
	return b.login(ctx, request.Operation, request.Username, request.Password, "", "", false)
}
func (b *BrowserLogin) Harvest(ctx context.Context, operation BrowserLoginOperation) (*BrowserLoginResult, error) {
	operation.Budget.MaxCredentialAttempts = 0
	return b.login(ctx, operation, "", "", "", "", true)
}
func (b *BrowserLogin) Continue(ctx context.Context, operation BrowserLoginOperation, challengeID, verificationCode string) (*BrowserLoginResult, error) {
	if strings.TrimSpace(challengeID) == "" || strings.TrimSpace(verificationCode) == "" {
		return nil, browserError("invalid_request", 0, 0)
	}
	return b.login(ctx, operation, "", "", challengeID, verificationCode, false)
}
func (b *BrowserLogin) Cancel(ctx context.Context, operation BrowserLoginOperation) error {
	// Cancellation remains available after the login deadline expires. It has a
	// separate short transport/context deadline and sends the same owner binding.
	if err := validateBrowserOperation(operation, false); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := browserRequest{BrowserLoginOperation: operation, Platform: "x"}
	var result struct {
		Cancelled bool `json:"cancelled"`
	}
	_, err := b.do(ctx, http.MethodPost, "/v1/challenges/cancel", body, &result)
	if err != nil {
		return err
	}
	if !result.Cancelled {
		return browserError("protocol", http.StatusOK, 0)
	}
	return nil
}

type browserRequest struct {
	BrowserLoginOperation
	Platform         string `json:"platform"`
	Username         string `json:"username,omitempty"`
	Password         string `json:"password,omitempty"`
	ChallengeID      string `json:"challenge_id,omitempty"`
	VerificationCode string `json:"verification_code,omitempty"`
}

func validateBrowserOperation(o BrowserLoginOperation, deadline bool) error {
	for _, value := range []string{o.ProfileKey, o.OperationOwner, o.ConnectionID, o.Generation, o.Revision, o.RecoveryClaim} {
		if strings.TrimSpace(value) == "" || len(value) > 1024 {
			return browserError("invalid_request", 0, 0)
		}
	}
	if len(o.OperationOwner) < 32 {
		return browserError("invalid_request", 0, 0)
	}
	if o.ProxyURL != "" {
		u, err := url.Parse(o.ProxyURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") || u.Host == "" || o.ProxyLease == "" {
			return browserError("invalid_request", 0, 0)
		}
	}
	for _, n := range []int{o.Budget.MaxBrowserAttempts, o.Budget.MaxCredentialAttempts, o.Budget.MaxSolverAttempts} {
		if n < 0 || n > 1 {
			return browserError("invalid_request", 0, 0)
		}
	}
	if deadline && o.Budget.DeadlineAt.IsZero() {
		return browserError("invalid_request", 0, 0)
	}
	return nil
}

func (b *BrowserLogin) login(ctx context.Context, o BrowserLoginOperation, username, password, id, code string, harvest bool) (*BrowserLoginResult, error) {
	if err := validateBrowserOperation(o, true); err != nil {
		return nil, err
	}
	aggregateBudget := o.Budget
	if id != "" {
		// Retained-browser continuation may spend no new browser, credential
		// or solver allowance. The response still reports aggregate work.
		o.Budget.MaxBrowserAttempts = 0
		o.Budget.MaxCredentialAttempts = 0
		o.Budget.MaxSolverAttempts = 0
	}
	deadline := o.Budget.DeadlineAt
	for _, cap := range []time.Time{time.Now().Add(240 * time.Second), time.Now().Add(b.hc.Timeout)} {
		if cap.Before(deadline) {
			deadline = cap
		}
	}
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	o.Budget.DeadlineAt = deadline
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var capabilities struct {
		RecoveryBudget int      `json:"recovery_budget"`
		InteractiveX   int      `json:"interactive_x"`
		ProfileHarvest []string `json:"profile_harvest"`
	}
	if _, err := b.do(ctx, http.MethodGet, "/v1/capabilities", nil, &capabilities); err != nil {
		return nil, err
	}
	hasHarvest := !harvest
	for _, platform := range capabilities.ProfileHarvest {
		if platform == "x" {
			hasHarvest = true
		}
	}
	if capabilities.RecoveryBudget != 1 || capabilities.InteractiveX != 1 || !hasHarvest {
		return nil, browserError("service", http.StatusServiceUnavailable, 0)
	}
	var out browserResultWire
	status, err := b.do(ctx, http.MethodPost, "/v1/login/bounded", browserRequest{o, "x", username, password, id, code}, &out)
	if !out.validAttempts(aggregateBudget) || out.DeadlineAt.IsZero() || out.DeadlineAt.After(deadline) {
		// A transport/API failure may report no work metadata. Preserve its
		// classification and return no result: callers must account unknown
		// work conservatively. A purported successful result must prove bounds.
		if err != nil && out.Attempts == nil {
			return nil, err
		}
		return nil, browserError("protocol", status, 0)
	}
	result := &BrowserLoginResult{Attempts: BrowserLoginAttempts{*out.Attempts.Browser, *out.Attempts.Credential, *out.Attempts.Solver, out.Attempts.Complete}, DeadlineAt: out.DeadlineAt}
	if err != nil {
		return result, err
	}
	if out.Challenge != nil {
		ch := out.Challenge
		if out.OK || (status != 200 && status != 401) || out.FailureType != "verification_required" || ch.ID == "" || len(ch.ID) > 1024 || ch.Method == "" || len(ch.Method) > 128 || len(ch.MaskedDestination) > 256 || ch.ExpiresAt.IsZero() || !ch.ExpiresAt.After(time.Now()) || ch.ExpiresAt.After(out.DeadlineAt) {
			return nil, browserError("protocol", status, 0)
		}
		result.Challenge = ch
		return result, nil
	}
	if !out.OK || status < 200 || status >= 300 {
		return result, browserError(classifyBrowserFailure(out.FailureType, status), status, 0)
	}
	if out.FailureType != "" {
		return nil, browserError("protocol", status, 0)
	}
	s := Session{AuthToken: out.Session.AuthToken, CT0: out.Session.CT0, Twid: out.Session.Twid, KDT: out.Session.KDT, UserAgent: out.Session.UserAgent, Proxy: o.ProxyURL}
	// Conflicting projections are malformed, not a candidate session.
	for key, value := range map[string]string{"auth_token": s.AuthToken, "ct0": s.CT0, "twid": s.Twid, "kdt": s.KDT} {
		if cookie := out.Cookies[key]; value != "" && cookie != "" && cookie != value {
			return nil, browserError("protocol", status, 0)
		}
	}
	if s.AuthToken == "" {
		s.AuthToken = out.Cookies["auth_token"]
	}
	if s.CT0 == "" {
		s.CT0 = out.Cookies["ct0"]
	}
	if s.Twid == "" {
		s.Twid = out.Cookies["twid"]
	}
	if s.KDT == "" {
		s.KDT = out.Cookies["kdt"]
	}
	if s.Validate() != nil || strings.TrimSpace(s.UserAgent) == "" {
		return nil, browserError("protocol", status, 0)
	}
	result.Session = &s
	return result, nil
}

type browserResultWire struct {
	OK          bool                   `json:"ok"`
	FailureType string                 `json:"failureType"`
	Cookies     map[string]string      `json:"cookies"`
	Session     Session                `json:"session"`
	Challenge   *BrowserLoginChallenge `json:"challenge"`
	Attempts    *struct {
		Browser    *int `json:"browser"`
		Credential *int `json:"credential"`
		Solver     *int `json:"solver"`
		Complete   bool `json:"complete"`
	} `json:"attempts"`
	DeadlineAt time.Time `json:"deadline_at"`
}

func (r browserResultWire) validAttempts(b BrowserLoginBudget) bool {
	a := r.Attempts
	return a != nil && a.Complete && a.Browser != nil && a.Credential != nil && a.Solver != nil && *a.Browser >= 0 && *a.Browser <= b.MaxBrowserAttempts && *a.Credential >= 0 && *a.Credential <= b.MaxCredentialAttempts && *a.Solver >= 0 && *a.Solver <= b.MaxSolverAttempts
}
func classifyBrowserFailure(kind string, status int) string {
	switch kind {
	case "verification_required", "captcha_required":
		return "challenge"
	case "challenge_not_found", "challenge_expired":
		return "challenge_expired"
	case "operation_owner_mismatch", "challenge_identity_mismatch", "proxy_lease_mismatch", "proxy_identity_mismatch":
		return "owner_mismatch"
	case "proxy_error":
		return "proxy"
	case "rate_limited", "attempts_exhausted", "resends_exhausted":
		return "rate_limited"
	case "login_rejected", "invalid_credentials", "logged_out":
		return "unauthorized"
	case "transport_error":
		return "transport"
	case "service_unavailable", "shutting_down", "recovery_budget_unsupported", "profile_busy", "login_in_progress", "challenge_capacity":
		return "service"
	case "invalid_request", "invalid_operation_owner", "invalid_budget":
		return "invalid_request"
	}
	if status == 429 {
		return "rate_limited"
	}
	if status >= 500 {
		return "service"
	}
	// Unknown provider failures do not imply invalid credentials.
	return "protocol"
}

// do never retries or follows redirects. Provider strings are deliberately
// discarded even for malformed JSON and errors raised by custom transports.
func (b *BrowserLogin) do(ctx context.Context, method, path string, body, target any) (int, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, browserError("invalid_request", 0, 0)
		}
		reader = bytes.NewReader(raw)
	}
	u := b.endpoint.ResolveReference(&url.URL{Path: path})
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return 0, browserError("invalid_request", 0, 0)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if b.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+b.bearer)
	}
	resp, err := b.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, browserError("transport", 0, 0)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return resp.StatusCode, browserError("protocol", resp.StatusCode, 0)
	}
	var envelope struct {
		Version string          `json:"version"`
		OK      bool            `json:"ok"`
		Data    json.RawMessage `json:"data"`
		Error   *struct {
			Code    string          `json:"code"`
			Details json.RawMessage `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Version != "v1" || (envelope.OK && envelope.Error != nil) {
		return resp.StatusCode, browserError("protocol", resp.StatusCode, 0)
	}
	wait := parseRetryAfter(resp.Header.Get("Retry-After"), 0)
	if wait == 0 {
		wait = parseRetryAfter(rlHeader(resp.Header, "Reset"), 0)
	}
	if !envelope.OK {
		kind := ""
		if envelope.Error != nil {
			kind = envelope.Error.Code
			if _, ok := target.(*browserResultWire); ok && len(envelope.Error.Details) > 0 {
				_ = json.Unmarshal(envelope.Error.Details, target)
			}
		}
		return resp.StatusCode, browserError(classifyBrowserFailure(kind, resp.StatusCode), resp.StatusCode, wait)
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" || json.Unmarshal(envelope.Data, target) != nil {
		return resp.StatusCode, browserError("protocol", resp.StatusCode, 0)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Login failures and pending challenges use an OK v1 envelope with HTTP401.
		if _, ok := target.(*browserResultWire); !ok {
			return resp.StatusCode, browserError(classifyBrowserFailure("", resp.StatusCode), resp.StatusCode, wait)
		}
		if out, ok := target.(*browserResultWire); ok && out.Challenge == nil {
			return resp.StatusCode, browserError(classifyBrowserFailure(out.FailureType, resp.StatusCode), resp.StatusCode, wait)
		}
	}
	return resp.StatusCode, nil
}
