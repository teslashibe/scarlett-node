package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	x "github.com/teslashibe/x-go"
)

type X struct {
	Config config.Config
	Base   http.RoundTripper
	Proof  http.RoundTripper
}
type xSpec struct {
	Operation    string         `json:"operation"`
	QueryID      string         `json:"query_id"`
	Variables    map[string]any `json:"variables"`
	Features     map[string]any `json:"features"`
	FieldToggles map[string]any `json:"field_toggles,omitempty"`
	CursorFrom   *int           `json:"cursor_from,omitempty"`
}
type xPlan struct {
	Type        string  `json:"type"`
	Exchanges   []xSpec `json:"exchanges"`
	MaxAttempts int     `json:"max_attempts"`
	ProofMode   string  `json:"proof_mode,omitempty"`
	ProofPolicy string  `json:"proof_policy,omitempty"`
}

// xRelayPolicy is the only relay policy this node knows. Under it the
// verifier, not the node, holds the TLS session keys for the X connection.
const xRelayPolicy = "x-relay-v1"

// relay reports whether the plan asks for a keyed relay proof, and whether
// its proof mode and policy are a pair this node may serve.
func (p xPlan) relay(c config.Config) (relay, ok bool) {
	switch {
	case (p.ProofMode == "" || p.ProofMode == "mpc") && p.ProofPolicy == "":
		return false, true
	case p.ProofMode == "relay" && p.ProofPolicy == xRelayPolicy:
		// The operator must have opted in: this mode changes who could read
		// the session cookie, so a coordinator cannot select it alone.
		return true, c.XRelay
	}
	return false, false
}

func privateJSON(path string, out any) error {
	f, e := localfs.OpenPrivate(path)
	if e != nil {
		return errors.New("local provider credential file unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.Size() > 8192 {
		return errors.New("provider credential file must be private, regular and bounded")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 8193))
	if e != nil || len(raw) > 8192 {
		return errors.New("provider credential file unreadable")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid local provider credentials")
	}
	return nil
}
func safeSecret(s string, max int, required bool) bool {
	if len(s) > max || required && s == "" {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 || strings.ContainsRune(";=\\\"", rune(b)) {
			return false
		}
	}
	return true
}
func XConfigured(path string) bool { _, err := readXSession(path); return err == nil }

func readXSession(path string) (x.Session, error) {
	var session x.Session
	if e := privateJSON(path, &session); e != nil {
		return session, e
	}
	// A local proxy option would replace the proof-aware transport in x-go.
	if session.Proxy != "" || session.Validate() != nil || !safeSecret(session.AuthToken, 64, true) || !safeSecret(session.CT0, 160, true) || !safeSecret(session.KDT, 64, false) || len(session.Twid) > 64 || strings.ContainsAny(session.Twid, "\r\n;") || len(session.UserAgent) > 512 || strings.ContainsAny(session.UserAgent, "\r\n") {
		return x.Session{}, errors.New("invalid or unsupported X session")
	}
	return session, nil
}

// Unique integer JSON matches the verifier policy and rejects ambiguous keys.
func uniqueJSON(raw []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		if depth > 16 {
			return nil, errors.New("JSON nesting too deep")
		}
		token, e := d.Token()
		if e != nil {
			return nil, e
		}
		switch t := token.(type) {
		case json.Delim:
			if t == '{' {
				m := map[string]any{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return nil, e
					}
					key, ok := k.(string)
					if !ok {
						return nil, errors.New("invalid JSON key")
					}
					if _, exists := m[key]; exists {
						return nil, errors.New("duplicate JSON key")
					}
					v, e := value(depth + 1)
					if e != nil {
						return nil, e
					}
					m[key] = v
				}
				_, e = d.Token()
				return m, e
			}
			if t == '[' {
				a := []any{}
				for d.More() {
					v, e := value(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				_, e = d.Token()
				return a, e
			}
			return nil, errors.New("invalid JSON delimiter")
		case json.Number:
			if _, e := strconv.ParseInt(string(t), 10, 64); e != nil {
				if _, e := strconv.ParseUint(string(t), 10, 64); e != nil {
					return nil, errors.New("non-integer JSON number")
				}
			}
			return t, nil
		default:
			return token, nil
		}
	}
	v, e := value(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	return v, nil
}
func validID(id string, max int) bool {
	if len(id) == 0 || len(id) > max {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func xRequestPolicy(r *coordinator.XRequest) (string, int, bool) {
	if r == nil {
		return "", 0, false
	}
	switch r.Operation {
	case "search":
		return "SearchTimeline", r.Pages, utf8.ValidString(r.Query) && r.Query == strings.TrimSpace(r.Query) && len(r.Query) > 0 && len(r.Query) <= 256 && r.Username == "" && r.PostID == "" && r.Count >= 1 && r.Count <= 20 && r.Pages >= 1 && r.Pages <= 3
	case "profile":
		return "UserByScreenName", 1, validID(r.Username, 15) && !strings.Contains(r.Username, "-") && r.Query == "" && r.PostID == "" && r.Count == 0 && r.Pages == 0
	case "post", "thread":
		n, e := strconv.ParseUint(r.PostID, 10, 64)
		ok := e == nil && n > 0 && len(r.PostID) <= 20 && r.Query == "" && r.Username == "" && r.Count == 0 && r.Pages == 0
		if r.Operation == "post" {
			return "TweetResultByRestId", 1, ok
		}
		return "TweetDetail", 1, ok
	}
	return "", 0, false
}
func validateXLease(c config.Config, l coordinator.Lease) (xPlan, time.Time, string) {
	var plan xPlan
	op, pages, ok := xRequestPolicy(l.XRequest)
	request, e := json.Marshal(l.XRequest)
	if !ok || e != nil || l.ServiceType != "x_read" || l.Version != coordinator.Version || l.JobID == "" || l.SignedJobID == "" || l.Attempt == "" || l.Fence == "" || l.Profile != c.Profile || SHA(string(request)) != l.InputSHA256 || len(request) > c.MaxInputBytes || l.ModelID != "" || l.Prompt != "" || l.MaxInputTokens != 0 || l.MaxOutputTokens != 0 || len(l.CodexPayload) != 0 || len(l.XPayload) == 0 || len(l.XPayload) > 65536 || len(l.VerifierToken) != 64 || !isHex(l.VerifierToken) {
		return plan, time.Time{}, "invalid_lease"
	}
	if _, e := uniqueJSON(l.XPayload); e != nil {
		return plan, time.Time{}, "invalid_lease"
	}
	d := json.NewDecoder(bytes.NewReader(l.XPayload))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(&plan) != nil || plan.Type != "x.read" || len(plan.Exchanges) != pages || plan.MaxAttempts != pages {
		return plan, time.Time{}, "invalid_lease"
	}
	if _, ok := plan.relay(c); !ok {
		return plan, time.Time{}, "invalid_lease"
	}
	for i, s := range plan.Exchanges {
		if s.Operation != op || !validID(s.QueryID, 64) || s.Variables == nil || s.Features == nil || i == 0 && s.CursorFrom != nil || i > 0 && (s.CursorFrom == nil || *s.CursorFrom != i-1) {
			return plan, time.Time{}, "invalid_lease"
		}
		if _, ok := s.Variables["cursor"]; ok {
			return plan, time.Time{}, "invalid_lease"
		}
		if i > 0 && !reflect.DeepEqual(s.Variables, plan.Exchanges[0].Variables) {
			return plan, time.Time{}, "invalid_lease"
		}
		switch op {
		case "SearchTimeline":
			if s.Variables["rawQuery"] != l.XRequest.Query || s.Variables["count"] != json.Number(strconv.Itoa(l.XRequest.Count)) || s.Variables["product"] != "Latest" {
				return plan, time.Time{}, "invalid_lease"
			}
		case "UserByScreenName":
			if s.Variables["screen_name"] != l.XRequest.Username {
				return plan, time.Time{}, "invalid_lease"
			}
		case "TweetResultByRestId":
			if s.Variables["tweetId"] != l.XRequest.PostID {
				return plan, time.Time{}, "invalid_lease"
			}
		case "TweetDetail":
			if s.Variables["focalTweetId"] != l.XRequest.PostID {
				return plan, time.Time{}, "invalid_lease"
			}
		}
	}
	now := time.Now()
	deadline := l.LeaseDeadline
	if !deadline.After(now) || !l.SettlementDeadline.After(now) {
		return plan, time.Time{}, "expired"
	}
	if l.SettlementDeadline.Before(deadline) {
		deadline = l.SettlementDeadline
	}
	if c.InferenceTimeout < time.Until(deadline) {
		deadline = now.Add(c.InferenceTimeout)
	}
	return plan, deadline, ""
}

type xBoundTransport struct {
	base, proof http.RoundTripper
	bootstrap   bool
	specs       []xSpec
	next        int
}

func (t *xBoundTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.User != nil {
		return nil, errUnprovenXCall
	}
	if t.bootstrap {
		if r.URL.Host == "x.com" && strings.HasPrefix(r.URL.Path, "/i/api/") {
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/i/api/graphql/"), "/")
			if len(parts) != 2 || parts[1] != "Viewer" && parts[1] != "UserByRestId" {
				return nil, errUnprovenXCall
			}
		} else if !(r.URL.Host == "x.com" && !strings.HasPrefix(r.URL.Path, "/i/api/") || r.URL.Host == "abs.twimg.com") {
			return nil, errUnprovenXCall
		}
		return t.base.RoundTrip(r)
	}
	if r.URL.Host != "x.com" || t.next >= len(t.specs) {
		return nil, errUnprovenXCall
	}
	s := t.specs[t.next]
	if r.URL.Path != "/i/api/graphql/"+s.QueryID+"/"+s.Operation || r.URL.Fragment != "" {
		return nil, errUnprovenXCall
	}
	q := r.URL.Query()
	for k, v := range q {
		if len(v) != 1 || k != "variables" && k != "features" && k != "fieldToggles" {
			return nil, errUnprovenXCall
		}
	}
	v, e := uniqueJSON([]byte(q.Get("variables")))
	if e != nil {
		return nil, errUnprovenXCall
	}
	vars, ok := v.(map[string]any)
	if !ok {
		return nil, errUnprovenXCall
	}
	if s.CursorFrom != nil {
		cursor, ok := vars["cursor"].(string)
		if !ok || cursor == "" || len(cursor) > 4096 {
			return nil, errUnprovenXCall
		}
		delete(vars, "cursor")
	}
	f, e := uniqueJSON([]byte(q.Get("features")))
	if e != nil || !reflect.DeepEqual(vars, s.Variables) || !reflect.DeepEqual(f, s.Features) {
		return nil, errUnprovenXCall
	}
	if s.FieldToggles != nil {
		f, e := uniqueJSON([]byte(q.Get("fieldToggles")))
		if e != nil || !reflect.DeepEqual(f, s.FieldToggles) {
			return nil, errUnprovenXCall
		}
	} else if _, present := q["fieldToggles"]; present {
		return nil, errUnprovenXCall
	}
	response, e := t.proof.RoundTrip(r)
	if e == nil {
		t.next++
	}
	return response, e
}
func (w X) Run(ctx context.Context, l coordinator.Lease) string {
	plan, deadline, code := validateXLease(w.Config, l)
	if code != "" {
		return code
	}
	session, e := readXSession(w.Config.XSession)
	if e != nil {
		return "auth_required"
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	base := w.Base
	if base == nil {
		base = http.DefaultTransport
	}
	proof := w.Proof
	if proof == nil {
		relay, _ := plan.relay(w.Config)
		proof = XTransport{Prover: w.Config.Prover, Verifier: w.Config.Verifier, VerifierCA: w.Config.VerifierCA, PlaintextFixture: w.Config.VerifierPlaintextFixture, Token: l.VerifierToken, Relay: relay}
	}
	transport := &xBoundTransport{base: base, proof: proof, bootstrap: true, specs: plan.Exchanges}
	ids := map[string]string{}
	for _, s := range plan.Exchanges {
		if previous, ok := ids[s.Operation]; ok && previous != s.QueryID {
			return "invalid_lease"
		}
		ids[s.Operation] = s.QueryID
	}
	client, e := session.NewClient(ctx, x.WithHTTPClient(&http.Client{Transport: transport, Timeout: w.Config.InferenceTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}), x.WithRetry(1, time.Millisecond), x.WithQueryIDs(ids), x.WithMinRequestGap(time.Second))
	if e != nil {
		return w.failure(ctx, e)
	}
	transport.bootstrap = false
	request := l.XRequest
	switch request.Operation {
	case "profile":
		_, e = client.GetProfile(ctx, request.Username)
	case "post":
		_, e = client.GetTweet(ctx, request.PostID)
	case "thread":
		_, e = client.GetTweetDetail(ctx, request.PostID)
	case "search":
		cursor := ""
		for i := 0; i < request.Pages; i++ {
			var page x.TweetPage
			page, e = client.SearchTweetsPage(ctx, request.Query, request.Count, cursor, x.WithSearchType(x.SearchLatest))
			if e != nil {
				break
			}
			if i+1 < request.Pages && page.NextCursor == "" {
				return "x_incomplete"
			}
			cursor = page.NextCursor
		}
	}
	if e != nil {
		return w.failure(ctx, e)
	}
	if transport.next != len(plan.Exchanges) {
		return "x_incomplete"
	}
	// The coordinator reads the verifier's own response copies; none are submitted.
	return ""
}
func xFailure(ctx context.Context, e error) string {
	if ctx.Err() != nil {
		return "expired"
	}
	if errors.Is(e, errUnprovenXCall) {
		return "invalid_lease"
	}
	if errors.Is(e, x.ErrRateLimited) {
		return "x_rate_limited"
	}
	if errors.Is(e, x.ErrUnauthorized) || errors.Is(e, x.ErrInvalidAuth) {
		return "auth_required"
	}
	return "x_request_failed"
}

// Only a typed rate-limit observation affects scheduling. Raw provider errors
// and response headers never enter local status or coordinator reports.
func (w X) failure(ctx context.Context, e error) string {
	var limited *x.RateLimitError
	if errors.As(e, &limited) && w.Config.AccountCooldown != nil {
		w.Config.AccountCooldown(limited.Wait)
	}
	return xFailure(ctx, e)
}
