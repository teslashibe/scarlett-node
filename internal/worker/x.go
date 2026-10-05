package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	x "github.com/teslashibe/x-go"
)

// X serves x_read leases. Base carries the unproven bootstrap fetches of
// client construction (nil: http.DefaultTransport); Proof replaces the
// per-lease proving transport in tests; Clients is the warm client cache
// (nil: DefaultXClients).
type X struct {
	Config  config.Config
	Base    http.RoundTripper
	Proof   http.RoundTripper
	Clients *XClients
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

// xTransport is the proving transport a validated plan asks for.
func xTransport(c config.Config, plan xPlan, token string) XTransport {
	relay, ok := plan.relay(c)
	return XTransport{Prover: c.Prover, Verifier: c.Verifier, VerifierCA: c.VerifierCA, PlaintextFixture: c.VerifierPlaintextFixture, Token: token, Relay: relay && ok}
}

// XOfferServable reports whether this node could serve an x_read offer's
// proof mode, from the payload the offer carries. It lets the node decline
// before funded acceptance instead of burning the job afterwards. An offer
// without a payload cannot be judged yet and passes.
func XOfferServable(c config.Config, payload json.RawMessage) bool {
	if len(payload) == 0 {
		return true
	}
	var plan struct {
		ProofMode   string `json:"proof_mode"`
		ProofPolicy string `json:"proof_policy"`
	}
	if json.Unmarshal(payload, &plan) != nil {
		return false
	}
	_, ok := xPlan{ProofMode: plan.ProofMode, ProofPolicy: plan.ProofPolicy}.relay(c)
	return ok
}

// relay reports whether the plan asks for a keyed relay proof, and whether
// its proof mode and policy are a pair this node may serve.
func (p xPlan) relay(c config.Config) (relay, ok bool) {
	switch {
	case (p.ProofMode == "" || p.ProofMode == "mpc") && p.ProofPolicy == "":
		return false, true
	case p.ProofMode == "relay" && p.ProofPolicy == xRelayPolicy:
		// The operator must have opted in: this mode changes who could read
		// the session cookie, so a coordinator cannot select it alone. A node
		// that has caught its verifier misusing the session serves no more
		// relay until an operator restarts it.
		return true, c.XRelay && !RelayHalted()
	}
	return false, false
}

// relayMisuseMarker is how a caught verifier misuse arrives from the relay
// helper's stderr. It must match relay::node::MISUSE in prover/src/relay/node.rs.
const relayMisuseMarker = "verifier misused this node's X session"

// relayHalt latches the first time this node catches its verifier sealing
// something other than the node's own request. It is a node-wide stop, not a
// per-account one: every account routes through the single operator-run
// verifier, so a misuse implicates the verifier, not the account. The node
// keeps serving MPC-TLS and offers no more keyed relay until an operator
// restarts it and investigates — deliberately sticky, because this is a trust
// break the operator should see, not a transient error to retry past.
var relayHalt struct {
	sync.Mutex
	halted bool
	reason string
	at     time.Time
	// file, when set, makes the halt durable: it is written on halt and read
	// at startup, so a restart (the desktop app restarts the node on its own)
	// cannot quietly re-arm relay. `scarlett-node relay-resume` removes it.
	file string
}

// RelayHaltFile is the marker's name inside the node's state directory.
const RelayHaltFile = "relay-halt"

// LoadRelayHalt makes the halt durable under dir and restores one left by an
// earlier run. Call once at startup, before any heartbeat.
func LoadRelayHalt(dir string) error {
	path := filepath.Join(dir, RelayHaltFile)
	raw, err := os.ReadFile(path)
	relayHalt.Lock()
	defer relayHalt.Unlock()
	relayHalt.file = path
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	relayHalt.halted = true
	relayHalt.reason = strings.TrimSpace(string(raw))
	fmt.Fprintf(os.Stderr, "keyed relay stays halted from an earlier run (%s); run `scarlett-node relay-resume` once the verifier has been checked\n", relayHalt.reason)
	return nil
}

// HaltRelay stops this node from offering or accepting keyed-relay work and
// prints one alert line. Safe to call repeatedly; only the first halts and alerts.
func HaltRelay(reason string) {
	relayHalt.Lock()
	first := !relayHalt.halted
	relayHalt.halted, relayHalt.reason, relayHalt.at = true, reason, time.Now()
	file := relayHalt.file
	relayHalt.Unlock()
	if !first {
		return
	}
	fmt.Fprintf(os.Stderr, "ALERT keyed relay halted: %s — this node serves no more relay jobs until `scarlett-node relay-resume`; investigate the verifier first\n", reason)
	if file != "" {
		// Best effort: the in-memory halt holds for this run regardless.
		if err := localfs.WriteAtomic(file, []byte(reason+"\n"), true); err != nil {
			fmt.Fprintln(os.Stderr, "keyed relay halt could not be recorded:", err)
		}
	}
}

// RelayHaltReason is the recorded reason, or empty when relay is not halted.
func RelayHaltReason() string {
	relayHalt.Lock()
	defer relayHalt.Unlock()
	if !relayHalt.halted {
		return ""
	}
	return relayHalt.reason
}

// RelayHalted reports whether a caught verifier misuse has stopped relay on
// this node. MPC-TLS X reads are unaffected.
func RelayHalted() bool {
	relayHalt.Lock()
	defer relayHalt.Unlock()
	return relayHalt.halted
}

// ResetRelayHaltForTests clears the latch and forgets the marker path. The
// only runtime reset is the operator's `scarlett-node relay-resume`.
func ResetRelayHaltForTests() {
	relayHalt.Lock()
	relayHalt.halted, relayHalt.reason, relayHalt.at, relayHalt.file = false, "", time.Time{}, ""
	relayHalt.Unlock()
}

// privateBytes reads a small private credential file; its callers never log
// the content. Errors carry no content either.
func privateBytes(path string) ([]byte, error) {
	f, e := localfs.OpenPrivate(path)
	if e != nil {
		return nil, errors.New("local provider credential file unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || info.Size() > 8192 {
		return nil, errors.New("provider credential file must be private, regular and bounded")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 8193))
	if e != nil || len(raw) > 8192 {
		return nil, errors.New("provider credential file unreadable")
	}
	return raw, nil
}
func decodePrivateJSON(raw []byte, out any) error {
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
func XConfigured(path string) bool { _, _, err := readXSession(path); return err == nil }

// XSessionStamp returns the private, locally valid session content fingerprint.
// An empty stamp means the session cannot be used. Never log the fingerprint.
func XSessionStamp(path string) string {
	_, stamp, err := readXSession(path)
	if err != nil {
		return ""
	}
	return stamp
}

// readXSession reads and checks a session file. The stamp is the SHA-256 of
// the file's content: a warm client built from one stamp is dropped when the
// file no longer hashes to it. The hash reveals nothing about the content and
// is never logged.
func readXSession(path string) (x.Session, string, error) {
	var session x.Session
	raw, e := privateBytes(path)
	if e != nil {
		return session, "", e
	}
	if e := decodePrivateJSON(raw, &session); e != nil {
		return session, "", e
	}
	// A local proxy option would replace the proof-aware transport in x-go.
	if session.Proxy != "" || session.Validate() != nil || !safeSecret(session.AuthToken, 64, true) || !safeSecret(session.CT0, 160, true) || !safeSecret(session.KDT, 64, false) || len(session.Twid) > 64 || strings.ContainsAny(session.Twid, "\r\n;") || len(session.UserAgent) > 512 || strings.ContainsAny(session.UserAgent, "\r\n") {
		return x.Session{}, "", errors.New("invalid or unsupported X session")
	}
	return session, SHA(string(raw)), nil
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

// Run serves one x_read lease on the account's warm client (see XClients).
// The lease is validated first, and acquire checks the session file before
// building, so invalid work never builds a client. A job waits for a build
// only when no usable client exists: the background has not built one yet
// (or its build failed), or the lease pins a query ID the client was not
// built with.
func (w X) Run(ctx context.Context, l coordinator.Lease) string {
	plan, deadline, code := validateXLease(w.Config, l)
	if code != "" {
		return code
	}
	ids := map[string]string{}
	for _, s := range plan.Exchanges {
		if previous, ok := ids[s.Operation]; ok && previous != s.QueryID {
			return "invalid_lease"
		}
		ids[s.Operation] = s.QueryID
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	clients := w.Clients
	if clients == nil {
		clients = defaultXClients
	}
	account := clients.account(w.Config, w.Config.LocalAccountID, w.Config.XSession, w.Base)
	proof := w.Proof
	if proof == nil {
		proof = xTransport(w.Config, plan, l.VerifierToken)
	}
	warm, e := account.acquire(ctx, ids, false)
	if e != nil {
		return w.failure(ctx, e)
	}
	// X's last reported quota on this account makes x-go hold the next read
	// back. When that wait cannot fit in the lease, the job would only burn its
	// deadline and leave its reserved slot behind: rest the account instead,
	// before any proof is spent.
	if wait, reset := warm.pacingWait(clients.gap()); wait > 0 {
		if wait >= time.Until(deadline) {
			return w.limited(reset)
		}
		if warm.exhausted() > 0 {
			// The reset fits in the lease. x-go would let the read through before
			// it, so the node waits here.
			select {
			case <-ctx.Done():
				return w.limited(warm.exhausted())
			case <-time.After(wait):
			}
		}
	}
	for attempt := 0; ; attempt++ {
		binding := &xBinding{specs: plan.Exchanges, proof: proof, warm: warm}
		code, e = w.read(withXBinding(ctx, binding), warm.client, *l.XRequest)
		if e == nil && code == "" && binding.proven() != len(plan.Exchanges) {
			code = "x_incomplete"
		}
		if e == nil {
			return code
		}
		// The client built its request with another query ID than the lease
		// pins, so the switchboard refused it before any proof was spent.
		// Build once with the lease's override and try again.
		if attempt == 0 && binding.wasStale() && binding.proven() == 0 {
			if warm, e = account.acquire(ctx, ids, true); e == nil {
				continue
			}
			return w.failure(ctx, e)
		}
		if xAuthFailure(e) {
			account.drop(warm)
		} else if ctx.Err() != nil && binding.idle() {
			// The job ended while x-go held its read back. When X's quota is used
			// up the client is kept, because a replacement would forget that, and
			// the account rests until the reset. Otherwise the slot the job
			// reserved stays on the shared client, which is replaced.
			if reset := warm.exhausted(); reset > 0 {
				return w.limited(reset)
			}
			account.replace(warm)
		}
		return w.failure(ctx, e)
	}
}

// limited is a job that cannot be served before X's quota window resets: the
// account rests until then.
func (w X) limited(reset time.Duration) string {
	if w.Config.AccountCooldown != nil {
		w.Config.AccountCooldown(reset)
	}
	return "x_rate_limited"
}

// read performs the lease's reads on client; ctx carries the job binding.
func (w X) read(ctx context.Context, client *x.Client, request coordinator.XRequest) (string, error) {
	var e error
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
				return "x_incomplete", nil
			}
			cursor = page.NextCursor
		}
	}
	// The coordinator reads the verifier's own response copies; none are submitted.
	return "", e
}
func xFailure(ctx context.Context, e error) string {
	// The relay helper caught the verifier sealing something other than this
	// node's own request. The request has already gone out; what the node can
	// still do is refuse to be used that way again and make the operator look.
	// That holds even when the lease has meanwhile expired.
	if e != nil && strings.Contains(e.Error(), relayMisuseMarker) {
		HaltRelay(relayMisuseMarker)
		return "relay_misuse"
	}
	if ctx.Err() != nil {
		return "expired"
	}
	if errors.Is(e, errUnprovenXCall) {
		return "invalid_lease"
	}
	if errors.Is(e, x.ErrRateLimited) {
		return "x_rate_limited"
	}
	if xAuthFailure(e) || errors.Is(e, errXSession) {
		return "auth_required"
	}
	return "x_request_failed"
}

// xAuthFailure reports whether X refused the session. x-go wraps any failure
// of its validation read as ErrUnauthorized, including a transport failure
// (ErrRequestFailed); that one is not X refusing the session and must not
// park the account until its session file changes.
func xAuthFailure(e error) bool {
	return (errors.Is(e, x.ErrUnauthorized) || errors.Is(e, x.ErrInvalidAuth)) && !errors.Is(e, x.ErrRequestFailed)
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
