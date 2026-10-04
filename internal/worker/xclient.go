package worker

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	x "github.com/teslashibe/x-go"
)

// One x-go client per X account, kept warm across jobs.
//
// Building an x-go client costs four unproven requests to X (its own session
// validation, Viewer and UserByRestId, then the x.com page and script the
// X-Client-Transaction-Id header is derived from) and two one-second request
// gaps: about twelve seconds in production around a two-second proof. The
// node builds that client once per account and keeps it until the session
// file changes, X refuses the session, a read suggests its transaction
// material is stale, or a background refresh replaces it. A job on a warm
// account does only its proven reads.
//
// The client is shared, so nothing about a job may live in it. Each job's
// pinned exchanges, proof transport and exchange counter travel in the
// request context as an xBinding; the client's one transport, xSwitchboard,
// reads the binding from each request. Two jobs on one account each see only
// their own, and a request that carries no binding is refused.

const (
	// xRefreshInterval is how long an account may sit idle before its client
	// is rebuilt in the background. The rebuild's first request is x-go's
	// Viewer read, which is also the session check that finds a cookie that
	// died while nobody was buying: on a dead session X refuses that first
	// request and nothing else is sent. An account that proved a read within
	// the interval has shown its session alive and skips the rebuild.
	xRefreshInterval = 30 * time.Minute
	// xClientMaxAge rebuilds even a busy account's client. Its transaction
	// material comes from the x.com deploy that was current when it was
	// built; a proven read's success vouches for that deploy, not the next.
	xClientMaxAge = 6 * time.Hour
	// xRefreshRetry spaces out background rebuilds after a transient failure;
	// the client built earlier keeps serving meanwhile.
	xRefreshRetry = time.Minute
	// xBuildTimeout bounds a construction when the configuration has no
	// inference timeout to borrow.
	xBuildTimeout = 45 * time.Second
)

// xBinding is one job's hold on a shared client: the lease's pinned
// exchanges, the proof transport carrying its verifier token, and how many
// exchanges have been proven.
type xBinding struct {
	proof    http.RoundTripper
	specs    []xSpec
	mu       sync.Mutex
	next     int
	mismatch bool
}
type xBindingKey struct{}

func withXBinding(ctx context.Context, b *xBinding) context.Context {
	return context.WithValue(ctx, xBindingKey{}, b)
}

// proven is how many of the job's exchanges the proof transport has answered.
func (b *xBinding) proven() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.next
}

// mismatched reports that x-go built a read with a query ID other than the
// one the lease pinned for its operation. The request did not leave the node.
func (b *xBinding) mismatched() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mismatch
}

var errXQueryIDMismatch = errors.New("x-go built the read with a query ID the lease did not pin")

// roundTrip checks a bound request against the job's next pinned exchange,
// exactly as the verifier will, and proves it through the job's transport.
func (b *xBinding) roundTrip(r *http.Request) (*http.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.URL.Fragment != "" || b.next >= len(b.specs) || !strings.HasPrefix(r.URL.Path, "/i/api/graphql/") {
		return nil, errUnprovenXCall
	}
	s := b.specs[b.next]
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/i/api/graphql/"), "/")
	if len(parts) != 2 || parts[1] != s.Operation {
		return nil, errUnprovenXCall
	}
	if parts[0] != s.QueryID {
		b.mismatch = true
		return nil, errXQueryIDMismatch
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
	response, e := b.proof.RoundTrip(r)
	if e == nil {
		b.next++
	}
	return response, e
}

// xSwitchboard is the one transport behind a cached x-go client. What it lets
// through depends on the request's context, never on a field a job could
// leave behind. A request bound to a job is checked against that job's
// pinned exchange and proven through that job's transport. An unbound
// request is refused, except while the client is being built: then x-go's
// own session validation (Viewer and UserByRestId) and its transaction-ID
// bootstrap pages go through Base unproven. Once construction ends, unbound
// requests are refused for good.
type xSwitchboard struct {
	base         http.RoundTripper
	constructing atomic.Bool
}

func (s *xSwitchboard) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.User != nil {
		return nil, errUnprovenXCall
	}
	api := r.URL.Host == "x.com" && strings.HasPrefix(r.URL.Path, "/i/api/")
	if b, _ := r.Context().Value(xBindingKey{}).(*xBinding); b != nil {
		if !api {
			return nil, errUnprovenXCall
		}
		return stripRateLimit(b.roundTrip(r))
	}
	if !s.constructing.Load() {
		return nil, errUnprovenXCall
	}
	if api {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/i/api/graphql/"), "/")
		if len(parts) != 2 || parts[1] != "Viewer" && parts[1] != "UserByRestId" {
			return nil, errUnprovenXCall
		}
	} else if r.URL.Host != "x.com" && r.URL.Host != "abs.twimg.com" {
		return nil, errUnprovenXCall
	}
	return stripRateLimit(s.base.RoundTrip(r))
}

// stripRateLimit removes X's rate-limit headers from a successful response
// before x-go sees it. x-go keeps one such state per client and paces every
// later request by it, although X's limits are per operation: one search
// response (50 per window) would otherwise slow every read on the account to
// one per twenty seconds for the next fifteen minutes. A 429 keeps its
// headers, so x-go still reports how long the account must rest.
func stripRateLimit(resp *http.Response, err error) (*http.Response, error) {
	if err == nil && resp != nil && resp.StatusCode == http.StatusOK {
		for _, prefix := range []string{"X-Rate-Limit-", "X-Ratelimit-", "Ratelimit-"} {
			for _, name := range []string{"Limit", "Remaining", "Reset"} {
				resp.Header.Del(prefix + name)
			}
		}
	}
	return resp, err
}

// xWarmClient is one built x-go client and what it was built from.
type xWarmClient struct {
	client     *x.Client
	board      *xSwitchboard
	stamp      string
	ids        map[string]string
	built      time.Time
	lastProven time.Time
}

// xBuild is one construction in progress. Everyone who needs the client
// waits on ready; the builder installs the result.
type xBuild struct {
	ready  chan struct{}
	cancel context.CancelFunc
	stamp  string
	ids    map[string]string
	result *xWarmClient
	err    error
}

// xAccount is the cache's view of one session file.
type xAccount struct {
	current    *xWarmClient
	build      *xBuild
	retryAfter time.Time
}

// due reports that the account's client should be rebuilt in the background.
func (a *xAccount) due(now time.Time) bool {
	w := a.current
	if w == nil || a.build != nil || now.Before(a.retryAfter) {
		return false
	}
	idle := now.Sub(w.built) >= xRefreshInterval && now.Sub(w.lastProven) >= xRefreshInterval
	return idle || now.Sub(w.built) >= xClientMaxAge
}

type xClientCache struct {
	mu       sync.Mutex
	accounts map[string]*xAccount
	// ids are the GraphQL query IDs leases have pinned, by operation. Clients
	// are built with them so the reads x-go emits carry the IDs the verifier
	// expects; a lease that pins an ID the client lacks rebuilds it once.
	ids map[string]string
}

var xClients = newXClientCache()

func newXClientCache() *xClientCache {
	return &xClientCache{accounts: map[string]*xAccount{}, ids: map[string]string{}}
}

// xClientKey is the cache key for a session file: the file is the account in
// both single-session and managed-accounts modes.
func xClientKey(path string) string { return filepath.Clean(path) }

// xSessionStamp identifies the credentials a client was built from, so a
// rewritten session file replaces the client whatever its timestamps say and
// a merely rewritten-but-identical one does not.
func xSessionStamp(s x.Session) string {
	raw, _ := json.Marshal(s)
	return SHA(string(raw))
}

func xCovers(have, need map[string]string) bool {
	for op, id := range need {
		if have[op] != id {
			return false
		}
	}
	return true
}

func (c *xClientCache) learn(ids map[string]string) {
	c.mu.Lock()
	maps.Copy(c.ids, ids)
	c.mu.Unlock()
}

// account returns the entry for key, creating it. The caller holds c.mu.
func (c *xClientCache) account(key string) *xAccount {
	a := c.accounts[key]
	if a == nil {
		a = &xAccount{}
		c.accounts[key] = a
	}
	return a
}

// startBuild constructs a client for the account in the background and
// installs the result. The caller holds c.mu.
func (c *xClientCache) startBuild(a *xAccount, session x.Session, stamp string, base http.RoundTripper, timeout time.Duration) *xBuild {
	ids := make(map[string]string, len(c.ids))
	maps.Copy(ids, c.ids)
	if timeout <= 0 {
		timeout = xBuildTimeout
	}
	// The build is bounded on its own, not by the job that happened to need
	// it first: another job, or the warm-up, may be waiting on it too.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	b := &xBuild{ready: make(chan struct{}), cancel: cancel, stamp: stamp, ids: ids}
	a.build = b
	go func() {
		defer cancel()
		w, err := buildXClient(ctx, session, stamp, base, timeout, ids)
		c.mu.Lock()
		b.result, b.err = w, err
		if a.build == b {
			a.build = nil
			switch {
			case err == nil:
				a.current = w
			case xBuildFailure(err) == "auth_required":
				// X refused the session itself: no client built from it may
				// go on serving.
				a.current = nil
			default:
				a.retryAfter = time.Now().Add(xRefreshRetry)
			}
		}
		c.mu.Unlock()
		close(b.ready)
	}()
	return b
}

// buildXClient is the construction-time path: x-go validates the session and
// bootstraps its transaction material through the switchboard's Base, then
// the switchboard refuses unbound requests forever.
func buildXClient(ctx context.Context, session x.Session, stamp string, base http.RoundTripper, timeout time.Duration, ids map[string]string) (*xWarmClient, error) {
	if base == nil {
		base = http.DefaultTransport
	}
	board := &xSwitchboard{base: base}
	board.constructing.Store(true)
	defer board.constructing.Store(false)
	client, err := session.NewClient(ctx, x.WithHTTPClient(&http.Client{Transport: board, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}), x.WithRetry(1, time.Millisecond), x.WithQueryIDs(ids), x.WithMinRequestGap(time.Second))
	if err != nil {
		return nil, err
	}
	return &xWarmClient{client: client, board: board, stamp: stamp, ids: ids, built: time.Now()}, nil
}

// get returns the account's client for a job, building one when none is
// serving. A client built from other credentials than the session file now
// holds is dropped first. With strict set, the client must carry the lease's
// query IDs; a job asks for that after x-go built a read with its own.
func (c *xClientCache) get(ctx context.Context, key string, session x.Session, stamp string, base http.RoundTripper, timeout time.Duration, need map[string]string, strict bool) (*xWarmClient, error) {
	c.mu.Lock()
	a := c.account(key)
	if w := a.current; w != nil && (w.stamp != stamp || strict && !xCovers(w.ids, need)) {
		a.current = nil
	}
	if w := a.current; w != nil {
		c.mu.Unlock()
		return w, nil
	}
	b := a.build
	if b != nil && (b.stamp != stamp || strict && !xCovers(b.ids, need)) {
		b.cancel()
		a.build, b = nil, nil
	}
	if b == nil {
		b = c.startBuild(a, session, stamp, base, timeout)
	}
	c.mu.Unlock()
	select {
	case <-b.ready:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if b.err != nil {
		return nil, b.err
	}
	return b.result, nil
}

// warm makes sure a client built from the session file is serving: it builds
// one when none is, rebuilds a stale one in the background while the old one
// keeps serving, and otherwise does nothing. It returns the outcome code and
// whether there is one to report; a cancelled ctx reports nothing.
func (c *xClientCache) warm(ctx context.Context, key string, session x.Session, stamp string, base http.RoundTripper, timeout time.Duration) (string, bool) {
	c.mu.Lock()
	a := c.account(key)
	if w := a.current; w != nil && w.stamp != stamp {
		a.current = nil
	}
	if a.current != nil && a.build == nil && !a.due(time.Now()) {
		c.mu.Unlock()
		return "", true
	}
	b := a.build
	if b != nil && b.stamp != stamp {
		b.cancel()
		a.build, b = nil, nil
	}
	if b == nil {
		b = c.startBuild(a, session, stamp, base, timeout)
	}
	c.mu.Unlock()
	select {
	case <-b.ready:
	case <-ctx.Done():
		return "", false
	}
	if b.err != nil {
		return xBuildFailure(b.err), true
	}
	return "", true
}

// drop forgets w if it is still the account's serving client. A job that is
// mid-read keeps its pointer; the next job builds afresh.
func (c *xClientCache) drop(key string, w *xWarmClient) {
	c.mu.Lock()
	if a := c.accounts[key]; a != nil && a.current == w {
		a.current = nil
	}
	c.mu.Unlock()
}

// forget drops whatever client serves key: the session file is gone or unusable.
func (c *xClientCache) forget(key string) {
	c.mu.Lock()
	if a := c.accounts[key]; a != nil {
		a.current = nil
	}
	c.mu.Unlock()
}

// proven records that w just answered a proven read: the session is alive
// and its transaction material accepted, so the background refresh can wait.
func (c *xClientCache) proven(key string, w *xWarmClient) {
	c.mu.Lock()
	if a := c.accounts[key]; a != nil && a.current == w {
		w.lastProven = time.Now()
	}
	c.mu.Unlock()
}

// xBuildFailure classifies a failed construction. x-go reports any failed
// session validation as ErrUnauthorized with the cause wrapped inside; only a
// cause that is not a transport failure means X refused the session, and a
// node that came up before its network must not mark its account dead.
func xBuildFailure(e error) string {
	switch {
	case errors.Is(e, x.ErrRateLimited):
		return "x_rate_limited"
	case errors.Is(e, x.ErrRequestFailed), errors.Is(e, context.DeadlineExceeded), errors.Is(e, context.Canceled):
		return "x_request_failed"
	case errors.Is(e, x.ErrUnauthorized), errors.Is(e, x.ErrInvalidAuth):
		return "auth_required"
	}
	return "x_request_failed"
}

// xStaleClient reports a proven read X answered with HTTP 404, which is how
// X refuses a gated read whose X-Client-Transaction-Id no longer verifies.
// The client is dropped so the next job bootstraps fresh material.
func xStaleClient(e error) bool {
	var op *x.OperationError
	return errors.As(e, &op) && op.Status == http.StatusNotFound
}

// XClientState is what the warm-client cache holds for one session file.
type XClientState struct {
	// Warm: a validated client built from the file is serving jobs.
	Warm bool
	// Building: a construction, first or refresh, is in progress.
	Building bool
	// Stale: the serving client is due a background refresh.
	Stale bool
}

// XClientStatus reports the cache's state for the session file at path.
func XClientStatus(path string, now time.Time) XClientState {
	xClients.mu.Lock()
	defer xClients.mu.Unlock()
	a := xClients.accounts[xClientKey(path)]
	if a == nil {
		return XClientState{}
	}
	return XClientState{Warm: a.current != nil, Building: a.build != nil, Stale: a.due(now)}
}

// xWarmSem serializes background warm-ups node-wide: one account at a time,
// so a node with eight accounts does not open eight bootstraps at once. Jobs
// never queue behind it; a job builds on demand and a queued warm-up finds
// the client already there.
var xWarmSem = make(chan struct{}, 1)

// WarmXClient builds the x-go client for the session file at path, or
// refreshes a stale one while the old one keeps serving, and reports the
// outcome to done: "" once a client built from the file serves, else the
// failure code the account's state machine understands. A cancelled ctx
// reports nothing. Jobs never wait for this; it only makes the first one fast
// and finds a session that died while the account was idle.
func WarmXClient(ctx context.Context, path string, base http.RoundTripper, timeout time.Duration, done func(code string)) {
	select {
	case xWarmSem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-xWarmSem }()
	key := xClientKey(path)
	session, e := readXSession(path)
	if e != nil {
		xClients.forget(key)
		done("auth_required")
		return
	}
	if code, report := xClients.warm(ctx, key, session, xSessionStamp(session), base, timeout); report {
		done(code)
	}
}

// ShutdownXClients abandons every cached client and cancels constructions in
// progress. Jobs still running keep the client they hold.
func ShutdownXClients() {
	xClients.mu.Lock()
	defer xClients.mu.Unlock()
	for _, a := range xClients.accounts {
		if a.build != nil {
			a.build.cancel()
		}
	}
	xClients.accounts = map[string]*xAccount{}
}

// ResetXClientsForTests empties the cache, including the query IDs it learned.
func ResetXClientsForTests() {
	ShutdownXClients()
	xClients.mu.Lock()
	xClients.ids = map[string]string{}
	xClients.mu.Unlock()
}

// AgeXClientForTests backdates the serving client for path: built is when it
// was constructed and proven when it last answered a proven read.
func AgeXClientForTests(path string, built, proven time.Time) bool {
	xClients.mu.Lock()
	defer xClients.mu.Unlock()
	a := xClients.accounts[xClientKey(path)]
	if a == nil || a.current == nil {
		return false
	}
	a.current.built, a.current.lastProven, a.retryAfter = built, proven, time.Time{}
	return true
}
