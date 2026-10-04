package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	x "github.com/teslashibe/x-go"
)

// xMinGap is the pause x-go keeps between two requests of one account. It
// lives on the shared client, so concurrent jobs on one account share it.
const xMinGap = time.Second

// DefaultXRefresh is how often a warm client's transaction-ID material is
// rebuilt in the background when SCARLETT_X_REFRESH_SECONDS is not set.
const DefaultXRefresh = 30 * time.Minute

// xBuildTimeout bounds one client construction when the configuration
// carries no inference timeout (tests and warm-ups without a full config).
const xBuildTimeout = 30 * time.Second

// errXSession is a session file that cannot be used: missing, not private,
// or not a valid x-go session. It classifies as auth_required.
var errXSession = errors.New("local X session unavailable")

// errXDropped is a refresh whose client was dropped while it ran.
var errXDropped = errors.New("x client dropped during refresh")

// XClients keeps one warm x-go client per X account so a job does only its
// proven reads. The account key is the session file path, which is the
// natural key in both single-session and managed-accounts mode. A client is
// built lazily (or by Warm at node start) and reused until the session file's
// content changes, a proven read fails with an auth error, or Stop; a timer
// also rebuilds its transaction-ID material in the background without
// repeating the session-validation reads. Dropping or replacing a client is
// an atomic pointer swap: in-flight jobs keep the pointer they hold.
type XClients struct {
	mu       sync.Mutex
	accounts map[string]*xAccount
	// minGap overrides x-go's request pacing; zero means xMinGap. Tests only.
	minGap time.Duration
	// log receives one line per build outcome; nil means os.Stderr. Lines
	// name the local account ID, never the session path or its contents.
	log io.Writer
}

// NewXClients returns an empty cache. Production uses DefaultXClients.
func NewXClients() *XClients { return &XClients{accounts: map[string]*xAccount{}} }

var defaultXClients = NewXClients()

// DefaultXClients is the process-wide cache X.Run uses when X.Clients is nil.
func DefaultXClients() *XClients { return defaultXClients }

// XAccount names one configured X account for Warm: its local ID (for the
// log line) and its session file path (the cache key).
type XAccount struct{ ID, Path string }

// Warm builds the client of each account in turn, so the first job on it is
// fast, and prints one line per account. A failure leaves the account to the
// job path, which builds on demand. It returns when every account has been
// tried or ctx ends.
func (c *XClients) Warm(ctx context.Context, cfg config.Config, accounts []XAccount) {
	for _, acct := range accounts {
		if ctx.Err() != nil {
			return
		}
		a := c.account(cfg, acct.ID, acct.Path, nil)
		if _, err := a.acquire(ctx, nil, false); err != nil {
			a.logf("x client warm-up failed for account %s: %s", a.id, xFailure(context.Background(), err))
			continue
		}
		a.logf("x client ready for account %s", a.id)
	}
}

// Stop ends every refresher and forgets every client. Jobs that hold a client
// keep it; later jobs build again.
func (c *XClients) Stop() {
	c.mu.Lock()
	accounts := c.accounts
	c.accounts = map[string]*xAccount{}
	c.mu.Unlock()
	for _, a := range accounts {
		a.close()
	}
}

func (c *XClients) gap() time.Duration {
	if c.minGap > 0 {
		return c.minGap
	}
	return xMinGap
}

// account returns the cache entry for path, creating it on first use. base,
// the timeout and the refresh interval are fixed by whoever creates the entry:
// in production always http.DefaultTransport and the node's configuration.
func (c *XClients) account(cfg config.Config, id, path string, base http.RoundTripper) *xAccount {
	c.mu.Lock()
	defer c.mu.Unlock()
	if a, ok := c.accounts[path]; ok {
		return a
	}
	if base == nil {
		base = http.DefaultTransport
	}
	if id == "" {
		id = "x_read"
	}
	a := &xAccount{clients: c, id: id, path: path, board: &xSwitchboard{base: base}, timeout: cfg.InferenceTimeout, refresh: cfg.XRefresh, stop: make(chan struct{})}
	if a.timeout <= 0 {
		a.timeout = xBuildTimeout
	}
	if a.refresh <= 0 {
		a.refresh = DefaultXRefresh
	}
	c.accounts[path] = a
	go a.refresher()
	return a
}

// xAccount is one account's warm client and the build that may be replacing it.
type xAccount struct {
	clients  *XClients
	id, path string
	board    *xSwitchboard
	timeout  time.Duration
	refresh  time.Duration

	mu      sync.Mutex
	current *xWarm
	build   *xBuild
	gen     uint64
	stop    chan struct{}
	stopped bool
}

// xWarm is one built client with what it was built from.
type xWarm struct {
	client *x.Client
	stamp  string            // SHA-256 of the session file it was built from
	ids    map[string]string // query ID overrides it was built with
	replay *xValidation      // its construction-time validation answers
	gen    uint64
}

// serves reports whether this client builds the requests a lease pins. An
// override it carries must match; an operation it has no override for is
// tried optimistically (x-go's pinned default is expected to match) unless
// strict, which a retry after a mismatch asks for.
func (w *xWarm) serves(ids map[string]string, strict bool) bool {
	for op, qid := range ids {
		have, ok := w.ids[op]
		if ok && have != qid || !ok && strict {
			return false
		}
	}
	return true
}

// xBuild is one construction in progress; done closes when warm or err is
// set. kind is "" for a build a job waits for, "refresh" for the timer's
// transaction-ID refresh and "rebuild" for the background rebuild after an
// authentication failure; the last two log their outcome, since no job sees it.
type xBuild struct {
	done chan struct{}
	kind string
	warm *xWarm
	err  error
}

// acquire returns a client for a job: the current one when it was built from
// the session file as it is now and serves ids, otherwise the one the build
// in progress produces (starting one when needed), waiting at most until ctx
// ends. Only a job that finds no usable client waits.
func (a *xAccount) acquire(ctx context.Context, ids map[string]string, strict bool) (*xWarm, error) {
	for {
		_, stamp, err := readXSession(a.path)
		if err != nil {
			return nil, errXSession
		}
		a.mu.Lock()
		cur := a.current
		if cur != nil && cur.stamp != stamp {
			// The file changed under the client: it would send stale cookies.
			a.current, cur = nil, nil
			a.logf("x session for account %s changed; rebuilding its client", a.id)
		}
		if cur != nil && cur.serves(ids, strict) {
			a.mu.Unlock()
			return cur, nil
		}
		b := a.build
		if b == nil {
			b = a.startBuild(cur, ids, "")
		}
		a.mu.Unlock()
		select {
		case <-b.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if b.err != nil {
			return nil, b.err
		}
		// A build that read another version of the file, or lacks an override
		// this lease needs, is not this job's client; the next round compares
		// it with the file as it is now and builds again if it must.
		if b.warm.stamp == stamp && b.warm.serves(ids, strict) {
			return b.warm, nil
		}
	}
}

// drop forgets warm after a proven read failed with an auth error and starts
// a validated rebuild in the background. Other jobs holding warm keep it.
func (a *xAccount) drop(warm *xWarm) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current != warm {
		return
	}
	a.current = nil
	a.logf("x client for account %s dropped after an authentication failure; rebuilding", a.id)
	if a.build == nil {
		a.startBuild(nil, warm.ids, "rebuild")
	}
}

// startBuild starts constructing a client with the overrides of prior plus
// ids. prior's validation answers are replayed when the session file is
// unchanged, so only the transaction-ID material is fetched. Caller holds a.mu.
func (a *xAccount) startBuild(prior *xWarm, ids map[string]string, kind string) *xBuild {
	merged := map[string]string{}
	if prior != nil {
		for k, v := range prior.ids {
			merged[k] = v
		}
	}
	for k, v := range ids {
		merged[k] = v
	}
	b := &xBuild{done: make(chan struct{}), kind: kind}
	a.build = b
	go a.run(b, prior, merged)
	return b
}

func (a *xAccount) run(b *xBuild, prior *xWarm, ids map[string]string) {
	defer close(b.done)
	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	go func() {
		select {
		case <-a.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	warm, err := a.construct(ctx, prior, ids)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.build = nil
	if err == nil && b.kind == "refresh" {
		switch {
		case a.current == nil:
			// Dropped while the refresh ran: its validation was replayed, not
			// repeated, so it must not stand in for the validated rebuild the
			// next job starts.
			err = errXDropped
		case warm.client.TransactionInitErr() != nil && a.current.client.TransactionInitErr() == nil:
			// A refresh that lost the transaction-ID material the current
			// client has would make gated reads 404; keep serving that one.
			err = fmt.Errorf("%w: transaction bootstrap failed: %v", x.ErrRequestFailed, warm.client.TransactionInitErr())
		}
	}
	if err != nil {
		b.err = err
		if b.kind == "rebuild" {
			a.logf("x client rebuild for account %s failed: %s", a.id, xFailure(context.Background(), err))
		}
		return
	}
	a.gen++
	warm.gen = a.gen
	if !a.stopped {
		a.current = warm
	}
	b.warm = warm
	if b.kind == "rebuild" {
		a.logf("x client rebuilt for account %s", a.id)
	}
}

// construct builds one x-go client. Its validation reads and bootstrap
// fetches are the only unproven requests the switchboard lets through, and
// only while this construction runs.
func (a *xAccount) construct(ctx context.Context, prior *xWarm, ids map[string]string) (*xWarm, error) {
	session, stamp, err := readXSession(a.path)
	if err != nil {
		return nil, errXSession
	}
	con := &xConstruction{}
	if prior != nil && prior.stamp == stamp && prior.replay != nil && prior.replay.complete() {
		con.replay = prior.replay
	}
	defer con.done.Store(true)
	hc := &http.Client{Transport: a.board, Timeout: a.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client, err := session.NewClient(withXConstruction(ctx, con), x.WithHTTPClient(hc), x.WithRetry(1, time.Millisecond), x.WithQueryIDs(ids), x.WithMinRequestGap(a.clients.gap()))
	if err != nil {
		return nil, err
	}
	replay := con.replay
	if replay == nil {
		replay = &con.captured
	}
	return &xWarm{client: client, stamp: stamp, ids: ids, replay: replay}, nil
}

// refreshNow rebuilds the current client's transaction-ID material while it
// keeps serving, then swaps. Nothing to do without a current client or while
// another build runs.
func (a *xAccount) refreshNow() error {
	a.mu.Lock()
	cur := a.current
	if cur == nil || a.build != nil {
		a.mu.Unlock()
		return nil
	}
	b := a.startBuild(cur, nil, "refresh")
	a.mu.Unlock()
	<-b.done
	if b.err == nil {
		a.logf("x client refreshed for account %s", a.id)
		return nil
	}
	a.mu.Lock()
	if errors.Is(b.err, errXSession) && a.current == cur {
		// The session file is gone or unusable: nothing to keep warm. A later
		// job finds no client and builds from whatever the file is by then.
		a.current = nil
	}
	kept := a.current != nil
	a.mu.Unlock()
	if kept {
		a.logf("x client refresh failed for account %s: %s; keeping the current client", a.id, xFailure(context.Background(), b.err))
	} else {
		a.logf("x client refresh for account %s discarded: %s; the next job rebuilds the client", a.id, xFailure(context.Background(), b.err))
	}
	return b.err
}

func (a *xAccount) refresher() {
	timer := time.NewTimer(a.refresh)
	defer timer.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-timer.C:
			_ = a.refreshNow()
			timer.Reset(a.refresh)
		}
	}
}

func (a *xAccount) close() {
	a.mu.Lock()
	if !a.stopped {
		a.stopped = true
		close(a.stop)
	}
	a.current = nil
	a.mu.Unlock()
}

// generation is the build count that produced the current client; tests use it.
func (a *xAccount) generation() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current == nil {
		return 0
	}
	return a.current.gen
}

func (a *xAccount) logf(format string, args ...any) {
	w := a.clients.log
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintf(w, format+"\n", args...)
}

// xSwitchboard is the one transport every client of an account is built on.
// It holds no per-job state: a request carries its job binding, or the
// construction it belongs to, in its context, and anything else is refused.
type xSwitchboard struct{ base http.RoundTripper }

func (s *xSwitchboard) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.User != nil {
		return nil, errUnprovenXCall
	}
	if b := xBindingFrom(r.Context()); b != nil {
		return b.roundTrip(r)
	}
	if con := xConstructionFrom(r.Context()); con != nil && !con.done.Load() {
		return con.roundTrip(s.base, r)
	}
	return nil, errUnprovenXCall
}

// xBinding is one job's view of the shared client: the exchanges its lease
// pins, in order, and the proof transport carrying its verifier token.
type xBinding struct {
	specs []xSpec
	proof http.RoundTripper
	mu    sync.Mutex
	next  int
	// stale is set when the first request used another query ID for the
	// pinned operation: the client lacks the lease's override. No proof was
	// spent, so the job rebuilds with the override and tries once more.
	stale bool
}

type xBindingKey struct{}

func withXBinding(ctx context.Context, b *xBinding) context.Context {
	return context.WithValue(ctx, xBindingKey{}, b)
}
func xBindingFrom(ctx context.Context) *xBinding {
	b, _ := ctx.Value(xBindingKey{}).(*xBinding)
	return b
}

func (b *xBinding) roundTrip(r *http.Request) (*http.Response, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if r.URL.Host != "x.com" || b.next >= len(b.specs) {
		return nil, errUnprovenXCall
	}
	s := b.specs[b.next]
	if r.URL.Path != "/i/api/graphql/"+s.QueryID+"/"+s.Operation || r.URL.Fragment != "" {
		if b.next == 0 && strings.HasPrefix(r.URL.Path, "/i/api/graphql/") && strings.HasSuffix(r.URL.Path, "/"+s.Operation) {
			b.stale = true
		}
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
	response, e := b.proof.RoundTrip(r)
	if e == nil {
		b.next++
	}
	return response, e
}

func (b *xBinding) proven() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.next
}

func (b *xBinding) wasStale() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stale
}

// xConstruction is one client construction. While it runs, and only then,
// the switchboard lets x-go's two session-validation reads (Viewer and
// UserByRestId, each once) and its transaction-ID bootstrap fetches through
// Base unproven. With replay set, the validation reads are answered from the
// account's earlier validated construction and never leave the node: a
// refresh fetches only the bootstrap pages. Once done is set nothing more
// passes, so a kept context cannot reopen the door.
type xConstruction struct {
	done     atomic.Bool
	replay   *xValidation
	mu       sync.Mutex
	served   map[string]bool
	captured xValidation
}

type xConstructionKey struct{}

func withXConstruction(ctx context.Context, c *xConstruction) context.Context {
	return context.WithValue(ctx, xConstructionKey{}, c)
}
func xConstructionFrom(ctx context.Context) *xConstruction {
	c, _ := ctx.Value(xConstructionKey{}).(*xConstruction)
	return c
}

func (c *xConstruction) roundTrip(base http.RoundTripper, r *http.Request) (*http.Response, error) {
	if r.URL.Host == "x.com" && strings.HasPrefix(r.URL.Path, "/i/api/") {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/i/api/graphql/"), "/")
		if len(parts) != 2 || parts[1] != "Viewer" && parts[1] != "UserByRestId" {
			return nil, errUnprovenXCall
		}
		op := parts[1]
		c.mu.Lock()
		if c.served == nil {
			c.served = map[string]bool{}
		}
		repeated := c.served[op]
		c.served[op] = true
		c.mu.Unlock()
		if repeated {
			return nil, errUnprovenXCall
		}
		if c.replay != nil {
			return c.replay.answer(op).response(r), nil
		}
		response, err := base.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		c.captured.capture(op, response)
		return response, nil
	}
	if r.URL.Host == "x.com" || r.URL.Host == "abs.twimg.com" {
		return base.RoundTrip(r)
	}
	return nil, errUnprovenXCall
}

// xValidation holds the answers X gave to one validated construction's two
// reads, replayed to later constructions of the same session so x-go's
// constructor passes without another network read. It holds the node's own
// account profile, nothing from any job.
type xValidation struct {
	mu           sync.Mutex
	viewer, user xAnswer
}

// xAnswerLimit bounds a recorded answer; UserByRestId profiles are a few KB.
const xAnswerLimit = 1 << 20

type xAnswer struct {
	status      int
	contentType string
	body        []byte
	complete    bool
}

func (v *xValidation) answer(op string) xAnswer {
	v.mu.Lock()
	defer v.mu.Unlock()
	if op == "Viewer" {
		return v.viewer
	}
	return v.user
}

func (v *xValidation) complete() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.viewer.complete && v.user.complete
}

// capture records the response as x-go reads it. The answer is complete only
// once x-go has read the whole body and it fit the limit.
func (v *xValidation) capture(op string, response *http.Response) {
	rec := &xRecorder{ReadCloser: response.Body, limit: xAnswerLimit}
	rec.onClose = func(body []byte, ok bool) {
		v.mu.Lock()
		defer v.mu.Unlock()
		a := xAnswer{status: response.StatusCode, contentType: response.Header.Get("Content-Type"), body: body, complete: ok}
		if op == "Viewer" {
			v.viewer = a
		} else {
			v.user = a
		}
	}
	response.Body = rec
}

func (a xAnswer) response(r *http.Request) *http.Response {
	h := http.Header{}
	if a.contentType != "" {
		h.Set("Content-Type", a.contentType)
	}
	return &http.Response{Status: fmt.Sprintf("%d %s", a.status, http.StatusText(a.status)), StatusCode: a.status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: h, Body: io.NopCloser(bytes.NewReader(a.body)), ContentLength: int64(len(a.body)), Request: r}
}

// xRecorder copies a body as it is read and reports it once closed.
type xRecorder struct {
	io.ReadCloser
	limit   int
	buf     bytes.Buffer
	eof     bool
	over    bool
	once    sync.Once
	onClose func(body []byte, ok bool)
}

func (r *xRecorder) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		if r.buf.Len()+n > r.limit {
			r.over = true
		} else {
			r.buf.Write(p[:n])
		}
	}
	if err == io.EOF {
		r.eof = true
	}
	return n, err
}

func (r *xRecorder) Close() error {
	err := r.ReadCloser.Close()
	r.once.Do(func() { r.onClose(r.buf.Bytes(), r.eof && !r.over) })
	return err
}
