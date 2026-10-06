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
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
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

// xRetryBase is the first delay before the background retries something that
// failed: a client build, or the transaction-ID bootstrap of an installed
// client. It doubles per failure up to the account's refresh interval.
const xRetryBase = time.Minute

// errXSession is a session file that cannot be used: missing, not private,
// or not a valid x-go session. It classifies as auth_required.
var errXSession = errors.New("local X session unavailable")

// errXDropped is a refresh whose client was dropped while it ran.
var errXDropped = errors.New("x client dropped during refresh")

// XClients keeps one warm x-go client per X account so a job does only its
// proven reads. The account key is the session file path, which is the
// natural key in both single-session and managed-accounts mode. A client is
// built lazily (or by Warm at node start) and reused until the session file's
// content changes, a proven read fails with an auth error, Retain evicts its
// account, or Stop; a timer also rebuilds its transaction-ID material in the
// background and asks X once whether the session still holds. Dropping or
// replacing a client is an atomic pointer swap: in-flight jobs keep the
// pointer they hold.
type XClients struct {
	// Base carries the unproven construction requests of accounts created
	// without a transport of their own; nil means http.DefaultTransport. Set
	// it before first use.
	Base http.RoundTripper

	mu       sync.Mutex
	accounts map[string]*xAccount
	// identities retain bounded pacing domains across alias removal and re-add.
	identities map[string]*xIdentityDomain
	// observe is told the outcome of each build that asked X to validate a
	// session; see Observe.
	observe         func(path, stamp, code string)
	observeIdentity func(path string, identity VerifiedXIdentity)
	// refreshAdmission checks pool availability before an autonomous refresh.
	refreshAdmission func(path string) bool
	// minGap overrides x-go's request pacing; zero means xMinGap. Tests only.
	minGap time.Duration
	// retry overrides xRetryBase. Tests only.
	retry time.Duration
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

// Observe sets the function told the outcome of every build that asked X to
// validate a session: the account's session path, validated content stamp and
// "" when the client was installed, otherwise the failure code (auth_required, x_rate_limited or
// x_request_failed). It is called with none of the cache's locks held, never
// for a build whose validation was only replayed, and never with an outcome
// for file content the session file no longer holds at dispatch. The observer
// must compare the stamp again while applying the outcome. Ensure also reports ""
// for an account that already has a validated client. Set it before the first
// build.
func (c *XClients) Observe(f func(path, stamp, code string)) {
	c.mu.Lock()
	c.observe = f
	c.mu.Unlock()
}

// RefreshAdmission sets the pool check for autonomous refreshes. It runs with
// no cache or account lock held. A denied refresh keeps the serving client and
// existing retry schedule; explicit job admission remains the pool's decision.
// A nil check allows refreshes for standalone users. Set before the first build.
func (c *XClients) RefreshAdmission(f func(path string) bool) {
	c.mu.Lock()
	c.refreshAdmission = f
	c.mu.Unlock()
}

func (c *XClients) canRefresh(path string) bool {
	c.mu.Lock()
	admit := c.refreshAdmission
	c.mu.Unlock()
	return admit == nil || admit(path)
}

// Warm builds the client of each account in turn, so the first job on it is
// fast, and prints one line per account. A failure leaves the account to
// Ensure, which retries in the background, and to the job path as the last
// resort. It returns when every account has been tried or ctx ends.
func (c *XClients) Warm(ctx context.Context, cfg config.Config, accounts []XAccount) {
	for _, acct := range accounts {
		if ctx.Err() != nil {
			return
		}
		a := c.account(cfg, acct.ID, acct.Path, nil)
		warm, err := a.acquire(ctx, nil, false)
		if err != nil {
			a.logf("x client warm-up failed for account %s: %s", a.id, xFailure(context.Background(), err))
			continue
		}
		// A client without transaction-ID material has already logged that its
		// bootstrap will be retried; it is not ready for gated reads.
		if warm.client.TransactionInitErr() == nil {
			a.logf("x client ready for account %s", a.id)
		}
	}
}

// Ensure keeps accounts warm after start without blocking: it starts a
// validated background build for the first account that has no current client
// built from its session file as it is now, has no build running and is past
// its failure backoff. One build per call keeps a node with many cold accounts
// from bursting at X; the caller's next tick takes the next account. A failed
// background build backs off from xRetryBase, doubling up to the refresh
// interval, and a session X refused is not tried again until its file changes.
// It reads session files only, unless a build is due. An account whose client
// was built from its session file as it is now is reported to the observer as
// validated, so an account whose rest ended or whose file was only rewritten
// does not look as if it were still warming.
func (c *XClients) Ensure(cfg config.Config, accounts []XAccount) {
	observe := c.observer()
	for started, i := false, 0; i < len(accounts); i++ {
		stamp, built := c.account(cfg, accounts[i].ID, accounts[i].Path, nil).ensure(!started)
		started = started || built
		if stamp != "" {
			if identity, ok := c.VerifiedIdentity(accounts[i].Path); ok {
				c.reportIdentity(accounts[i].Path, identity)
			}
			if observe != nil {
				observe(accounts[i].Path, stamp, "")
			}
		}
	}
}

// Retain closes and forgets every account whose session path is not in keep,
// so an account removed from the node stops being refreshed against X.
func (c *XClients) Retain(keep map[string]bool) {
	c.mu.Lock()
	var gone []*xAccount
	for path, a := range c.accounts {
		if !keep[path] {
			delete(c.accounts, path)
			gone = append(gone, a)
		}
	}
	c.mu.Unlock()
	for _, a := range gone {
		a.close()
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

func (c *XClients) retryBase() time.Duration {
	if c.retry > 0 {
		return c.retry
	}
	return xRetryBase
}

func (c *XClients) observer() func(path, stamp, code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observe
}

// account returns the cache entry for path, creating it on first use. base,
// the timeout and the refresh interval are fixed by whoever creates the entry:
// in production always c.Base and the node's configuration.
func (c *XClients) account(cfg config.Config, id, path string, base http.RoundTripper) *xAccount {
	c.mu.Lock()
	defer c.mu.Unlock()
	if a, ok := c.accounts[path]; ok {
		return a
	}
	if base == nil {
		base = c.Base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	if id == "" {
		id = "x_read"
	}
	a := &xAccount{clients: c, id: id, path: path, board: &xSwitchboard{base: base}, timeout: cfg.InferenceTimeout, refresh: cfg.XRefresh, stop: make(chan struct{}), kick: make(chan struct{}, 1)}
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
	// acquiring pins identity domains between job admission and obtaining the
	// warm client's reference, including concurrent removal from the cache.
	acquiring int
	// kick tells the refresher that a client without transaction-ID material
	// was installed, so it retries the bootstrap soon.
	kick chan struct{}
	// ids are the overrides of the last installed client, kept across a drop
	// so a background build serves the same leases.
	ids map[string]string
	// What the background remembers of the last failed build, for the session
	// file content (failed is its stamp) that build read: whether X refused
	// that session, and when the next background build may start.
	failed  string
	refused bool
	backoff time.Duration
	retryAt time.Time
}

// xWarm is one built client with what it was built from.
type xWarm struct {
	client   *x.Client
	identity VerifiedXIdentity
	stamp    string            // SHA-256 of the session file it was built from
	ids      map[string]string // query ID overrides it was built with
	replay   *xValidation      // its construction-time validation answers
	gen      uint64
	// lastReq is when this client last sent a request, in Unix nanoseconds:
	// the end of its construction, then each read handed to a proof transport.
	lastReq atomic.Int64
}

// pacingWait is the least time x-go would hold this client's next request
// back because of the rate-limit state X last reported, and the time until
// that window resets. With quota left it mirrors x-go's adaptive gap, which
// spreads what is left over the window; a gap no wider than the fixed request
// gap is ordinary pacing and counts as no wait. With no quota left the wait is
// the whole time to the reset: x-go measures its hold from the last request, so
// it lets a read through once half the window has passed, and X would only
// answer that read with a rate limit.
func (w *xWarm) pacingWait(minGap time.Duration) (wait, reset time.Duration) {
	rs := w.client.RateLimit()
	reset = rs.ResetIn()
	if reset <= 0 {
		return 0, 0
	}
	if rs.Remaining <= 0 {
		return reset, reset
	}
	gap := reset / time.Duration(max(int64(float64(rs.Remaining)*0.9), 1))
	if gap <= minGap {
		return 0, reset
	}
	return max(time.Until(w.client.LastRequestAt().Add(gap)), 0), reset
}

// exhausted is the time until X's quota window resets when X last reported no
// request left in it, and zero otherwise.
func (w *xWarm) exhausted() time.Duration {
	if rs := w.client.RateLimit(); rs.Remaining <= 0 {
		return rs.ResetIn()
	}
	return 0
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
// set. kind is "" for a build a job (or Warm) waits for, "rebuild" for the
// background rebuild after an authentication failure, "warm" for Ensure's
// background build, "refresh" for the timer's refresh, which lets the Viewer
// read go to X, and "replay" for a background replacement that only fetches
// the transaction-ID material again. The background kinds log their outcome,
// since no job sees it.
type xBuild struct {
	done chan struct{}
	kind string
	warm *xWarm
	err  error
}

// xSwap reports whether kind replaces a serving client in the background. Such
// a build's failure belongs to nobody: the current client keeps serving.
func xSwap(kind string) bool { return kind == "refresh" || kind == "replay" }

// xRefused reports whether a build failed because X refused the session
// itself. A rate limit or a transport failure is not a refusal, and neither is
// a not-found answer, which is what a rotated query ID looks like.
func xRefused(e error) bool {
	return xAuthFailure(e) && !errors.Is(e, x.ErrRateLimited) && !errors.Is(e, x.ErrNotFound)
}

// acquire returns a client for a job: the current one when it was built from
// the session file as it is now and serves ids, otherwise the one the build
// in progress produces (starting one when needed), waiting at most until ctx
// ends. Only a job that finds no usable client waits. The failure of a
// background swap the job happened to wait on is not the job's: it starts a
// build of its own instead, at most twice.
func (a *xAccount) acquire(ctx context.Context, ids map[string]string, strict bool) (*xWarm, error) {
	end := diagnostics.Start(ctx, "client_acquire", 0)
	outcome := "error"
	defer func() { end(outcome) }()
	waited := false
	for inherited := 0; ; {
		_, stamp, err := readXSession(a.path)
		if err != nil {
			return nil, errXSession
		}
		a.mu.Lock()
		if a.stopped {
			a.mu.Unlock()
			return nil, errXDropped
		}
		cur := a.current
		rotated := cur != nil && cur.stamp != stamp
		if cur != nil && cur.stamp != stamp {
			// The file changed under the client: it would send stale cookies.
			a.current, cur = nil, nil
			a.logf("x session for account %s changed; rebuilding its client", a.id)
		}
		if cur != nil && cur.serves(ids, strict) {
			a.mu.Unlock()
			outcome = "cache_hit"
			if waited {
				outcome = "cache_miss"
			}
			return cur, nil
		}
		b := a.build
		if b == nil {
			b = a.startBuild(cur, ids, "")
		}
		a.mu.Unlock()
		waited = true
		var endRebuild func(string)
		if strict || cur != nil || rotated || b.kind == "rebuild" || b.kind == "replay" {
			endRebuild = diagnostics.Start(ctx, "client_rebuild", 0)
		}
		select {
		case <-b.done:
			if endRebuild != nil {
				endRebuild(diagnosticOutcome(ctx, b.err))
			}
		case <-ctx.Done():
			outcome = "cancelled"
			if endRebuild != nil {
				endRebuild(outcome)
			}
			return nil, ctx.Err()
		}
		// The file can rotate while validation or bootstrap is in progress.
		// Never return a client for the content seen before that wait.
		if _, now, err := readXSession(a.path); err != nil {
			return nil, errXSession
		} else if now != stamp {
			continue
		}
		a.mu.Lock()
		stopped := a.stopped
		a.mu.Unlock()
		if stopped {
			return nil, errXDropped
		}
		if b.err != nil {
			if xSwap(b.kind) && inherited < 2 {
				inherited++
				continue
			}
			return nil, b.err
		}
		// A build that read another version of the file, or lacks an override
		// this lease needs, is not this job's client; the next round compares
		// it with the file as it is now and builds again if it must.
		if b.warm.stamp == stamp && b.warm.serves(ids, strict) {
			outcome = "cache_miss"
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

// replace swaps warm for a client with fresh pacing state, in the background
// and without asking X anything but the bootstrap pages. A job that ended
// while x-go held its request back leaves the slot it reserved on the shared
// client; later jobs would wait behind it.
func (a *xAccount) replace(warm *xWarm) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current != warm || a.build != nil || a.stopped {
		return
	}
	a.logf("x client for account %s is being replaced after a job ended waiting for its request slot", a.id)
	a.startBuild(warm, nil, "replay")
}

// ensure returns the validated stamp when the account has a client built from
// its session file as it is now. When it has none, one is due and start allows it, ensure starts
// a validated background build and reports that as built.
func (a *xAccount) ensure(start bool) (validatedStamp string, built bool) {
	_, stamp, err := readXSession(a.path)
	if err != nil {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopped {
		return "", false
	}
	if a.current != nil && a.current.stamp == stamp {
		return stamp, false
	}
	if !start || a.build != nil {
		return "", false
	}
	if a.failed != stamp {
		// What an earlier build learned was about other file content.
		a.failed, a.refused, a.backoff, a.retryAt = "", false, 0, time.Time{}
	}
	if a.refused || time.Now().Before(a.retryAt) {
		return "", false
	}
	if a.current != nil {
		a.logf("x session for account %s changed; rebuilding its client", a.id)
	}
	a.startBuild(a.current, a.ids, "warm")
	return "", true
}

// noteFailure backs the background off after a failed build of the session
// file content stamp names. Caller holds a.mu.
func (a *xAccount) noteFailure(stamp string, err error) {
	if a.failed != stamp || a.backoff <= 0 {
		a.backoff = a.clients.retryBase()
	} else {
		a.backoff *= 2
	}
	a.backoff = min(a.backoff, a.refresh)
	a.failed = stamp
	wait := a.backoff
	// X said when it will answer again; asking sooner only extends the limit.
	var limited *x.RateLimitError
	if errors.As(err, &limited) && limited.Wait > wait {
		wait = limited.Wait
	}
	a.retryAt = time.Now().Add(wait)
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
	warm, stamp, asked, err := a.construct(ctx, prior, ids, b.kind)
	a.mu.Lock()
	a.build = nil
	if err == nil && xSwap(b.kind) {
		switch {
		case a.current == nil:
			// Dropped while the swap ran: it must not stand in for the validated
			// rebuild the next job, or Ensure, starts.
			err = errXDropped
		case warm.client.TransactionInitErr() != nil && a.current.client.TransactionInitErr() == nil:
			// A swap that lost the transaction-ID material the current client
			// has would make gated reads 404; keep serving that one.
			err = fmt.Errorf("%w: transaction bootstrap failed: %v", x.ErrRequestFailed, warm.client.TransactionInitErr())
		}
	}
	// Stop and eviction cancel a build; its error says nothing about X.
	report := asked && !a.stopped && !errors.Is(err, errXDropped)
	code := ""
	if err != nil {
		b.err = err
		code = xFailure(context.Background(), err)
		if code == "auth_required" && asked && !xRefused(err) {
			// X answered the validation, but not with a refusal (a not-found is
			// what a rotated query ID looks like). The account must not be parked
			// until its session file changes, or the retry below could never run.
			code = "x_request_failed"
		}
		switch {
		case a.stopped || errors.Is(err, errXDropped):
		case xRefused(err):
			// X refused this session: nothing asks again until the file changes.
			// That includes the refresher, so a client built from other file
			// content goes too; it would send cookies the file no longer holds.
			a.failed, a.refused = stamp, true
			if a.current != nil && (a.current.stamp != stamp || b.kind == "refresh" && a.current == prior) {
				a.current = nil
			}
		case b.kind == "refresh":
			// X did not refuse the session and the current client keeps serving:
			// a refresh that could not reach X is no news about the account.
			report = false
		case !xSwap(b.kind):
			a.noteFailure(stamp, err)
		}
		switch b.kind {
		case "rebuild":
			a.logf("x client rebuild for account %s failed: %s", a.id, code)
		case "warm":
			a.logf("x client warm-up failed for account %s: %s", a.id, code)
		}
	} else {
		a.gen++
		warm.gen = a.gen
		if !a.stopped {
			a.current = warm
		}
		b.warm = warm
		a.ids = warm.ids
		a.failed, a.refused, a.backoff, a.retryAt = "", false, 0, time.Time{}
		degraded := warm.client.TransactionInitErr() != nil
		if degraded && !xSwap(b.kind) {
			// Ungated reads work on this client, so it serves; the refresher
			// owns the retry (a swap is already one of its retries).
			a.logf("x client for account %s has no transaction-ID material; the bootstrap will be retried", a.id)
			select {
			case a.kick <- struct{}{}:
			default:
			}
		}
		switch {
		case b.kind == "rebuild":
			a.logf("x client rebuilt for account %s", a.id)
		case b.kind == "warm" && !degraded:
			a.logf("x client ready for account %s", a.id)
		}
	}
	identityReport := err == nil && !a.stopped
	a.syncIdentityDomains()
	a.mu.Unlock()
	if identityReport {
		a.clients.reportIdentity(a.path, warm.identity)
	}
	observe := a.clients.observer()
	if !report || observe == nil {
		return
	}
	// The outcome is about the file content this build read. When the session
	// file was replaced while X answered, it says nothing about the new one.
	if _, now, e := readXSession(a.path); e != nil || now != stamp {
		return
	}
	// Reported before done closes, so whoever waited on this build finds the
	// outcome already applied.
	observe(a.path, stamp, code)
}

// construct builds one x-go client. Its validation reads and bootstrap
// fetches are the only unproven requests the switchboard lets through, and
// only while this construction runs. It also returns the stamp of the session
// file it read and whether it asked X to validate that session.
func (a *xAccount) construct(ctx context.Context, prior *xWarm, ids map[string]string, kind string) (*xWarm, string, bool, error) {
	session, stamp, err := readXSession(a.path)
	if err != nil {
		return nil, "", false, errXSession
	}
	// Only the timer's refresh repeats the Viewer read: once per interval is
	// the light check that notices a session X revoked while the node was idle.
	con := &xConstruction{revalidate: kind == "refresh"}
	if prior != nil && prior.stamp == stamp && prior.replay != nil && prior.replay.complete() {
		con.replay = prior.replay
	}
	defer con.done.Store(true)
	hc := &http.Client{Transport: a.board, Timeout: a.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	// Each shared identity reserves up to a quarter of the minimum gap as extra
	// delay (250 ms in production), including requests after an idle interval.
	gap := a.clients.gap()
	client, err := session.NewClient(withXConstruction(ctx, con), x.WithHTTPClient(hc), x.WithRetry(1, time.Millisecond), x.WithQueryIDs(ids), x.WithMinRequestGap(gap), x.WithRequestJitter(gap/4), x.WithIdentityPacing(a.pacingFor))
	if err != nil {
		return nil, stamp, con.asked.Load(), err
	}
	identity, err := verifiedXClient(ctx, client)
	if err != nil {
		return nil, stamp, con.asked.Load(), err
	}
	identity.Stamp = stamp
	replay := con.replay
	if replay == nil {
		replay = &con.captured
	}
	warm := &xWarm{client: client, identity: identity, stamp: stamp, ids: ids, replay: replay}
	warm.lastReq.Store(time.Now().UnixNano())
	return warm, stamp, con.asked.Load(), nil
}

// refreshNow is the timer's refresh: it rebuilds the current client's
// transaction-ID material and asks X once whether the session still holds,
// while the current client keeps serving, then swaps.
func (a *xAccount) refreshNow() error { return a.swap("refresh") }

// swap builds a replacement of the current client in the background kind
// names and waits for it. Nothing to do without a current client or while
// another build runs.
func (a *xAccount) swap(kind string) error {
	a.mu.Lock()
	cur := a.current
	if cur == nil || a.build != nil {
		a.mu.Unlock()
		return nil
	}
	b := a.startBuild(cur, nil, kind)
	a.mu.Unlock()
	<-b.done
	if b.err == nil {
		if b.warm.client.TransactionInitErr() != nil {
			a.logf("x client for account %s still has no transaction-ID material; the bootstrap will be retried", a.id)
		} else {
			a.logf("x client refreshed for account %s", a.id)
		}
		return nil
	}
	a.mu.Lock()
	if errors.Is(b.err, errXSession) && a.current == cur {
		// The session file is gone or unusable: nothing to keep warm. Ensure, or
		// a later job, builds from whatever the file is by then.
		a.current = nil
	}
	kept := a.current != nil
	a.mu.Unlock()
	switch {
	case xRefused(b.err):
		a.logf("x session for account %s was refused by X; its client is dropped until the session file changes", a.id)
	case kept:
		a.logf("x client refresh failed for account %s: %s; keeping the current client", a.id, xFailure(context.Background(), b.err))
	default:
		a.logf("x client refresh for account %s discarded: %s; the client is rebuilt in the background or by the next job", a.id, xFailure(context.Background(), b.err))
	}
	return b.err
}

// degraded reports whether the current client lacks transaction-ID material.
func (a *xAccount) degraded() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current != nil && a.current.client.TransactionInitErr() != nil
}

// refresher refreshes the client every refresh interval. While the current
// client has no transaction-ID material it retries the bootstrap sooner, from
// xRetryBase and doubling up to the interval; those retries replay the
// validation, so each costs only the two bootstrap fetches.
func (a *xAccount) refresher() {
	wait, next := a.refresh, a.clients.retryBase()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-a.kick:
			next = a.clients.retryBase()
		case <-timer.C:
			if !a.clients.canRefresh(a.path) {
				timer.Reset(wait)
				continue
			}
			kind := "refresh"
			if wait < a.refresh && a.degraded() {
				kind = "replay"
			}
			_ = a.swap(kind)
			if !a.degraded() {
				next = a.clients.retryBase()
				wait = a.refresh
				timer.Reset(wait)
				continue
			}
		}
		wait = min(next, a.refresh)
		next = min(next*2, a.refresh)
		timer.Reset(wait)
	}
}

func (a *xAccount) close() {
	a.mu.Lock()
	if !a.stopped {
		a.stopped = true
		close(a.stop)
	}
	a.current = nil
	if a.acquiring == 0 {
		a.detachIdentityDomains()
	}
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
	// warm is the client the job reads on; it learns when a read was sent.
	warm *xWarm
	mu   sync.Mutex
	next int
	// sent counts the reads handed to the proof transport, proven or not.
	sent int
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
	exchange := b.next + 1
	endBinding := diagnostics.Start(r.Context(), "binding_check", exchange)
	bound := false
	defer func() {
		if !bound {
			endBinding("error")
		}
	}()
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
	bound = true
	endBinding("success")
	b.sent++
	if b.warm != nil {
		b.warm.lastReq.Store(time.Now().UnixNano())
	}
	r = r.WithContext(withXExchange(r.Context(), exchange))
	response, e := b.proof.RoundTrip(r)
	if e == nil {
		b.next++
	}
	return response, e
}

// idle reports whether every read the job handed to the proof transport was
// proven. A job that failed while idle never had its failing read sent: with
// an ended context, x-go was still holding that read back for pacing.
func (b *xBinding) idle() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sent == b.next
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
// account's earlier validated construction and never leave the node, except
// that revalidate lets the Viewer read go to X: the timer's refresh asks X
// once whether the session still holds. Once done is set nothing more
// passes, so a kept context cannot reopen the door.
type xConstruction struct {
	done       atomic.Bool
	replay     *xValidation
	revalidate bool
	// asked is set once a validation read was sent to X rather than replayed.
	asked    atomic.Bool
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
		if c.replay != nil && !(c.revalidate && op == "Viewer") {
			return c.replay.answer(op).response(r), nil
		}
		c.asked.Store(true)
		response, err := base.RoundTrip(r)
		if err != nil {
			return nil, err
		}
		if c.replay == nil {
			c.captured.capture(op, response)
		}
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
