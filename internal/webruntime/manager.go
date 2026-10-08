package webruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

const (
	defaultIdle     = 120 * time.Second
	prewarmIdle     = 30 * time.Second
	recycleAfter    = 50
	sampleEvery     = 2 * time.Second
	sampleBusy      = 500 * time.Millisecond
	verifyEvery     = 6 * time.Hour
	readyTimeout    = 20 * time.Second
	readyPoll       = 50 * time.Millisecond
	stopGrace       = 7 * time.Second
	failureWindow   = 10 * time.Minute
	failureLimit    = 3
	helperFailedFor = 10 * time.Minute
	backoffStart    = 60 * time.Second
	backoffMax      = time.Hour
	minPhysical     = 8 << 30
	htmlCap         = 10485760
	maxResultBytes  = 80 << 20
	gib             = 1 << 30
)

// Config wires the browser tier. main injects the core egress guard and the
// operator's settings; everything else has a default.
type Config struct {
	// ResourceDir holds web-runtime.json, the archive and x-login-runtime/.
	ResourceDir string
	StateDir    string
	// XLoginNode is the Node the Playwright driver runs on; default
	// <ResourceDir>/x-login-runtime/node[.exe].
	XLoginNode string
	Guard      EgressGuard
	// Resolver resolves page-chosen names; default net.DefaultResolver.
	Resolver func(ctx context.Context, host string) ([]netip.Addr, error)
	// UpstreamProxy is SCARLETT_WEB_EGRESS_PROXY; the egress proxy then
	// reaches every checked address through it with CONNECT <ip>:<port>.
	UpstreamProxy *url.URL
	// UpstreamAuthorization is its Proxy-Authorization value, as config.WebProxy
	// holds it; userinfo in UpstreamProxy is used when this is empty.
	UpstreamAuthorization string
	// Capacity is browser pages at once, 1–4; 0 picks 1 below 16 GiB of
	// physical memory and 2 otherwise.
	Capacity int
	// IdleTimeout stops an idle helper; 0 means 120 s.
	IdleTimeout time.Duration
	// Solvers is the operator's captcha-solver accounts, or nil.
	Solvers *Solvers
	// Logf receives state transitions and closed reasons only.
	Logf func(format string, args ...any)
}

func (c Config) withDefaults() Config {
	if c.XLoginNode == "" && c.ResourceDir != "" {
		c.XLoginNode = filepath.Join(c.ResourceDir, "x-login-runtime", nodeName())
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = defaultIdle
	}
	if c.Resolver == nil {
		c.Resolver = defaultResolver
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	return c
}

// Thresholds are the helper tree's recycle and kill sizes for a capacity:
// recycle above 1.25 GiB + 0.75 GiB × capacity, kill 1.5 GiB above that.
func Thresholds(capacity int) (recycle, kill uint64) {
	recycle = 5*gib/4 + uint64(capacity)*3*gib/4
	return recycle, recycle + 3*gib/2
}

// FetchRequest is one page render, as the helper takes it.
type FetchRequest struct {
	URL            string `json:"url"`
	Wait           string `json:"wait"`
	WaitMS         int    `json:"wait_ms"`
	WaitSelector   string `json:"wait_selector"`
	TimeoutMS      int    `json:"timeout_ms"`
	BlockResources bool   `json:"block_resources"`
	SolveChallenge bool   `json:"solve_challenge"`
}

func (r FetchRequest) String() string   { return "web browser fetch [redacted]" }
func (r FetchRequest) GoString() string { return r.String() }

func (r FetchRequest) validate() error {
	invalid := errors.New("web browser fetch request invalid")
	if len(r.URL) > 2048 || !(strings.HasPrefix(r.URL, "https://") || strings.HasPrefix(r.URL, "http://")) || strings.ContainsFunc(r.URL, func(c rune) bool { return c <= ' ' || c >= 0x7f }) {
		return invalid
	}
	if r.Wait != "load" && r.Wait != "networkidle" || r.WaitMS < 0 || r.WaitMS > 15000 || r.TimeoutMS < 5000 || r.TimeoutMS > 45000 || len(r.WaitSelector) > 256 {
		return invalid
	}
	for i := 0; i < len(r.WaitSelector); i++ {
		if r.WaitSelector[i] < 0x20 || r.WaitSelector[i] > 0x7e {
			return invalid
		}
	}
	return nil
}

// helperFetch is POST /v1/fetch: the request plus whether this fetch may use
// the operator's solver, which the Manager decides from today's spend.
type helperFetch struct {
	FetchRequest
	Solver bool `json:"solver"`
}

// FetchResult is the helper's answer. It holds page content and cookie
// values for the worker only; it is never logged.
type FetchResult struct {
	Outcome        string      `json:"outcome"`
	Error          string      `json:"error"`
	FinalURL       string      `json:"final_url"`
	StatusCode     int         `json:"status_code"`
	Headers        [][2]string `json:"headers"`
	SetCookieNames []string    `json:"set_cookie_names"`
	ContentType    string      `json:"content_type"`
	HTML           string      `json:"html"`
	HTMLTruncated  bool        `json:"html_truncated"`
	Cookies        []Cookie    `json:"cookies"`
	Challenge      string      `json:"challenge"`
	Redirects      []Redirect  `json:"redirects"`
	StartedAtMS    int64       `json:"started_at_ms"`
	Timings        Timings     `json:"timings"`
	// Solver is "used" when the operator's captcha solver cleared the page,
	// "needed" when the page stopped at a captcha that takes one, else "".
	Solver string `json:"solver"`
	// SolverCostMicroUSD is the providers' estimated charge for this fetch.
	SolverCostMicroUSD int64 `json:"solver_cost_micro_usd"`
}

func (FetchResult) String() string   { return "web browser result [redacted]" }
func (FetchResult) GoString() string { return "webruntime.FetchResult{}" }

type Cookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	Secure   bool    `json:"secure"`
	HTTPOnly bool    `json:"http_only"`
}

func (Cookie) String() string   { return "cookie [redacted]" }
func (Cookie) GoString() string { return "webruntime.Cookie{}" }

type Redirect struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

type Timings struct {
	ContextMS   int64 `json:"context_ms"`
	NavigateMS  int64 `json:"navigate_ms"`
	SettleMS    int64 `json:"settle_ms"`
	ChallengeMS int64 `json:"challenge_ms"`
	TotalMS     int64 `json:"total_ms"`
}

func (r *FetchResult) validate() error {
	invalid := fmt.Errorf("%w: result invalid", ErrHelper)
	switch r.Outcome {
	case "ok", "timeout", "failed":
	default:
		return invalid
	}
	switch r.Error {
	case "", "navigation_failed", "tls", "timeout", "crashed", "too_large":
	default:
		return invalid
	}
	switch r.Challenge {
	case "none", "solved", "unsolved":
	default:
		return invalid
	}
	switch r.Solver {
	case "", "used", "needed":
	default:
		return invalid
	}
	if r.SolverCostMicroUSD < 0 || r.SolverCostMicroUSD > maxFetchMicroUSD {
		return invalid
	}
	if r.Outcome == "ok" && (r.StatusCode < 100 || r.StatusCode > 999) || len(r.HTML) > htmlCap || !utf8.ValidString(r.HTML) ||
		len(r.Headers) > 128 || len(r.SetCookieNames) > 50 || len(r.Redirects) > 20 || len(r.Cookies) > 1000 || len(r.FinalURL) > 8192 {
		return invalid
	}
	return nil
}

// Health is the heartbeat's browser entry (contract C.8).
type Health struct {
	State    string // "ready" or "unavailable"
	Reason   Reason // set iff unavailable
	Capacity int
	InFlight int
	Version  string // iff ready
	// Solvers are the operator's captcha-solver providers this browser may
	// use now: configured, and today's spend under its cap. Names only.
	Solvers []string
}

var (
	// ErrHelper means the render itself failed: navigation, TLS, crash,
	// timeout, memory kill or a broken helper exchange (web_browser_failed).
	ErrHelper = errors.New("web browser helper failed")
	// ErrBusy means every page slot is in use.
	ErrBusy = fmt.Errorf("%w: every browser page slot is in use", ErrUnavailable)
)

// deps are the Manager's seams for tests.
type deps struct {
	now           func() time.Time
	physical      func() (uint64, error)
	ensure        func(Config) (Root, error)
	verify        func(Root) error
	ensureBrowser func(context.Context, Config, BrowserPin) (Browser, error)
	verifyBrowser func(string, Inventory) error
	quick         func(Root, Browser) error
	command       func(Root) (string, []string)
	sample        func(*proc) (uint64, []procInfo, error)
	pressure      func() int
	unregister    func(app string)
	tick          time.Duration
	busyTick      time.Duration
	readyTimeout  time.Duration
	stopGrace     time.Duration
}

func defaultDeps() deps {
	return deps{
		now: time.Now, physical: physicalMemory, ensure: Ensure, verify: Verify, ensureBrowser: EnsureBrowser, verifyBrowser: VerifyBrowser,
		quick: func(r Root, b Browser) error {
			if err := verifyQuick(r); err != nil {
				return err
			}
			return verifyBrowserQuick(b.Dir, r.Browser.Inventory)
		},
		command: func(r Root) (string, []string) {
			return r.Python(), []string{"-I", "-B", "-X", "utf8", "-m", "scarlett_web_helper"}
		},
		sample:     sampleProc,
		pressure:   memoryPressure,
		unregister: unregisterApp,
		tick:       sampleEvery, busyTick: sampleBusy, readyTimeout: readyTimeout, stopGrace: stopGrace,
	}
}

func sampleProc(p *proc) (uint64, []procInfo, error) {
	bytes, err := p.treeBytes()
	return bytes, p.snapshot(), err
}

// Manager owns the browser tier's lifecycle:
// preparing → idle → starting → warm → draining → idle, or unavailable.
type Manager struct {
	cfg   Config
	d     deps
	stats ProxyStats

	mu          sync.Mutex
	changed     chan struct{}
	kick        chan struct{}
	prepared    bool
	reason      Reason
	capacity    int
	inFlight    int
	root        Root
	browser     Browser
	helper      *helper
	starting    bool
	stopping    chan struct{}
	failures    []time.Time
	failedUntil time.Time
	lastUse     time.Time
	nextVerify  time.Time
	verifying   bool
	logged      string
	closed      bool
	spend       spendRecord
	spendLoaded bool
}

type helper struct {
	p        *proc
	stdin    io.WriteCloser
	done     chan struct{}
	endpoint string
	bearer   string
	client   *http.Client
	proxy    *egressProxy
	deny     *denyListener
	stderr   *markerWriter
	lock     *os.File
	inFlight int
	served   int
	draining bool
	prewarm  bool
	tree     []procInfo
}

func (h *helper) exited() bool {
	select {
	case <-h.done:
		return true
	default:
		return false
	}
}

// New returns a Manager. Run prepares it in the background and supervises it.
func New(cfg Config) *Manager {
	return &Manager{cfg: cfg.withDefaults(), d: defaultDeps(), changed: make(chan struct{}), kick: make(chan struct{}, 1),
		reason: ReasonBrowserDownloading}
}

// UserAgent is the browser's (and the proven re-fetch's) User-Agent.
func (m *Manager) UserAgent() string { return UserAgent(runtime.GOOS, PinnedMajor) }

// Stats are the proxy counters.
func (m *Manager) Stats() *ProxyStats { return &m.stats }

func (m *Manager) notify() {
	close(m.changed)
	m.changed = make(chan struct{})
	m.logState()
}

func (m *Manager) wake() {
	select {
	case m.kick <- struct{}{}:
	default:
	}
}

// logState logs a transition once: a state name and closed reason only.
func (m *Manager) logState() {
	name := "idle"
	h := m.healthLocked()
	switch {
	case m.closed:
		name = "stopped"
	case h.State != "ready":
		name = "unavailable/" + string(h.Reason)
		if !m.prepared && m.reason == ReasonBrowserDownloading {
			name = "preparing"
		}
	case m.starting:
		name = "starting"
	case m.helper != nil && m.helper.draining:
		name = "draining"
	case m.helper != nil:
		name = "warm"
	}
	if name != m.logged {
		m.logged = name
		m.cfg.Logf("web browser: %s", name)
	}
}

// Health reports the heartbeat's browser entry.
func (m *Manager) Health() Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthLocked()
}

func (m *Manager) healthLocked() Health {
	switch {
	case m.closed:
		return Health{State: "unavailable", Reason: ReasonHelperFailed}
	case !m.prepared:
		return Health{State: "unavailable", Reason: m.reason}
	case m.d.now().Before(m.failedUntil):
		return Health{State: "unavailable", Reason: ReasonHelperFailed}
	}
	h := Health{State: "ready", Capacity: m.capacity, InFlight: m.inFlight, Version: m.browser.Version}
	if m.solverAllowedLocked() {
		h.Solvers = m.cfg.Solvers.Providers()
	}
	return h
}

// Fetch renders one page. Errors wrapping ErrUnavailable mean the tier could
// not take the job (web_browser_unavailable); ErrHelper means the render or
// the helper failed (web_browser_failed). A result whose Outcome is not "ok"
// is returned without an error.
func (m *Manager) Fetch(ctx context.Context, req FetchRequest) (FetchResult, error) {
	if err := req.validate(); err != nil {
		return FetchResult{}, err
	}
	m.mu.Lock()
	if h := m.healthLocked(); h.State != "ready" {
		m.mu.Unlock()
		return FetchResult{}, fail(h.Reason, "browser tier not ready")
	}
	if m.inFlight >= m.capacity {
		m.mu.Unlock()
		return FetchResult{}, ErrBusy
	}
	m.inFlight++
	m.mu.Unlock()
	m.wake() // sample at the busy rate while the page renders
	defer func() {
		m.mu.Lock()
		m.inFlight--
		m.lastUse = m.d.now()
		m.notify()
		m.mu.Unlock()
	}()
	h, err := m.acquire(ctx, false)
	if err != nil {
		return FetchResult{}, err
	}
	m.mu.Lock()
	solver := m.solverAllowedLocked()
	m.mu.Unlock()
	res, err := m.call(ctx, h, helperFetch{FetchRequest: req, Solver: solver})
	if err == nil {
		m.recordSpend(res.SolverCostMicroUSD)
	}
	m.mu.Lock()
	h.inFlight--
	h.served++
	if err != nil || h.served >= recycleAfter {
		// A Go-side deadline or broken exchange may leave a wedged renderer
		// holding a page slot; restart once the others finish.
		h.draining = true
	}
	m.notify()
	m.mu.Unlock()
	m.wake()
	return res, err
}

// Prewarm starts the helper ahead of a likely browser job. A start that only
// pre-warmed stops after 30 s idle.
func (m *Manager) Prewarm() {
	m.mu.Lock()
	ready := m.healthLocked().State == "ready" && m.helper == nil && !m.starting && m.stopping == nil
	m.mu.Unlock()
	if !ready {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), m.d.readyTimeout+5*time.Second)
		defer cancel()
		_, _ = m.acquire(ctx, true)
	}()
}

// acquire returns a live, non-draining helper, starting one when needed. A
// fetch counts itself in the helper; a pre-warm does not.
func (m *Manager) acquire(ctx context.Context, prewarm bool) (*helper, error) {
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, fail(ReasonHelperFailed, "manager closed")
		}
		if h := m.healthLocked(); h.State != "ready" {
			m.mu.Unlock()
			return nil, fail(h.Reason, "browser tier not ready")
		}
		h := m.helper
		switch {
		case h != nil && !h.draining && !h.exited():
			if !prewarm {
				h.inFlight++
				h.prewarm = false
			}
			m.mu.Unlock()
			return h, nil
		case h != nil && (h.draining || h.exited()) && h.inFlight == 0 && m.stopping == nil:
			m.detachLocked(h)
			m.mu.Unlock()
			continue
		case h == nil && !m.starting && m.stopping == nil:
			m.starting = true
			m.notify()
			m.mu.Unlock()
			started, err := m.startHelper(context.WithoutCancel(ctx))
			m.mu.Lock()
			m.starting = false
			if err != nil {
				m.recordFailureLocked(err)
				m.notify()
				m.mu.Unlock()
				m.wake()
				if ReasonOf(err) == "" {
					return nil, fail(ReasonHelperFailed, "browser helper did not start")
				}
				return nil, err
			}
			started.prewarm = prewarm
			m.helper = started
			m.lastUse = m.d.now()
			m.notify()
			m.mu.Unlock()
			continue
		}
		wait := m.changed
		m.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: waiting for the browser helper: %w", ErrUnavailable, ctx.Err())
		}
	}
}

// detachLocked hands h to a stopper goroutine; acquire waits for it to finish
// so two helpers never share the runtime lock.
func (m *Manager) detachLocked(h *helper) {
	m.helper = nil
	done := make(chan struct{})
	m.stopping = done
	m.notify()
	go func() {
		m.stopHelper(h)
		m.mu.Lock()
		close(done)
		m.stopping = nil
		m.notify()
		m.mu.Unlock()
	}()
}

func (m *Manager) recordFailureLocked(err error) {
	now := m.d.now()
	switch reason := ReasonOf(err); reason {
	case ReasonDepsMissing, ReasonSandboxUnavailable, ReasonRuntimeInvalid, ReasonBrowserInvalid, ReasonDiskLow, ReasonRuntimeMissing:
		// The environment changed under a prepared tier: prepare again.
		m.prepared = false
		m.reason = reason
	default:
		recent := m.failures[:0]
		for _, at := range m.failures {
			if now.Sub(at) < failureWindow {
				recent = append(recent, at)
			}
		}
		m.failures = append(recent, now)
		if len(m.failures) >= failureLimit {
			m.failures = nil
			m.failedUntil = now.Add(helperFailedFor)
		}
	}
}

func (m *Manager) call(ctx context.Context, h *helper, req helperFetch) (FetchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutMS)*time.Millisecond+5*time.Second)
	defer cancel()
	body, err := json.Marshal(req)
	if err != nil {
		return FetchResult{}, ErrHelper
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.endpoint+"/v1/fetch", bytes.NewReader(body))
	if err != nil {
		return FetchResult{}, ErrHelper
	}
	httpReq.Header.Set("Authorization", "Bearer "+h.bearer)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(httpReq)
	if err != nil {
		return FetchResult{}, fmt.Errorf("%w: helper exchange failed", ErrHelper)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return FetchResult{}, fmt.Errorf("%w: helper refused the fetch", ErrHelper)
	}
	var envelope struct {
		Data *FetchResult `json:"data"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResultBytes))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&envelope); err != nil || envelope.Data == nil {
		return FetchResult{}, fmt.Errorf("%w: helper answer unreadable", ErrHelper)
	}
	if err = envelope.Data.validate(); err != nil {
		return FetchResult{}, err
	}
	return *envelope.Data, nil
}

// Run prepares the tier (with backoff 60 s → 1 h on failure) and supervises
// it until ctx ends: memory samples every 2 s, every 500 ms while a page
// renders, idle stops, recycling, a helper_failed hold, and a full re-verify
// every 6 h while no helper is warm.
func (m *Manager) Run(ctx context.Context) {
	defer m.Close(context.Background())
	backoff := backoffStart
	var next time.Time
	timer := time.NewTimer(m.d.tick)
	defer timer.Stop()
	for {
		m.mu.Lock()
		need := !m.prepared && !m.closed
		m.mu.Unlock()
		if need && !m.d.now().Before(next) {
			err := m.prepare(ctx)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				if ReasonOf(err) == ReasonMemoryLow {
					next = m.d.now().Add(100 * 365 * 24 * time.Hour)
				} else {
					next = m.d.now().Add(backoff)
					backoff = min(2*backoff, backoffMax)
				}
			} else {
				backoff = backoffStart
			}
		}
		m.tick()
		m.mu.Lock()
		wait := m.d.tick
		if m.inFlight > 0 {
			wait = min(wait, m.d.busyTick)
		}
		m.mu.Unlock()
		timer.Reset(wait)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-m.kick:
		}
	}
}

// prepare runs the RAM check, wipes crash dumps and partial downloads,
// ensures and fully verifies the runtime and the browser, then starts and
// stops the helper once (surfacing deps_missing and sandbox_unavailable) and
// collects old runtime and browser versions.
func (m *Manager) prepare(ctx context.Context) (err error) {
	defer func() {
		m.mu.Lock()
		if err != nil {
			m.prepared = false
			if m.reason = ReasonOf(err); m.reason == "" {
				m.reason = ReasonHelperFailed
			}
		}
		m.notify()
		m.mu.Unlock()
	}()
	m.mu.Lock()
	m.reason = ReasonBrowserDownloading
	m.notify()
	m.mu.Unlock()
	physical, perr := m.d.physical()
	if perr == nil && physical < minPhysical {
		return fail(ReasonMemoryLow, "less than 8 GiB of physical memory")
	}
	capacity := m.cfg.Capacity
	if capacity <= 0 {
		capacity = 1
		if perr == nil && physical >= 16<<30 {
			capacity = 2
		}
	}
	capacity = min(max(capacity, 1), 4)
	if err = stateDir(m.cfg.StateDir); err != nil {
		return fail(ReasonRuntimeInvalid, "private node state inaccessible")
	}
	state := filepath.Join(m.cfg.StateDir, "web-browser")
	if err = privateDir(state); err != nil {
		return fail(ReasonRuntimeInvalid, "private browser state inaccessible")
	}
	_ = removeTree(filepath.Join(state, "crashpad"))
	cleanBrowserPartials(m.cfg.StateDir)
	root, err := m.d.ensure(m.cfg)
	if err != nil {
		return err
	}
	if err = m.d.verify(root); err != nil {
		// Rebuild a damaged extraction once from the verified archive.
		_ = removeTree(root.Dir)
		if root, err = m.d.ensure(m.cfg); err == nil {
			err = m.d.verify(root)
		}
		if err != nil {
			return err
		}
	}
	browser, err := m.d.ensureBrowser(ctx, m.cfg, root.Browser)
	if err != nil {
		return err
	}
	if err = m.d.verifyBrowser(browser.Dir, root.Browser.Inventory); err != nil {
		m.d.unregister(appBundle(browser.Executable))
		_ = removeTree(browser.Dir)
		return err
	}
	m.mu.Lock()
	m.root, m.browser, m.capacity = root, browser, capacity
	m.mu.Unlock()
	probe, err := m.startHelper(ctx)
	if err != nil {
		if ReasonOf(err) == "" {
			return fail(ReasonHelperFailed, "browser launch probe failed")
		}
		return err
	}
	m.stopHelper(probe)
	_ = gcBrowsers(m.cfg.StateDir, filepath.Base(browser.Dir), m.d.unregister)
	_ = gcRuntimes(m.cfg.StateDir, filepath.Base(root.Dir))
	m.mu.Lock()
	m.prepared, m.reason = true, ""
	m.failures, m.failedUntil = nil, time.Time{}
	m.nextVerify = m.d.now().Add(verifyEvery)
	m.mu.Unlock()
	return nil
}

// tick is one supervision step.
func (m *Manager) tick() {
	m.mu.Lock()
	now := m.d.now()
	h := m.helper
	if h == nil || m.stopping != nil {
		verify := m.prepared && h == nil && m.stopping == nil && !m.starting && m.inFlight == 0 && !m.verifying && !now.Before(m.nextVerify)
		root, browser := m.root, m.browser
		if verify {
			// The hash takes a while; sampling goes on meanwhile.
			m.verifying = true
			go m.backgroundVerify(root, browser)
		}
		m.mu.Unlock()
		return
	}
	idle := m.cfg.IdleTimeout
	if h.prewarm {
		idle = prewarmIdle
	}
	if h.inFlight == 0 && (h.exited() || h.draining || !m.prepared || now.Sub(m.lastUse) >= idle) {
		m.detachLocked(h)
		m.mu.Unlock()
		return
	}
	capacity := m.capacity
	m.mu.Unlock()
	if h.exited() {
		return
	}
	bytes, tree, err := m.d.sample(h.p)
	if err != nil {
		return
	}
	recycle, kill := Thresholds(capacity)
	level := m.d.pressure()
	m.mu.Lock()
	if len(tree) > 0 {
		h.tree = tree
	}
	switch {
	case bytes > kill, h.inFlight > 0 && (level >= pressureCritical || level >= pressureWarn && bytes > recycle):
		// In-flight fetches fail web_browser_failed. Under host memory
		// pressure the operator's machine comes first, whatever RSS says
		// (compressed and swapped renderer pages do not count in it).
		h.draining = true
		h.p.kill(h.tree)
	case bytes > recycle:
		h.draining = true
	}
	m.notify()
	m.mu.Unlock()
}

// backgroundVerify re-hashes the runtime and the browser while no helper is
// warm. A failure drains the tier and prepares it again.
func (m *Manager) backgroundVerify(root Root, browser Browser) {
	err := m.d.verify(root)
	if err == nil {
		err = m.d.verifyBrowser(browser.Dir, root.Browser.Inventory)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifying = false
	m.nextVerify = m.d.now().Add(verifyEvery)
	if err != nil {
		m.prepared = false
		m.reason = ReasonOf(err)
		m.notify()
	}
}

// Close stops the helper and refuses further work.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	h := m.helper
	m.helper = nil
	stopping := m.stopping
	m.notify()
	m.mu.Unlock()
	if h != nil {
		m.stopHelper(h)
	}
	if stopping != nil {
		select {
		case <-stopping:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// markerWriter keeps only the helper's closed launch marker. Everything else
// on stderr (driver and browser noise, which may name URLs) is dropped; at
// most one partial line of 256 bytes is held.
type markerWriter struct {
	mu     sync.Mutex
	line   []byte
	marker string
	total  int64
}

const markerPrefix = "SCARLETT_WEB_BROWSER_ERROR="

func (w *markerWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += int64(len(b))
	for _, c := range b {
		if c == '\n' {
			if line := strings.TrimSpace(string(w.line)); strings.HasPrefix(line, markerPrefix) {
				switch value := strings.TrimPrefix(line, markerPrefix); value {
				case "deps_missing", "sandbox_unavailable", "launch_failed":
					w.marker = value
				}
			}
			w.line = w.line[:0]
			continue
		}
		if len(w.line) < 256 {
			w.line = append(w.line, c)
		}
	}
	return len(b), nil
}

func (w *markerWriter) Marker() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.marker
}

// helperEnv is the helper's whole environment: an allowlist, nothing inherited.
func (m *Manager) helperEnv(state, bearer string, browser Browser, proxy, deny string, capacity int) []string {
	home := filepath.Join(state, "home")
	tmp := filepath.Join(state, "tmp")
	var env []string
	if runtime.GOOS == "windows" {
		for _, key := range []string{"SystemRoot", "WINDIR"} {
			if value := os.Getenv(key); value != "" {
				env = append(env, key+"="+value)
			}
		}
	}
	env = append(env,
		"TMPDIR="+tmp, "TEMP="+tmp, "TMP="+tmp,
		"HOME="+home, "USERPROFILE="+home,
		"LOCALAPPDATA="+filepath.Join(home, "AppData", "Local"), "APPDATA="+filepath.Join(home, "AppData", "Roaming"),
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "XDG_CACHE_HOME="+filepath.Join(home, ".cache"),
		"XDG_DATA_HOME="+filepath.Join(home, ".local", "share"),
		"BREAKPAD_DUMP_LOCATION="+filepath.Join(state, "crashpad"),
		"PLAYWRIGHT_NODEJS_PATH="+m.cfg.XLoginNode,
		"PLAYWRIGHT_BROWSERS_PATH="+filepath.Join(state, "none"),
		"PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1",
		"WEB_HELPER_BEARER="+bearer,
		"WEB_BROWSER_EXECUTABLE="+browser.Executable, "WEB_BROWSER_VERSION="+browser.Version,
		"WEB_USER_AGENT="+m.UserAgent(),
		"WEB_EGRESS_PROXY="+proxy, "WEB_DENY_PROXY="+deny,
		"WEB_MAX_PAGES="+strconv.Itoa(capacity))
	return append(env, m.solverEnv()...)
}

// startHelper starts one helper and waits for it to be ready: private state,
// a bearer, the runtime lock, a size-and-mode check of the runtime and the
// browser, the two listeners, then the port the helper bound (its first
// stdout line), then GET /v1/ready and /v1/capabilities every 50 ms, all
// within 20 s. The helper binds its own port, so no other local process can
// take a port the node chose and receive the bearer.
func (m *Manager) startHelper(ctx context.Context) (*helper, error) {
	m.mu.Lock()
	root, browser, capacity := m.root, m.browser, m.capacity
	m.mu.Unlock()
	state := filepath.Join(m.cfg.StateDir, "web-browser")
	home := filepath.Join(state, "home")
	for _, dir := range []string{state, home, filepath.Join(home, "AppData", "Local"), filepath.Join(home, "AppData", "Roaming"),
		filepath.Join(home, ".config"), filepath.Join(home, ".cache"), filepath.Join(home, ".local", "share"),
		filepath.Join(state, "crashpad"), filepath.Join(state, "none")} {
		if err := privateDir(dir); err != nil {
			return nil, fail(ReasonRuntimeInvalid, "private browser state inaccessible")
		}
	}
	if err := wipeDir(filepath.Join(state, "tmp")); err != nil {
		return nil, fail(ReasonRuntimeInvalid, "private browser state inaccessible")
	}
	if free, err := diskFree(state); err != nil || free < minStartFreeBytes {
		return nil, fail(ReasonDiskLow, "not enough free disk to start the browser")
	}
	if err := m.d.quick(root, browser); err != nil {
		return nil, err
	}
	bearer, err := token(filepath.Join(state, "bearer"))
	if err != nil {
		return nil, fail(ReasonRuntimeInvalid, "private bearer unavailable")
	}
	lock, err := localfs.LockPrivate(filepath.Join(state, "runtime.lock"))
	if err != nil {
		return nil, errors.New("a browser helper is already active for this installation")
	}
	h := &helper{lock: lock, bearer: bearer, done: make(chan struct{}), stderr: &markerWriter{},
		client: &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}}
	ok := false
	defer func() {
		if !ok {
			m.cleanup(h)
		}
	}()
	if h.proxy, err = newEgressProxy(m.cfg.Guard, m.cfg.Resolver, m.cfg.UpstreamProxy, m.cfg.UpstreamAuthorization, 32*capacity+16, &m.stats); err != nil {
		return nil, errors.New("egress proxy unavailable")
	}
	if h.deny, err = newDenyListener(&m.stats); err != nil {
		return nil, errors.New("deny listener unavailable")
	}
	portRead, portWrite, err := os.Pipe()
	if err != nil {
		return nil, errors.New("helper stdout unavailable")
	}
	defer portWrite.Close()
	exe, args := m.d.command(root)
	cmd := exec.Command(exe, args...)
	cmd.Dir = home
	cmd.Env = m.helperEnv(state, bearer, browser, h.proxy.URL(), h.deny.URL(), capacity)
	cmd.Stdout = portWrite
	cmd.Stderr = h.stderr
	if h.stdin, err = cmd.StdinPipe(); err != nil {
		portRead.Close()
		return nil, errors.New("helper stdin unavailable")
	}
	_, kill := Thresholds(capacity)
	if h.p, err = startProcess(cmd, kill+2*gib); err != nil {
		h.stdin.Close()
		portRead.Close()
		return nil, errors.New("helper could not start")
	}
	portWrite.Close()
	ports := make(chan int, 1)
	go readHelperPort(portRead, ports)
	h.p.done = h.done
	go func() {
		_ = cmd.Wait()
		close(h.done)
		m.wake()
	}()
	ctx, cancel := context.WithTimeout(ctx, m.d.readyTimeout)
	defer cancel()
	select {
	case port := <-ports:
		if port <= 0 {
			// A helper that could not start closes stdout as it exits; its
			// launch marker is read once it has.
			select {
			case <-h.done:
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
			}
			return nil, h.startError("helper reported no port")
		}
		h.endpoint = "http://127.0.0.1:" + strconv.Itoa(port)
	case <-h.done:
		return nil, h.startError("helper exited before readiness")
	case <-ctx.Done():
		return nil, h.startError("helper readiness timed out")
	}
	for {
		select {
		case <-h.done:
			return nil, h.startError("helper exited before readiness")
		case <-ctx.Done():
			return nil, h.startError("helper readiness timed out")
		default:
		}
		if h.ready(ctx, capacity, m.solversMatch) {
			h.tree = h.p.snapshot()
			ok = true
			return h, nil
		}
		select {
		case <-ctx.Done():
		case <-h.done:
		case <-time.After(readyPoll):
		}
	}
}

// helperPortPrefix starts the helper's first stdout line.
const helperPortPrefix = "SCARLETT_WEB_HELPER_PORT="

// readHelperPort reads the helper's first stdout line, at most 64 bytes, and
// sends the loopback port it names, or 0 when the line is anything else.
// The rest of stdout is discarded until the helper ends.
func readHelperPort(r *os.File, ports chan<- int) {
	defer r.Close()
	line := make([]byte, 0, 64)
	buf := make([]byte, 1)
	port := 0
	for len(line) < 64 {
		if n, err := r.Read(buf); n == 0 || err != nil {
			break
		}
		if buf[0] == '\n' {
			if value, ok := strings.CutPrefix(string(line), helperPortPrefix); ok {
				if n, err := strconv.Atoi(value); err == nil && n > 0 && n < 65536 && strconv.Itoa(n) == value {
					port = n
				}
			}
			break
		}
		line = append(line, buf[0])
	}
	ports <- port
	_, _ = io.Copy(io.Discard, r)
}

func (h *helper) startError(what string) error {
	switch h.stderr.Marker() {
	case "deps_missing":
		return fail(ReasonDepsMissing, "browser shared libraries missing")
	case "sandbox_unavailable":
		return fail(ReasonSandboxUnavailable, "browser sandbox unavailable")
	}
	return errors.New(what)
}

func (h *helper) ready(ctx context.Context, capacity int, solversMatch func([]string) bool) bool {
	get := func(path string, out any) bool {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.endpoint+path, nil)
		req.Header.Set("Authorization", "Bearer "+h.bearer)
		resp, err := h.client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(out) == nil
	}
	var ready struct {
		Data struct {
			Status string `json:"status"`
		} `json:"data"`
	}
	var caps struct {
		Data struct {
			WebBrowser     int      `json:"web_browser"`
			Engine         string   `json:"engine"`
			BrowserVersion string   `json:"browser_version"`
			MaxPages       int      `json:"max_pages"`
			Solvers        []string `json:"solvers"`
		} `json:"data"`
	}
	// The helper names the solver providers it built; they must be the
	// configured ones (none without a configuration).
	return get("/v1/ready", &ready) && ready.Data.Status == "ready" && get("/v1/capabilities", &caps) &&
		caps.Data.WebBrowser == 1 && caps.Data.Engine == Engine && caps.Data.BrowserVersion == PinnedVersion && caps.Data.MaxPages == capacity &&
		caps.Data.Solvers != nil && solversMatch(caps.Data.Solvers)
}

// stopHelper ends a helper: EOF on stdin asks for a graceful stop; after 7 s
// the whole tree is killed. Leftover descendants of a graceful stop are
// killed too, and on macOS CfT is unregistered from LaunchServices.
func (m *Manager) stopHelper(h *helper) {
	if h.p != nil && !h.exited() {
		h.tree = append(h.p.snapshot(), h.tree...)
	}
	if h.stdin != nil {
		h.stdin.Close()
	}
	if h.p != nil {
		select {
		case <-h.done:
		case <-time.After(m.d.stopGrace):
			h.p.kill(h.tree)
			select {
			case <-h.done:
			case <-time.After(2 * time.Second):
			}
		}
	}
	m.cleanup(h)
}

func (m *Manager) cleanup(h *helper) {
	if h.p != nil {
		if !h.exited() {
			h.p.kill(h.tree)
			select {
			case <-h.done:
			case <-time.After(2 * time.Second):
			}
		}
		// Survivors of the snapshot (Chrome leads its own process group).
		h.p.kill(h.tree)
		for deadline := time.Now().Add(3 * time.Second); alive(h.tree) && time.Now().Before(deadline); {
			time.Sleep(100 * time.Millisecond)
		}
		h.p.release()
		m.d.unregister(appBundle(m.browserExecutable()))
	}
	if h.client != nil {
		h.client.CloseIdleConnections()
	}
	if h.proxy != nil {
		h.proxy.Close()
	}
	if h.deny != nil {
		h.deny.Close()
	}
	if h.lock != nil {
		h.lock.Close()
	}
}

func (m *Manager) browserExecutable() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.browser.Executable
}
