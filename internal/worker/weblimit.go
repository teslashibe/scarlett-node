package worker

import (
	"math"
	"slices"
	"sync"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
)

// The adaptive web limit's rules (SCARLETT_WEB_CONCURRENCY=auto).
const (
	// webLimitWindow healthy pages in a row at the current limit earn one more
	// slot. The latency rules read the helper_wall p90 of the last this many.
	webLimitWindow = 20
	// webLimitBaseline is the span of the trailing p50 baseline, and
	// webLimitBaselineCap bounds its samples (sixteen 1.5 s pages at once
	// fill five minutes with about 3,200).
	webLimitBaseline    = 5 * time.Minute
	webLimitBaselineCap = 4096
	// The window's p90 may be at most webLimitGrowLatency times the baseline
	// to grow, and above webLimitCutLatency times it the limit halves.
	webLimitGrowLatency = 1.25
	webLimitCutLatency  = 2.0
	// webLimitGrowCPU is the host CPU use at or above which the limit does
	// not grow.
	webLimitGrowCPU = 0.70
	// webLimitEvents pages that timed out or that the verifier turned away
	// (verifier_busy) within webLimitEventSpan halve the limit.
	webLimitEvents    = 3
	webLimitEventSpan = 60 * time.Second
	// webLimitPressureHold is the least time between two halvings for memory
	// pressure: pages running when the limit fell still hold their memory.
	webLimitPressureHold = 5 * time.Second
	// webLimitSampleEvery is how often the host is sampled at most.
	webLimitSampleEvery = time.Second
	// webTimeoutWall is how long a failed relay helper run lasts before it
	// counts as a timeout. The verifier ends a web hop that idles 20 s after
	// a response byte, or has none 60 s after the request, as session_timeout
	// (api/verifier-v1.md 8.2), which reaches the node as web_fetch_failed.
	webTimeoutWall = 20 * time.Second
)

// Why the adaptive web limit last changed: status.json web_limit.limit_reason.
const (
	// WebLimitStart: unchanged since the node started.
	WebLimitStart = "start"
	// WebLimitHealthy: 20 healthy pages at the limit, one slot more.
	WebLimitHealthy = "healthy"
	// WebLimitTimeouts: 3 pages timed out within 60 s, halved.
	WebLimitTimeouts = "timeouts"
	// WebLimitVerifierBusy: the verifier turned 3 pages away within 60 s, halved.
	WebLimitVerifierBusy = "verifier_busy"
	// WebLimitLatency: helper_wall p90 above twice the baseline, halved.
	WebLimitLatency = "latency"
	// WebLimitMemoryPressure: host memory pressure, halved.
	WebLimitMemoryPressure = "memory_pressure"
)

// ValidWebLimitReason reports whether reason is one the limiter gives.
func ValidWebLimitReason(reason string) bool {
	switch reason {
	case WebLimitStart, WebLimitHealthy, WebLimitTimeouts, WebLimitVerifierBusy, WebLimitLatency, WebLimitMemoryPressure:
		return true
	}
	return false
}

// MemoryLevel is the host's memory pressure as the web limit reads it.
type MemoryLevel int

const (
	// MemoryNormal lets the limit grow; it is also what an unreadable host reports.
	MemoryNormal MemoryLevel = iota
	// MemoryWarn holds the limit: no growth, no cut.
	MemoryWarn
	// MemoryCritical halves the limit.
	MemoryCritical
)

// HostLoad is one host sample: CPU use in [0, 1] when CPUKnown, and memory.
type HostLoad struct {
	CPU      float64
	CPUKnown bool
	Memory   MemoryLevel
}

// HostSampler reads the host's load; the limiter calls Sample at most once
// a second.
type HostSampler interface {
	Sample(now time.Time) HostLoad
}

// WebLimitChange is one change of the adaptive web limit.
type WebLimitChange struct {
	From, To int
	Reason   string
	At       time.Time
}

// WebLimitStatus is the adaptive web limit now, why it last changed and
// when (zero until the first change).
type WebLimitStatus struct {
	Limit     int
	Reason    string
	ChangedAt time.Time
}

// WebLimitOptions configure a WebLimiter. Host nil samples this host, Now
// nil is time.Now. OnChange runs after each change, outside the limiter's
// lock but possibly inside a caller's lock around Tick, so it must not call
// back into that caller.
type WebLimitOptions struct {
	Min, Start, Max int
	Host            HostSampler
	Now             func() time.Time
	OnChange        func(WebLimitChange)
}

// WebLimiter is the adaptive web limit (SCARLETT_WEB_CONCURRENCY=auto): an
// additive-increase, multiplicative-decrease limit on the relay web pages
// the node runs at once, within [Min, Max] and starting at Start.
//
//   - One more slot after 20 healthy pages in a row at the current limit: each
//     proven with no timeout or verifier_busy, while at least half the limit
//     was running when it was admitted, as RFC 7661 and Netflix's AIMD limiter
//     require before growing a window, so a node serving one page at a time
//     never climbs on pages it ran alone. Their helper_wall p90 must be within
//     1.25x the p50 of every proven page in the last five minutes, host CPU
//     under 70% and memory pressure normal.
//   - Halved, never below Min, on 3 pages that timed out or that the verifier
//     turned away within 60 s, on a p90 above twice the baseline, or on
//     critical memory pressure. Pages admitted before a halving ran under the
//     higher limit and never count toward the next one.
//   - A failed page that did not time out, such as a refused or unreachable
//     target, says nothing about this node and leaves the run of healthy
//     pages as it was.
//
// A page's helper_wall is the mean wall time of its proven relay hops. The
// limit only gates admission: the service pool never cancels a running page,
// and after a halving it admits again once fewer pages than the new limit run.
type WebLimiter struct {
	mu       sync.Mutex
	min, max int
	host     HostSampler
	now      func() time.Time
	onChange func(WebLimitChange)

	limit     int
	reason    string
	changedAt time.Time
	// gen counts changes; a page keeps the gen it was admitted at. cutGen is
	// the gen the last halving set: older pages ran under a higher limit.
	gen, cutGen uint64
	cutAt       time.Time
	// streak is the run of healthy pages at gen, and window their latest
	// helper_wall values, oldest first.
	streak int
	window []time.Duration
	// baseline is every proven page's helper_wall for webLimitBaseline,
	// oldest first; events the counted timeouts and verifier_busy pages.
	baseline  []webLimitSample
	events    []time.Time
	load      HostLoad
	sampledAt time.Time
}

type webLimitSample struct {
	at   time.Time
	wall time.Duration
}

// NewWebLimiter returns a limiter at o.Start, clamped to [o.Min, o.Max].
func NewWebLimiter(o WebLimitOptions) *WebLimiter {
	l := &WebLimiter{min: max(o.Min, 1), host: o.Host, now: o.Now, onChange: o.OnChange, reason: WebLimitStart}
	l.max = max(o.Max, l.min)
	l.limit = min(max(o.Start, l.min), l.max)
	if l.now == nil {
		l.now = time.Now
	}
	if l.host == nil {
		l.host = NewHostSampler()
	}
	return l
}

// Limit is how many web pages may run at once now.
func (l *WebLimiter) Limit() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}

// Status is the limit now and why it last changed.
func (l *WebLimiter) Status() WebLimitStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	return WebLimitStatus{Limit: l.limit, Reason: l.reason, ChangedAt: l.changedAt}
}

// Admit opens a page admitted while inFlight web pages run, itself included.
// The page reports to the limiter as the worker runs it.
func (l *WebLimiter) Admit(inFlight int) *WebPage {
	l.mu.Lock()
	defer l.mu.Unlock()
	return &WebPage{l: l, gen: l.gen, utilized: 2*inFlight >= l.limit}
}

// Tick samples the host when due and halves the limit under critical memory
// pressure, so pressure acts even while no page finishes.
func (l *WebLimiter) Tick() {
	l.mu.Lock()
	change := l.pressureLocked(l.now())
	l.mu.Unlock()
	l.notify(change)
}

func (l *WebLimiter) notify(change *WebLimitChange) {
	if change != nil && l.onChange != nil {
		l.onChange(*change)
	}
}

// WebPage is one admitted web page's report to its limiter. It implements
// config.WebObserver; it is safe to call from any goroutine, and calls after
// Done are ignored.
type WebPage struct {
	l        *WebLimiter
	gen      uint64
	utilized bool
	// Guarded by l.mu: the proven hops' wall time and count, whether a
	// timeout or verifier_busy was counted, and whether the page is done.
	wall    time.Duration
	hops    int
	flagged bool
	done    bool
}

var _ config.WebObserver = (*WebPage)(nil)

// Hop takes one relay helper run of the page.
func (p *WebPage) Hop(code string, wall time.Duration, timedOut bool) {
	l := p.l
	l.mu.Lock()
	var change *WebLimitChange
	switch {
	case p.done:
	case code == "":
		p.wall += max(wall, 0)
		p.hops++
	case code == "verifier_busy":
		change = l.flagLocked(p, WebLimitVerifierBusy, l.now())
	case timedOut:
		change = l.flagLocked(p, WebLimitTimeouts, l.now())
	}
	l.mu.Unlock()
	l.notify(change)
}

// Done ends the page with its job code; timedOut is set when it ran out of
// its deadline.
func (p *WebPage) Done(code string, timedOut bool) {
	l := p.l
	l.mu.Lock()
	var change *WebLimitChange
	if !p.done {
		p.done = true
		now := l.now()
		if timedOut {
			change = l.flagLocked(p, WebLimitTimeouts, now)
		}
		if change == nil {
			change = l.finishLocked(p, code, now)
		}
		if change == nil {
			change = l.pressureLocked(now)
		}
	}
	l.mu.Unlock()
	l.notify(change)
}

// flagLocked counts a page that timed out or was turned away, once per page
// and only if it was admitted since the last halving, and halves the limit
// when enough of them fall within webLimitEventSpan. Either ends the run of
// healthy pages.
func (l *WebLimiter) flagLocked(p *WebPage, reason string, now time.Time) *WebLimitChange {
	l.streak = 0
	counted := !p.flagged && p.gen >= l.cutGen
	p.flagged = true
	if !counted {
		return nil
	}
	kept := l.events[:0]
	for _, at := range l.events {
		if now.Sub(at) < webLimitEventSpan {
			kept = append(kept, at)
		}
	}
	l.events = append(kept, now)
	if len(l.events) < webLimitEvents {
		return nil
	}
	return l.cutLocked(reason, now)
}

// finishLocked applies a finished page: a proven one joins the baseline, and
// a healthy one at the current limit joins the window, which may then halve
// the limit for latency or, with the host idle enough, grow it by one.
func (l *WebLimiter) finishLocked(p *WebPage, code string, now time.Time) *WebLimitChange {
	if code != "" || p.hops == 0 {
		return nil
	}
	wall := p.wall / time.Duration(p.hops)
	l.baseline = append(l.baseline, webLimitSample{now, wall})
	l.pruneLocked(now)
	if p.flagged || !p.utilized || p.gen != l.gen {
		return nil
	}
	l.window = append(l.window, wall)
	if len(l.window) > webLimitWindow {
		l.window = slices.Delete(l.window, 0, len(l.window)-webLimitWindow)
	}
	l.streak++
	if len(l.window) < webLimitWindow {
		return nil
	}
	base, ok := l.baselineLocked(now)
	if !ok {
		return nil
	}
	p90 := float64(percentile(slices.Clone(l.window), 0.9))
	if p90 > webLimitCutLatency*float64(base) {
		return l.cutLocked(WebLimitLatency, now)
	}
	if l.streak < webLimitWindow || l.limit >= l.max || p90 > webLimitGrowLatency*float64(base) {
		return nil
	}
	if load := l.sampleLocked(now); load.Memory != MemoryNormal || load.CPUKnown && load.CPU >= webLimitGrowCPU {
		return nil
	}
	return l.setLocked(l.limit+1, WebLimitHealthy, now)
}

// pruneLocked drops baseline samples older than webLimitBaseline, and the
// oldest beyond webLimitBaselineCap.
func (l *WebLimiter) pruneLocked(now time.Time) {
	drop := 0
	for drop < len(l.baseline) && now.Sub(l.baseline[drop].at) > webLimitBaseline {
		drop++
	}
	if drop = max(drop, len(l.baseline)-webLimitBaselineCap); drop > 0 {
		l.baseline = slices.Delete(l.baseline, 0, drop)
	}
}

// baselineLocked is the p50 of the proven pages of the last
// webLimitBaseline, once there are at least a window's worth.
func (l *WebLimiter) baselineLocked(now time.Time) (time.Duration, bool) {
	l.pruneLocked(now)
	if len(l.baseline) < webLimitWindow {
		return 0, false
	}
	walls := make([]time.Duration, len(l.baseline))
	for i, s := range l.baseline {
		walls[i] = s.wall
	}
	return percentile(walls, 0.5), true
}

// pressureLocked halves the limit under critical memory pressure, at most
// once per webLimitPressureHold.
func (l *WebLimiter) pressureLocked(now time.Time) *WebLimitChange {
	if l.sampleLocked(now).Memory != MemoryCritical || !l.cutAt.IsZero() && now.Sub(l.cutAt) < webLimitPressureHold {
		return nil
	}
	return l.cutLocked(WebLimitMemoryPressure, now)
}

func (l *WebLimiter) sampleLocked(now time.Time) HostLoad {
	if l.sampledAt.IsZero() || now.Sub(l.sampledAt) >= webLimitSampleEvery || now.Before(l.sampledAt) {
		l.load, l.sampledAt = l.host.Sample(now), now
	}
	return l.load
}

// cutLocked halves the limit, never below the floor. Its evidence is spent
// either way.
func (l *WebLimiter) cutLocked(reason string, now time.Time) *WebLimitChange {
	l.events = l.events[:0]
	l.cutAt = now
	to := max(l.min, l.limit/2)
	if to == l.limit {
		return nil
	}
	change := l.setLocked(to, reason, now)
	l.cutGen = l.gen
	return change
}

// setLocked moves the limit and starts a new generation: the run of healthy
// pages and their window start again at the new limit.
func (l *WebLimiter) setLocked(to int, reason string, now time.Time) *WebLimitChange {
	change := &WebLimitChange{From: l.limit, To: to, Reason: reason, At: now}
	l.limit, l.reason, l.changedAt = to, reason, now
	l.gen++
	l.streak = 0
	l.window = l.window[:0]
	return change
}

// percentile is the nearest-rank q quantile of values, which it sorts.
func percentile(values []time.Duration, q float64) time.Duration {
	slices.Sort(values)
	i := int(math.Ceil(q*float64(len(values)))) - 1
	return values[min(max(i, 0), len(values)-1)]
}
