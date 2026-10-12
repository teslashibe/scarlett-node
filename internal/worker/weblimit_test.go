package worker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
)

// limitHost is a host whose load the test sets.
type limitHost struct {
	mu   sync.Mutex
	load HostLoad
}

func (h *limitHost) Sample(time.Time) HostLoad {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.load
}

func (h *limitHost) set(load HostLoad) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.load = load
}

// limitRig drives a limiter with a synthetic clock, host and page stream.
type limitRig struct {
	t       *testing.T
	l       *WebLimiter
	host    *limitHost
	at      time.Time
	changes []WebLimitChange
}

func newLimitRig(t *testing.T, start int) *limitRig {
	r := &limitRig{t: t, host: &limitHost{}, at: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
	r.l = NewWebLimiter(WebLimitOptions{Min: config.WebAutoMin, Start: start, Max: config.WebAutoMax, Host: r.host, Now: func() time.Time { return r.at }, OnChange: func(c WebLimitChange) { r.changes = append(r.changes, c) }})
	return r
}

func (r *limitRig) advance(d time.Duration) { r.at = r.at.Add(d) }

// run finishes one page admitted with inFlight pages running, proven in one
// hop of wall time, a second after the previous one.
func (r *limitRig) run(inFlight int, wall time.Duration) {
	p := r.l.Admit(inFlight)
	r.advance(time.Second)
	p.Hop("", wall, false)
	p.Done("", false)
}

// busy runs n pages at the limit, each proven in one hop of a steady,
// slightly jittered wall time around base.
func (r *limitRig) busy(n int, base time.Duration) {
	for i := 0; i < n; i++ {
		r.run(r.l.Limit(), base+time.Duration(i%5)*20*time.Millisecond)
	}
}

func (r *limitRig) want(limit int, reason string) {
	r.t.Helper()
	if s := r.l.Status(); s.Limit != limit || s.Reason != reason {
		r.t.Fatalf("limit %d (%s), want %d (%s); changes %+v", s.Limit, s.Reason, limit, reason, r.changes)
	}
}

func TestWebLimiterGrowsAfterTwentyHealthyPages(t *testing.T) {
	r := newLimitRig(t, config.WebAutoStart)
	r.want(4, WebLimitStart)
	if !r.l.Status().ChangedAt.IsZero() {
		t.Fatal("start has no change time")
	}
	r.busy(19, 1500*time.Millisecond)
	r.want(4, WebLimitStart)
	r.busy(1, 1500*time.Millisecond)
	r.want(5, WebLimitHealthy)
	if len(r.changes) != 1 || r.changes[0] != (WebLimitChange{From: 4, To: 5, Reason: WebLimitHealthy, At: r.at}) || r.l.Status().ChangedAt != r.at {
		t.Fatalf("change %+v", r.changes)
	}
	// Twenty more at the new limit, not counting what came before it.
	r.busy(19, 1500*time.Millisecond)
	r.want(5, WebLimitHealthy)
	r.busy(1, 1500*time.Millisecond)
	r.want(6, WebLimitHealthy)

	// A page admitted before a change ran under the old limit: it finishes
	// healthy but counts toward neither the run nor the window.
	early := r.l.Admit(6)
	r.busy(20, 1500*time.Millisecond)
	r.want(7, WebLimitHealthy)
	early.Hop("", 1500*time.Millisecond, false)
	early.Done("", false)
	r.busy(19, 1500*time.Millisecond)
	r.want(7, WebLimitHealthy)
	r.busy(1, 1500*time.Millisecond)
	r.want(8, WebLimitHealthy)

	// Redirect chains count as one page, at the mean of their proven hops.
	r = newLimitRig(t, 4)
	for i := 0; i < 20; i++ {
		p := r.l.Admit(4)
		r.advance(time.Second)
		p.Hop("", 1400*time.Millisecond, false)
		p.Hop("", 1600*time.Millisecond, false)
		p.Done("", false)
	}
	r.want(5, WebLimitHealthy)
}

// A node serving pages one at a time never climbs: a page counts only when
// at least half the limit was running when it was admitted.
func TestWebLimiterGrowsOnlyWhenTheLimitIsUsed(t *testing.T) {
	r := newLimitRig(t, 8)
	for i := 0; i < 100; i++ {
		r.run(3, 1500*time.Millisecond)
	}
	r.want(8, WebLimitStart)
	for i := 0; i < 20; i++ {
		r.run(4, 1500*time.Millisecond)
	}
	r.want(9, WebLimitHealthy)
}

func TestWebLimiterGrowthGates(t *testing.T) {
	// Busy CPU holds the limit; the run is kept, so the next healthy page
	// after the CPU calms grows it.
	r := newLimitRig(t, 4)
	r.host.set(HostLoad{CPU: 0.70, CPUKnown: true})
	r.busy(30, 1500*time.Millisecond)
	r.want(4, WebLimitStart)
	r.host.set(HostLoad{CPU: 0.69, CPUKnown: true})
	r.advance(webLimitSampleEvery)
	r.busy(1, 1500*time.Millisecond)
	r.want(5, WebLimitHealthy)

	// Memory warn holds too, and unknown CPU does not.
	r = newLimitRig(t, 4)
	r.host.set(HostLoad{Memory: MemoryWarn})
	r.busy(25, 1500*time.Millisecond)
	r.want(4, WebLimitStart)
	r.host.set(HostLoad{})
	r.advance(webLimitSampleEvery)
	r.busy(1, 1500*time.Millisecond)
	r.want(5, WebLimitHealthy)

	// A p90 above 1.25x the baseline but within 2x holds: no growth, no cut.
	r = newLimitRig(t, 8)
	for i := 0; i < 60; i++ {
		r.run(1, time.Second) // the baseline only
	}
	r.busy(40, 1400*time.Millisecond)
	r.want(8, WebLimitStart)
	// One p90 within 1.25x again grows it: the run was kept.
	r.busy(20, 1100*time.Millisecond)
	r.want(9, WebLimitHealthy)

	// Too few proven pages in the last five minutes: no latency rule yet.
	r = newLimitRig(t, 4)
	for i := 0; i < 20; i++ {
		r.run(4, 1500*time.Millisecond)
		r.advance(15 * time.Second)
	}
	r.want(4, WebLimitStart)
}

func TestWebLimiterHalvesOnTimeouts(t *testing.T) {
	r := newLimitRig(t, 8)
	pages := make([]*WebPage, 8)
	for i := range pages {
		pages[i] = r.l.Admit(i + 1)
	}
	pages[0].Hop("web_fetch_failed", 21*time.Second, true)
	// A page counts once, however many of its hops time out.
	pages[0].Hop("web_fetch_failed", 21*time.Second, true)
	r.advance(10 * time.Second)
	pages[1].Done("expired", true)
	r.want(8, WebLimitStart)
	r.advance(10 * time.Second)
	pages[2].Hop("expired", 3*time.Second, true)
	r.want(4, WebLimitTimeouts)
	if len(r.changes) != 1 || r.changes[0].From != 8 || r.changes[0].To != 4 {
		t.Fatalf("changes %+v", r.changes)
	}
	// The other pages were admitted under 8: their timeouts are not new
	// evidence against 4.
	for _, p := range pages[3:] {
		p.Hop("web_connect_failed", 25*time.Second, true)
		p.Done("web_connect_failed", false)
	}
	r.want(4, WebLimitTimeouts)

	// At 4, three timeouts more than 60 s apart do nothing; three within
	// 60 s halve again.
	for i := 0; i < 3; i++ {
		p := r.l.Admit(4)
		p.Done("expired", true)
		r.advance(31 * time.Second)
	}
	r.want(4, WebLimitTimeouts)
	for i := 0; i < 3; i++ {
		r.l.Admit(4).Done("expired", true)
		r.advance(time.Second)
	}
	r.want(2, WebLimitTimeouts)

	// Fast failures are not timeouts, and a failed page leaves the run of
	// healthy pages as it was: the target said nothing about this node.
	r = newLimitRig(t, 4)
	r.busy(10, 1500*time.Millisecond)
	for i := 0; i < 10; i++ {
		p := r.l.Admit(4)
		p.Hop("web_fetch_failed", 300*time.Millisecond, false)
		p.Done("web_fetch_failed", false)
	}
	r.want(4, WebLimitStart)
	r.busy(10, 1500*time.Millisecond)
	r.want(5, WebLimitHealthy)

	// A timeout ends the run: twenty healthy pages must follow it.
	r = newLimitRig(t, 4)
	r.busy(19, 1500*time.Millisecond)
	p := r.l.Admit(4)
	p.Hop("web_fetch_failed", 22*time.Second, true)
	p.Done("web_fetch_failed", false)
	r.busy(19, 1500*time.Millisecond)
	r.want(4, WebLimitStart)
	r.busy(1, 1500*time.Millisecond)
	r.want(5, WebLimitHealthy)
}

func TestWebLimiterHalvesOnVerifierBusy(t *testing.T) {
	r := newLimitRig(t, 16)
	first := r.l.Admit(16)
	for i := 0; i < 5; i++ {
		first.Hop("verifier_busy", 30*time.Millisecond, false)
	}
	r.advance(20 * time.Second)
	r.l.Admit(16).Hop("verifier_busy", 30*time.Millisecond, false)
	r.want(16, WebLimitStart)
	r.advance(20 * time.Second)
	third := r.l.Admit(16)
	third.Hop("verifier_busy", 30*time.Millisecond, false)
	r.want(8, WebLimitVerifierBusy)
	// A page proven after the verifier turned it away is not healthy.
	third.Hop("", 1500*time.Millisecond, false)
	third.Done("", false)
	r.busy(19, 1500*time.Millisecond)
	r.want(8, WebLimitVerifierBusy)
	r.busy(1, 1500*time.Millisecond)
	r.want(9, WebLimitHealthy)
}

func TestWebLimiterHalvesOnLatency(t *testing.T) {
	r := newLimitRig(t, 8)
	for i := 0; i < 200; i++ {
		r.run(1, time.Second) // the baseline only
	}
	r.busy(19, 2500*time.Millisecond)
	r.want(8, WebLimitStart)
	r.busy(1, 2500*time.Millisecond)
	r.want(4, WebLimitLatency)
	// The window starts again at the new limit, against the same baseline.
	r.busy(19, 2500*time.Millisecond)
	r.want(4, WebLimitLatency)
	r.busy(1, 2500*time.Millisecond)
	r.want(2, WebLimitLatency)

	// The baseline trails: once most of its pages are the slow ones, they
	// are the baseline, and a steady p90 grows the limit again.
	r = newLimitRig(t, 8)
	for i := 0; i < 30; i++ {
		r.run(1, time.Second)
	}
	r.busy(20, 2500*time.Millisecond)
	r.want(4, WebLimitLatency)
	r.busy(20, 2500*time.Millisecond)
	r.want(5, WebLimitHealthy)
	// Likewise once the fast pages are older than five minutes.
	r = newLimitRig(t, 8)
	for i := 0; i < 30; i++ {
		r.run(1, time.Second)
	}
	r.advance(webLimitBaseline + time.Second)
	r.busy(20, 2500*time.Millisecond)
	r.want(9, WebLimitHealthy)
}

func TestWebLimiterHalvesOnMemoryPressure(t *testing.T) {
	r := newLimitRig(t, 16)
	r.host.set(HostLoad{Memory: MemoryWarn})
	r.l.Tick()
	r.want(16, WebLimitStart)
	r.host.set(HostLoad{Memory: MemoryCritical})
	r.advance(webLimitSampleEvery)
	r.l.Tick()
	r.want(8, WebLimitMemoryPressure)
	// Pages running when it fell still hold their memory: at most one cut
	// per webLimitPressureHold.
	r.advance(webLimitSampleEvery)
	r.l.Tick()
	r.want(8, WebLimitMemoryPressure)
	r.advance(webLimitPressureHold)
	r.l.Tick()
	r.want(4, WebLimitMemoryPressure)
	// A finishing page applies it too.
	r.advance(webLimitPressureHold)
	r.l.Admit(1).Done("web_dns_failed", false)
	r.want(2, WebLimitMemoryPressure)
	r.advance(webLimitPressureHold)
	r.l.Tick()
	r.want(2, WebLimitMemoryPressure)
	if len(r.changes) != 3 {
		t.Fatalf("changes %+v", r.changes)
	}
	// The host is read at most once a second.
	calls := 0
	counting := &countingHost{calls: &calls}
	l := NewWebLimiter(WebLimitOptions{Min: 2, Start: 4, Max: 16, Host: counting, Now: func() time.Time { return r.at }})
	for i := 0; i < 50; i++ {
		l.Tick()
	}
	if calls != 1 {
		t.Fatal("host sampled", calls, "times in one second")
	}
}

type countingHost struct{ calls *int }

func (h *countingHost) Sample(time.Time) HostLoad { *h.calls++; return HostLoad{} }

func TestWebLimiterBounds(t *testing.T) {
	for start, want := range map[int]int{0: 2, 1: 2, 2: 2, 4: 4, 16: 16, 17: 16, 99: 16} {
		if got := newLimitRig(t, start).l.Limit(); got != want {
			t.Errorf("start %d: %d, want %d", start, got, want)
		}
	}
	r := newLimitRig(t, 16)
	r.busy(60, 1500*time.Millisecond)
	r.want(16, WebLimitStart)
	r = newLimitRig(t, 3)
	for i := 0; i < 3; i++ {
		r.l.Admit(3).Done("expired", true)
	}
	r.want(2, WebLimitTimeouts)
	for i := 0; i < 6; i++ {
		r.l.Admit(2).Done("expired", true)
	}
	r.want(2, WebLimitTimeouts)
	if len(r.changes) != 1 {
		t.Fatalf("a floor halving changed the limit: %+v", r.changes)
	}
}

func TestWebPageCallsAfterDoneAreIgnored(t *testing.T) {
	r := newLimitRig(t, 4)
	for i := 0; i < 20; i++ {
		p := r.l.Admit(4)
		r.advance(time.Second)
		p.Hop("", 1500*time.Millisecond, false)
		p.Done("", false)
		p.Done("", false)
		p.Hop("verifier_busy", time.Millisecond, false)
		p.Hop("expired", time.Minute, true)
	}
	r.want(5, WebLimitHealthy)
	// A page that never ran a hop, such as an invalid lease, is neutral.
	for i := 0; i < 50; i++ {
		r.l.Admit(5).Done("invalid_lease", false)
		r.l.Admit(5).Done("", false)
	}
	r.want(5, WebLimitHealthy)
}

// Pages report from their own goroutines while the pool ticks.
func TestWebLimiterConcurrentPages(t *testing.T) {
	l := NewWebLimiter(WebLimitOptions{Min: 2, Start: 4, Max: 16, Host: &limitHost{}})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				p := l.Admit(l.Limit())
				p.Hop("", time.Duration(1000+i%7)*time.Millisecond, false)
				if (g+i)%97 == 0 {
					p.Hop("verifier_busy", time.Millisecond, false)
				}
				p.Done("", false)
				l.Tick()
			}
		}(g)
	}
	wg.Wait()
	if s := l.Status(); s.Limit < 2 || s.Limit > 16 || !ValidWebLimitReason(s.Reason) {
		t.Fatalf("%+v", s)
	}
}

func TestWebLimitHostSignals(t *testing.T) {
	raw := make([]byte, 24)
	binary.LittleEndian.PutUint32(raw[0:], 6*2048+1024) // 6.5
	binary.LittleEndian.PutUint64(raw[16:], 2048)
	if load, ok := parseLoadavg(raw, 13); !ok || load != 0.5 {
		t.Fatal("loadavg", load, ok)
	}
	if load, ok := parseLoadavg(raw, 4); !ok || load != 1 {
		t.Fatal("loadavg above one per CPU", load, ok)
	}
	for _, bad := range [][]byte{raw[:23], make([]byte, 24)} {
		if _, ok := parseLoadavg(bad, 8); ok {
			t.Fatal("short or unscaled loadavg read")
		}
	}
	if _, ok := parseLoadavg(raw, 0); ok {
		t.Fatal("loadavg without CPUs")
	}

	stat := []byte("cpu  100 20 30 800 50 0 0 0 7 0\ncpu0 1 2 3 4 5 6 7 8 9 10\nintr 1 2 3\n")
	if busy, total, ok := parseProcStat(stat); !ok || busy != 150 || total != 1000 {
		t.Fatal("proc stat", busy, total, ok)
	}
	for _, bad := range []string{"", "cpu0 1 2 3 4 5 6 7 8\n", "cpu 1 2 3\n", "cpu a 2 3 4 5 6 7 8\n", "cpu 0 0 0 0 0 0 0 0\n"} {
		if _, _, ok := parseProcStat([]byte(bad)); ok {
			t.Errorf("proc stat %q read", bad)
		}
	}
	meminfo := []byte("MemTotal:       16000000 kB\nMemFree:         1000000 kB\nMemAvailable:    2000000 kB\nBuffers: x kB\n")
	if available, total, ok := parseMeminfo(meminfo); !ok || available != 2000000 || total != 16000000 {
		t.Fatal("meminfo", available, total, ok)
	}
	for _, bad := range []string{"MemTotal: 100 kB\n", "MemAvailable: 100 kB\n", "MemTotal: 100 kB\nMemAvailable: 200 kB\n", "MemTotal: 0 kB\nMemAvailable: 0 kB\n"} {
		if _, _, ok := parseMeminfo([]byte(bad)); ok {
			t.Errorf("meminfo %q read", bad)
		}
	}
	for percent, want := range map[float64]MemoryLevel{0: MemoryCritical, 4.9: MemoryCritical, 5: MemoryWarn, 14.9: MemoryWarn, 15: MemoryNormal, 52: MemoryNormal, 100: MemoryNormal} {
		if got := memoryLevel(percent); got != want {
			t.Errorf("%v%% available: %v, want %v", percent, got, want)
		}
	}

	var w cpuWindow
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	if _, known := w.observe(at, 100, 1000); known {
		t.Fatal("one reading has no CPU use")
	}
	if _, known := w.observe(at.Add(webCPUSpan-time.Millisecond), 900, 2000); known {
		t.Fatal("CPU use measured over less than its span")
	}
	if use, known := w.observe(at.Add(webCPUSpan), 800, 2000); !known || use != 0.7 {
		t.Fatal("cpu", use, known)
	}
	// Counters that went back start a new span; the last use stands.
	if use, known := w.observe(at.Add(2*webCPUSpan), 10, 20); !known || use != 0.7 {
		t.Fatal("reset", use, known)
	}
	if use, known := w.observe(at.Add(3*webCPUSpan), 20, 40); !known || use != 0.5 {
		t.Fatal("after reset", use, known)
	}
}

func TestWebLimitHostSamplerOnThisHost(t *testing.T) {
	h := NewHostSampler()
	now := time.Now()
	load := h.Sample(now)
	if load.Memory < MemoryNormal || load.Memory > MemoryCritical || load.CPUKnown && (load.CPU < 0 || load.CPU > 1) {
		t.Fatalf("%+v", load)
	}
	if runtime.GOOS == "darwin" && !load.CPUKnown {
		t.Fatal("macOS load average unread")
	}
	if load = h.Sample(now.Add(webCPUSpan)); load.CPUKnown && (load.CPU < 0 || load.CPU > 1) {
		t.Fatalf("%+v", load)
	}
}

// webObserverLog records what a web worker reports to the limit.
type webObserverLog struct {
	mu   sync.Mutex
	hops []string
	done []string
}

func (o *webObserverLog) Hop(code string, wall time.Duration, timedOut bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if wall <= 0 {
		code += "!nowall"
	}
	o.hops = append(o.hops, fmt.Sprintf("%s/%v", code, timedOut))
}

func (o *webObserverLog) Done(code string, timedOut bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.done = append(o.done, fmt.Sprintf("%s/%v", code, timedOut))
}

func (o *webObserverLog) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return fmt.Sprint(o.hops, o.done)
}

// The web worker reports each relay helper run and the page's outcome to the
// lease's observer: proven hops with their wall time, each verifier_busy,
// timeouts, and nothing for a page refused before any hop.
func TestWebWorkerReportsToTheLimit(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	for _, tc := range []struct{ name, mode, want string }{
		{"proven", "web-final", "[/false] [/false]"},
		{"redirect chain", "web-chain", "[/false /false /false] [/false]"},
		{"busy then proven", "web-busy", "[verifier_busy/false verifier_busy/false /false] [/false]"},
		{"fast failure", "web-fetch", "[web_fetch_failed/false] [web_fetch_failed/false]"},
		{"later hop fails", "web-later-fails", "[/false web_fetch_failed/false] [/false]"},
		{"page too large", "web-too-large", "[page_too_large/false] [page_too_large/false]"},
		{"deadline", "web-sleep", "[expired/true] [expired/true]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &webObserverLog{}
			c := webConfig()
			c.WebObserver = log
			l := webFixtureLease(t)
			if tc.mode == "web-sleep" {
				l.LeaseDeadline = time.Now().Add(webReportMargin + 2500*time.Millisecond)
				l.SettlementDeadline = l.LeaseDeadline
			}
			runWeb(t, tc.mode, l, c, publicAnswers)
			if got := log.String(); got != tc.want {
				t.Fatalf("observed %s, want %s", got, tc.want)
			}
		})
	}
	t.Run("refused before any hop", func(t *testing.T) {
		log := &webObserverLog{}
		c := webConfig()
		c.WebObserver = log
		runWeb(t, "web-final", webFixtureLease(t), c, map[string][]netip.Addr{})
		if got := log.String(); got != "[] [web_dns_failed/false]" {
			t.Fatal(got)
		}
		bad := webFixtureLease(t)
		bad.Profile = "other"
		log = &webObserverLog{}
		c.WebObserver = log
		runWeb(t, "web-final", bad, c, publicAnswers)
		if got := log.String(); got != "[] [invalid_lease/false]" {
			t.Fatal(got)
		}
	})
}

// deadlineOnly has a deadline but no error yet, as a context whose deadline
// timer has not fired.
type deadlineOnly struct {
	context.Context
	at time.Time
}

func (d deadlineOnly) Deadline() (time.Time, bool) { return d.at, true }

// A failed helper run is a timeout when the page's deadline ended it or it
// lasted webTimeoutWall or its whole budget; never when cancelled, and never
// for a refusal, a proven hop or a page over the ceiling.
func TestWebHopTimeoutClassification(t *testing.T) {
	classify := func(ctx context.Context, code string, ran time.Duration) string {
		log := &webObserverLog{}
		c := webConfig()
		c.WebObserver = log
		Web{Config: c}.observeHop(ctx, code, time.Now().Add(-ran))
		return log.String()
	}
	background := context.Background()
	for _, tc := range []struct {
		code string
		ran  time.Duration
		want bool
	}{
		{"web_fetch_failed", time.Second, false},
		{"web_fetch_failed", webTimeoutWall, true},
		{"web_connect_failed", 75 * time.Second, true},
		{"web_proxy_failed", 30 * time.Second, true},
		{"verifier_busy", time.Minute, false},
		{"", time.Minute, false},
		{"page_too_large", time.Minute, false},
		{"relay_misuse", time.Minute, false},
		{"prover_error", time.Minute, false},
	} {
		want := fmt.Sprintf("[%s/%v] []", tc.code, tc.want)
		if got := classify(background, tc.code, tc.ran); got != want {
			t.Errorf("%s after %v: %s, want %s", tc.code, tc.ran, got, want)
		}
	}
	// A run that lasted its budget, up to the page deadline, timed out even
	// before the context's own timer has fired.
	if got := classify(deadlineOnly{background, time.Now().Add(-time.Millisecond)}, "web_fetch_failed", 3*time.Second); got != "[web_fetch_failed/true] []" {
		t.Fatal("budget", got)
	}
	if got := classify(deadlineOnly{background, time.Now().Add(time.Second)}, "web_fetch_failed", 3*time.Second); got != "[web_fetch_failed/false] []" {
		t.Fatal("within budget", got)
	}
	expired, cancelExpired := context.WithDeadline(background, time.Now().Add(-time.Millisecond))
	defer cancelExpired()
	if got := classify(expired, "expired", time.Millisecond); got != "[expired/true] []" {
		t.Fatal("deadline", got)
	}
	cancelled, stop := context.WithCancel(background)
	stop()
	if got := classify(cancelled, "expired", time.Minute); got != "[expired/false] []" || !errors.Is(cancelled.Err(), context.Canceled) {
		t.Fatal("cancelled", got)
	}
	// No observer, no report.
	Web{Config: webConfig()}.observeHop(background, "web_fetch_failed", time.Now())
}
