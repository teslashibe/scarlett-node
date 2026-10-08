package webruntime

import (
	"encoding/json"
	"io"
	"path/filepath"
	"slices"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// SolverProviders are the captcha-solver providers the helper's router knows.
var SolverProviders = []string{"capmonster", "capsolver", "2captcha"}

// Solvers is the operator's own captcha-solver accounts. The helper gets the
// keys in WEB_SOLVER_CONFIG, takes the variable out of its environment before
// the driver or the browser start, and sends each key only to its provider.
// Keys are never logged, never in a result and never reported; String and
// GoString redact the whole value.
type Solvers struct {
	// Keys maps a provider in SolverProviders to its key.
	Keys map[string]string
	// MaxSolvesPerFetch bounds paid solves on one page (1-4).
	MaxSolvesPerFetch int
	// MaxMicroUSDPerDay bounds the providers' estimated spend per UTC day.
	// Once it is reached the helper gets no solver until the next day, and
	// the heartbeat stops naming the providers.
	MaxMicroUSDPerDay int64
	// Experimental lets the router take challenge kinds its providers do not
	// document as stable.
	Experimental bool
}

func (Solvers) String() string   { return "web solvers [redacted]" }
func (Solvers) GoString() string { return "webruntime.Solvers{}" }

// Providers are the configured providers, in SolverProviders order.
func (s *Solvers) Providers() []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, name := range SolverProviders {
		if s.Keys[name] != "" {
			out = append(out, name)
		}
	}
	return out
}

func (s *Solvers) valid() bool {
	if s == nil || len(s.Providers()) == 0 || len(s.Providers()) != len(s.Keys) || s.MaxSolvesPerFetch < 1 || s.MaxSolvesPerFetch > 4 || s.MaxMicroUSDPerDay < 1 {
		return false
	}
	return true
}

// helperConfig is WEB_SOLVER_CONFIG: the keys and the router options.
func (s *Solvers) helperConfig() string {
	config := map[string]any{"max_solves_per_fetch": s.MaxSolvesPerFetch, "experimental": s.Experimental}
	for _, name := range s.Providers() {
		config[name] = s.Keys[name]
	}
	raw, _ := json.Marshal(config)
	return string(raw)
}

// maxFetchMicroUSD bounds one fetch's reported spend: a fresh-context retry
// can add a second helper pass of at most $10.
const maxFetchMicroUSD = 20_000_000

// spendFile keeps the day's solver spend across node restarts.
const spendFile = "solver-spend.json"

type spendRecord struct {
	Day      string `json:"day"`
	MicroUSD int64  `json:"micro_usd"`
}

// day is the UTC calendar day of t.
func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// spentLocked is today's recorded spend, read from the state file once.
// Caller holds m.mu.
func (m *Manager) spentLocked() int64 {
	today := day(m.d.now())
	if !m.spendLoaded {
		m.spendLoaded = true
		if f, err := localfs.OpenPrivate(filepath.Join(m.cfg.StateDir, "web-browser", spendFile)); err == nil {
			var r spendRecord
			if json.NewDecoder(io.LimitReader(f, 4096)).Decode(&r) == nil && r.MicroUSD >= 0 {
				m.spend = r
			}
			f.Close()
		}
	}
	if m.spend.Day != today {
		m.spend = spendRecord{Day: today}
	}
	return m.spend.MicroUSD
}

// solverAllowedLocked reports whether the next fetch may use the operator's
// solver: one is configured and today's spend is under the cap. Caller holds
// m.mu.
func (m *Manager) solverAllowedLocked() bool {
	s := m.cfg.Solvers
	return s.valid() && m.spentLocked() < s.MaxMicroUSDPerDay
}

// recordSpend adds a fetch's estimated solver spend to today's and keeps it
// in the private state file. A failed write keeps the in-memory total.
func (m *Manager) recordSpend(micro int64) {
	if micro <= 0 {
		return
	}
	m.mu.Lock()
	m.spentLocked()
	m.spend.MicroUSD += micro
	record := m.spend
	reached := m.cfg.Solvers.valid() && record.MicroUSD >= m.cfg.Solvers.MaxMicroUSDPerDay
	m.mu.Unlock()
	if raw, err := json.Marshal(record); err == nil {
		dir := filepath.Join(m.cfg.StateDir, "web-browser")
		if privateDir(dir) == nil {
			_ = localfs.WriteAtomic(filepath.Join(dir, spendFile), append(raw, '\n'), true)
		}
	}
	if reached {
		m.cfg.Logf("web browser: solver daily cap reached")
	}
}

// solversMatch reports whether the providers a helper built are the
// configured ones.
func (m *Manager) solversMatch(built []string) bool {
	want := slices.Clone(m.cfg.Solvers.Providers())
	got := slices.Clone(built)
	slices.Sort(want)
	slices.Sort(got)
	return slices.Equal(want, got)
}

// solverEnv is the helper's WEB_SOLVER_CONFIG entry, or nothing.
func (m *Manager) solverEnv() []string {
	if !m.cfg.Solvers.valid() {
		return nil
	}
	return []string{"WEB_SOLVER_CONFIG=" + m.cfg.Solvers.helperConfig()}
}
