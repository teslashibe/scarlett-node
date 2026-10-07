// Package diagnostics records optional, private operational timings. None of
// these observations are proof, billing, or recovery evidence.
package diagnostics

import (
	"encoding/json"
	"math"
	"time"
)

const (
	Version         = 1
	MaxAttempts     = 200
	MaxSpans        = 64
	MaxExchanges    = 6 // three X pages, or six web hops (five redirects)
	MaxHistoryBytes = 1 << 20
	MaxAttemptBytes = 8 << 10
	MaxHelperBytes  = 8 << 10
	Retention       = 24 * time.Hour
	MaxMilliseconds = float64(Retention / time.Millisecond)
)

type Metadata struct {
	ID        string
	Operation string
	Pages     int
	ProofMode string
}

type Span struct {
	Phase      string  `json:"phase"`
	Source     string  `json:"source"`
	Exchange   int     `json:"exchange"`
	StartMS    float64 `json:"start_ms"`
	DurationMS float64 `json:"duration_ms"`
	Outcome    string  `json:"outcome"`
}

type Record struct {
	ID             string          `json:"id"`
	Operation      string          `json:"operation"`
	Pages          int             `json:"pages"`
	ProofMode      string          `json:"proof_mode"`
	StartedAt      time.Time       `json:"started_at"`
	Outcome        string          `json:"outcome"`
	DurationMS     *float64        `json:"duration_ms,omitempty"`
	Spans          []Span          `json:"spans"`
	MissingPhases  []string        `json:"missing_phases"`
	UnclassifiedMS *float64        `json:"unclassified_ms,omitempty"`
	Truncated      bool            `json:"truncated,omitempty"`
	QuotaSnapshots []QuotaSnapshot `json:"quota_snapshots,omitempty"`
}

type QuotaSnapshot struct {
	ObservedAt     time.Time `json:"observed_at"`
	CapturedAt     time.Time `json:"captured_at"`
	NextEligibleAt time.Time `json:"next_eligible_at"`
	Exchange       int       `json:"exchange"`
	Operation      string    `json:"operation"`
	Mode           string    `json:"mode"`
	Limit          int       `json:"limit"`
	Remaining      int       `json:"remaining"`
	Reset          time.Time `json:"reset"`
	Complete       bool      `json:"complete"`
	Authoritative  bool      `json:"authoritative"`
}

func validQuota(q QuotaSnapshot, started time.Time) bool {
	return q.Exchange >= 1 && q.Exchange <= MaxExchanges && (q.Operation == "search" || q.Operation == "profile" || q.Operation == "post" || q.Operation == "thread") && (q.Mode == "conservative" || q.Mode == "quota_budget") && q.Limit >= 0 && q.Limit <= 1000000000 && q.Remaining >= 0 && q.Remaining <= 1000000000 && (!q.Complete || q.Limit > 0 && q.Remaining <= q.Limit && !q.Reset.IsZero() && !q.ObservedAt.IsZero()) && (!q.Authoritative || !q.Reset.IsZero()) && (q.Reset.IsZero() || !q.Reset.After(started.Add(30*24*time.Hour))) && !q.CapturedAt.IsZero() && !q.CapturedAt.Before(started.Add(-time.Second)) && !q.ObservedAt.After(q.CapturedAt) && (q.NextEligibleAt.IsZero() || !q.NextEligibleAt.After(q.CapturedAt.Add(30*24*time.Hour)))
}

type Summary struct {
	Operation string    `json:"operation"`
	Pages     int       `json:"pages"`
	ProofMode string    `json:"proof_mode"`
	Samples   int       `json:"samples"`
	P50MS     *float64  `json:"p50_ms,omitempty"`
	P95MS     *float64  `json:"p95_ms,omitempty"`
	NewestAt  time.Time `json:"newest_at"`
}

type Snapshot struct {
	Version   int        `json:"version"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	LoadError string     `json:"load_error,omitempty"`
	Attempts  []Record   `json:"attempts"`
	Summaries []Summary  `json:"summaries"`
}

type history struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Attempts  []Record  `json:"attempts"`
}

var operations = words("search", "profile", "post", "thread", "codex", "scrape", "other")
var proofModes = words("relay", "mpc", "none")
var outcomes = words("success", "running", "interrupted", "cancelled", "error", "auth_required", "capacity_unavailable", "expired", "gateway_error", "invalid_gateway_response", "invalid_lease", "prover_error", "usage_out_of_bounds", "x_error", "x_incomplete", "x_rate_limited", "x_reset_wait", "report_error", "journal_error", "accept_error", "report_pending", "rejected", "cache_hit", "cache_miss", "service_unavailable", "x_request_failed", "execution_uncertain", "relay_misuse", "web_egress_denied", "web_dns_failed", "web_connect_failed", "web_proxy_failed", "web_fetch_failed")
var nodePhases = words("worker_acquire", "account_acquire", "accept_http", "worker", "client_acquire", "client_rebuild", "binding_check", "page_wall", "pacing_wait", "quota_wait", "request_encode", "proof_journal_begin", "helper_wall", "helper_stdout_decode", "response_decode", "proof_journal_complete", "journal_lock", "journal_scan", "journal_write", "journal_finish", "journal_ready", "journal_terminal", "report_prepare", "report_http")

func init() {
	for _, phase := range []string{"fixed_gap_wait", "jitter_wait", "quota_spread_wait", "quota_reset_wait"} {
		nodePhases[phase] = true
	}
}

var helperPhases = words("helper_total", "control_config", "verifier_tcp_connect", "verifier_tls", "x_tcp_connect", "relay_session", "x_tls_ready", "ot_ready", "relay_authorization", "request_sent", "response_first_byte", "response_complete", "opening_check", "proof_finalize")

func words(values ...string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, value := range values {
		m[value] = true
	}
	return m
}

func outcome(value string) string {
	if value == "" {
		return "success"
	}
	if !outcomes[value] {
		return "error"
	}
	return value
}

func finiteMS(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= MaxMilliseconds
}

func validSpan(span Span) bool {
	return (span.Source == "node" && nodePhases[span.Phase] || span.Source == "helper" && helperPhases[span.Phase]) && span.Exchange >= 0 && span.Exchange <= MaxExchanges && (span.Source != "helper" || span.Exchange > 0) && finiteMS(span.StartMS) && finiteMS(span.DurationMS) && span.StartMS+span.DurationMS <= MaxMilliseconds && outcomes[span.Outcome]
}

func validRecord(record Record) bool {
	if len(record.QuotaSnapshots) > MaxExchanges {
		return false
	}
	seenQuota := map[int]bool{}
	for _, q := range record.QuotaSnapshots {
		if !validQuota(q, record.StartedAt) || seenQuota[q.Exchange] {
			return false
		}
		seenQuota[q.Exchange] = true
	}
	if len(record.ID) != 64 || !operations[record.Operation] || !proofModes[record.ProofMode] || record.Pages < 0 || record.Pages > MaxExchanges || record.StartedAt.IsZero() || !outcomes[record.Outcome] || len(record.Spans) > MaxSpans || len(record.MissingPhases) > len(nodePhases)+len(helperPhases) {
		return false
	}
	for _, ch := range record.ID {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	if record.DurationMS != nil && !finiteMS(*record.DurationMS) || record.UnclassifiedMS != nil && (!finiteMS(*record.UnclassifiedMS) || record.DurationMS == nil || *record.UnclassifiedMS > *record.DurationMS) {
		return false
	}
	if record.Outcome == "running" && record.DurationMS != nil {
		return false
	}
	for _, span := range record.Spans {
		if !validSpan(span) {
			return false
		}
		if record.DurationMS != nil && span.Source == "node" && span.StartMS+span.DurationMS > *record.DurationMS+0.000001 {
			return false
		}
	}
	for _, phase := range record.MissingPhases {
		if !nodePhases[phase] && !helperPhases[phase] {
			return false
		}
	}
	raw, err := json.Marshal(record)
	return err == nil && len(raw) <= MaxAttemptBytes
}
