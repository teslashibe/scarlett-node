package diagnostics

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

var errInvalid = errors.New("invalid diagnostic history")

// Read returns a safe local export. It never follows a nonregular history file
// or returns file names, decode errors, or unvalidated data to callers.
func Read(dir string) Snapshot {
	snapshot, _ := read(dir)
	return snapshot
}

// read reports when validated history needs retention cleanup on disk. Read
// remains an export-only operation; the store publishes cleanup asynchronously.
func read(dir string) (Snapshot, bool) {
	empty := Snapshot{Version: Version, Attempts: []Record{}, Summaries: []Summary{}}
	if dir == "" {
		empty.LoadError = "unavailable"
		return empty, false
	}
	path := filepath.Join(dir, historyName)
	if err := localfs.CheckOwnedDir(dir); err != nil {
		empty.LoadError = "io_error"
		return empty, false
	}
	f, err := localfs.OpenPrivate(path)
	if errors.Is(err, os.ErrNotExist) {
		return empty, false
	}
	if err != nil {
		empty.LoadError = "io_error"
		return empty, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		empty.LoadError = "io_error"
		return empty, false
	}
	if info.Size() > MaxHistoryBytes {
		empty.LoadError = "too_large"
		return empty, false
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxHistoryBytes+1))
	if err != nil {
		empty.LoadError = "io_error"
		return empty, false
	}
	if len(raw) > MaxHistoryBytes {
		empty.LoadError = "too_large"
		return empty, false
	}
	var stored history
	if strictJSON(raw, &stored) != nil || !requiredHistoryFields(raw) || stored.Version != Version || stored.UpdatedAt.IsZero() || stored.Attempts == nil || len(stored.Attempts) > MaxAttempts {
		empty.LoadError = "corrupt"
		return empty, false
	}
	now := time.Now()
	expired := false
	seen := make(map[string]bool, len(stored.Attempts))
	for _, record := range stored.Attempts {
		if !validRecord(record) || seen[record.ID] {
			empty.LoadError = "corrupt"
			empty.Attempts = []Record{}
			return empty, false
		}
		seen[record.ID] = true
		record.StartedAt = record.StartedAt.UTC()
		if now.Sub(record.StartedAt) > Retention {
			expired = true
			continue
		}
		record = boundedRecord(record)
		empty.Attempts = append(empty.Attempts, record)
	}
	updatedAt := stored.UpdatedAt.UTC()
	empty.UpdatedAt = &updatedAt
	empty.Summaries = summarize(empty.Attempts)
	return empty, expired
}

// Numeric zero is a legitimate observation only when the field was actually
// present. Decode defaults must not turn omitted or null timings into evidence.
func requiredHistoryFields(raw []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || !present(top, "version", "updated_at", "attempts") {
		return false
	}
	var records []map[string]json.RawMessage
	if json.Unmarshal(top["attempts"], &records) != nil {
		return false
	}
	for _, record := range records {
		if !present(record, "id", "operation", "pages", "proof_mode", "started_at", "outcome", "spans", "missing_phases") {
			return false
		}
		var spans []map[string]json.RawMessage
		if json.Unmarshal(record["spans"], &spans) != nil {
			return false
		}
		for _, span := range spans {
			if !present(span, "phase", "source", "exchange", "start_ms", "duration_ms", "outcome") {
				return false
			}
		}
		if rawQuota, exists := record["quota_snapshots"]; exists {
			var quotas []map[string]json.RawMessage
			if json.Unmarshal(rawQuota, &quotas) != nil {
				return false
			}
			for _, quota := range quotas {
				if !present(quota, "exchange", "operation", "mode", "limit", "remaining", "reset", "complete", "authoritative", "observed_at", "captured_at", "next_eligible_at") {
					return false
				}
			}
		}
	}
	return true
}

func present(fields map[string]json.RawMessage, names ...string) bool {
	for _, name := range names {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

func strictJSON(raw []byte, out any) error {
	if rejectDuplicateKeys(raw) != nil {
		return errInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil || decoder.Decode(new(any)) != io.EOF {
		return errInvalid
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errInvalid
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errInvalid
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errInvalid
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errInvalid
	}
	return nil
}

func (s *Store) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{Version: Version, LoadError: "unavailable", Attempts: []Record{}, Summaries: []Summary{}}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Store) snapshotLocked() Snapshot {
	s.pruneLocked()
	result := Snapshot{Version: Version, LoadError: s.loadError, Attempts: make([]Record, 0, len(s.attempts)), Summaries: []Summary{}}
	if s.updatedAt != nil {
		updated := *s.updatedAt
		result.UpdatedAt = &updated
	}
	now := s.monoNow()
	for _, a := range s.attempts {
		record := a.record
		record.Spans = append([]Span{}, record.Spans...)
		record.QuotaSnapshots = append([]QuotaSnapshot(nil), record.QuotaSnapshots...)
		if record.DurationMS != nil {
			duration := *record.DurationMS
			record.DurationMS = &duration
		}
		for i := range record.Spans {
			span := &record.Spans[i]
			if !a.finished && span.Source == "node" && span.Outcome == "running" {
				span.DurationMS = boundedDuration(now.Sub(a.spanStarts[i]), span.StartMS)
			}
		}
		record = boundedRecord(record)
		result.Attempts = append(result.Attempts, record)
	}
	// Retained record byte bounds and the total history limit are independent of
	// recovery retention. Prefer newer records when the export reaches its cap.
	for len(result.Attempts) > 0 {
		updated := time.Now().UTC()
		if result.UpdatedAt != nil {
			updated = *result.UpdatedAt
		}
		raw, err := json.Marshal(history{Version: Version, UpdatedAt: updated, Attempts: result.Attempts})
		if err == nil && len(raw) <= MaxHistoryBytes {
			break
		}
		result.Attempts = result.Attempts[1:]
	}
	result.Summaries = summarize(result.Attempts)
	return result
}

func boundedRecord(record Record) Record {
	record = derived(record)
	for {
		raw, err := json.Marshal(record)
		if err == nil && len(raw) <= MaxAttemptBytes {
			return record
		}
		if len(record.Spans) == 0 {
			return record
		}
		index := lowestPriority(record.Spans)
		record.Spans = append(record.Spans[:index], record.Spans[index+1:]...)
		record.Truncated = true
		record = derived(record)
	}
}

func derived(record Record) Record {
	record.MissingPhases = []string{}
	seen := make(map[string]bool, len(record.Spans))
	for _, span := range record.Spans {
		seen[span.Phase] = true
	}
	for _, phase := range []string{"account_acquire", "accept_http", "worker", "report_http"} {
		if !seen[phase] {
			record.MissingPhases = append(record.MissingPhases, phase)
		}
	}
	if record.ProofMode != "none" && record.Pages > 0 {
		for _, phase := range []string{"helper_wall", "helper_total"} {
			for exchange := 1; exchange <= record.Pages; exchange++ {
				found := false
				for _, span := range record.Spans {
					if span.Phase == phase && span.Exchange == exchange {
						found = true
						break
					}
				}
				if !found {
					record.MissingPhases = append(record.MissingPhases, phase)
					break
				}
			}
		}
	}
	record.UnclassifiedMS = nil
	if record.DurationMS != nil {
		type interval struct{ start, end float64 }
		intervals := make([]interval, 0, len(record.Spans))
		for _, span := range record.Spans {
			// Helper times have a separate clock origin. Container spans cannot
			// explain their children or hide unmeasured node gaps.
			if span.Source != "node" || span.Phase == "worker" || span.Phase == "page_wall" {
				continue
			}
			start, end := span.StartMS, span.StartMS+span.DurationMS
			if end > *record.DurationMS {
				end = *record.DurationMS
			}
			if start < end {
				intervals = append(intervals, interval{start, end})
			}
		}
		sort.Slice(intervals, func(i, j int) bool { return intervals[i].start < intervals[j].start })
		covered, start, end := 0.0, -1.0, -1.0
		for _, next := range intervals {
			if start < 0 {
				start, end = next.start, next.end
				continue
			}
			if next.start <= end {
				if next.end > end {
					end = next.end
				}
				continue
			}
			covered += end - start
			start, end = next.start, next.end
		}
		if start >= 0 {
			covered += end - start
		}
		unknown := *record.DurationMS - covered
		if unknown < 0 {
			unknown = 0
		}
		record.UnclassifiedMS = &unknown
	}
	return record
}

func summarize(records []Record) []Summary {
	type key struct {
		operation, proof string
		pages            int
	}
	type cohort struct {
		values []float64
		newest time.Time
	}
	groups := map[key]*cohort{}
	for _, record := range records {
		// Success percentiles compare complete attempts. Failure prefixes remain
		// in history but are not folded into a success-latency distribution.
		if record.Outcome != "success" || record.DurationMS == nil {
			continue
		}
		k := key{record.Operation, record.ProofMode, record.Pages}
		group := groups[k]
		if group == nil {
			group = &cohort{}
			groups[k] = group
		}
		group.values = append(group.values, *record.DurationMS)
		if record.StartedAt.After(group.newest) {
			group.newest = record.StartedAt
		}
	}
	result := make([]Summary, 0, len(groups))
	for k, group := range groups {
		sort.Float64s(group.values)
		p50, p95 := percentile(group.values, 50), percentile(group.values, 95)
		result = append(result, Summary{Operation: k.operation, Pages: k.pages, ProofMode: k.proof, Samples: len(group.values), P50MS: &p50, P95MS: &p95, NewestAt: group.newest})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Operation != result[j].Operation {
			return result[i].Operation < result[j].Operation
		}
		if result[i].Pages != result[j].Pages {
			return result[i].Pages < result[j].Pages
		}
		return result[i].ProofMode < result[j].ProofMode
	})
	return result
}

func percentile(sorted []float64, percent int) float64 {
	index := (len(sorted)*percent+99)/100 - 1
	if index < 0 {
		index = 0
	}
	return sorted[index]
}

func priority(phase, source string) int {
	switch phase {
	case "account_acquire", "accept_http", "report_http", "journal_terminal":
		return 10
	case "worker_acquire", "helper_wall", "helper_total", "quota_wait", "pacing_wait":
		return 8
	case "worker", "page_wall", "response_complete", "relay_session":
		return 6
	case "journal_write", "response_decode", "proof_finalize":
		return 4
	case "journal_lock", "journal_scan":
		return 1
	}
	if source == "helper" {
		return 2
	}
	return 3
}

func lowestPriority(spans []Span) int {
	index := 0
	for i := range spans {
		if priority(spans[i].Phase, spans[i].Source) < priority(spans[index].Phase, spans[index].Source) {
			index = i
		}
	}
	return index
}
