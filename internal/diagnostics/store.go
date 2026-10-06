package diagnostics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sync"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

const historyName = "diagnostics-v1.json"

// Store coalesces optional diagnostics separately from the recovery journal.
// Recording a phase never performs filesystem I/O.
type Store struct {
	mu            sync.Mutex
	flushMu       sync.Mutex
	closeOnce     sync.Once
	closeDone     chan struct{}
	dir           string
	attempts      []*Attempt
	dirty         bool
	lastFlush     time.Time
	updatedAt     *time.Time
	loadError     string
	retainedBytes int
	wallNow       func() time.Time
	monoNow       func() time.Time
}

type Attempt struct {
	store           *Store
	record          Record
	started         time.Time
	spanStarts      []time.Time
	spanGenerations []uint64
	finished        bool
	retained        bool
}

// New loads only bounded, private, validated history. An unavailable or corrupt
// file affects diagnostics status; it cannot prevent provider work.
func New(dir string) *Store {
	s := &Store{dir: dir, attempts: make([]*Attempt, 0), wallNow: time.Now, monoNow: time.Now, closeDone: make(chan struct{})}
	snapshot := Read(dir)
	s.loadError, s.updatedAt = snapshot.LoadError, snapshot.UpdatedAt
	for _, record := range snapshot.Attempts {
		if record.Outcome == "running" {
			record.Outcome = "interrupted"
			record.DurationMS, record.UnclassifiedMS = nil, nil
			for i := range record.Spans {
				if record.Spans[i].Outcome == "running" {
					record.Spans[i].Outcome = "interrupted"
				}
			}
			s.changedLocked()
		}
		s.attempts = append(s.attempts, &Attempt{store: s, record: record, finished: true, retained: true})
		s.retainedBytes += 700 + len(record.Spans)*144
	}
	for s.retainedBytes > MaxHistoryBytes {
		s.dropOldestLocked()
		s.changedLocked()
	}
	return s
}

func (s *Store) Begin(meta Metadata) *Attempt {
	if s == nil || len(meta.ID) == 0 || len(meta.ID) > 512 || !operations[meta.Operation] || !proofModes[meta.ProofMode] || meta.Pages < 0 || meta.Pages > MaxExchanges {
		return nil
	}
	id := meta.ID
	if !validKey(id) {
		key := sha256.Sum256([]byte(id))
		id = hex.EncodeToString(key[:])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	for _, old := range s.attempts {
		if old.record.ID == id {
			return nil
		}
	}
	for len(s.attempts) >= MaxAttempts || s.retainedBytes+700 > MaxHistoryBytes {
		s.dropOldestLocked()
	}
	a := &Attempt{store: s, started: s.monoNow(), retained: true, record: Record{ID: id, Operation: meta.Operation, Pages: meta.Pages, ProofMode: meta.ProofMode, StartedAt: s.wallNow().UTC(), Outcome: "running", Spans: make([]Span, 0), MissingPhases: make([]string, 0)}}
	s.attempts = append(s.attempts, a)
	s.retainedBytes += 700
	s.changedLocked()
	return a
}

type attemptKey struct{}

func (a *Attempt) Context(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil {
		return ctx
	}
	return context.WithValue(ctx, attemptKey{}, a)
}

func fromContext(ctx context.Context) *Attempt {
	if ctx == nil {
		return nil
	}
	a, _ := ctx.Value(attemptKey{}).(*Attempt)
	return a
}

// Enabled allows integrations to skip optional observer/context allocations.
func Enabled(ctx context.Context) bool { return fromContext(ctx) != nil }

var noop = func(string) {}

// Start records a measured prefix immediately, including when the phase later
// fails. Invalid phase names and absent context are cheap no-ops.
func Start(ctx context.Context, phase string, exchange int) func(string) {
	a := fromContext(ctx)
	if a == nil || !nodePhases[phase] || exchange < 0 || exchange > MaxExchanges {
		return noop
	}
	s := a.store
	s.mu.Lock()
	if a.finished || !a.retained {
		s.mu.Unlock()
		return noop
	}
	index := a.spanSlotLocked(phase, "node")
	if index < 0 {
		s.mu.Unlock()
		return noop
	}
	now := s.monoNow()
	a.record.Spans[index] = Span{Phase: phase, Source: "node", Exchange: exchange, StartMS: milliseconds(now.Sub(a.started)), Outcome: "running"}
	a.spanStarts[index] = now
	a.spanGenerations[index]++
	generation := a.spanGenerations[index]
	s.changedLocked()
	s.mu.Unlock()
	var once sync.Once
	return func(code string) {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			if a.finished || !a.retained || a.spanGenerations[index] != generation {
				return
			}
			span := &a.record.Spans[index]
			span.DurationMS = boundedDuration(s.monoNow().Sub(now), span.StartMS)
			span.Outcome = outcome(code)
			s.changedLocked()
		})
	}
}

func (a *Attempt) Finish(code string) {
	if a == nil {
		return
	}
	s := a.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if a.finished || !a.retained {
		return
	}
	now := s.monoNow()
	a.finished = true
	a.record.Outcome = outcome(code)
	if a.record.Outcome == "running" {
		a.record.Outcome = "interrupted"
	}
	duration := milliseconds(now.Sub(a.started))
	a.record.DurationMS = &duration
	for i := range a.record.Spans {
		span := &a.record.Spans[i]
		if span.Source == "node" && span.Outcome == "running" {
			span.DurationMS = boundedDuration(now.Sub(a.spanStarts[i]), span.StartMS)
			span.Outcome = "interrupted"
			if a.record.Outcome == "cancelled" {
				span.Outcome = "cancelled"
			}
		}
	}
	s.changedLocked()
}

func (a *Attempt) spanSlotLocked(phase, source string) int {
	// Conservative wire accounting bounds memory while recording without JSON
	// encoding in the provider hot path. Export applies the exact byte bound too.
	if len(a.record.Spans) >= MaxSpans || 700+(len(a.record.Spans)+1)*144 > MaxAttemptBytes || a.store.retainedBytes+144 > MaxHistoryBytes {
		a.record.Truncated = true
		a.store.changedLocked()
		if len(a.record.Spans) == 0 {
			return -1
		}
		index := lowestPriority(a.record.Spans)
		if priority(phase, source) <= priority(a.record.Spans[index].Phase, a.record.Spans[index].Source) {
			return -1
		}
		return index
	}
	index := len(a.record.Spans)
	a.record.Spans = append(a.record.Spans, Span{})
	a.spanStarts = append(a.spanStarts, time.Time{})
	a.spanGenerations = append(a.spanGenerations, 0)
	a.store.retainedBytes += 144
	return index
}

func validKey(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, ch := range id {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}

func milliseconds(duration time.Duration) float64 {
	if duration < 0 {
		return 0
	}
	if duration > Retention {
		return MaxMilliseconds
	}
	return float64(duration.Microseconds()) / 1000
}

func boundedDuration(duration time.Duration, start float64) float64 {
	value := milliseconds(duration)
	if value > MaxMilliseconds-start {
		return MaxMilliseconds - start
	}
	return value
}

func (s *Store) changedLocked() { s.dirty = true; now := s.wallNow().UTC(); s.updatedAt = &now }

func (s *Store) dropOldestLocked() {
	index := 0
	for i, a := range s.attempts {
		if a.finished {
			index = i
			break
		}
	}
	s.attempts[index].retained = false
	s.retainedBytes -= 700 + len(s.attempts[index].record.Spans)*144
	s.attempts = append(s.attempts[:index], s.attempts[index+1:]...)
}

func (s *Store) pruneLocked() {
	now := s.wallNow()
	retained := s.attempts[:0]
	for _, a := range s.attempts {
		// Active records use monotonic age; persisted records use wall-clock age.
		old := now.Sub(a.record.StartedAt) > Retention
		if !a.started.IsZero() {
			old = s.monoNow().Sub(a.started) > Retention
		}
		if old {
			a.retained = false
			s.retainedBytes -= 700 + len(a.record.Spans)*144
			s.dirty = true
			continue
		}
		retained = append(retained, a)
	}
	s.attempts = retained
}

// Run flushes at most once per second. Cancellation does not affect jobs; Close
// performs a bounded final flush after callers have stopped recording.
func (s *Store) Run(ctx context.Context) {
	if s == nil || ctx == nil {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closeDone:
			return
		case <-ticker.C:
			s.flush(false)
		}
	}
}

func (s *Store) Close() {
	if s == nil {
		return
	}
	s.closeOnce.Do(func() { go func() { defer close(s.closeDone); s.flush(true) }() })
	// A stuck filesystem must not hold node shutdown open. Coalescing can use
	// up to one second of this budget; any unfinished snapshot remains optional.
	timer := time.NewTimer(1500 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-s.closeDone:
	case <-timer.C:
	}
}

func (s *Store) flush(final bool) {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	if !s.dirty || s.dir == "" {
		s.mu.Unlock()
		return
	}
	remaining := time.Second - time.Since(s.lastFlush)
	s.mu.Unlock()
	if remaining > 0 {
		if !final {
			return
		}
		time.Sleep(remaining)
	}
	s.mu.Lock()
	snapshot := s.snapshotLocked()
	updated := s.wallNow().UTC()
	s.dirty = false
	s.lastFlush = time.Now()
	s.mu.Unlock()
	raw, err := json.Marshal(history{Version: Version, UpdatedAt: updated, Attempts: snapshot.Attempts})
	if err == nil && len(raw) > MaxHistoryBytes {
		err = errInvalid
	}
	if err == nil {
		err = writePrivate(s.dir, raw)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.loadError = "write_error"
		s.dirty = true
	} else {
		s.loadError = ""
	}
}

func writePrivate(dir string, raw []byte) error {
	if err := localfs.CheckOwnedDir(dir); err != nil {
		return err
	}
	// Reuse platform-specific private ACL/ownership and publication guarantees.
	// Durable writes are coalesced here, never added to a phase or provider call.
	return localfs.WriteAtomic(filepath.Join(dir, historyName), raw, true)
}
