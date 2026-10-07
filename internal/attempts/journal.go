// Package attempts persists provider-call boundaries and exact coordinator
// reports. A started record is uncertainty, never permission to repeat work.
package attempts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/teslashibe/scarlett-node/internal/diagnostics"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

const maxRecords = 1024
const maxRecordBytes = 192000
const maxTerminalRecords = 100000
const maxTerminalBytes = 128 << 20
const Retention = 24 * time.Hour

// MinRetention is how long a terminal record always outlives both its lease
// deadline and its acknowledgement. Offers expire at their deadline and every
// executor refuses an expired lease before any provider call, so after this
// margin for clock corrections a record no longer guards a runnable lease.
// Retention governs ordinary removal; only terminal storage over its limits
// removes older receipts sooner, oldest first.
const MinRetention = time.Hour

var (
	ErrExists   = errors.New("attempt already journaled; reconcile without provider replay")
	ErrConflict = errors.New("attempt journal identity conflict")
)

// Limits bound private receipt retention. Live records (started or ready) can
// still need a provider call, proof, report or coordinator reconciliation.
// MaxRecords caps them, and each reserves its full encoded record size so
// committing the provider report cannot consume another accepted attempt's
// space. Terminal records keep only replay metadata; MaxTerminalRecords and
// MaxTerminalBytes bound them separately and they never reserve admission
// space. Zero terminal limits select the defaults. The journal's files stay
// within MaxTotalBytes plus MaxTerminalBytes.
type Limits struct {
	MaxRecords         int   `json:"max_records"`
	MaxRecordBytes     int   `json:"max_record_bytes"`
	MaxTotalBytes      int64 `json:"max_total_bytes"`
	MaxTerminalRecords int   `json:"max_terminal_records"`
	MaxTerminalBytes   int64 `json:"max_terminal_bytes"`
}

func DefaultLimits() Limits {
	return Limits{maxRecords, maxRecordBytes, 256 << 20, maxTerminalRecords, maxTerminalBytes}
}
func (l Limits) Validate() error {
	if l.MaxRecords < 1 || l.MaxRecords > 1000000 || l.MaxRecordBytes < maxRecordBytes || l.MaxRecordBytes > 1<<20 || l.MaxTotalBytes < int64(l.MaxRecordBytes) || l.MaxTotalBytes > 16<<30 {
		return errors.New("invalid attempt journal limits")
	}
	if l.MaxTerminalRecords < 0 || l.MaxTerminalRecords > 1000000 || l.MaxTerminalBytes < 0 || l.MaxTerminalBytes > 16<<30 || l.MaxTerminalBytes != 0 && l.MaxTerminalBytes < int64(l.MaxRecordBytes) {
		return errors.New("invalid attempt journal limits")
	}
	return nil
}
func (l Limits) withDefaults() Limits {
	if l.MaxTerminalRecords == 0 {
		l.MaxTerminalRecords = maxTerminalRecords
	}
	if l.MaxTerminalBytes == 0 {
		l.MaxTerminalBytes = maxTerminalBytes
	}
	return l
}

// Capacity reports admission room. Records, Bytes and ReservedBytes count live
// records only; terminal receipts are counted apart. AvailableRecords is how
// many new attempts Begin accepts now: it falls to zero for live work, or when
// receipts too recent to prune fill terminal storage on their own.
type Capacity struct {
	Limits           Limits `json:"limits"`
	Records          int    `json:"records"`
	Bytes            int64  `json:"bytes"`
	ReservedBytes    int64  `json:"reserved_bytes"`
	TerminalRecords  int    `json:"terminal_records"`
	TerminalBytes    int64  `json:"terminal_bytes"`
	AvailableRecords int    `json:"available_records"`
}

type Record struct {
	ProviderAccountID string        `json:"provider_account_id,omitempty"`
	ProviderService   string        `json:"provider_service,omitempty"`
	JobID             string        `json:"job_id"`
	Attempt           string        `json:"attempt"`
	Fence             string        `json:"fence"`
	Fingerprint       string        `json:"fingerprint"`
	Deadline          time.Time     `json:"deadline"`
	State             string        `json:"state"` // started, ready, terminal
	Kind              string        `json:"kind,omitempty"`
	Body              []byte        `json:"body,omitempty"` // base64 on disk preserves exact report bytes
	SubmissionSHA256  string        `json:"submission_sha256,omitempty"`
	UpdatedAt         time.Time     `json:"updated_at"`
	ProofTraffic      *ProofTraffic `json:"proof_traffic,omitempty"`
	// NoProvider marks an attempt that never runs provider work, such as a
	// rejection. Older readers ignore it and treat the record as unbound.
	NoProvider bool `json:"no_provider,omitempty"`
}

type Journal struct {
	mu     sync.Mutex
	dir    string
	lock   *os.File
	limits Limits
	// index holds every record's accounting fields. The exclusive lock makes
	// this process the only writer, so accounting never rereads every record;
	// a scan still lists the directory and validates any file it has not seen.
	// A failed write or removal clears it until the next full scan.
	index map[string]entry
}

type entry struct {
	state     string
	size      int64
	deadline  time.Time
	updatedAt time.Time
}

func entryOf(r Record, size int64) entry {
	return entry{state: r.State, size: size, deadline: r.Deadline, updatedAt: r.UpdatedAt}
}

// live records may still need provider work, a report or reconciliation.
func (e entry) live() bool { return e.state != "terminal" }

// prunable reports whether a terminal record is past MinRetention.
func (e entry) prunable(now time.Time) bool {
	return !e.live() && now.After(e.deadline.Add(MinRetention)) && now.After(e.updatedAt.Add(MinRetention))
}

// settled orders terminal records by when their lease and acknowledgement
// were both over.
func (e entry) settled() time.Time {
	if e.updatedAt.After(e.deadline) {
		return e.updatedAt
	}
	return e.deadline
}

// Open holds an OS lock until Close, including across worker goroutines. A
// crash releases the lock; starting a second process never claims live work.
func Open(dir string) (*Journal, error) { return OpenWithLimits(dir, DefaultLimits()) }
func OpenWithLimits(dir string, limits Limits) (*Journal, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	limits = limits.withDefaults()
	if _, err := os.Lstat(dir); err == nil {
		if err = localfs.CheckDir(dir); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := localfs.EnsureDir(dir); err != nil {
		return nil, err
	}
	f, err := localfs.LockPrivate(filepath.Join(dir, ".lock"))
	if err != nil {
		return nil, err
	}
	j := &Journal{dir: dir, lock: f, limits: limits}
	// The exclusive lock makes abandoned atomic-write files safe to remove.
	entries, err := os.ReadDir(dir)
	if err != nil {
		j.Close()
		return nil, err
	}
	for _, file := range entries {
		if strings.HasPrefix(file.Name(), ".write-") {
			if err := os.Remove(filepath.Join(dir, file.Name())); err != nil {
				j.Close()
				return nil, err
			}
		}
	}
	// Every record is read and validated once; a bad file refuses to open.
	if err := j.scanContext(context.Background()); err != nil {
		j.Close()
		return nil, err
	}
	if err := j.makeRoom(time.Now()); err != nil {
		j.Close()
		return nil, err
	}
	return j, nil
}
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return nil
	}
	f := j.lock
	j.lock = nil
	return f.Close()
}
func Hash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func key(r Record) string    { return Hash([]byte(r.JobID + "\x00" + r.Attempt + "\x00" + r.Fence)) }

// Key identifies an attempt by job, attempt and fence, as its file name does.
func (r Record) Key() string { return key(r) }

// sameBinding compares the provider binding fixed when the attempt began.
func sameBinding(a, b Record) bool {
	return a.ProviderAccountID == b.ProviderAccountID && a.ProviderService == b.ProviderService && a.NoProvider == b.NoProvider
}
func validField(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, c := range []byte(s) {
		if c < 33 || c > 126 || c == '/' || c == '\\' || c == 0 {
			return false
		}
	}
	return true
}
func validHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func valid(r Record) bool {
	if r.ProofTraffic != nil && !r.ProofTraffic.valid(r.Fingerprint) {
		return false
	}
	if r.ProviderAccountID != "" && (!validField(r.ProviderAccountID) || (r.ProviderService != "codex" && r.ProviderService != "x_read")) || r.ProviderAccountID == "" && r.ProviderService != "" || r.NoProvider && r.ProviderAccountID != "" {
		return false
	}
	if !validField(r.JobID) || !validField(r.Attempt) || !validField(r.Fence) || !validHash(r.Fingerprint) || r.Deadline.IsZero() || r.UpdatedAt.IsZero() {
		return false
	}
	switch r.State {
	case "started":
		return r.Kind == "" && len(r.Body) == 0 && r.SubmissionSHA256 == ""
	case "ready":
		return (r.Kind == "proven" || r.Kind == "fail" || r.Kind == "result") && len(r.Body) > 0 && len(r.Body) <= 131072 && json.Valid(r.Body) && Hash(r.Body) == r.SubmissionSHA256
	case "terminal":
		return len(r.Body) == 0 && (r.SubmissionSHA256 == "" || validHash(r.SubmissionSHA256))
	default:
		return false
	}
}
func (j *Journal) read(name string) (Record, error) {
	r, _, err := j.readSized(name)
	return r, err
}
func (j *Journal) readSized(name string) (Record, int64, error) {
	var r Record
	f, err := localfs.OpenPrivate(name)
	if err != nil {
		return r, 0, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(j.limits.MaxRecordBytes)+1))
	if err != nil {
		return r, 0, err
	}
	if len(data) > j.limits.MaxRecordBytes || json.Unmarshal(data, &r) != nil || !valid(r) || filepath.Base(name) != key(r)+".json" {
		return r, 0, errors.New("invalid attempt record")
	}
	return r, int64(len(data)), nil
}
func (j *Journal) path(k string) string { return filepath.Join(j.dir, k+".json") }
func (j *Journal) write(r Record) error {
	return j.writeContext(context.Background(), r)
}

func (j *Journal) writeContext(ctx context.Context, r Record) error {
	if j.lock == nil {
		return errors.New("journal closed")
	}
	if !valid(r) {
		return errors.New("invalid attempt record")
	}
	data, err := json.Marshal(r)
	if err != nil || len(data) > j.limits.MaxRecordBytes {
		return errors.New("attempt record too large")
	}
	if j.index == nil {
		if err := j.scanContext(ctx); err != nil {
			return err
		}
	}
	k := key(r)
	// A live record reserves a full record. A terminal one only shrinks the
	// record it replaces, so finishing an attempt never waits for space.
	if r.State != "terminal" {
		reserved := int64(j.limits.MaxRecordBytes)
		for other, e := range j.index {
			if other != k && e.live() {
				reserved += int64(j.limits.MaxRecordBytes)
			}
		}
		if reserved > j.limits.MaxTotalBytes {
			return errors.New("attempt journal storage full")
		}
	}
	finish := diagnostics.Start(ctx, "journal_write", 0)
	err = localfs.WriteAtomic(j.path(k), data, true)
	finish(journalOutcome(err))
	if err != nil {
		// The file may or may not have changed. Read it again before trusting
		// accounting.
		j.index = nil
		return err
	}
	j.index[k] = entryOf(r, int64(len(data)))
	return nil
}

// scanContext lists the journal directory against the index. A record file
// the index lacks is read and validated, an indexed file that is gone is
// dropped, and any other entry fails closed. With no index it reads them all.
func (j *Journal) scanContext(ctx context.Context) (err error) {
	finish := diagnostics.Start(ctx, "journal_scan", 0)
	defer func() { finish(journalOutcome(err)) }()
	if j.lock == nil {
		return errors.New("journal closed")
	}
	dir, err := os.Open(j.dir)
	if err != nil {
		return err
	}
	names, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		return err
	}
	index := j.index
	if index == nil {
		index = make(map[string]entry, len(names))
	}
	seen := make(map[string]bool, len(names))
	unread := []string{}
	for _, name := range names {
		if name == ".lock" || strings.HasPrefix(name, ".write-") {
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			return errors.New("unexpected file in attempt journal")
		}
		k := strings.TrimSuffix(name, ".json")
		seen[k] = true
		if _, ok := index[k]; !ok {
			unread = append(unread, name)
		}
	}
	records, sizes, err := j.readAll(unread)
	if err != nil {
		return err
	}
	for i, r := range records {
		index[key(r)] = entryOf(r, sizes[i])
	}
	live := 0
	var bytes int64
	for k, e := range index {
		if !seen[k] {
			delete(index, k)
		} else if e.live() {
			live++
			bytes += e.size
		}
	}
	j.index = index
	if live > j.limits.MaxRecords {
		return errors.New("attempt journal capacity exceeded")
	}
	if bytes > j.limits.MaxTotalBytes {
		return errors.New("attempt journal storage capacity exceeded")
	}
	return nil
}

// readAll reads and validates record files on a few goroutines. Opening a
// file can cost far more than reading it, so a journal holding a day of
// receipts would otherwise take many seconds to open.
func (j *Journal) readAll(names []string) ([]Record, []int64, error) {
	records := make([]Record, len(names))
	sizes := make([]int64, len(names))
	errs := make([]error, len(names))
	var next atomic.Int64
	var wg sync.WaitGroup
	for range min(len(names), 8) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := int(next.Add(1)) - 1; i < len(names); i = int(next.Add(1)) - 1 {
				records[i], sizes[i], errs[i] = j.readSized(filepath.Join(j.dir, names[i]))
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, nil, err
		}
	}
	return records, sizes, nil
}

func (j *Journal) capacity(now time.Time) Capacity {
	c := Capacity{Limits: j.limits}
	var recent int
	var recentBytes int64
	for _, e := range j.index {
		if e.live() {
			c.Records++
			c.Bytes += e.size
			c.ReservedBytes += int64(j.limits.MaxRecordBytes)
			continue
		}
		c.TerminalRecords++
		c.TerminalBytes += e.size
		if !e.prunable(now) {
			recent++
			recentBytes += e.size
		}
	}
	c.AvailableRecords = max(0, min(j.limits.MaxRecords-c.Records, int(max(int64(0), j.limits.MaxTotalBytes-c.ReservedBytes)/int64(j.limits.MaxRecordBytes))))
	// Older receipts are pruned to make room. Receipts within MinRetention may
	// still guard a runnable lease, so only when they alone fill terminal
	// storage does admission wait for them to age.
	if recent >= j.limits.MaxTerminalRecords || recentBytes >= j.limits.MaxTerminalBytes {
		c.AvailableRecords = 0
	}
	return c
}
func (j *Journal) Capacity() (Capacity, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.index == nil {
		if err := j.scanContext(context.Background()); err != nil {
			return Capacity{}, err
		}
	}
	return j.capacity(time.Now()), nil
}

// trimTerminal removes receipts past MinRetention, oldest first, until
// terminal records number at most keepRecords and take at most keepBytes, or
// no older receipt is left. Live records are never candidates.
func (j *Journal) trimTerminal(now time.Time, keepRecords int, keepBytes int64) error {
	var records int
	var bytes int64
	for _, e := range j.index {
		if !e.live() {
			records++
			bytes += e.size
		}
	}
	if records <= keepRecords && bytes <= keepBytes {
		return nil
	}
	type candidate struct {
		key string
		entry
	}
	old := []candidate{}
	for k, e := range j.index {
		if e.prunable(now) {
			old = append(old, candidate{k, e})
		}
	}
	sort.Slice(old, func(a, b int) bool {
		if !old[a].settled().Equal(old[b].settled()) {
			return old[a].settled().Before(old[b].settled())
		}
		return old[a].key < old[b].key
	})
	removed := false
	for _, c := range old {
		if records <= keepRecords && bytes <= keepBytes {
			break
		}
		if err := os.Remove(j.path(c.key)); err != nil && !os.IsNotExist(err) {
			j.index = nil
			return err
		}
		delete(j.index, c.key)
		records--
		bytes -= c.size
		removed = true
	}
	if !removed {
		return nil
	}
	return localfs.SyncDir(j.dir)
}

// makeRoom trims terminal storage just below its limits, so one more attempt
// can finish within them.
func (j *Journal) makeRoom(now time.Time) error {
	return j.trimTerminal(now, j.limits.MaxTerminalRecords-1, j.limits.MaxTerminalBytes-1)
}

func (j *Journal) Begin(r Record) error {
	return j.BeginContext(context.Background(), r)
}

// BeginContext records local timings without changing the durable attempt.
func (j *Journal) BeginContext(ctx context.Context, r Record) error {
	j.lockContext(ctx)
	defer j.mu.Unlock()
	r.State = "started"
	r.Kind = ""
	r.Body = nil
	r.SubmissionSHA256 = ""
	r.UpdatedAt = time.Now().UTC()
	if !valid(r) {
		return errors.New("invalid attempt identity")
	}
	old, err := j.read(filepath.Join(j.dir, key(r)+".json"))
	if err == nil {
		if old.Fingerprint != r.Fingerprint || !old.Deadline.Equal(r.Deadline) || !sameBinding(old, r) {
			return ErrConflict
		}
		return ErrExists
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err := j.scanContext(ctx); err != nil {
		return err
	}
	now := time.Now()
	if err := j.makeRoom(now); err != nil {
		return err
	}
	if j.capacity(now).AvailableRecords < 1 {
		return errors.New("attempt journal full; reconcile before accepting work")
	}
	return j.writeContext(ctx, r)
}
func (j *Journal) Ready(r Record, kind string, body []byte) (Record, error) {
	return j.ReadyContext(context.Background(), r, kind, body)
}

// ReadyContext preserves the exact report bytes while recording local timings.
func (j *Journal) ReadyContext(ctx context.Context, r Record, kind string, body []byte) (Record, error) {
	j.lockContext(ctx)
	defer j.mu.Unlock()
	old, err := j.read(filepath.Join(j.dir, key(r)+".json"))
	if err != nil {
		return Record{}, err
	}
	if old.Fingerprint != r.Fingerprint || !sameBinding(old, r) {
		return Record{}, ErrConflict
	}
	if old.State != "started" {
		if old.State == "ready" && old.Kind == kind && old.SubmissionSHA256 == Hash(body) {
			return old, nil
		}
		return Record{}, ErrConflict
	}
	old.State = "ready"
	old.Kind = kind
	old.Body = append([]byte(nil), body...)
	old.SubmissionSHA256 = Hash(body)
	old.UpdatedAt = time.Now().UTC()
	if err = j.writeContext(ctx, old); err != nil {
		return Record{}, err
	}
	return old, nil
}

// Terminal removes private result content immediately, preserving replay metadata.
func (j *Journal) Terminal(r Record) error {
	return j.TerminalContext(context.Background(), r)
}

// TerminalContext records local timings while removing private result content.
func (j *Journal) TerminalContext(ctx context.Context, r Record) error {
	j.lockContext(ctx)
	defer j.mu.Unlock()
	old, err := j.read(filepath.Join(j.dir, key(r)+".json"))
	if err != nil {
		return err
	}
	if old.Fingerprint != r.Fingerprint || !sameBinding(old, r) {
		return ErrConflict
	}
	old.State = "terminal"
	old.Body = nil
	old.UpdatedAt = time.Now().UTC()
	return j.writeContext(ctx, old)
}
func (j *Journal) Pending() ([]Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.index == nil {
		if err := j.scanContext(context.Background()); err != nil {
			return nil, err
		}
	}
	result := []Record{}
	for k, e := range j.index {
		if !e.live() {
			continue
		}
		r, err := j.read(j.path(k))
		if os.IsNotExist(err) {
			delete(j.index, k)
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	sort.Slice(result, func(i, k int) bool { return key(result[i]) < key(result[k]) })
	return result, nil
}

// Purge never removes a live uncertain attempt. Expired private bodies are
// removed after retention, while metadata stays until coordinator
// reconciliation. Terminal metadata goes once both its deadline and its
// acknowledgement are Retention old, or sooner, oldest first and never before
// MinRetention, while terminal storage is above seven eighths of its limits.
func (j *Journal) Purge(now time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.scanContext(context.Background()); err != nil {
		return err
	}
	var expired, unready []string
	for k, e := range j.index {
		if e.state == "terminal" && now.After(e.deadline.Add(Retention)) && now.After(e.updatedAt.Add(Retention)) {
			expired = append(expired, k)
		} else if e.state == "ready" && now.After(e.deadline.Add(Retention)) {
			unready = append(unready, k)
		}
	}
	for _, k := range expired {
		if err := os.Remove(j.path(k)); err != nil && !os.IsNotExist(err) {
			j.index = nil
			return err
		}
		delete(j.index, k)
	}
	for _, k := range unready {
		r, err := j.read(j.path(k))
		if err != nil {
			return err
		}
		r.State = "started"
		r.Kind = ""
		r.Body = nil
		r.SubmissionSHA256 = ""
		r.UpdatedAt = now.UTC()
		if err = j.write(r); err != nil {
			return err
		}
	}
	// Trimming to seven eighths every purge keeps removals small and leaves
	// admission room to spare.
	l := j.limits
	if err := j.trimTerminal(now, l.MaxTerminalRecords-max(1, l.MaxTerminalRecords/8), l.MaxTerminalBytes-l.MaxTerminalBytes/8); err != nil {
		return err
	}
	return localfs.SyncDir(j.dir)
}

// lockContext measures only the wait for the journal's existing mutex.
func (j *Journal) lockContext(ctx context.Context) {
	finish := diagnostics.Start(ctx, "journal_lock", 0)
	j.mu.Lock()
	finish("success")
}

func journalOutcome(err error) string {
	if err != nil {
		return "error"
	}
	return "success"
}
