// Package attempts persists provider-call boundaries and exact coordinator
// reports. A started record is uncertainty, never permission to repeat work.
package attempts

import (
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
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

const maxRecords = 1024
const maxRecordBytes = 192000
const Retention = 24 * time.Hour

var (
	ErrExists   = errors.New("attempt already journaled; reconcile without provider replay")
	ErrConflict = errors.New("attempt journal identity conflict")
)

// Limits bound private receipt retention. Pending records reserve their full
// encoded record size so committing the provider report cannot consume another
// accepted attempt's space.
type Limits struct {
	MaxRecords     int   `json:"max_records"`
	MaxRecordBytes int   `json:"max_record_bytes"`
	MaxTotalBytes  int64 `json:"max_total_bytes"`
}

func DefaultLimits() Limits { return Limits{maxRecords, maxRecordBytes, 256 << 20} }
func (l Limits) Validate() error {
	if l.MaxRecords < 1 || l.MaxRecords > 1000000 || l.MaxRecordBytes < maxRecordBytes || l.MaxRecordBytes > 1<<20 || l.MaxTotalBytes < int64(l.MaxRecordBytes) || l.MaxTotalBytes > 16<<30 {
		return errors.New("invalid attempt journal limits")
	}
	return nil
}

type Capacity struct {
	Limits           Limits `json:"limits"`
	Records          int    `json:"records"`
	Bytes            int64  `json:"bytes"`
	ReservedBytes    int64  `json:"reserved_bytes"`
	AvailableRecords int    `json:"available_records"`
}

type Record struct {
	ProviderAccountID string    `json:"provider_account_id,omitempty"`
	ProviderService   string    `json:"provider_service,omitempty"`
	JobID             string    `json:"job_id"`
	Attempt           string    `json:"attempt"`
	Fence             string    `json:"fence"`
	Fingerprint       string    `json:"fingerprint"`
	Deadline          time.Time `json:"deadline"`
	State             string    `json:"state"` // started, ready, terminal
	Kind              string    `json:"kind,omitempty"`
	Body              []byte    `json:"body,omitempty"` // base64 on disk preserves exact report bytes
	SubmissionSHA256  string    `json:"submission_sha256,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type Journal struct {
	mu     sync.Mutex
	dir    string
	lock   *os.File
	limits Limits
}

// Open holds an OS lock until Close, including across worker goroutines. A
// crash releases the lock; starting a second process never claims live work.
func Open(dir string) (*Journal, error) { return OpenWithLimits(dir, DefaultLimits()) }
func OpenWithLimits(dir string, limits Limits) (*Journal, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
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
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".write-") {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				j.Close()
				return nil, err
			}
		}
	}
	if _, err := j.Pending(); err != nil {
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
	if r.ProviderAccountID != "" && (!validField(r.ProviderAccountID) || (r.ProviderService != "codex" && r.ProviderService != "x_read")) || r.ProviderAccountID == "" && r.ProviderService != "" {
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
	var r Record
	f, err := localfs.OpenPrivate(name)
	if err != nil {
		return r, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(j.limits.MaxRecordBytes)+1))
	if err != nil {
		return r, err
	}
	if len(data) > j.limits.MaxRecordBytes || json.Unmarshal(data, &r) != nil || !valid(r) || filepath.Base(name) != key(r)+".json" {
		return r, errors.New("invalid attempt record")
	}
	return r, nil
}
func (j *Journal) write(r Record) error {
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
	records, err := j.records()
	if err != nil {
		return err
	}
	var reserved int64
	for _, existing := range records {
		if key(existing) == key(r) {
			continue
		}
		if existing.State != "terminal" {
			reserved += int64(j.limits.MaxRecordBytes)
		} else {
			info, err := os.Stat(filepath.Join(j.dir, key(existing)+".json"))
			if err != nil {
				return err
			}
			reserved += info.Size()
		}
	}
	if r.State != "terminal" {
		reserved += int64(j.limits.MaxRecordBytes)
	} else {
		reserved += int64(len(data))
	}
	if reserved > j.limits.MaxTotalBytes {
		return errors.New("attempt journal storage full")
	}
	return localfs.WriteAtomic(filepath.Join(j.dir, key(r)+".json"), data, true)
}
func (j *Journal) records() ([]Record, error) {
	if j.lock == nil {
		return nil, errors.New("journal closed")
	}
	entries, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, err
	}
	result := []Record{}
	var total int64
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".write-") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			return nil, errors.New("unexpected file in attempt journal")
		}
		r, err := j.read(filepath.Join(j.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		total += info.Size()
		if total > j.limits.MaxTotalBytes {
			return nil, errors.New("attempt journal storage capacity exceeded")
		}
		result = append(result, r)
		if len(result) > j.limits.MaxRecords {
			return nil, errors.New("attempt journal capacity exceeded")
		}
	}
	return result, nil
}
func (j *Journal) capacity(records []Record) (Capacity, error) {
	c := Capacity{Limits: j.limits, Records: len(records)}
	for _, r := range records {
		info, err := os.Stat(filepath.Join(j.dir, key(r)+".json"))
		if err != nil {
			return c, err
		}
		c.Bytes += info.Size()
		if r.State != "terminal" {
			c.ReservedBytes += int64(j.limits.MaxRecordBytes)
		} else {
			c.ReservedBytes += info.Size()
		}
	}
	c.AvailableRecords = min(j.limits.MaxRecords-c.Records, int(max(int64(0), j.limits.MaxTotalBytes-c.ReservedBytes)/int64(j.limits.MaxRecordBytes)))
	return c, nil
}
func (j *Journal) Capacity() (Capacity, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	records, err := j.records()
	if err != nil {
		return Capacity{}, err
	}
	return j.capacity(records)
}

func (j *Journal) Begin(r Record) error {
	j.mu.Lock()
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
		if old.Fingerprint != r.Fingerprint || !old.Deadline.Equal(r.Deadline) || old.ProviderAccountID != r.ProviderAccountID || old.ProviderService != r.ProviderService {
			return ErrConflict
		}
		return ErrExists
	}
	if !os.IsNotExist(err) {
		return err
	}
	records, err := j.records()
	if err != nil {
		return err
	}
	capacity, err := j.capacity(records)
	if err != nil {
		return err
	}
	if capacity.AvailableRecords < 1 {
		return errors.New("attempt journal full; reconcile before accepting work")
	}
	return j.write(r)
}
func (j *Journal) Ready(r Record, kind string, body []byte) (Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	old, err := j.read(filepath.Join(j.dir, key(r)+".json"))
	if err != nil {
		return Record{}, err
	}
	if old.Fingerprint != r.Fingerprint || old.ProviderAccountID != r.ProviderAccountID || old.ProviderService != r.ProviderService {
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
	if err = j.write(old); err != nil {
		return Record{}, err
	}
	return old, nil
}

// Terminal removes private result content immediately, preserving replay metadata.
func (j *Journal) Terminal(r Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	old, err := j.read(filepath.Join(j.dir, key(r)+".json"))
	if err != nil {
		return err
	}
	if old.Fingerprint != r.Fingerprint || old.ProviderAccountID != r.ProviderAccountID || old.ProviderService != r.ProviderService {
		return ErrConflict
	}
	old.State = "terminal"
	old.Body = nil
	old.UpdatedAt = time.Now().UTC()
	return j.write(old)
}
func (j *Journal) Pending() ([]Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	records, err := j.records()
	if err != nil {
		return nil, err
	}
	result := []Record{}
	for _, r := range records {
		if r.State != "terminal" {
			result = append(result, r)
		}
	}
	sort.Slice(result, func(i, k int) bool { return key(result[i]) < key(result[k]) })
	return result, nil
}

// Purge never removes a live uncertain attempt. Expired private bodies are
// removed after retention, while metadata stays until coordinator reconciliation.
func (j *Journal) Purge(now time.Time) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	records, err := j.records()
	if err != nil {
		return err
	}
	for _, r := range records {
		if r.State == "terminal" && now.After(r.Deadline.Add(Retention)) && now.After(r.UpdatedAt.Add(Retention)) {
			if err = os.Remove(filepath.Join(j.dir, key(r)+".json")); err != nil {
				return err
			}
		} else if r.State == "ready" && now.After(r.Deadline.Add(Retention)) {
			r.State = "started"
			r.Kind = ""
			r.Body = nil
			r.SubmissionSHA256 = ""
			r.UpdatedAt = now.UTC()
			if err = j.write(r); err != nil {
				return err
			}
		}
	}
	return localfs.SyncDir(j.dir)
}
