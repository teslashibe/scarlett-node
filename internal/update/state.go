package update

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// Phases of one install, in order. A pending update moves forward only:
// staged → draining → handoff → installed → verifying → healthy, or to
// unhealthy → rolled_back, or to failed when nothing was replaced.
const (
	PhaseStaged     = "staged"
	PhaseDraining   = "draining"
	PhaseHandoff    = "handoff"
	PhaseInstalled  = "installed"
	PhaseVerifying  = "verifying"
	PhaseHealthy    = "healthy"
	PhaseUnhealthy  = "unhealthy"
	PhaseRolledBack = "rolled_back"
	PhaseFailed     = "failed"
)

var phases = []string{PhaseStaged, PhaseDraining, PhaseHandoff, PhaseInstalled, PhaseVerifying, PhaseHealthy, PhaseUnhealthy, PhaseRolledBack, PhaseFailed}

// Pending is the install in progress, if any.
type Pending struct {
	Phase string `json:"phase"`
	From  string `json:"from"`
	To    string `json:"to"`
	// Kind is mac-app, nsis or headless.
	Kind string `json:"kind"`
	// Staged is the verified new bundle or installer; App is the installed
	// app bundle or executable it replaces; Previous is the rollback source.
	Staged   string `json:"staged,omitempty"`
	App      string `json:"app,omitempty"`
	Previous string `json:"previous,omitempty"`
	// DrainOwner is updater when the updater paused new work and must resume
	// it, operator when the operator had already paused, else none.
	DrainOwner    string    `json:"drain_owner"`
	ResumeServing bool      `json:"resume_serving"`
	AppPID        int       `json:"app_pid,omitempty"`
	GuardPID      int       `json:"guard_pid,omitempty"`
	StartedAt     time.Time `json:"started_at"`
	Reason        string    `json:"reason,omitempty"`
}

// Snooze hides an optional update until a time.
type Snooze struct {
	Version string    `json:"version"`
	Until   time.Time `json:"until"`
}

// Seen records when this device first saw a release, for the staged rollout.
type Seen struct {
	Version string    `json:"version"`
	At      time.Time `json:"at"`
}

// State is the private update-state.json.
type State struct {
	Schema int `json:"schema"`
	// Installed and HighWater are the last version that reported healthy;
	// nothing below HighWater is installed again except by rollback.
	Installed string   `json:"installed,omitempty"`
	HighWater string   `json:"high_water,omitempty"`
	Announced string   `json:"announced,omitempty"`
	Snooze    *Snooze  `json:"snooze,omitempty"`
	FirstSeen *Seen    `json:"first_seen,omitempty"`
	Postponed int      `json:"postponed,omitempty"`
	Failed    []string `json:"failed,omitempty"`
	Pending   *Pending `json:"pending,omitempty"`
}

const maxStateBytes = 16 << 10

func validOptionalVersion(v string) bool { return v == "" || coordinator.ValidVersion(v) }

func validPath(p string) bool {
	return p == "" || (filepath.IsAbs(p) && filepath.Clean(p) == p && len(p) <= 1024)
}

// Validate enforces the state file's schema.
func (s *State) Validate() error {
	bad := errors.New("invalid update state")
	if s.Schema != 1 || !validOptionalVersion(s.Installed) || !validOptionalVersion(s.HighWater) || !validOptionalVersion(s.Announced) || len(s.Failed) > 16 || s.Postponed < 0 || s.Postponed > 16 {
		return bad
	}
	for _, v := range s.Failed {
		if !coordinator.ValidVersion(v) {
			return bad
		}
	}
	if s.Snooze != nil && !coordinator.ValidVersion(s.Snooze.Version) || s.FirstSeen != nil && !coordinator.ValidVersion(s.FirstSeen.Version) {
		return bad
	}
	if p := s.Pending; p != nil {
		if !slices.Contains(phases, p.Phase) || !coordinator.ValidVersion(p.From) || !coordinator.ValidVersion(p.To) ||
			(p.Kind != "mac-app" && p.Kind != "nsis" && p.Kind != "headless") || !validPath(p.Staged) || !validPath(p.App) || !validPath(p.Previous) ||
			(p.DrainOwner != "updater" && p.DrainOwner != "operator" && p.DrainOwner != "none") || p.AppPID < 0 || p.GuardPID < 0 || len(p.Reason) > 64 {
			return bad
		}
		for _, r := range p.Reason {
			if !(r >= 'a' && r <= 'z' || r == '_') {
				return bad
			}
		}
	}
	return nil
}

// MarkFailed records a version that must not install automatically again.
func (s *State) MarkFailed(version string) {
	if slices.Contains(s.Failed, version) {
		return
	}
	s.Failed = append(s.Failed, version)
	if len(s.Failed) > 16 {
		s.Failed = s.Failed[len(s.Failed)-16:]
	}
}

// HasFailed reports whether version failed before.
func (s *State) HasFailed(version string) bool { return slices.Contains(s.Failed, version) }

// DecodeState strictly decodes one state document.
func DecodeState(raw []byte) (State, error) {
	var s State
	if len(raw) > maxStateBytes {
		return s, errors.New("update state too large")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil || d.Decode(new(any)) != io.EOF {
		return State{}, errors.New("invalid update state")
	}
	return s, s.Validate()
}

// StateFile is a private update-state.json beside its lock.
type StateFile struct{ Path string }

// Lock serializes read-modify-write of the state file.
func (f StateFile) Lock() (io.Closer, error) {
	if !filepath.IsAbs(f.Path) || filepath.Base(f.Path) != "update-state.json" {
		return nil, errors.New("invalid update state path")
	}
	if err := localfs.CheckDir(filepath.Dir(f.Path)); err != nil {
		return nil, err
	}
	return localfs.LockPrivateWait(f.Path + ".lock")
}

// Read returns the state, or a fresh one when none was saved.
func (f StateFile) Read() (State, error) {
	file, err := localfs.OpenPrivate(f.Path)
	if os.IsNotExist(err) {
		return State{Schema: 1}, nil
	}
	if err != nil {
		return State{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return State{}, err
	}
	return DecodeState(raw)
}

// Exists reports whether a state was ever saved.
func (f StateFile) Exists() bool {
	_, err := os.Lstat(f.Path)
	return err == nil
}

// Write validates and atomically replaces the state.
func (f StateFile) Write(s State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return localfs.WriteAtomic(f.Path, raw, true)
}

// Update runs one locked read-modify-write.
func (f StateFile) Update(change func(*State) error) (State, error) {
	lock, err := f.Lock()
	if err != nil {
		return State{}, err
	}
	defer lock.Close()
	s, err := f.Read()
	if err != nil {
		return State{}, err
	}
	if err = change(&s); err != nil {
		return s, err
	}
	return s, f.Write(s)
}

// RolloutWindow spreads optional updates so the network never drains at once.
const RolloutWindow = 4 * time.Hour

// RolloutOffset is this node's fixed place in the window for one release.
func RolloutOffset(nodeID, version string) time.Duration {
	sum := sha256.Sum256([]byte(nodeID + "\x00" + version))
	return time.Duration(binary.BigEndian.Uint64(sum[:8]) % uint64(RolloutWindow))
}
