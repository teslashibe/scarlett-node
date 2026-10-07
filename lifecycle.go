package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

// Local observations contain no credentials, prompts, outputs or proof tokens.
// A fresh observation is not independent provider or coordinator evidence.
type runtimeStatus struct {
	Accounts           []accountStatus             `json:"accounts,omitempty"`
	JournalCapacity    *attempts.Capacity          `json:"journal_capacity,omitempty"`
	Version            string                      `json:"version"`
	State              string                      `json:"state"`
	NodeID             string                      `json:"node_id,omitempty"`
	UpdatedAt          time.Time                   `json:"updated_at"`
	LastHeartbeatAt    time.Time                   `json:"last_heartbeat_at"`
	InFlight           int                         `json:"in_flight"`
	UnresolvedAttempts int                         `json:"unresolved_attempts"`
	Services           []coordinator.ServiceHealth `json:"services"`
	DrainRequested     bool                        `json:"drain_requested"`
	// RelayHalted is set while this node refuses keyed relay after catching
	// its verifier misusing a session; cleared by `scarlett-node relay-resume`.
	RelayHalted bool `json:"relay_halted,omitempty"`
	// JournalFull is set while the attempt journal alone stops new work:
	// unfinished attempts, or receipts too recent to prune, fill it.
	JournalFull bool `json:"journal_full,omitempty"`
	// Release is this build's release version. LatestRelease is the newest
	// release the coordinator last reported; UpdateAvailable is set when it is
	// newer than Release, and UpdateRequired while the coordinator offers this
	// release no new jobs.
	Release         string `json:"release"`
	LatestRelease   string `json:"latest_release,omitempty"`
	UpdateAvailable bool   `json:"update_available,omitempty"`
	UpdateRequired  bool   `json:"update_required,omitempty"`
}

// observeRelease copies the coordinator's last release notice into status and
// logs when this build first needs or stops needing an update.
func (s *runtimeStatus) observeRelease(notice coordinator.ReleaseNotice, ok bool) {
	if !ok {
		return
	}
	if notice.Required && !s.UpdateRequired {
		fmt.Fprintf(os.Stderr, "release: update required; the coordinator offers %s no new jobs (latest %s)\n", coordinator.NodeRelease, notice.Latest)
	} else if notice.UpdateAvailable() && !notice.Required && notice.Latest != s.LatestRelease {
		fmt.Fprintf(os.Stderr, "release: Scarlett Node %s is available (running %s)\n", notice.Latest, coordinator.NodeRelease)
	}
	s.LatestRelease = notice.Latest
	s.UpdateAvailable = notice.UpdateAvailable()
	s.UpdateRequired = notice.Required
}

// statusFresh is how old status.json may be before a running node reads as
// offline. The loop writes it once per heartbeat, and a heartbeat the
// coordinator never answers runs for the hold plus HeartbeatGrace before the
// failure backoff, so the bound sits above their sum.
const statusFresh = coordinator.HeartbeatWaitSeconds*time.Second + coordinator.HeartbeatGrace + 15*time.Second

func localCommand(command string, output io.Writer) error {
	dir := os.Getenv("SCARLETT_STATE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir = config.DefaultStateDir(home)
	}
	if !filepath.IsAbs(dir) {
		return errors.New("state directory must be absolute")
	}
	if err := prepareStateDir(dir); err != nil {
		return err
	}
	if command == "diagnostics" {
		return json.NewEncoder(output).Encode(diagnostics.Read(dir))
	}
	switch command {
	case "drain":
		if err := writeLocalFile(dir, "drain", []byte("drained\n")); err != nil {
			return err
		}
	case "resume":
		if _, err := drainRequested(dir); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(dir, "drain")); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := syncDirectory(dir); err != nil {
			return err
		}
	case "relay-resume":
		// The operator has checked the verifier. A running node observes the
		// removed marker on its next admission or service-health check; the
		// returned status may still predate that observation.
		if err := os.Remove(filepath.Join(dir, worker.RelayHaltFile)); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := syncDirectory(dir); err != nil {
			return err
		}
	}
	status := runtimeStatus{Version: coordinator.Version, State: "offline", Release: coordinator.NodeRelease, Services: []coordinator.ServiceHealth{}}
	raw, err := readLocalFile(filepath.Join(dir, "status.json"), 16384)
	if err == nil {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&status) != nil || decoder.Decode(new(any)) != io.EOF || status.Version != coordinator.Version || len(status.Services) > 2 || status.InFlight < 0 || status.InFlight > 64 || status.UnresolvedAttempts < 0 || status.UnresolvedAttempts > 1000000 || !validIdentityField(status.NodeID, 128) || (status.State != "running" && status.State != "draining" && status.State != "stopped") {
			return errors.New("invalid local status")
		}
		if !validAccountStatuses(status.Accounts) {
			return errors.New("invalid local account status")
		}
		if (status.LatestRelease != "" && !coordinator.ValidVersion(status.LatestRelease)) || (status.UpdateAvailable || status.UpdateRequired) && status.LatestRelease == "" {
			return errors.New("invalid local release status")
		}
		// The status file may come from an earlier build; this build's
		// release is what the desktop app runs.
		status.Release = coordinator.NodeRelease
		status.UpdateAvailable = status.LatestRelease != "" && coordinator.CompareVersions(status.LatestRelease, coordinator.NodeRelease) > 0
		if c := status.JournalCapacity; c != nil && (c.Limits.Validate() != nil || c.Records < 0 || c.Records > c.Limits.MaxRecords || c.Bytes < 0 || c.Bytes > c.Limits.MaxTotalBytes || c.ReservedBytes < c.Bytes || c.TerminalRecords < 0 || c.TerminalBytes < 0 || c.AvailableRecords < 0 || c.AvailableRecords > c.Limits.MaxRecords-c.Records) {
			return errors.New("invalid journal capacity status")
		}
		if time.Since(status.UpdatedAt) > statusFresh || status.UpdatedAt.After(time.Now().Add(time.Second)) {
			status.State = "offline"
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	status.DrainRequested, err = drainRequested(dir)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(status)
}

func readLocalFile(name string, limit int64) ([]byte, error) {
	f, err := localfs.OpenPrivate(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, errors.New("local state file must be regular, private and bounded")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(raw) > int(limit) {
		return nil, errors.New("local state file too large")
	}
	return raw, err
}

func drainRequested(dir string) (bool, error) {
	raw, err := readLocalFile(filepath.Join(dir, "drain"), 8)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if string(raw) != "drained\n" {
		return false, errors.New("invalid drain request")
	}
	return true, nil
}

func saveRuntimeStatus(dir string, status runtimeStatus) error {
	status.UpdatedAt = time.Now().UTC()
	raw, err := json.Marshal(status)
	if err != nil {
		return err
	}
	return writeLocalFile(dir, "status.json", raw)
}

func writeLocalFile(dir, name string, raw []byte) error {
	return localfs.WriteAtomic(filepath.Join(dir, name), raw, true)
}
func syncDirectory(dir string) error { return localfs.SyncDir(dir) }

func waitForWorkers(workers *sync.WaitGroup, cancel func(), grace time.Duration) {
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		cancel()
		<-done
	}
}
