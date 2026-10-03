package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
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
}

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
	}
	status := runtimeStatus{Version: coordinator.Version, State: "offline", Services: []coordinator.ServiceHealth{}}
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
		if c := status.JournalCapacity; c != nil && (c.Limits.Validate() != nil || c.Records < 0 || c.Records > c.Limits.MaxRecords || c.Bytes < 0 || c.Bytes > c.Limits.MaxTotalBytes || c.ReservedBytes < c.Bytes || c.AvailableRecords < 0 || c.AvailableRecords > c.Limits.MaxRecords-c.Records) {
			return errors.New("invalid journal capacity status")
		}
		if time.Since(status.UpdatedAt) > 30*time.Second || status.UpdatedAt.After(time.Now().Add(time.Second)) {
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
