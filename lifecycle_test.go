package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

func TestLocalDrainPersistsAcrossRestartAndStatusExcludesPrivateIdentity(t *testing.T) {
	dir := privateTestDir(t)
	t.Setenv("SCARLETT_STATE_DIR", dir)
	t.Setenv("SCARLETT_CREDENTIAL", "synthetic-secret")
	var output bytes.Buffer
	if e := localCommand("drain", &output); e != nil {
		t.Fatal(e)
	}
	if drained, e := drainRequested(dir); e != nil || !drained {
		t.Fatal("drain not retained", e)
	}
	s := runtimeStatus{Version: coordinator.Version, State: "running", NodeID: "synthetic-node", InFlight: 1, Services: []coordinator.ServiceHealth{{Kind: "codex", State: "configured", Capacity: 1}}}
	if e := saveRuntimeStatus(dir, s); e != nil {
		t.Fatal(e)
	}
	output.Reset()
	if e := localCommand("status", &output); e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(output.Bytes(), []byte("synthetic-secret")) || !bytes.Contains(output.Bytes(), []byte(`"drain_requested":true`)) {
		t.Fatal("status lost drain or disclosed identity")
	}
	output.Reset()
	if e := localCommand("resume", &output); e != nil {
		t.Fatal(e)
	}
	if drained, e := drainRequested(dir); e != nil || drained {
		t.Fatal("resume did not remove persisted drain", e)
	}
	// A killed process cannot leave a fresh-looking running status indefinitely.
	s.UpdatedAt = time.Now().Add(-time.Minute)
	raw, _ := json.Marshal(s)
	if e := writeLocalFile(dir, "status.json", raw); e != nil {
		t.Fatal(e)
	}
	output.Reset()
	if e := localCommand("status", &output); e != nil || !bytes.Contains(output.Bytes(), []byte(`"state":"offline"`)) {
		t.Fatal("stale status reported running", e)
	}
}

func TestLocalControlRejectsSymlinksFifosOversizeAndCredentialFields(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "public", "large", "credential"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateTestDir(t)
			t.Setenv("SCARLETT_STATE_DIR", dir)
			path := filepath.Join(dir, "status.json")
			switch kind {
			case "symlink":
				if e := os.Symlink("missing", path); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := createFIFOFixture(t, path); e != nil {
					t.Fatal(e)
				}
			case "public":
				writePrivateFixture(path, []byte(`{}`), 0644)
			case "large":
				writePrivateFixture(path, bytes.Repeat([]byte("x"), 16385), 0600)
			case "credential":
				writePrivateFixture(path, []byte(`{"credential":"synthetic-private"}`), 0600)
			}
			var output bytes.Buffer
			if e := localCommand("status", &output); e == nil || output.Len() != 0 {
				t.Fatal("untrusted local file accepted")
			}
		})
	}
}

func TestGracefulShutdownLetsAcceptedWorkFinishAndBoundsCancellation(t *testing.T) {
	for _, finish := range []bool{true, false} {
		var wg sync.WaitGroup
		ctx, cancel := context.WithCancel(context.Background())
		completed := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			if finish {
				time.Sleep(5 * time.Millisecond)
			} else {
				<-ctx.Done()
			}
			close(completed)
		}()
		waitForWorkers(&wg, cancel, 50*time.Millisecond)
		select {
		case <-completed:
		default:
			t.Fatal("shutdown returned before work finished")
		}
		if finish && ctx.Err() != nil {
			t.Fatal("accepted work was cancelled before grace expired")
		}
		if !finish && ctx.Err() == nil {
			t.Fatal("shutdown exceeded grace without cancellation")
		}
		cancel()
	}
}

// A relay halt survives the process: a restart restores it from the state
// directory, status reports it, and only the operator's relay-resume clears it.
func TestRelayHaltPersistsUntilRelayResume(t *testing.T) {
	dir := privateTestDir(t)
	t.Setenv("SCARLETT_STATE_DIR", dir)
	worker.ResetRelayHaltForTests()
	t.Cleanup(worker.ResetRelayHaltForTests)
	if e := worker.LoadRelayHalt(dir); e != nil || worker.RelayHalted() {
		t.Fatal("fresh state directory reported a halt", e)
	}
	worker.HaltRelay("verifier misused this node's X session")
	if raw, e := os.ReadFile(filepath.Join(dir, worker.RelayHaltFile)); e != nil || !bytes.Contains(raw, []byte("misused")) {
		t.Fatal("halt not recorded", e)
	}
	// "Restart": forget the in-memory latch, load the directory again.
	worker.ResetRelayHaltForTests()
	if e := worker.LoadRelayHalt(dir); e != nil || !worker.RelayHalted() || worker.RelayHaltReason() == "" {
		t.Fatal("halt not restored after restart", e)
	}
	s := runtimeStatus{Version: coordinator.Version, State: "running", NodeID: "synthetic-node", Services: []coordinator.ServiceHealth{{Kind: "x_read", State: "ready", Capacity: 1}}, RelayHalted: worker.RelayHalted()}
	if e := saveRuntimeStatus(dir, s); e != nil {
		t.Fatal(e)
	}
	var output bytes.Buffer
	if e := localCommand("status", &output); e != nil || !bytes.Contains(output.Bytes(), []byte(`"relay_halted":true`)) {
		t.Fatal("status does not show the halt", e, output.String())
	}
	output.Reset()
	if e := localCommand("relay-resume", &output); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, worker.RelayHaltFile)); !os.IsNotExist(e) {
		t.Fatal("relay-resume left the marker", e)
	}
	worker.ResetRelayHaltForTests()
	if e := worker.LoadRelayHalt(dir); e != nil || worker.RelayHalted() {
		t.Fatal("halt came back after relay-resume", e)
	}
	// Resuming when nothing is halted is harmless.
	if e := localCommand("relay-resume", &output); e != nil {
		t.Fatal(e)
	}
}
