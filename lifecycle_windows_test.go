package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// The actual native executable crashes after starting synthetic provider work.
// Restart must preserve drain and reconcile uncertainty without provider replay.
func TestWindowsActualCLICrashRecoveryDrainAndTLS(t *testing.T) {
	binary := os.Getenv("SCARLETT_TEST_NODE_BINARY")
	if binary == "" {
		t.Skip("set SCARLETT_TEST_NODE_BINARY to native built node")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) != 1 {
			t.Error("uncertain provider work replayed")
			w.WriteHeader(500)
			return
		}
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer provider.Close()
	lease := testLease()
	credential := strings.Repeat("ab", 32)
	var offered atomic.Bool
	reconciled := make(chan struct{}, 1)
	drained := make(chan struct{}, 1)
	resumed := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			t.Error("missing scoped bearer")
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/node/v1/heartbeat":
			var h coordinator.Heartbeat
			if json.NewDecoder(r.Body).Decode(&h) != nil {
				w.WriteHeader(400)
				return
			}
			if h.State == "exhausted" {
				select {
				case drained <- struct{}{}:
				default:
				}
			}
			if h.State == "available" && offered.Load() {
				select {
				case resumed <- struct{}{}:
				default:
				}
			}
			if h.State == "available" && offered.CompareAndSwap(false, true) {
				json.NewEncoder(w).Encode(coordinator.HeartbeatReply{Lease: &lease})
			} else {
				io.WriteString(w, `{"lease":null}`)
			}
		case "/api/node/v1/jobs/synthetic/attempt":
			json.NewEncoder(w).Encode(coordinator.AttemptStatus{Version: coordinator.Version, JobID: lease.JobID, Attempt: lease.Attempt, Fence: lease.Fence, State: "live", ReplaySafe: true})
		case "/api/node/v1/jobs/synthetic/fail":
			var f coordinator.Failure
			if json.NewDecoder(r.Body).Decode(&f) != nil || f.Code != "execution_uncertain" || f.Attempt != lease.Attempt || f.Fence != lease.Fence {
				t.Error("lost uncertainty/fence")
				w.WriteHeader(400)
				return
			}
			select {
			case reconciled <- struct{}{}:
			default:
			}
			w.WriteHeader(204)
		default:
			t.Error("unexpected coordinator route")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	dir := privateTestDir(t)
	ca := filepath.Join(dir, "public-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "native state λ with spaces")
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "SCARLETT_") && !strings.HasPrefix(e, "CODEX_HOME=") {
			env = append(env, e)
		}
	}
	env = append(env, "SCARLETT_EXECUTOR=gateway", "SCARLETT_GATEWAY="+provider.URL, "SCARLETT_COORDINATOR="+server.URL, "SCARLETT_COORDINATOR_CA_FILE="+ca, "SCARLETT_STATE_DIR="+state, "SCARLETT_PROFILE=standard", "SCARLETT_CREDENTIAL="+credential, "SCARLETT_NODE_ID=synthetic-node")
	start := func() *exec.Cmd {
		cmd := exec.Command(binary, "run")
		cmd.Env = env
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
		})
		return cmd
	}
	command := func(action string) []byte {
		cmd := exec.Command(binary, action)
		cmd.Env = env
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatal("local command failed", action, err)
		}
		if bytes.Contains(raw, []byte(credential)) {
			t.Fatal("local command disclosed credential")
		}
		return raw
	}
	wait := func(ch <-chan struct{}, label string) {
		select {
		case <-ch:
		case <-time.After(20 * time.Second):
			t.Fatal(label)
		}
	}
	first := start()
	wait(entered, "native provider did not start")
	if !bytes.Contains(command("drain"), []byte(`"drain_requested":true`)) {
		t.Fatal("drain not persisted")
	}
	if err := first.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if first.Wait() == nil {
		t.Fatal("crashed process succeeded")
	}
	second := start()
	wait(reconciled, "restart did not reconcile uncertain work")
	wait(drained, "restart lost drain")
	if !bytes.Contains(command("resume"), []byte(`"drain_requested":false`)) {
		t.Fatal("resume not persisted")
	}
	wait(resumed, "resume did not restore admission")
	if calls.Load() != 1 {
		t.Fatal("provider was called again")
	}
	if err := second.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	second.Wait()
	once.Do(func() { close(release) })
}
