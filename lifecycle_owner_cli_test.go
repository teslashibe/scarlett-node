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
	"syscall"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

func TestActualDesktopOwnerDrainFinishesAcceptedWorkAndSurvivesRestart(t *testing.T) {
	testActualCLIDrain(t, true)
}
func testActualCLIDrain(t *testing.T, owned bool) {
	binary := os.Getenv("SCARLETT_TEST_NODE_BINARY")
	if binary == "" {
		t.Skip("set SCARLETT_TEST_NODE_BINARY to the built companion")
	}
	entered, release, cancelled := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) != 1 {
			t.Error("provider work repeated")
			w.WriteHeader(500)
			return
		}
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			close(cancelled)
			return
		}
		io.WriteString(w, `{"model":"gpt-5.6-luna","choices":[{"message":{"content":"synthetic answer"},"finish_reason":"stop"}],"usage_source":"upstream","usage":{"prompt_tokens":8,"completion_tokens":4}}`)
	}))
	defer provider.Close()
	var offered atomic.Bool
	drained, resumed, receipt := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
	lease := testLease()
	credential := strings.Repeat("ab", 32)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			t.Error("missing scoped credential")
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/node/v1/heartbeat":
			var h coordinator.Heartbeat
			if json.NewDecoder(r.Body).Decode(&h) != nil {
				t.Error("invalid heartbeat")
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
		case "/api/node/v1/jobs/synthetic/result":
			var result coordinator.Result
			if json.NewDecoder(r.Body).Decode(&result) != nil || result.Output != "synthetic answer" {
				t.Error("accepted work lost result")
				w.WriteHeader(400)
				return
			}
			select {
			case receipt <- struct{}{}:
			default:
			}
			w.WriteHeader(204)
		default:
			t.Error("unexpected coordinator request")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if e := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(dir, "state")
	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "SCARLETT_") && !strings.HasPrefix(e, "CODEX_HOME=") {
			env = append(env, e)
		}
	}
	env = append(env, "SCARLETT_EXECUTOR=gateway", "SCARLETT_GATEWAY="+provider.URL, "SCARLETT_COORDINATOR="+server.URL, "SCARLETT_COORDINATOR_CA_FILE="+ca, "SCARLETT_STATE_DIR="+state, "SCARLETT_PROFILE=standard", "SCARLETT_CREDENTIAL="+credential, "SCARLETT_NODE_ID=synthetic-node")
	owners := map[*exec.Cmd]io.WriteCloser{}
	run := func() *exec.Cmd {
		cmd := exec.Command(binary, "run")
		if owned {
			cmd = exec.Command(binary, "desktop", "run")
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			owners[cmd] = input
		}
		cmd.Env = env
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if e := cmd.Start(); e != nil {
			t.Fatal(e)
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
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatal("local command failed", action, e)
		}
		if bytes.Contains(out, []byte(credential)) {
			t.Fatal("status leaked credential")
		}
		return out
	}
	await := func(ch <-chan struct{}, what string) {
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatal(what)
		}
	}
	requestStop := func(cmd *exec.Cmd) {
		var err error
		if owned {
			err = owners[cmd].Close()
		} else {
			err = cmd.Process.Signal(syscall.SIGTERM)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	stop := func(cmd *exec.Cmd) {
		requestStop(cmd)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case e := <-done:
			if e != nil {
				t.Fatal("node exit", e)
			}
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			<-done
			t.Fatal("shutdown did not finish")
		}
	}
	cmd := run()
	await(entered, "provider was not entered")
	command("drain")
	await(drained, "drain did not suppress availability")
	if out := command("status"); !bytes.Contains(out, []byte(`"drain_requested":true`)) || !bytes.Contains(out, []byte(`"in_flight":1`)) {
		t.Fatal("status lost draining work")
	}
	requestStop(cmd)
	select {
	case <-cancelled:
		t.Fatal("shutdown cancelled accepted work immediately")
	case <-time.After(100 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	await(receipt, "shutdown lost accepted receipt")
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown failed")
	}
	if out := command("status"); !bytes.Contains(out, []byte(`"state":"stopped"`)) || !bytes.Contains(out, []byte(`"unresolved_attempts":0`)) {
		t.Fatal("stopped snapshot lost acknowledgement")
	}
	// A new process must keep the persisted drain; resume requires a local command.
	select {
	case <-drained:
	default:
	}
	cmd = run()
	await(drained, "restart forgot drain")
	stop(cmd)
	select {
	case <-resumed:
	default:
	}
	command("resume")
	cmd = run()
	await(resumed, "resume did not restore availability")
	stop(cmd)
	if calls.Load() != 1 {
		t.Fatal("restart repeated provider work")
	}
}
