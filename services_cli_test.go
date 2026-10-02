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
	"syscall"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// Optional actual CLI smoke uses only private test files and a synthetic TLS
// coordinator that never offers work, so no provider or verifier is contacted.
func TestActualServicesCLIHeartbeatOnly(t *testing.T) {
	binary := os.Getenv("SCARLETT_TEST_NODE_BINARY")
	if binary == "" {
		t.Skip("set SCARLETT_TEST_NODE_BINARY to an explicitly built node")
	}
	seen := make(chan coordinator.Heartbeat, 1)
	credential := strings.Repeat("ab", 32)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/node/v1/heartbeat" || r.Header.Get("Authorization") != "Bearer "+credential {
			t.Error("unexpected CLI request")
			w.WriteHeader(403)
			return
		}
		var h coordinator.Heartbeat
		if json.NewDecoder(r.Body).Decode(&h) != nil {
			t.Error("invalid heartbeat")
		}
		select {
		case seen <- h:
		default:
		}
		io.WriteString(w, `{"lease":null}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	home := filepath.Join(dir, "codex")
	os.Mkdir(home, 0700)
	os.WriteFile(filepath.Join(home, "auth.json"), []byte(`{"synthetic_fixture":true}`), 0600)
	session := filepath.Join(dir, "session.json")
	os.WriteFile(session, []byte(`{"auth_token":"synthetic-auth","ct0":"synthetic-csrf"}`), 0600)
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	state := filepath.Join(dir, "state")
	cmd := exec.Command(binary, "run")
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "SCARLETT_") && !strings.HasPrefix(e, "CODEX_HOME=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "SCARLETT_EXECUTOR=services", "SCARLETT_VERIFIER=127.0.0.1:17047", "SCARLETT_SERVICES=codex,x_read", "SCARLETT_COORDINATOR="+server.URL, "SCARLETT_COORDINATOR_CA_FILE="+ca, "SCARLETT_CODEX_HOME="+home, "SCARLETT_X_SESSION="+session, "SCARLETT_PROFILE=standard", "SCARLETT_STATE_DIR="+state, "SCARLETT_CREDENTIAL="+credential, "SCARLETT_NODE_ID=synthetic-node")
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	select {
	case h := <-seen:
		if h.Capacity != 2 || h.State != "available" || len(h.Services) != 2 || h.Services[0].State != "configured" || h.Services[1].State != "configured" {
			t.Fatal("CLI invented readiness or mixed capacities")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("CLI did not heartbeat")
	}
	if e := cmd.Process.Signal(syscall.SIGTERM); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal("CLI did not stop cleanly", e)
		}
	case <-time.After(5 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("CLI did not stop")
	}
	if bytes.Contains(stderr.Bytes(), []byte(credential)) || bytes.Contains(stderr.Bytes(), []byte("synthetic-auth")) || bytes.Contains(stderr.Bytes(), []byte("synthetic-csrf")) {
		t.Fatal("secret in CLI output")
	}
	j, e := attempts.Open(filepath.Join(state, "attempts"))
	if e != nil {
		t.Fatal("process did not release journal lock", e)
	}
	defer j.Close()
}
