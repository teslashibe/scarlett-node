//go:build unix

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
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// A fake helper and synthetic TLS coordinator hold one accepted job across
// removal and shutdown. Neither helper nor coordinator contacts a provider.
func TestActualAccountShutdownSnapshotsDrainingAndFinishedWork(t *testing.T) {
	binary := os.Getenv("SCARLETT_TEST_NODE_BINARY")
	if binary == "" {
		t.Skip("set SCARLETT_TEST_NODE_BINARY for actual node shutdown coverage")
	}
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	os.Mkdir(state, 0700)
	home := filepath.Join(dir, "codex")
	os.Mkdir(home, 0700)
	os.WriteFile(filepath.Join(home, "auth.json"), freshSyntheticCodexAuth(), 0600)
	registry := filepath.Join(state, "accounts.json")
	raw, _ := json.Marshal(accountFile{Version: 1, Accounts: []providerAccount{{"sole", "codex", home, 1}}})
	os.WriteFile(registry, raw, 0600)
	marker, release := filepath.Join(dir, "started"), filepath.Join(dir, "release")
	helper := filepath.Join(dir, "synthetic-prover")
	script := "#!/bin/sh\nprintf 'started' > '" + marker + "'\nwhile [ ! -f '" + release + "' ]; do sleep 0.05; done\nprintf '{\"status\":\"proof_sent\"}\\n'\n"
	if e := os.WriteFile(helper, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	l := communityOffer(t)
	var offered atomic.Bool
	var reports atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/node/v1/heartbeat":
			if offered.CompareAndSwap(false, true) {
				json.NewEncoder(w).Encode(map[string]any{"lease": l})
			} else {
				io.WriteString(w, `{"lease":null}`)
			}
		case strings.HasSuffix(r.URL.Path, "/accept"):
			records, e := os.ReadDir(filepath.Join(state, "attempts"))
			if e != nil {
				t.Error(e)
			}
			pinned := false
			for _, record := range records {
				if !strings.HasSuffix(record.Name(), ".json") {
					continue
				}
				body, e := os.ReadFile(filepath.Join(state, "attempts", record.Name()))
				var a attempts.Record
				if e == nil && json.Unmarshal(body, &a) == nil && a.ProviderAccountID == "sole" && a.ProviderService == "codex" {
					pinned = true
				}
			}
			if !pinned {
				t.Error("selected account missing before acceptance")
			}
			accepted := l
			accepted.VerifierToken = strings.Repeat("c", 64)
			json.NewEncoder(w).Encode(coordinator.LeaseAcceptance{Version: coordinator.Version, State: "leased", FundingAuthority: "production_receipt", Lease: accepted})
		case strings.HasSuffix(r.URL.Path, "/proven"):
			reports.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected synthetic route %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	ca := filepath.Join(dir, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	cmd := exec.Command(binary, "run")
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "SCARLETT_") && !strings.HasPrefix(env, "CODEX_HOME=") {
			cmd.Env = append(cmd.Env, env)
		}
	}
	cmd.Env = append(cmd.Env, "SCARLETT_EXECUTOR=services", "SCARLETT_SERVICES=codex", "SCARLETT_VERIFIER=127.0.0.1:17047", "SCARLETT_COORDINATOR="+server.URL, "SCARLETT_COORDINATOR_CA_FILE="+ca, "SCARLETT_STATE_DIR="+state, "SCARLETT_CREDENTIAL="+strings.Repeat("ab", 32), "SCARLETT_NODE_ID=synthetic-node", "SCARLETT_PROFILE=standard", "SCARLETT_PROVER="+helper)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = io.Discard
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			os.WriteFile(release, []byte("finish"), 0600)
			cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				cmd.Process.Kill()
				<-done
			}
		}
	})
	waitUntil := func(name string, condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if condition() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s: %s", name, stderr.String())
	}
	waitUntil("accepted synthetic provider", func() bool { _, e := os.Stat(marker); return e == nil })
	// Removal happens after selection and before shutdown's next local snapshot.
	if e := writeLocalFile(state, "accounts.json", []byte(`{"version":1,"accounts":[]}`)); e != nil {
		t.Fatal(e)
	}
	if e := cmd.Process.Signal(syscall.SIGTERM); e != nil {
		t.Fatal(e)
	}
	var status runtimeStatus
	waitUntil("accurate draining account snapshot", func() bool {
		body, e := readLocalFile(filepath.Join(state, "status.json"), 16384)
		if e != nil || json.Unmarshal(body, &status) != nil || status.State != "draining" {
			return false
		}
		return len(status.Accounts) == 1 && status.Accounts[0].ID == "sole" && status.Accounts[0].State == "draining" && status.Accounts[0].InFlight == 1 && len(status.Services) == 2 && status.Services[0].InFlight == 1 && status.Services[0].Capacity == 1
	})
	if e := os.WriteFile(release, []byte("finish"), 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal("node did not stop cleanly", e, stderr.String())
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		<-done
		t.Fatal("node failed to finish synthetic work")
	}
	body, e := readLocalFile(filepath.Join(state, "status.json"), 16384)
	status = runtimeStatus{}
	if e != nil || json.Unmarshal(body, &status) != nil || status.State != "stopped" || status.InFlight != 0 || len(status.Accounts) != 0 || status.Services[0].InFlight != 0 || status.Services[0].Capacity != 0 {
		t.Fatal("stopped status retained stale accepted account work", e)
	}
	journal, e := attempts.Open(filepath.Join(state, "attempts"))
	if e != nil {
		t.Fatal(e)
	}
	pending, e := journal.Pending()
	journal.Close()
	if e != nil || len(pending) != 0 || reports.Load() != 1 {
		t.Fatal("shutdown lost journal cleanup or repeated provider report", e)
	}
	records, _ := os.ReadDir(filepath.Join(state, "attempts"))
	pinned := false
	for _, record := range records {
		if !strings.HasSuffix(record.Name(), ".json") {
			continue
		}
		body, _ := os.ReadFile(filepath.Join(state, "attempts", record.Name()))
		var a attempts.Record
		if json.Unmarshal(body, &a) == nil && a.State == "terminal" && a.ProviderAccountID == "sole" && a.ProviderService == "codex" {
			pinned = true
		}
	}
	if !pinned {
		t.Fatal("terminal journal lost selected account identity")
	}
}
