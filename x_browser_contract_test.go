package main

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	x "github.com/teslashibe/x-go"
)

// This opt-in test joins the actual Go adapter, HTTP envelope and real Chromium
// recipe. Its fixture intercepts every browser request before X can be contacted.
func TestBrowserLoginRuntimeContract(t *testing.T) {
	node := os.Getenv("SCARLETT_TEST_X_LOGIN_NODE")
	if node == "" {
		t.Skip("set SCARLETT_TEST_X_LOGIN_NODE to a reviewed Node binary after installing the fixture Chromium")
	}
	if !filepath.IsAbs(node) {
		t.Fatal("fixture Node path must be absolute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, "scripts/x-login-contract-fixture.mjs")
	// Provider solver/proxy/runtime overrides never enter the synthetic process.
	for _, key := range []string{"HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP", "SystemRoot", "PLAYWRIGHT_BROWSERS_PATH"} {
		if value := os.Getenv(key); value != "" {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = input.Close()
			_ = command.Wait()
		}
	})
	scanner := bufio.NewScanner(output)
	scanner.Buffer(make([]byte, 4096), 65536)
	if !scanner.Scan() {
		t.Fatal("fixture did not start")
	}
	var endpoint struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(scanner.Bytes(), &endpoint) != nil || !strings.HasPrefix(endpoint.URL, "http://127.0.0.1:") {
		t.Fatal("invalid fixture endpoint")
	}
	browser, err := x.NewBrowserLogin(x.BrowserLoginConfig{URL: endpoint.URL, BearerToken: "synthetic-contract-bearer"})
	if err != nil {
		t.Fatal(err)
	}
	operation := x.BrowserLoginOperation{
		ProfileKey: "synthetic-http-profile", OperationOwner: strings.Repeat("a", 48),
		ConnectionID: "synthetic-connection", Generation: "1", Revision: "1", RecoveryClaim: "synthetic-claim",
		Budget: x.BrowserLoginBudget{DeadlineAt: time.Now().Add(time.Minute), MaxBrowserAttempts: 1, MaxCredentialAttempts: 1},
	}
	first, err := browser.Start(ctx, x.BrowserLoginRequest{Username: "synthetic-user", Password: "synthetic-password", Operation: operation})
	if err != nil || first == nil || first.Challenge == nil || first.Attempts.Browser != 1 || first.Attempts.Credential != 1 {
		t.Fatalf("start did not establish a bounded pending challenge: %v", err)
	}
	invalid, err := browser.Continue(ctx, operation, first.Challenge.ID, "000000")
	if err != nil || invalid == nil || invalid.Challenge == nil || !invalid.DeadlineAt.Equal(first.DeadlineAt) {
		t.Fatalf("invalid code did not retain the original operation: %v", err)
	}
	result, err := browser.Continue(ctx, operation, invalid.Challenge.ID, "123456")
	if err != nil || result == nil || result.Session == nil || result.Challenge != nil || result.Session.AuthToken != "synthetic-auth_token" || result.Session.UserAgent == "" || result.Attempts.Browser != 1 || result.Attempts.Credential != 1 {
		t.Fatalf("same-browser code continuation did not produce a candidate session: %v", err)
	}
	_ = input.Close()
	var observed struct {
		Observed *struct {
			Launches    int      `json:"launches"`
			Passwords   int      `json:"passwords"`
			Codes       []string `json:"codes"`
			Navigations int      `json:"navigations"`
		} `json:"observed"`
	}
	for scanner.Scan() {
		var candidate = observed
		if json.Unmarshal(scanner.Bytes(), &candidate) == nil && candidate.Observed != nil {
			observed = candidate
		}
	}
	if err := command.Wait(); err != nil {
		t.Fatal("fixture failed to shut down cleanly")
	}
	stopped = true
	if scanner.Err() != nil || observed.Observed == nil || observed.Observed.Launches != 1 || observed.Observed.Passwords != 1 || observed.Observed.Navigations != 3 || strings.Join(observed.Observed.Codes, ",") != "000000,123456" {
		t.Fatal("browser observation did not establish one password and code-only continuation")
	}
}
