package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	x "github.com/teslashibe/x-go"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeXLogin struct {
	starts, continues, cancels int
	start                      func(context.Context, x.BrowserLoginRequest) (*x.BrowserLoginResult, error)
	continuation               func(context.Context, x.BrowserLoginOperation, string, string) (*x.BrowserLoginResult, error)
}

func (f *fakeXLogin) Start(c context.Context, r x.BrowserLoginRequest) (*x.BrowserLoginResult, error) {
	f.starts++
	return f.start(c, r)
}
func (f *fakeXLogin) Continue(c context.Context, o x.BrowserLoginOperation, id, code string) (*x.BrowserLoginResult, error) {
	f.continues++
	return f.continuation(c, o, id, code)
}
func (f *fakeXLogin) Cancel(context.Context, x.BrowserLoginOperation) error { f.cancels++; return nil }
func loginFixture(t *testing.T) (*xLoginOperation, *fakeXLogin, xLoginMessage) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	t.Setenv("SCARLETT_ACCOUNTS_FILE", filepath.Join(dir, "accounts.json"))
	b := &fakeXLogin{}
	o := newXLoginOperation(dir, b)
	o.verify = func(context.Context, x.Session, string, string) (string, error) { return "123", nil }
	t.Cleanup(o.close)
	return o, b, xLoginMessage{Action: "start", ID: "local-x", Concurrency: 1, Username: "fixture_user", Password: "synthetic-private-password"}
}
func pendingResult(deadline time.Time) *x.BrowserLoginResult {
	return &x.BrowserLoginResult{Challenge: &x.BrowserLoginChallenge{ID: "fixture-challenge", Method: "email", MaskedDestination: "f***@example.test", ExpiresAt: deadline.Add(-time.Second)}}
}
func candidateResult() *x.BrowserLoginResult {
	return &x.BrowserLoginResult{Session: &x.Session{AuthToken: "synthetic-token", CT0: "synthetic-csrf", UserAgent: "fixture Chrome"}}
}
func TestInteractiveXLoginChallengeAndCommit(t *testing.T) {
	o, b, m := loginFixture(t)
	var original x.BrowserLoginOperation
	b.start = func(_ context.Context, r x.BrowserLoginRequest) (*x.BrowserLoginResult, error) {
		original = r.Operation
		if r.Password != m.Password || r.Operation.Budget.MaxCredentialAttempts != 1 {
			t.Fatal("wrong start budget")
		}
		return pendingResult(r.Operation.Budget.DeadlineAt), nil
	}
	b.continuation = func(_ context.Context, p x.BrowserLoginOperation, id, code string) (*x.BrowserLoginResult, error) {
		if p != original || id != "fixture-challenge" || code != "654321" {
			t.Fatal("binding lost")
		}
		return candidateResult(), nil
	}
	r := o.handle(context.Background(), m)
	if r.Status != "pending" {
		t.Fatal(r)
	}
	raw, _ := json.Marshal(r)
	for _, secret := range []string{m.Password, original.OperationOwner, "synthetic-token", "654321"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("secret in projection")
		}
	}
	r = o.handle(context.Background(), xLoginMessage{Action: "continue", ID: m.ID, ChallengeID: r.ChallengeID, Code: "654321"})
	if r.Status != "updated" || b.starts != 1 || b.continues != 1 {
		t.Fatal(r)
	}
	stored, err := readLocalFile(filepath.Join(o.dir, "accounts", "x_read-local-x", "session.json"), 65536)
	if err != nil {
		t.Fatal(err)
	}
	var s x.Session
	json.Unmarshal(stored, &s)
	if s.UserAgent != "fixture Chrome" || s.Twid != "u%3D123" {
		t.Fatal("UA lost")
	}
	f, err := loadAccounts(accountFilePath(o.dir))
	if err != nil || len(f.Accounts) != 1 {
		t.Fatal("registry missing")
	}
}
func TestInteractiveXLoginBindingCancelExpiryRestart(t *testing.T) {
	for _, mode := range []string{"wrong_account", "wrong_challenge", "cancel", "expiry", "restart"} {
		t.Run(mode, func(t *testing.T) {
			o, b, m := loginFixture(t)
			b.start = func(_ context.Context, r x.BrowserLoginRequest) (*x.BrowserLoginResult, error) {
				return pendingResult(r.Operation.Budget.DeadlineAt), nil
			}
			r := o.handle(context.Background(), m)
			if r.Status != "pending" {
				t.Fatal(r)
			}
			next := xLoginMessage{Action: "continue", ID: m.ID, ChallengeID: r.ChallengeID, Code: "123456"}
			switch mode {
			case "wrong_account":
				next.ID = "another"
			case "wrong_challenge":
				next.ChallengeID = "other"
			case "cancel":
				next.Action = "cancel"
			case "expiry":
				o.now = func() time.Time { return time.Now().Add(5 * time.Minute) }
			case "restart":
				o.close()
			}
			result := o.handle(context.Background(), next)
			if mode == "cancel" {
				if result.Status != "cancelled" {
					t.Fatal(result)
				}
			} else if result.Code != "restart_login" {
				t.Fatal(result)
			}
			if b.continues != 0 {
				t.Fatal("invalid continuation reached provider")
			}
			if _, err := loadAccounts(accountFilePath(o.dir)); !os.IsNotExist(err) {
				t.Fatal("session committed")
			}
		})
	}
}
func TestInteractiveXLoginDuplicateOwnership(t *testing.T) {
	o, b, m := loginFixture(t)
	b.start = func(_ context.Context, r x.BrowserLoginRequest) (*x.BrowserLoginResult, error) {
		return pendingResult(r.Operation.Budget.DeadlineAt), nil
	}
	if o.handle(context.Background(), m).Status != "pending" {
		t.Fatal("start failed")
	}
	other := newXLoginOperation(o.dir, b)
	defer other.close()
	if other.handle(context.Background(), m).Code != "login_busy" {
		t.Fatal("duplicate process acquired profile")
	}
	if o.handle(context.Background(), m).Code != "login_busy" {
		t.Fatal("duplicate start accepted")
	}
	if b.starts != 1 {
		t.Fatal("duplicate provider work")
	}
}
func TestInteractiveXReconnectKeepsPreviousSession(t *testing.T) {
	for _, mode := range []string{"verify_failure", "changed", "rate_limited", "valid_saved", "saved_rate_limit", "verified_replacement"} {
		t.Run(mode, func(t *testing.T) {
			o, b, m := loginFixture(t)
			m.Reconnect = true
			account := providerAccount{m.ID, "x_read", filepath.Join(o.dir, "accounts", "x_read-"+m.ID, "session.json"), 2}
			prepareStateDir(filepath.Join(o.dir, "accounts"))
			prepareStateDir(filepath.Dir(account.Path))
			prior := []byte(`{"auth_token":"previous","ct0":"previous-csrf","user_agent":"previous-UA","proxy":"http://localhost:8888"}`)
			writeLocalFile(filepath.Dir(account.Path), "session.json", prior)
			registry, _ := json.Marshal(accountFile{1, []providerAccount{account}})
			writeLocalFile(o.dir, "accounts.json", registry)
			calls := 0
			o.verify = func(context.Context, x.Session, string, string) (string, error) {
				calls++
				if mode == "valid_saved" {
					return "123", nil
				}
				if mode == "saved_rate_limit" {
					return "", x.ErrRateLimited
				}
				if calls == 1 {
					return "", x.ErrUnauthorized
				}
				if mode == "changed" {
					writeLocalFile(filepath.Dir(account.Path), "session.json", []byte(`{"auth_token":"changed","ct0":"csrf"}`))
					return "123", nil
				}
				if mode == "verified_replacement" {
					return "123", nil
				}
				return "", errors.New("fixture mismatch")
			}
			b.start = func(context.Context, x.BrowserLoginRequest) (*x.BrowserLoginResult, error) {
				if mode == "rate_limited" {
					return nil, &x.BrowserLoginError{Kind: "rate_limited", RetryAfter: time.Minute}
				}
				return candidateResult(), nil
			}
			result := o.handle(context.Background(), m)
			if mode == "valid_saved" {
				if result.Status != "updated" || b.starts != 0 {
					t.Fatal(result)
				}
			} else if mode == "verified_replacement" {
				if result.Status != "updated" {
					t.Fatal(result)
				}
			} else if result.Status != "error" {
				t.Fatal(result)
			}
			saved, _ := readLocalFile(account.Path, 65536)
			if mode == "verified_replacement" {
				var session x.Session
				if json.Unmarshal(saved, &session) != nil || session.Twid != "u%3D123" || session.Proxy != "http://localhost:8888" || session.UserAgent != "fixture Chrome" {
					t.Fatal("verified browser affinity lost")
				}
				registry, _ := loadAccounts(accountFilePath(o.dir))
				if len(registry.Accounts) != 1 || registry.Accounts[0].Concurrency != 2 {
					t.Fatal("account metadata changed")
				}
			} else if mode != "changed" && string(saved) != string(prior) {
				t.Fatal("previous session overwritten")
			}
			if mode == "saved_rate_limit" && b.starts != 0 {
				t.Fatal("rate limit caused password submission")
			}
		})
	}
}
func TestInteractiveXLoginCancelBeforeCommit(t *testing.T) {
	o, b, m := loginFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	b.start = func(context.Context, x.BrowserLoginRequest) (*x.BrowserLoginResult, error) {
		cancel()
		return candidateResult(), nil
	}
	if result := o.handle(ctx, m); result.Status != "error" {
		t.Fatal(result)
	}
	if _, err := loadAccounts(accountFilePath(o.dir)); !os.IsNotExist(err) {
		t.Fatal("cancelled login committed")
	}
}

func TestInteractiveXOwnerPipeCancelsBlockedStart(t *testing.T) {
	for _, mode := range []string{"cancel", "queued_eof"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			t.Setenv("SCARLETT_STATE_DIR", dir)
			t.Setenv("SCARLETT_ACCOUNTS_FILE", filepath.Join(dir, "accounts.json"))
			bearer := filepath.Join(dir, "bearer")
			os.WriteFile(bearer, []byte(strings.Repeat("a", 64)), 0600)
			t.Setenv("SCARLETT_X_LOGIN_BEARER_FILE", bearer)
			entered := make(chan struct{})
			exited := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/capabilities":
					json.NewEncoder(w).Encode(map[string]any{"version": "v1", "ok": true, "data": map[string]any{"interactive_x": 1, "recovery_budget": 1}})
				case "/v1/login/bounded":
					io.Copy(io.Discard, r.Body)
					close(entered)
					<-r.Context().Done()
					close(exited)
				default:
					json.NewEncoder(w).Encode(map[string]any{"version": "v1", "ok": true, "data": map[string]bool{"ok": true}})
				}
			}))
			defer server.Close()
			t.Setenv("SCARLETT_X_LOGIN_URL", server.URL)
			inputR, inputW := io.Pipe()
			defer inputR.Close()
			defer inputW.Close()
			var output bytes.Buffer
			done := make(chan error, 1)
			go func() { done <- xLoginCommand(inputR, &output) }()
			encoder := json.NewEncoder(inputW)
			encoder.Encode(xLoginMessage{Action: "start", ID: "fixture", Concurrency: 1, Username: "fixture", Password: "synthetic-password"})
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("start not reached")
			}
			if mode == "cancel" {
				encoder.Encode(xLoginMessage{Action: "cancel", ID: "fixture"})
			} else {
				encoder.Encode(xLoginMessage{Action: "continue", ID: "fixture", ChallengeID: "queued", Code: "654321"})
				inputW.Close()
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("owner cancellation blocked")
			}
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("provider request not cancelled")
			}
			if strings.Contains(output.String(), "synthetic-password") || strings.Contains(output.String(), "654321") {
				t.Fatal("secret in output")
			}
			if _, err := loadAccounts(accountFilePath(dir)); !os.IsNotExist(err) {
				t.Fatal("cancelled request committed")
			}
		})
	}
}

type xLoginTransport func(*http.Request) (*http.Response, error)

func (f xLoginTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestInteractiveXVerifiesActualGoViewerIdentity(t *testing.T) {
	for _, mode := range []string{"match", "username_mismatch", "twid_mismatch", "rate_limited"} {
		t.Run(mode, func(t *testing.T) {
			viewerCalls := 0
			transport := xLoginTransport(func(r *http.Request) (*http.Response, error) {
				status := 200
				body := `{}`
				switch {
				case strings.HasSuffix(r.URL.Path, "/Viewer"):
					viewerCalls++
					if r.Header.Get("User-Agent") != "fixture Chrome" {
						t.Fatal("browser UA missing")
					}
					body = `{"data":{"viewer":{"user_results":{"result":{"rest_id":"123"}}}}}`
					if mode == "rate_limited" {
						status = 429
						body = `{}`
					}
				case strings.HasSuffix(r.URL.Path, "/UserByRestId"):
					body = `{"data":{"user":{"result":{"__typename":"User","rest_id":"123","legacy":{"screen_name":"fixture","name":"Fixture"}}}}}`
				default:
					status = 503
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			session := x.Session{AuthToken: "fixture-token", CT0: "fixture-csrf", UserAgent: "fixture Chrome"}
			username := " fixture "
			priorTwid := ""
			if mode == "username_mismatch" {
				username = "another"
			}
			if mode == "twid_mismatch" {
				session.Twid = "u%3D999"
			}
			id, err := verifyXLoginWithOptions(context.Background(), session, username, priorTwid, x.WithHTTPClient(&http.Client{Transport: transport}), x.WithMinRequestGap(0))
			if mode == "match" {
				if err != nil || id != "123" {
					t.Fatal("verified identity missing")
				}
			} else if err == nil {
				t.Fatal("unverified identity accepted")
			}
			if viewerCalls != 1 {
				t.Fatal("viewer retried")
			}
			if mode == "rate_limited" && (!errors.Is(err, x.ErrRateLimited) || errors.Is(err, x.ErrUnauthorized)) {
				t.Fatal("cooldown invalidated session")
			}
		})
	}
}

func TestInteractiveXLocalRPCDoesNotUseEnvironmentProxy(t *testing.T) {
	var proxyCalls atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { proxyCalls.Add(1); w.WriteHeader(http.StatusBadGateway) }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	var called atomic.Bool
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Password string `json:"password"`
		}
		if json.NewDecoder(r.Body).Decode(&payload) != nil || payload.Password != "synthetic-password" {
			t.Error("local credential RPC malformed")
		}
		called.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer service.Close()
	client := newXLoginRPCClient()
	transport := client.Transport.(*http.Transport)
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil {
		t.Fatal("local RPC inherited a proxy resolver")
	}
	// Route a compose-style hostname to a local fixture without DNS or provider traffic.
	address := strings.TrimPrefix(service.URL, "http://")
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	response, err := client.Post("http://x-login.compose.invalid/v1/login/bounded", "application/json", strings.NewReader(`{"password":"synthetic-password"}`))
	if err != nil {
		t.Fatal("local credential RPC failed")
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || !called.Load() || proxyCalls.Load() != 0 {
		t.Fatal("local credentials reached environment proxy")
	}
}

// Execute this same native test binary through the installer's launch/current
// symlink shape, including Darwin's os.Executable launch-path behavior.
func TestInteractiveXInstalledResourceLookup(t *testing.T) {
	if os.Getenv("SCARLETT_X_RESOURCE_LOOKUP_FIXTURE") == "1" {
		exe, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		dir, err := installedXLoginResourceDir(exe)
		if err != nil {
			os.Exit(3)
		}
		_, _ = os.Stdout.WriteString(dir)
		os.Exit(0)
	}
	if runtime.GOOS == "windows" {
		t.Skip("native Windows symlink creation requires platform privileges; install gate covers executable path")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal("native test executable unavailable")
	}
	canonical, err := filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal("native executable resolution failed")
	}
	root := t.TempDir()
	current := filepath.Join(root, "current")
	if err := os.Symlink(filepath.Dir(canonical), current); err != nil {
		t.Fatal(err)
	}
	launchDir := filepath.Join(root, "bin")
	if err := os.Mkdir(launchDir, 0700); err != nil {
		t.Fatal(err)
	}
	launch := filepath.Join(launchDir, "scarlett-node")
	if err := os.Symlink(filepath.Join(current, filepath.Base(canonical)), launch); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, launch, "-test.run=^TestInteractiveXInstalledResourceLookup$")
	command.Env = append(os.Environ(), "SCARLETT_X_RESOURCE_LOOKUP_FIXTURE=1")
	output, err := command.Output()
	if err != nil {
		t.Fatal("native symlink lookup fixture failed")
	}
	if string(output) != filepath.Dir(canonical) {
		t.Fatal("runtime resolved beside launch symlink instead of installed executable")
	}
	dangling := filepath.Join(root, "missing-node")
	if err := os.Symlink(filepath.Join(root, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := installedXLoginResourceDir(dangling); err == nil {
		t.Fatal("dangling executable did not fail closed")
	}
}
