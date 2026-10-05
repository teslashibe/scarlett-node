package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// No real provider token or identity is used. This unsigned JWT-shaped fixture
// exercises local expiry parsing only, never provider authentication.
func syntheticCodexAuth(expiry time.Time) []byte {
	return syntheticCodexClaims(fmt.Sprintf(`{"exp":%d}`, expiry.Unix()), nil)
}

func syntheticCodexClaims(claims string, expiresAt any) []byte {
	tokens := map[string]any{
		"access_token": "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".synthetic",
		"account_id":   "synthetic-private-account",
	}
	if expiresAt != nil {
		tokens["expires_at"] = expiresAt
	}
	raw, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": tokens})
	return raw
}

func freshSyntheticCodexAuth() []byte {
	return syntheticCodexAuth(time.Now().Add(365 * 24 * time.Hour))
}

func TestCodexExpiryFormatsFailClosed(t *testing.T) {
	valid := int64(2000000000)
	for _, tc := range []struct {
		name string
		data []byte
		want int64
	}{
		{"CLI JWT without expires_at", syntheticCodexClaims(fmt.Sprintf(`{"exp":%d}`, valid), nil), valid},
		{"earlier persisted expiry", syntheticCodexClaims(fmt.Sprintf(`{"exp":%d}`, valid), valid-10), valid - 10},
		{"persisted field cannot extend JWT", syntheticCodexClaims(fmt.Sprintf(`{"exp":%d}`, valid), valid+10), valid},
		{"unknown", []byte(`{"tokens":{"access_token":"opaque","account_id":"synthetic"}}`), 0},
		{"opaque persisted expiry", []byte(`{"tokens":{"access_token":"opaque","account_id":"synthetic","expires_at":2000000000}}`), 0},
		{"empty", []byte(`{}`), 0},
		{"malformed auth", []byte(`{"tokens":`), 0},
		{"trailing auth", append(syntheticCodexClaims(`{"exp":2000000000}`, nil), []byte(` {}`)...), 0},
		{"missing expiry", syntheticCodexClaims(`{"other":2000000000}`, nil), 0},
		{"null expiry", syntheticCodexClaims(`{"exp":null}`, nil), 0},
		{"negative expiry", syntheticCodexClaims(`{"exp":-1}`, nil), 0},
		{"zero expiry", syntheticCodexClaims(`{"exp":0}`, nil), 0},
		{"string expiry", syntheticCodexClaims(`{"exp":"2000000000"}`, nil), 0},
		{"fractional expiry", syntheticCodexClaims(`{"exp":2000000000.5}`, nil), 0},
		{"overflow expiry", syntheticCodexClaims(`{"exp":9223372036854775808}`, nil), 0},
		{"unrepresentable year", syntheticCodexClaims(`{"exp":9223372036854775807}`, nil), 0},
		{"duplicate expiry", syntheticCodexClaims(`{"exp":1,"exp":2000000000}`, nil), 0},
		{"malformed claims", syntheticCodexClaims(`{"exp":`, nil), 0},
		{"invalid persisted expiry", syntheticCodexClaims(`{"exp":2000000000}`, "2000000000"), 0},
		{"duplicate tokens", []byte(`{"tokens":{},"tokens":{}}`), 0},
		{"bad JWT payload", []byte(`{"tokens":{"access_token":"header.%.signature","account_id":"synthetic"}}`), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expiry, ok := codexAuthExpiry(tc.data)
			if tc.want == 0 {
				if ok {
					t.Fatal("unknown or malformed expiry admitted")
				}
			} else if !ok || expiry.Unix() != tc.want {
				t.Fatal("known expiry was not conservatively parsed")
			}
		})
	}
}

func TestCodexAdmissionDeadlineBoundary(t *testing.T) {
	home := privateTestDir(t)
	deadline := time.Unix(2000000000, 0)
	for _, tc := range []struct {
		delta time.Duration
		want  bool
	}{{-time.Second, false}, {0, false}, {time.Second, true}} {
		if err := writePrivateFixture(filepath.Join(home, "auth.json"), syntheticCodexAuth(deadline.Add(codexAdmissionClockMargin+tc.delta)), 0600); err != nil {
			t.Fatal(err)
		}
		if got := codexAdmissionValid(home, deadline); got != tc.want {
			t.Fatal("deadline/clock margin boundary was not enforced")
		}
	}
	if codexAdmissionValid(home, time.Time{}) || codexAdmissionValid("relative", deadline) {
		t.Fatal("unbounded or unrelated credential path admitted")
	}
}

func TestCodexAdmissionBlocksLegacyCapacityWithoutBlockingX(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"tokens":{"access_token":"opaque","account_id":"synthetic"}}`),
		syntheticCodexAuth(time.Now().Add(-time.Hour)),
		syntheticCodexAuth(time.Now().Add(90 * time.Second)),
	} {
		p := poolFixture(t, "codex", "x_read")
		if err := writePrivateFixture(filepath.Join(p.config.CodexHome, "auth.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		h := healthKind(t, p, "codex")
		if h.State != "auth_required" || h.Capacity != 0 || p.acquire("codex") || !p.acquire("x_read") {
			t.Fatal("invalid Codex expiry was advertised or affected X")
		}
		p.finish("x_read", "")
	}
}

func TestCodexAdmissionSelectsOnlyFreshAccountAndRepairsAfterReplacement(t *testing.T) {
	p := multiPool(t)
	f, err := loadAccounts(p.config.AccountsFile)
	if err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(f.Accounts[0].Path, "auth.json")
	if err := writePrivateFixture(first, syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	l, ok := p.acquireAccount("codex")
	x, xOK := p.acquireAccount("x_read")
	if !ok || l.id != "two" || !xOK {
		t.Fatal("expiry leaked across isolated accounts/services")
	}
	p.finishAccount(l, "")
	p.finishAccount(x, "")
	if err := writePrivateFixture(first, freshSyntheticCodexAuth(), 0600); err != nil {
		t.Fatal(err)
	}
	l, ok = p.acquireAccount("codex")
	if !ok || l.id != "one" {
		t.Fatal("fresh replacement did not restore only repaired account")
	}
	p.finishAccount(l, "")
}

func TestCodexAdmissionRejectsMissingOrOversizedAuth(t *testing.T) {
	home := privateTestDir(t)
	path := filepath.Join(home, "auth.json")
	if err := writePrivateFixture(path, make([]byte, 65537), 0600); err != nil {
		t.Fatal(err)
	}
	if codexAdmissionValid(home, time.Now()) {
		t.Fatal("oversized credential file admitted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if codexAdmissionValid(home, time.Now()) {
		t.Fatal("missing credential file admitted")
	}
}

func TestLegacyCodexAdmissionGateAppliesOnlyToFundedTLSNMode(t *testing.T) {
	home := privateTestDir(t)
	if err := writePrivateFixture(filepath.Join(home, "auth.json"), syntheticCodexAuth(time.Now().Add(-time.Hour)), 0600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := config.Config{Executor: config.ExecutorCodexTLSN, CodexHome: home}
	if !legacyCodexAdmissionBlocked(c, now) {
		t.Fatal("expired codex-tlsn credential advertised as available")
	}
	for _, other := range []config.Config{
		{Executor: config.ExecutorCodexTLSN, CodexHome: home, LocalFixture: true},
		{Executor: config.ExecutorServices, CodexHome: home},
		{Executor: config.ExecutorGateway, CodexHome: home},
	} {
		if legacyCodexAdmissionBlocked(other, now) {
			t.Fatal("legacy Codex gate applied outside funded codex-tlsn mode")
		}
	}
	if err := writePrivateFixture(filepath.Join(home, "auth.json"), freshSyntheticCodexAuth(), 0600); err != nil {
		t.Fatal(err)
	}
	if legacyCodexAdmissionBlocked(c, now) {
		t.Fatal("renewed credential stayed blocked")
	}
}

// codex-cli writes auth.json in place, and open-agent-api persists a renewal
// through os.CreateTemp in the same directory and a rename. The result keeps
// the DACL inherited from CODEX_HOME: v0.1.32 copies the replaced profile's
// owner, and its DACL only when protected, which a codex-cli profile is not.
func writeCodexAuthLikeCLI(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	externalCredentialFixture(t, path)
}

func replaceCodexAuthLikeGateway(t *testing.T, path string, raw []byte) {
	t.Helper()
	temp, err := os.CreateTemp(filepath.Dir(path), ".codex-auth-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp.Name())
	err = temp.Chmod(0600)
	if err == nil {
		_, err = temp.Write(raw)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temp.Name(), path)
	}
	if err != nil {
		t.Fatal(err)
	}
	externalCredentialFixture(t, path)
}

// desktopCodexAccount reserves CODEX_HOME as desktop Connect Codex does and
// registers it after codex-cli writes a fresh login there.
func desktopCodexAccount(t *testing.T, p *servicePool) string {
	t.Helper()
	profiles := filepath.Join(p.config.StateDir, "codex-logins")
	if err := localfs.EnsureDir(profiles); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(profiles, "codex-1")
	if err := localfs.CreateDir(home); err != nil {
		t.Fatal(err)
	}
	writeCodexAuthLikeCLI(t, filepath.Join(home, "auth.json"), freshSyntheticCodexAuth())
	saveAccountFixture(t, p, accountFile{Version: 1, Accounts: []providerAccount{{"codex-1", "codex", home, 1}}})
	return home
}

// On Windows these writes leave auth.json with only ACEs inherited from the
// profile. Strict private reads rejected it, so every desktop Codex account
// stayed auth_required and codex-tlsn stayed exhausted.
func TestDesktopCodexProfileAdmitsCLIAndGatewayWrittenLogins(t *testing.T) {
	p := poolFixture(t, "codex")
	home := desktopCodexAccount(t, p)
	auth := filepath.Join(home, "auth.json")
	if !codexAdmissionValid(home, codexAdmissionWindow(time.Now())) || legacyCodexAdmissionBlocked(config.Config{Executor: config.ExecutorCodexTLSN, CodexHome: home}, time.Now()) {
		t.Fatal("fresh codex-cli login cannot admit an offer")
	}
	if h := healthKind(t, p, "codex"); h.State != "configured" || h.Capacity != 1 {
		t.Fatal("codex-cli login left the desktop account unconfigured", h.State)
	}
	l, ok := p.acquireAccount("codex")
	if !ok || l.config.CodexHome != home {
		t.Fatal("codex-cli login was not selectable")
	}
	p.finishAccount(l, "")
	if healthKind(t, p, "codex").State != "ready" {
		t.Fatal("successful attempt did not mark the account ready")
	}
	// Each renewal is read again: an expired one blocks and a fresh one repairs.
	replaceCodexAuthLikeGateway(t, auth, syntheticCodexAuth(time.Now().Add(-time.Hour)))
	if healthKind(t, p, "codex").State != "auth_required" {
		t.Fatal("expired renewal was not observed")
	}
	// open-agent-api persists expires_at with a renewal. The larger file also
	// changes the refresh stamp when both writes share one coarse NTFS
	// timestamp tick, so the repair never depends on clock granularity.
	renewed := time.Now().Add(365 * 24 * time.Hour).Unix()
	replaceCodexAuthLikeGateway(t, auth, syntheticCodexClaims(fmt.Sprintf(`{"exp":%d}`, renewed), renewed))
	if h := healthKind(t, p, "codex"); h.State != "configured" || h.Capacity != 1 || !codexAdmissionValid(home, codexAdmissionWindow(time.Now())) {
		t.Fatal("renewed login did not restore the desktop account", h.State)
	}
}

// Legacy codex-tlsn heartbeats have no typed service health. A credential that
// cannot cover a funded offer must stop dispatch before polling; otherwise the
// local admission guard refuses each offer silently and it waits out its deadline.
func TestLegacyCodexTLSNHeartbeatHonorsLocalAdmission(t *testing.T) {
	for _, tc := range []struct {
		name  string
		auth  []byte
		state string
		offer bool
	}{
		{"expired", syntheticCodexAuth(time.Now().Add(-time.Hour)), "exhausted", true},
		{"shorter than an offer", syntheticCodexAuth(time.Now().Add(coordinator.MaxOfferLifetime)), "exhausted", false},
		{"unknown expiry", []byte(`{"tokens":{"access_token":"synthetic-opaque","account_id":"synthetic"}}`), "exhausted", false},
		{"fresh", freshSyntheticCodexAuth(), "available", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateTestDir(t)
			home := filepath.Join(dir, "codex")
			if err := privateFixtureMkdir(home, 0700); err != nil {
				t.Fatal(err)
			}
			if err := writePrivateFixture(filepath.Join(home, "auth.json"), tc.auth, 0600); err != nil {
				t.Fatal(err)
			}
			c := config.Config{Executor: config.ExecutorCodexTLSN, Profile: "standard", StateDir: filepath.Join(dir, "state"), CodexHome: home, Credential: "synthetic-credential", NodeID: "synthetic-node", Concurrency: 3, Bid: 100, Verifier: "locally-configured.invalid:7047", Prover: filepath.Join(dir, "synthetic-prover-never-run"), JournalLimits: attempts.DefaultLimits(), MaxInputBytes: 1024, MaxOutputTokens: 20, InferenceTimeout: 3 * time.Second}
			offer := testLease()
			offer.ServiceType, offer.AcceptanceRequired = "codex", true
			offer.SettlementDeadline = offer.LeaseDeadline
			offer.SignedJobID, offer.RequestSHA256 = strings.Repeat("a", 64), strings.Repeat("b", 64)
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			var heartbeats, other atomic.Int32
			received := make(chan coordinator.Heartbeat, 8)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/node/v1/heartbeat" {
					other.Add(1)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				var h coordinator.Heartbeat
				if json.NewDecoder(r.Body).Decode(&h) != nil {
					t.Error("invalid heartbeat")
				}
				select {
				case received <- h:
				default:
				}
				if heartbeats.Add(1) == 1 && tc.offer {
					// An unsolicited offer to a blocked node is still never funded.
					json.NewEncoder(w).Encode(map[string]any{"lease": offer})
					return
				}
				writer.Close()
				io.WriteString(w, `{"lease":null}`)
			}))
			defer server.Close()
			c.Coordinator = server.URL
			c.CoordinatorCA = filepath.Join(privateTestDir(t), "synthetic-coordinator-ca.pem")
			if err := writePrivateFixture(c.CoordinatorCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- runWithOwner(c, reader) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				writer.Close()
				t.Fatal("synthetic node did not stop")
			}
			close(received)
			count := 0
			for h := range received {
				count++
				if h.State != tc.state || h.Capacity != 3 || len(h.Services) != 0 {
					t.Fatalf("legacy heartbeat %s with capacity %d; want %s with positive legacy capacity", h.State, h.Capacity, tc.state)
				}
			}
			if count == 0 || (tc.offer && count < 2) || other.Load() != 0 {
				t.Fatal("missing heartbeat, or a blocked offer called acceptance or report HTTP")
			}
		})
	}
}
