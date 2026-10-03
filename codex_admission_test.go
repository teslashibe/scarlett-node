package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
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
