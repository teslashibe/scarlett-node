package main

import (
	"bytes"
	"encoding/json"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAccountCLIConnectAddListRemovePrivateAndNoCredentialOverwrite(t *testing.T) {
	dir := privateTestDir(t)
	t.Setenv("SCARLETT_STATE_DIR", dir)
	t.Setenv("SCARLETT_ACCOUNTS_FILE", "")
	var out bytes.Buffer
	call := func(args []string, input string) error {
		out.Reset()
		return fixtureAccountsCommand(args, strings.NewReader(input), &out)
	}
	if e := call([]string{"connect", "x_read", "first", "1"}, `{"auth_token":"synthetic-private-auth","ct0":"synthetic-private-csrf"}`); e != nil {
		t.Fatal(e)
	}
	if e := call([]string{"connect", "codex", "first", "2"}, `{"synthetic_auth":"private-codex-fixture"}`); e != nil {
		t.Fatal(e)
	}
	if e := call([]string{"list"}, ""); e != nil {
		t.Fatal(e)
	}
	if !json.Valid(out.Bytes()) || !strings.Contains(out.String(), "codex") {
		t.Fatal("missing safe account inventory")
	}
	for _, private := range []string{dir, "private-auth", "private-csrf", "private-codex-fixture"} {
		if strings.Contains(out.String(), private) {
			t.Fatal("inventory exposed private material")
		}
	}
	f, e := loadAccounts(filepath.Join(dir, "accounts.json"))
	if e != nil || len(f.Accounts) != 2 {
		t.Fatal("missing persisted accounts", e)
	}
	for _, a := range f.Accounts {
		path := a.Path
		if a.Service == "codex" {
			path = filepath.Join(path, "auth.json")
		}
		f, e := localfs.OpenPrivate(path)
		if e == nil {
			f.Close()
		}
		if e != nil {
			t.Fatal("credentials not private", e)
		}
	}
	if e := call([]string{"connect", "x_read", "first", "1"}, `{"auth_token":"replace","ct0":"replace"}`); e == nil {
		t.Fatal("existing credential overwritten")
	}
	if e := call([]string{"connect", "x_read", "invalid", "1"}, `{"auth_token":"missing csrf"}`); e == nil || strings.Contains(e.Error(), "missing csrf") {
		t.Fatal("invalid session or raw credential error", e)
	}
	if e := call([]string{"add", "codex", "../escape", dir, "1"}, ""); e == nil {
		t.Fatal("unsafe ID accepted")
	}
	if e := call([]string{"remove", "codex", "first"}, ""); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, "accounts", "codex-first", "auth.json")); e != nil {
		t.Fatal("removal destroyed draining credentials")
	}
}
func TestAccountCLIRejectsSymlinkAndOversizedSecretInput(t *testing.T) {
	dir := privateTestDir(t)
	t.Setenv("SCARLETT_STATE_DIR", dir)
	t.Setenv("SCARLETT_ACCOUNTS_FILE", "")
	target := filepath.Join(dir, "target")
	writePrivateFixture(target, []byte(`{"version":1,"accounts":[]}`), 0600)
	os.Symlink(target, filepath.Join(dir, "accounts.json"))
	var out bytes.Buffer
	if e := fixtureAccountsCommand([]string{"list"}, strings.NewReader(""), &out); e == nil {
		t.Fatal("symlink configuration accepted")
	}
	os.Remove(filepath.Join(dir, "accounts.json"))
	if e := fixtureAccountsCommand([]string{"connect", "codex", "one", "1"}, strings.NewReader(strings.Repeat("x", 65537)), &out); e == nil {
		t.Fatal("oversized secret input accepted")
	}
}
func TestNativeBinaryAccountCLIUsesPrivateStdin(t *testing.T) {
	binary := os.Getenv("SCARLETT_TEST_NODE_BINARY")
	if binary == "" {
		t.Skip("set SCARLETT_TEST_NODE_BINARY for native CLI coverage")
	}
	dir := privateTestDir(t)
	cmd := exec.Command(binary, "accounts", "connect", "codex", "native", "1")
	cmd.Env = append(os.Environ(), "SCARLETT_STATE_DIR="+dir, "SCARLETT_ACCOUNTS_FILE=")
	cmd.Stdin = strings.NewReader(`{"auth_token":"synthetic-native-auth","ct0":"synthetic-native-csrf"}`)
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("native connect: %v %s", e, out)
	}
	if bytes.Contains(out, []byte("synthetic-native")) {
		t.Fatal("native credential leaked")
	}
	cmd = exec.Command(binary, "accounts", "list")
	cmd.Env = append(os.Environ(), "SCARLETT_STATE_DIR="+dir, "SCARLETT_ACCOUNTS_FILE=")
	out, e = cmd.CombinedOutput()
	if e != nil || !bytes.Contains(out, []byte(`"native"`)) {
		t.Fatal("native inventory unavailable", e)
	}
}

// An X session that X expired or revoked is re-imported under the same local
// ID. Only an existing account's node-saved session is replaced, a rejected
// replacement leaves the previous session in place, and a running pool treats
// the account as configured again without being restarted.
func TestAccountCLIReconnectReplacesOnlyAnExistingNodeSavedXSession(t *testing.T) {
	dir := privateTestDir(t)
	t.Setenv("SCARLETT_STATE_DIR", dir)
	t.Setenv("SCARLETT_ACCOUNTS_FILE", "")
	var out bytes.Buffer
	call := func(args []string, input string) error {
		out.Reset()
		return fixtureAccountsCommand(args, strings.NewReader(input), &out)
	}
	if e := call([]string{"connect", "x_read", "first", "2"}, `{"auth_token":"synthetic-expired-auth","ct0":"synthetic-expired-csrf"}`); e != nil {
		t.Fatal(e)
	}
	session := filepath.Join(dir, "accounts", "x_read-first", "session.json")
	before, e := loadAccounts(filepath.Join(dir, "accounts.json"))
	if e != nil {
		t.Fatal(e)
	}
	pool := poolFixture(t, "x_read")
	pool.config.StateDir = dir
	pool.config.AccountsFile = filepath.Join(dir, "accounts.json")
	lease, ok := pool.acquireAccount("x_read")
	if !ok || lease.config.XSession != session {
		t.Fatal("connected account unavailable")
	}
	pool.finishAccount(lease, "auth_required")
	if status := pool.accountStatus(); len(status) != 1 || status[0].State != "auth_required" {
		t.Fatalf("expired session not reported: %+v", status)
	}

	if e := call([]string{"reconnect", "x_read", "first"}, `{"auth_token":"synthetic-fresh-auth","ct0":"synthetic-fresh-csrf"}`); e != nil {
		t.Fatal(e)
	}
	if out.String() != "{\"status\":\"updated\"}\n" {
		t.Fatal("reconnect returned unexpected output")
	}
	raw, e := os.ReadFile(session)
	if e != nil || !bytes.Contains(raw, []byte("synthetic-fresh-auth")) || bytes.Contains(raw, []byte("synthetic-expired")) {
		t.Fatal("session not replaced", e)
	}
	if f, e := localfs.OpenPrivate(session); e != nil {
		t.Fatal("replaced session is not private", e)
	} else {
		f.Close()
	}
	if _, e := os.Lstat(filepath.Join(dir, "accounts", "x_read-first", "session.replace.json")); !os.IsNotExist(e) {
		t.Fatal("staging credential left behind", e)
	}
	after, e := loadAccounts(filepath.Join(dir, "accounts.json"))
	if e != nil || len(after.Accounts) != 1 || after.Accounts[0] != before.Accounts[0] {
		t.Fatal("re-import changed the account registration", e)
	}
	if status := pool.accountStatus(); len(status) != 1 || status[0].State != "configured" || status[0].LastError != "" {
		t.Fatalf("running pool kept the expired state: %+v", status)
	}
	if _, ok := pool.acquireAccount("x_read"); !ok {
		t.Fatal("re-imported account did not admit work")
	}

	if e := call([]string{"reconnect", "x_read", "first"}, `{"auth_token":"synthetic-missing-csrf"}`); e == nil || strings.Contains(e.Error(), "synthetic") {
		t.Fatal("invalid session accepted or echoed", e)
	}
	if raw, _ := os.ReadFile(session); !bytes.Contains(raw, []byte("synthetic-fresh-auth")) {
		t.Fatal("rejected re-import damaged the previous session")
	}
	for _, args := range [][]string{
		{"reconnect", "x_read", "missing"},
		{"reconnect", "codex", "first"},
		{"reconnect", "x_read", "../first"},
		{"reconnect", "x_read"},
	} {
		if e := call(args, `{"auth_token":"synthetic-other-auth","ct0":"synthetic-other-csrf"}`); e == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	// A session registered from an operator-chosen path is never written to.
	external := filepath.Join(dir, "external-session.json")
	writePrivateFixture(external, []byte(`{"auth_token":"synthetic-external-auth","ct0":"synthetic-external-csrf"}`), 0600)
	if e := call([]string{"add", "x_read", "external", external, "1"}, ""); e != nil {
		t.Fatal(e)
	}
	if e := call([]string{"reconnect", "x_read", "external"}, `{"auth_token":"synthetic-other-auth","ct0":"synthetic-other-csrf"}`); e == nil {
		t.Fatal("re-import wrote outside the node's account storage")
	}
	if raw, _ := os.ReadFile(external); !bytes.Contains(raw, []byte("synthetic-external-auth")) {
		t.Fatal("external session changed")
	}
	// A removed account is not re-imported; its retained file stays as it was.
	if e := call([]string{"remove", "x_read", "first"}, ""); e != nil {
		t.Fatal(e)
	}
	if e := call([]string{"reconnect", "x_read", "first"}, `{"auth_token":"synthetic-other-auth","ct0":"synthetic-other-csrf"}`); e == nil {
		t.Fatal("removed account re-imported")
	}
	if raw, _ := os.ReadFile(session); !bytes.Contains(raw, []byte("synthetic-fresh-auth")) {
		t.Fatal("removed account's retained session changed")
	}
}
