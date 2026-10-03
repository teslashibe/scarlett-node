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
		return accountsCommand(args, strings.NewReader(input), &out)
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
	if e := accountsCommand([]string{"list"}, strings.NewReader(""), &out); e == nil {
		t.Fatal("symlink configuration accepted")
	}
	os.Remove(filepath.Join(dir, "accounts.json"))
	if e := accountsCommand([]string{"connect", "codex", "one", "1"}, strings.NewReader(strings.Repeat("x", 65537)), &out); e == nil {
		t.Fatal("oversized secret input accepted")
	}
}
func TestNativeBinaryAccountCLIUsesPrivateStdin(t *testing.T) {
	binary := os.Getenv("SCARLETT_TEST_NODE_BINARY")
	if binary == "" {
		t.Skip("set SCARLETT_TEST_NODE_BINARY for native CLI coverage")
	}
	dir := privateTestDir(t)
	cmd := exec.Command(binary, "accounts", "connect", "x_read", "native", "1")
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
