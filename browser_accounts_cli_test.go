package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// Fixtures replace the browser home with a disposable directory. No test reads
// a user's browser, Keychain, DPAPI key, copied identity or real provider token.
func browserHomeFixture(t *testing.T) (string, string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	profile := filepath.Join(home, ".mozilla", "firefox", "isolated.default")
	switch runtime.GOOS {
	case "darwin":
		profile = filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles", "isolated.default")
	case "windows":
		profile = filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "isolated.default")
	}
	if err := os.MkdirAll(profile, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(profile, "cookies.sqlite")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal("fixture database unavailable")
	}
	if _, err = db.Exec(`CREATE TABLE moz_cookies(host TEXT,name TEXT,value TEXT,expiry INTEGER,originAttributes TEXT,path TEXT,isSecure INTEGER);
INSERT INTO moz_cookies VALUES('.x.com','auth_token','synthetic-import-auth',0,'','/',1),('.x.com','ct0','synthetic-import-csrf',0,'','/',1)`); err != nil {
		db.Close()
		t.Fatal("fixture schema unavailable")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return home, path
}

func browserFixtureID(t *testing.T) string {
	t.Helper()
	var out bytes.Buffer
	if err := accountsCommand([]string{"browser-profiles"}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	var profiles []struct{ ID, Browser, Label string }
	if json.Unmarshal(out.Bytes(), &profiles) != nil || len(profiles) != 1 || profiles[0].Browser != "firefox" {
		t.Fatal("isolated browser inventory unavailable")
	}
	if strings.Contains(out.String(), "synthetic-import") || strings.Contains(out.String(), "cookies.sqlite") || strings.Contains(out.String(), os.Getenv("HOME")) {
		t.Fatal("browser inventory exposed credential or path")
	}
	return profiles[0].ID
}

func TestBrowserAccountImportPersistsPrivateSessionWithoutReturningCredentials(t *testing.T) {
	_, path := browserHomeFixture(t)
	dir := privateTestDir(t)
	t.Setenv("SCARLETT_STATE_DIR", dir)
	t.Setenv("SCARLETT_ACCOUNTS_FILE", "")
	id := browserFixtureID(t)
	before, _ := os.ReadFile(path)
	var out bytes.Buffer
	if err := accountsCommand([]string{"import-x", id, "browser-one", "2"}, nil, &out); err != nil {
		t.Fatal("isolated import failed", err)
	}
	if out.String() != "{\"status\":\"updated\"}\n" {
		t.Fatal("import returned unexpected output")
	}
	f, err := loadAccounts(filepath.Join(dir, "accounts.json"))
	if err != nil || len(f.Accounts) != 1 || f.Accounts[0].Service != "x_read" || f.Accounts[0].Concurrency != 2 {
		t.Fatal("account registration failed")
	}
	credential, err := localfs.OpenPrivate(f.Accounts[0].Path)
	if err != nil {
		t.Fatal("imported credential was not private")
	}
	credential.Close()
	raw, err := os.ReadFile(f.Accounts[0].Path)
	if err != nil || !bytes.Contains(raw, []byte("synthetic-import-auth")) || !bytes.Contains(raw, []byte("synthetic-import-csrf")) {
		t.Fatal("selected credential not persisted")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("source browser database changed")
	}
	out.Reset()
	if err := accountsCommand([]string{"import-x", id, "browser-one", "2"}, nil, &out); err == nil {
		t.Fatal("duplicate import overwrote credentials")
	}
}

func TestBrowserAccountImportBusyFailsWithoutRegisteringAccount(t *testing.T) {
	_, path := browserHomeFixture(t)
	dir := privateTestDir(t)
	t.Setenv("SCARLETT_STATE_DIR", dir)
	t.Setenv("SCARLETT_ACCOUNTS_FILE", "")
	id := browserFixtureID(t)
	if err := os.WriteFile(path+"-wal", []byte("synthetic active journal"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := accountsCommand([]string{"import-x", id, "busy-one", "1"}, nil, &out)
	if err == nil || err.Error() != "browser_busy" || out.String() != "{\"code\":\"browser_busy\",\"status\":\"error\"}\n" {
		t.Fatal("busy import did not return a fixed failure")
	}
	for _, p := range []string{filepath.Join(dir, "accounts.json"), filepath.Join(dir, "accounts", "x_read-busy-one", "session.json")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("failed import wrote account credentials")
		}
	}
}

func TestNativeBrowserImportFailureReturnsNonzeroWithoutPrivateOutput(t *testing.T) {
	binary := os.Getenv("SCARLETT_TEST_NODE_BINARY")
	if binary == "" {
		t.Skip("set SCARLETT_TEST_NODE_BINARY for native CLI coverage")
	}
	home, path := browserHomeFixture(t)
	dir := privateTestDir(t)
	t.Setenv("SCARLETT_STATE_DIR", dir)
	t.Setenv("SCARLETT_ACCOUNTS_FILE", "")
	id := browserFixtureID(t)
	os.WriteFile(path+"-wal", []byte("synthetic active journal"), 0600)
	cmd := exec.Command(binary, "accounts", "import-x", id, "native-busy", "1")
	cmd.Env = os.Environ()
	raw, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(raw, []byte("browser_busy")) {
		t.Fatal("native import did not fail")
	}
	for _, private := range []string{home, dir, "synthetic-import", "synthetic active journal"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("native import error exposed private data")
		}
	}
}

func TestBrowserAccountReimportReplacesSessionForTheSameID(t *testing.T) {
	_, path := browserHomeFixture(t)
	dir := privateTestDir(t)
	t.Setenv("SCARLETT_STATE_DIR", dir)
	t.Setenv("SCARLETT_ACCOUNTS_FILE", "")
	id := browserFixtureID(t)
	var out bytes.Buffer
	if err := accountsCommand([]string{"connect", "x_read", "browser-one", "2"}, strings.NewReader(`{"auth_token":"synthetic-expired-auth","ct0":"synthetic-expired-csrf"}`), &out); err != nil {
		t.Fatal(err)
	}
	session := filepath.Join(dir, "accounts", "x_read-browser-one", "session.json")
	// A busy store reports its fixed code and leaves the old session alone.
	if err := os.WriteFile(path+"-wal", []byte("synthetic active journal"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	err := accountsCommand([]string{"reimport-x", id, "browser-one"}, nil, &out)
	if err == nil || err.Error() != "browser_busy" || out.String() != "{\"code\":\"browser_busy\",\"status\":\"error\"}\n" {
		t.Fatal("busy re-import did not return a fixed failure", err)
	}
	if raw, _ := os.ReadFile(session); !bytes.Contains(raw, []byte("synthetic-expired-auth")) {
		t.Fatal("failed re-import changed the session")
	}
	if err := os.Remove(path + "-wal"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	out.Reset()
	if err := accountsCommand([]string{"reimport-x", id, "browser-one"}, nil, &out); err != nil {
		t.Fatal("isolated re-import failed", err)
	}
	if out.String() != "{\"status\":\"updated\"}\n" {
		t.Fatal("re-import returned unexpected output")
	}
	raw, err := os.ReadFile(session)
	if err != nil || !bytes.Contains(raw, []byte("synthetic-import-auth")) || bytes.Contains(raw, []byte("synthetic-expired")) {
		t.Fatal("browser session not installed", err)
	}
	f, err := loadAccounts(filepath.Join(dir, "accounts.json"))
	if err != nil || len(f.Accounts) != 1 || f.Accounts[0].Concurrency != 2 || f.Accounts[0].Path != session {
		t.Fatal("re-import changed the account registration", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("source browser database changed")
	}
	out.Reset()
	if err := accountsCommand([]string{"reimport-x", id, "unknown"}, nil, &out); err == nil {
		t.Fatal("re-import created a new account")
	}
}
