package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/teslashibe/scarlett-node/internal/browserx"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/worker"
	"golang.org/x/term"
)

const maxProviderAccounts = 8
const maxAccountsBytes = 16384

type providerAccount struct {
	ID          string `json:"id"`
	Service     string `json:"service"`
	Path        string `json:"path"` // Codex home or X session file; private local metadata
	Concurrency int    `json:"concurrency"`
}
type accountFile struct {
	Version  int               `json:"version"`
	Accounts []providerAccount `json:"accounts"`
}

func validAccountID(id string) bool {
	if len(id) < 1 || len(id) > 32 || id == "legacy" {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func validAccounts(f accountFile) bool {
	if f.Version != 1 || len(f.Accounts) > maxProviderAccounts*2 {
		return false
	}
	counts, ids, paths := map[string]int{}, map[string]bool{}, map[string]bool{}
	for index, a := range f.Accounts {
		key := a.Service + ":" + a.ID
		path := a.Service + ":" + filepath.Clean(a.Path)
		counts[a.Service]++
		if !validAccountID(a.ID) || a.Service != "codex" && a.Service != "x_read" || !filepath.IsAbs(a.Path) || len(a.Path) > 4096 || strings.ContainsAny(a.Path, "\x00\r\n") || a.Concurrency < 1 || a.Concurrency > 32 || counts[a.Service] > maxProviderAccounts || ids[key] || paths[path] {
			return false
		}
		// Two local names must not reference the same credential inode, even
		// through different home-directory aliases or hard links.
		credential := a.Path
		if a.Service == "codex" {
			credential = filepath.Join(credential, "auth.json")
		}
		if info, e := os.Stat(credential); e == nil {
			for _, other := range f.Accounts[:index] {
				if other.Service != a.Service {
					continue
				}
				otherPath := other.Path
				if other.Service == "codex" {
					otherPath = filepath.Join(otherPath, "auth.json")
				}
				if previous, e := os.Stat(otherPath); e == nil && os.SameFile(info, previous) {
					return false
				}
			}
		}
		ids[key], paths[path] = true, true
	}
	raw, e := json.Marshal(f)
	return e == nil && len(raw) <= maxAccountsBytes
}
func loadAccounts(path string) (accountFile, error) {
	f := accountFile{Version: 1, Accounts: []providerAccount{}}
	raw, e := readLocalFile(path, maxAccountsBytes)
	if e != nil {
		return f, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(new(any)) != io.EOF || !validAccounts(f) {
		return f, errors.New("invalid private account configuration")
	}
	return f, nil
}
func accountFilePath(dir string) string {
	if p := os.Getenv("SCARLETT_ACCOUNTS_FILE"); p != "" {
		return p
	}
	return filepath.Join(dir, "accounts.json")
}

// Account mutations are serialized independently of the running node's attempt
// lock. No CLI operation cancels or reassigns a provider attempt.
func accountsCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 1 && args[0] == "browser-profiles" {
		profiles, err := browserx.Profiles()
		if err != nil {
			return errors.New("local browser profiles unavailable")
		}
		return json.NewEncoder(output).Encode(profiles)
	}
	if len(args) < 1 {
		return errors.New("usage: scarlett-node accounts list|add|connect|reconnect|remove|browser-profiles|import-x|reimport-x")
	}
	dir := os.Getenv("SCARLETT_STATE_DIR")
	if dir == "" {
		h, e := os.UserHomeDir()
		if e != nil {
			return e
		}
		dir = config.DefaultStateDir(h)
	}
	if !filepath.IsAbs(dir) {
		return errors.New("state directory must be absolute")
	}
	if e := prepareStateDir(dir); e != nil {
		return e
	}
	path := accountFilePath(dir)
	if !filepath.IsAbs(path) {
		return errors.New("accounts file must be absolute")
	}
	// The CLI only writes into an existing private directory.
	if e := localfs.CheckDir(filepath.Dir(path)); e != nil {
		return errors.New("accounts directory must be private")
	}
	lock, e := localfs.LockPrivateWait(filepath.Join(filepath.Dir(path), ".accounts.lock"))
	if e != nil {
		return errors.New("cannot lock account configuration")
	}
	defer lock.Close()
	f, e := loadAccounts(path)
	if e != nil && !os.IsNotExist(e) {
		return errors.New("cannot read private account configuration")
	}
	if (args[0] == "reconnect" && len(args) == 3 && args[1] == "x_read") || (args[0] == "reimport-x" && len(args) == 3) {
		profile := ""
		if args[0] == "reimport-x" {
			profile = args[1]
		}
		return replaceXSession(dir, f, args[2], profile, input, output)
	}
	if args[0] == "list" && len(args) == 1 {
		type item struct {
			ID          string `json:"id"`
			Service     string `json:"service"`
			Concurrency int    `json:"concurrency"`
		}
		out := []item{}
		for _, a := range f.Accounts {
			out = append(out, item{a.ID, a.Service, a.Concurrency})
		}
		return json.NewEncoder(output).Encode(out)
	}
	if args[0] == "remove" && len(args) == 3 {
		found := false
		out := []providerAccount{}
		for _, a := range f.Accounts {
			if a.Service == args[1] && a.ID == args[2] {
				found = true
			} else {
				out = append(out, a)
			}
		}
		if !found {
			return errors.New("local account not found")
		}
		f.Accounts = out
	} else if (args[0] == "add" && len(args) == 5) || (args[0] == "connect" && len(args) == 4) || (args[0] == "import-x" && len(args) == 4) {
		n, e := strconv.Atoi(args[len(args)-1])
		if e != nil {
			return errors.New("invalid account concurrency")
		}
		a := providerAccount{ID: args[2], Service: args[1], Concurrency: n}
		if args[0] == "import-x" {
			a.Service = "x_read"
		}
		if args[0] == "add" {
			a.Path = args[3]
		} else {
			a.Path = filepath.Join(dir, "accounts", a.Service+"-"+a.ID)
			if a.Service == "x_read" {
				a.Path = filepath.Join(a.Path, "session.json")
			}
		}
		candidate := f
		candidate.Accounts = append(append([]providerAccount(nil), f.Accounts...), a)
		if !validAccounts(candidate) {
			return errors.New("invalid or duplicate account; use codex or x_read, a unique lowercase ID, an absolute path and concurrency 1..32")
		}
		if args[0] == "connect" || args[0] == "import-x" {
			credentialDir := a.Path
			name := "auth.json"
			if a.Service == "x_read" {
				credentialDir = filepath.Dir(a.Path)
				name = "session.json"
			}
			if e := prepareStateDir(filepath.Join(dir, "accounts")); e != nil {
				return e
			}
			if e := prepareStateDir(credentialDir); e != nil {
				return e
			}
			if _, e := os.Lstat(filepath.Join(credentialDir, name)); !os.IsNotExist(e) {
				return errors.New("refusing to overwrite account credentials")
			}
			profile := ""
			if args[0] == "import-x" {
				profile = args[1]
			}
			raw, e := readCredential(profile, input, output)
			if e != nil {
				return e
			}
			defer clear(raw)
			if e := writeLocalFile(credentialDir, name, raw); e != nil {
				return errors.New("cannot save private account credentials")
			}
			if a.Service == "x_read" && !worker.XConfigured(a.Path) {
				os.Remove(a.Path)
				return errors.New("invalid X session")
			}
		}
		f = candidate
	} else {
		return errors.New("usage: accounts list | browser-profiles | import-x PROFILE_ID ID CONCURRENCY | reimport-x PROFILE_ID ID | add SERVICE ID ABSOLUTE_PATH CONCURRENCY | connect SERVICE ID CONCURRENCY (credential JSON on protected stdin) | reconnect x_read ID (credential JSON on protected stdin) | remove SERVICE ID")
	}
	raw, e := json.Marshal(f)
	if e != nil {
		return e
	}
	if e = writeLocalFile(filepath.Dir(path), filepath.Base(path), raw); e != nil {
		return errors.New("cannot save private account configuration")
	}
	return json.NewEncoder(output).Encode(map[string]string{"status": "updated"})
}

// readCredential returns one credential JSON object, from the named browser
// profile or, without one, from protected stdin. A browser failure writes only
// its fixed code to output; credential content is never echoed.
func readCredential(profile string, input io.Reader, output io.Writer) ([]byte, error) {
	var raw []byte
	var e error
	if profile != "" {
		browser, path, err := browserx.Resolve(profile)
		if err == nil {
			raw, err = browserx.ReadSession(context.Background(), browser, path)
		}
		if err != nil {
			if encodeErr := json.NewEncoder(output).Encode(map[string]string{"status": "error", "code": browserx.Code(err)}); encodeErr != nil {
				return nil, encodeErr
			}
			return nil, err
		}
	} else if terminal, ok := input.(*os.File); ok && term.IsTerminal(int(terminal.Fd())) {
		fmt.Fprintln(os.Stderr, "Enter account credential JSON (hidden):")
		raw, e = term.ReadPassword(int(terminal.Fd()))
		fmt.Fprintln(os.Stderr)
	} else {
		raw, e = io.ReadAll(io.LimitReader(input, 65537))
	}
	if e != nil || len(raw) == 0 || len(raw) > 65536 || !json.Valid(raw) {
		clear(raw)
		return nil, errors.New("invalid credential JSON from protected stdin")
	}
	// Codex owns its authentication schema. Reject non-object JSON, leaving
	// provider validation to the helper without logging its content.
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil || len(obj) == 0 {
		clear(raw)
		return nil, errors.New("invalid credential object")
	}
	return raw, nil
}

// replaceXSession is the explicit re-import for an X account whose session X
// expired or revoked. It keeps the account's local ID, path and concurrency
// and replaces only the session this node wrote for it; connect and import-x
// still never overwrite. The new session is validated in a private staging
// file first, so a failed re-import leaves the previous session untouched. A
// running node sees the changed file on its next scheduling check and treats
// the account as configured again; attempts already in flight keep the session
// they started with.
func replaceXSession(dir string, f accountFile, id, profile string, input io.Reader, output io.Writer) error {
	var account *providerAccount
	for i := range f.Accounts {
		if f.Accounts[i].Service == "x_read" && f.Accounts[i].ID == id {
			account = &f.Accounts[i]
		}
	}
	if account == nil {
		return errors.New("local account not found")
	}
	credentialDir := filepath.Join(dir, "accounts", "x_read-"+id)
	if filepath.Clean(account.Path) != filepath.Join(credentialDir, "session.json") {
		return errors.New("only an X session this node saved can be re-imported")
	}
	if e := localfs.CheckDir(credentialDir); e != nil {
		return errors.New("account directory must be private")
	}
	raw, e := readCredential(profile, input, output)
	if e != nil {
		return e
	}
	defer clear(raw)
	const staging = "session.replace.json"
	defer os.Remove(filepath.Join(credentialDir, staging))
	if e := writeLocalFile(credentialDir, staging, raw); e != nil {
		return errors.New("cannot save private account credentials")
	}
	if !worker.XConfigured(filepath.Join(credentialDir, staging)) {
		return errors.New("invalid X session")
	}
	if e := writeLocalFile(credentialDir, "session.json", raw); e != nil {
		return errors.New("cannot save private account credentials")
	}
	return json.NewEncoder(output).Encode(map[string]string{"status": "updated"})
}
