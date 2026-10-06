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
	"time"

	"github.com/teslashibe/scarlett-node/internal/browserx"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/worker"
	x "github.com/teslashibe/x-go"
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
	return accountsCommandWithVerifier(args, input, output, func(ctx context.Context, session x.Session) (worker.VerifiedXIdentity, error) {
		return worker.VerifyXSession(ctx, session)
	})
}

func lockAccountRegistry(dir string) (*os.File, error) {
	path := accountFilePath(dir)
	if !filepath.IsAbs(path) || localfs.CheckOwnedDir(filepath.Dir(path)) != nil {
		return nil, errors.New("accounts directory must be private and owned")
	}
	return localfs.LockPrivateWait(filepath.Join(filepath.Dir(path), ".accounts.lock"))
}

func accountsCommandWithVerifier(args []string, input io.Reader, output io.Writer, verify xSessionVerifier) error {
	if len(args) > 1 && args[0] == "login-x" {
		return xLoginTerminalCommand(args[1:], input, output)
	}
	if len(args) == 1 && args[0] == "login-x" {
		return xLoginCommand(input, output)
	}
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
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		dir = config.DefaultStateDir(home)
	}
	if !filepath.IsAbs(dir) {
		return errors.New("state directory must be absolute")
	}
	if err := prepareStateDir(dir); err != nil {
		return err
	}
	path := accountFilePath(dir)
	lock, err := lockAccountRegistry(dir)
	if err != nil {
		return errors.New("cannot lock account configuration")
	}
	defer func() {
		if lock != nil {
			lock.Close()
		}
	}()
	registry, err := loadAccounts(path)
	if err != nil && !os.IsNotExist(err) {
		return errors.New("cannot read private account configuration")
	}
	if (args[0] == "reconnect" && len(args) == 3 && args[1] == "x_read") || (args[0] == "reimport-x" && len(args) == 3) {
		profile := ""
		if args[0] == "reimport-x" {
			profile = args[1]
		}
		lock.Close()
		lock = nil
		return replaceXSession(dir, registry, args[2], profile, input, output, verify)
	}
	if args[0] == "list" && len(args) == 1 {
		type item struct {
			ID          string `json:"id"`
			Service     string `json:"service"`
			Concurrency int    `json:"concurrency"`
			Username    string `json:"username,omitempty"`
		}
		out := []item{}
		for _, account := range registry.Accounts {
			row := item{ID: account.ID, Service: account.Service, Concurrency: account.Concurrency}
			if account.Service == "x_read" {
				if identity, err := verifiedXIdentity(dir, account.Path); err == nil {
					row.Username = identity.Username
				}
			}
			out = append(out, row)
		}
		return json.NewEncoder(output).Encode(out)
	}
	if args[0] == "remove" && len(args) == 3 {
		if !validAccountID(args[2]) || args[1] != "codex" && args[1] != "x_read" {
			return errors.New("invalid account removal")
		}
		out := []providerAccount{}
		for _, account := range registry.Accounts {
			if account.Service != args[1] || account.ID != args[2] {
				out = append(out, account)
			}
		}
		if len(out) != len(registry.Accounts) {
			registry.Accounts = out
			raw, err := json.Marshal(registry)
			if err != nil || writeLocalFile(filepath.Dir(path), filepath.Base(path), raw) != nil {
				return errors.New("cannot save private account configuration")
			}
		}
		return json.NewEncoder(output).Encode(map[string]string{"status": "updated"})
	}
	if !((args[0] == "add" && len(args) == 5) || (args[0] == "connect" && len(args) == 4) || (args[0] == "import-x" && len(args) == 4)) {
		return errors.New("usage: accounts list | browser-profiles | import-x PROFILE_ID ID CONCURRENCY | reimport-x PROFILE_ID ID | add SERVICE ID ABSOLUTE_PATH CONCURRENCY | connect SERVICE ID CONCURRENCY (credential JSON on protected stdin) | reconnect x_read ID (credential JSON on protected stdin) | remove SERVICE ID")
	}
	n, err := strconv.Atoi(args[len(args)-1])
	if err != nil {
		return errors.New("invalid account concurrency")
	}
	account := providerAccount{ID: args[2], Service: args[1], Concurrency: n}
	if args[0] == "import-x" {
		account.Service = "x_read"
	}
	if args[0] == "add" {
		account.Path = args[3]
	} else {
		account.Path = filepath.Join(dir, "accounts", account.Service+"-"+account.ID)
		if account.Service == "x_read" {
			account.Path = filepath.Join(account.Path, "session.json")
		}
	}
	candidate := registry
	candidate.Accounts = append(append([]providerAccount(nil), registry.Accounts...), account)
	if !validAccounts(candidate) {
		return errors.New("invalid or duplicate account; use codex or x_read, a unique lowercase ID, an absolute path and concurrency 1..32")
	}
	// Never keep the registry locked across browser reads, stdin or provider I/O.
	lock.Close()
	lock = nil
	owned := args[0] != "add"
	committed := false
	if owned {
		if account.Service == "x_read" {
			account.Path, err = newOwnedXSessionPath(dir, account.ID)
			if err != nil {
				return errors.New("cannot create private account storage")
			}
		} else {
			account.Path, err = newOwnedAccountDirectory(dir, account.Service, account.ID)
			if err != nil {
				return errors.New("cannot create private account storage")
			}
		}
		credentialPath := account.Path
		if account.Service == "codex" {
			credentialPath = filepath.Join(account.Path, "auth.json")
		}
		if _, err := os.Lstat(credentialPath); !os.IsNotExist(err) {
			return errors.New("refusing to overwrite account credentials")
		}
		profile := ""
		if args[0] == "import-x" {
			profile = args[1]
		}
		raw, err := readCredential(profile, input, output)
		if err != nil {
			return err
		}
		defer clear(raw)
		if err := localfs.WriteAtomic(credentialPath, raw, false); err != nil {
			return errors.New("cannot save private account credentials")
		}
		defer func() {
			if !committed {
				_ = os.Remove(credentialPath)
			}
		}()
	}
	var identity worker.VerifiedXIdentity
	verificationCtx := context.Background()
	if account.Service == "x_read" {
		var cancel context.CancelFunc
		verificationCtx, cancel = context.WithTimeout(verificationCtx, 30*time.Second)
		defer cancel()
		identity, err = verifyXCredential(verificationCtx, account.Path, verify)
		if err == nil {
			err = verifyRegisteredXIdentities(verificationCtx, dir, registry, "", verify)
		}
		if err != nil {
			return xAccountError(output, err)
		}
	}
	lock, err = lockAccountRegistry(dir)
	if err != nil {
		return errors.New("cannot lock account configuration")
	}
	registry, err = loadAccounts(path)
	if err != nil && !os.IsNotExist(err) {
		return errors.New("cannot read private account configuration")
	}
	candidate = registry
	candidate.Accounts = append(append([]providerAccount(nil), registry.Accounts...), account)
	if !validAccounts(candidate) {
		return errors.New("account registration changed")
	}
	if account.Service == "x_read" {
		if verificationCtx.Err() != nil {
			return xAccountError(output, verificationCtx.Err())
		}
		identityLock, err := lockXIdentities(dir)
		if err != nil {
			return xAccountError(output, err)
		}
		defer identityLock.Close()
		if verificationCtx.Err() != nil {
			return xAccountError(output, verificationCtx.Err())
		}
		identities, err := loadXIdentities(dir)
		if err == nil && worker.XSessionStamp(account.Path) != identity.Stamp {
			err = errXIdentityUnverified
		}
		if err == nil {
			err = rejectDuplicateXIdentity(registry, identities, account, identity)
		}
		if err != nil {
			return xAccountError(output, err)
		}
		pruneXIdentities(&identities, candidate, account.Path)
		identities.Identities[filepath.Clean(account.Path)] = identity
		if err := writeXIdentities(dir, identities); err != nil {
			return xAccountError(output, err)
		}
	}
	raw, err := json.Marshal(candidate)
	if err != nil || writeLocalFile(filepath.Dir(path), filepath.Base(path), raw) != nil {
		return errors.New("cannot save private account configuration")
	}
	committed = true
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

// replaceXSession validates outside registry locks. The final commit compares
// both registration and prior bytes; removal or another reconnect wins safely.
func replaceXSession(dir string, registry accountFile, id, profile string, input io.Reader, output io.Writer, verify xSessionVerifier) error {
	var account *providerAccount
	for i := range registry.Accounts {
		if registry.Accounts[i].Service == "x_read" && registry.Accounts[i].ID == id {
			copy := registry.Accounts[i]
			account = &copy
		}
	}
	if account == nil {
		return errors.New("local account not found")
	}
	if !ownedXSessionPath(dir, id, account.Path) {
		return errors.New("only an X session this node saved can be re-imported")
	}
	prior, err := readLocalFile(account.Path, 65536)
	if err != nil {
		return errors.New("cannot read previous X session")
	}
	defer clear(prior)
	priorIdentities, identityErr := loadXIdentities(dir)
	if identityErr != nil {
		return xAccountError(output, identityErr)
	}
	previousIdentity := priorIdentities.Identities[filepath.Clean(account.Path)]
	raw, err := readCredential(profile, input, output)
	if err != nil {
		return err
	}
	defer clear(raw)
	owner := opaqueLoginID()
	if owner == "" {
		return errors.New("cannot create private staging credentials")
	}
	staging := filepath.Join(filepath.Dir(account.Path), "session.verify-"+owner+".json")
	if err := localfs.WriteAtomic(staging, raw, false); err != nil {
		return errors.New("cannot save private account credentials")
	}
	defer os.Remove(staging)
	verificationCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := verifyXCredential(verificationCtx, staging, verify)
	if err == nil && validXIdentity(previousIdentity) && identity.ID != previousIdentity.ID {
		err = errXIdentityMismatch
	}
	if err == nil {
		err = verifyRegisteredXIdentities(verificationCtx, dir, registry, account.Path, verify)
	}
	if err != nil {
		return xAccountError(output, err)
	}
	lock, err := lockAccountRegistry(dir)
	if err != nil {
		return errors.New("cannot lock account configuration")
	}
	defer lock.Close()
	current, err := loadAccounts(accountFilePath(dir))
	if err != nil {
		return errors.New("cannot read private account configuration")
	}
	found := false
	for _, candidate := range current.Accounts {
		if candidate.Service == "x_read" && candidate.ID == id && candidate == *account {
			found = true
		}
	}
	stored, err := readLocalFile(account.Path, 65536)
	if err != nil || !found || !bytes.Equal(stored, prior) {
		clear(stored)
		return errors.New("account or session changed")
	}
	clear(stored)
	identityLock, err := lockXIdentities(dir)
	if err != nil {
		return xAccountError(output, err)
	}
	defer identityLock.Close()
	if verificationCtx.Err() != nil {
		return xAccountError(output, verificationCtx.Err())
	}
	identities, err := loadXIdentities(dir)
	if err == nil {
		// A warm client may authenticate this registration while the staged
		// replacement is being checked. Preserve that newly verified user too.
		latest := identities.Identities[filepath.Clean(account.Path)]
		if validXIdentity(latest) && latest.ID != identity.ID {
			err = errXIdentityMismatch
		}
	}
	if err == nil {
		err = rejectDuplicateXIdentity(current, identities, *account, identity)
	}
	if err != nil {
		return xAccountError(output, err)
	}
	pruneXIdentities(&identities, current, account.Path)
	identities.Identities[filepath.Clean(account.Path)] = identity
	// Publish the checked binding first. Until the synced credential replacement,
	// its stamp mismatch makes the old registration temporarily unverified.
	if err := writeXIdentities(dir, identities); err != nil {
		return xAccountError(output, err)
	}
	if err := localfs.WriteAtomic(account.Path, raw, true); err != nil {
		return errors.New("cannot save private account credentials")
	}
	return json.NewEncoder(output).Encode(map[string]string{"status": "updated"})
}
