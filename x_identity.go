package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/worker"
	x "github.com/teslashibe/x-go"
)

const maxXIdentitiesBytes = 32768
const maxXIdentities = 64

var errDuplicateXIdentity = errors.New("duplicate X account")
var errXIdentityUnverified = errors.New("X identity verification required")
var errXIdentityMismatch = errors.New("X account identity changed")

// This is private local metadata, never a coordinator claim. Only an
// authenticated Viewer response may supply ID and Username. Stamp binds it to
// the exact credential bytes that were checked, including proxy affinity.
type xIdentityFile struct {
	Version    int                                 `json:"version"`
	Identities map[string]worker.VerifiedXIdentity `json:"identities"`
}

type xSessionVerifier func(context.Context, x.Session) (worker.VerifiedXIdentity, error)

func validXIdentity(identity worker.VerifiedXIdentity) bool {
	if len(identity.ID) < 1 || len(identity.ID) > 32 || len(identity.Username) > 15 || len(identity.Stamp) != 64 {
		return false
	}
	for _, c := range identity.ID {
		if c < '0' || c > '9' {
			return false
		}
	}
	for _, c := range identity.Username {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	decoded, err := hex.DecodeString(identity.Stamp)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(identity.Stamp) == identity.Stamp
}

func validXIdentityPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && len(path) <= 4096 && !strings.ContainsAny(path, "\x00\r\n")
}

func xIdentitiesPath(dir string) string { return filepath.Join(dir, "x-identities.json") }

func loadXIdentities(dir string) (xIdentityFile, error) {
	f := xIdentityFile{Version: 1, Identities: map[string]worker.VerifiedXIdentity{}}
	raw, err := readLocalFile(xIdentitiesPath(dir), maxXIdentitiesBytes)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return f, errors.New("cannot read private X identities")
	}
	if !uniqueIdentityJSON(raw) {
		return f, errors.New("invalid private X identities")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(new(any)) != io.EOF || f.Version != 1 || f.Identities == nil || len(f.Identities) > maxXIdentities {
		return f, errors.New("invalid private X identities")
	}
	for path, identity := range f.Identities {
		if !validXIdentityPath(path) || !validXIdentity(identity) {
			return f, errors.New("invalid private X identities")
		}
	}
	return f, nil
}

// Duplicate object keys are ambiguous even in a private sidecar. Accept only
// the single bounded object tree expected by the versioned decoder below.
func uniqueIdentityJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 4 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		if delimiter, ok := token.(json.Delim); ok {
			if delimiter != '{' {
				return false
			}
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] || !value(depth+1) {
					return false
				}
				seen[name] = true
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		}
		return true
	}
	return value(0) && d.Decode(new(any)) == io.EOF
}

// xCredentialStamp also binds browser sessions with proxy affinity. Such a
// session may be verified for account management while XConfigured still
// rejects it for the proof transport; this fingerprint never establishes readiness.
func xCredentialStamp(path string) string {
	raw, err := readLocalFile(path, 65536)
	if err != nil {
		return ""
	}
	defer clear(raw)
	var session x.Session
	if json.Unmarshal(raw, &session) != nil || session.Validate() != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func verifiedXIdentity(dir, path string) (worker.VerifiedXIdentity, error) {
	f, err := loadXIdentities(dir)
	if err != nil {
		return worker.VerifiedXIdentity{}, err
	}
	identity := f.Identities[filepath.Clean(path)]
	if !validXIdentity(identity) || xCredentialStamp(path) != identity.Stamp {
		return worker.VerifiedXIdentity{}, errXIdentityUnverified
	}
	return identity, nil
}

func writeXIdentities(dir string, f xIdentityFile) error {
	if f.Version != 1 || f.Identities == nil || len(f.Identities) > maxXIdentities {
		return errors.New("invalid private X identities")
	}
	for path, identity := range f.Identities {
		if !validXIdentityPath(path) || !validXIdentity(identity) {
			return errors.New("invalid private X identities")
		}
	}
	raw, err := json.Marshal(f)
	if err != nil || len(raw) > maxXIdentitiesBytes {
		return errors.New("private X identities limit exceeded")
	}
	return writeLocalFile(dir, filepath.Base(xIdentitiesPath(dir)), raw)
}

// Runtime observers take only this lock. CLI commits always take the registry
// lock first, then this lock. No provider or browser request holds either.
func lockXIdentities(dir string) (*os.File, error) {
	if localfs.CheckOwnedDir(dir) != nil {
		return nil, errors.New("X identities directory must be private and owned")
	}
	return localfs.LockPrivateWait(filepath.Join(dir, ".x-identities.lock"))
}

func pruneXIdentities(f *xIdentityFile, registry accountFile, keep string) {
	active := map[string]bool{filepath.Clean(keep): true}
	for _, account := range registry.Accounts {
		if account.Service == "x_read" {
			active[filepath.Clean(account.Path)] = true
		}
	}
	for path := range f.Identities {
		if !active[path] {
			delete(f.Identities, path)
		}
	}
}

// saveXIdentity is the warm-client observation path. It rechecks the saved
// stamp so a delayed client build cannot bind a replacement session. Retired
// paths can be pruned: active drains retain their identity in the account pool.
func saveXIdentity(dir, path string, identity worker.VerifiedXIdentity) error {
	path = filepath.Clean(path)
	if !validXIdentityPath(path) || !validXIdentity(identity) || xCredentialStamp(path) != identity.Stamp {
		return errXIdentityUnverified
	}
	lock, err := lockXIdentities(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	f, err := loadXIdentities(dir)
	if err != nil {
		return err
	}
	if previous := f.Identities[path]; validXIdentity(previous) && previous.Stamp == identity.Stamp && previous.ID != identity.ID {
		return errXIdentityMismatch
	}
	registry, err := loadAccounts(accountFilePath(dir))
	if err != nil && !os.IsNotExist(err) {
		return errors.New("cannot read private account configuration")
	}
	if err == nil {
		registered := false
		for _, account := range registry.Accounts {
			if account.Service == "x_read" && filepath.Clean(account.Path) == path {
				registered = true
			}
		}
		if !registered {
			return errXIdentityUnverified
		}
	}
	pruneXIdentities(&f, registry, path)
	if xCredentialStamp(path) != identity.Stamp {
		return errXIdentityUnverified
	}
	f.Identities[path] = identity
	return writeXIdentities(dir, f)
}

func verifyXCredential(ctx context.Context, path string, verify xSessionVerifier) (worker.VerifiedXIdentity, error) {
	if ctx.Err() != nil {
		return worker.VerifiedXIdentity{}, errXIdentityUnverified
	}
	if !worker.XConfigured(path) {
		return worker.VerifiedXIdentity{}, errors.New("invalid X session")
	}
	raw, err := readLocalFile(path, 65536)
	if err != nil {
		return worker.VerifiedXIdentity{}, errors.New("cannot read private X session")
	}
	defer clear(raw)
	var session x.Session
	if json.Unmarshal(raw, &session) != nil {
		return worker.VerifiedXIdentity{}, errors.New("invalid X session")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	identity, err := verify(bounded, session)
	if err != nil || bounded.Err() != nil {
		return worker.VerifiedXIdentity{}, errors.New("X session verification failed")
	}
	stamp := sha256.Sum256(raw)
	identity.Stamp = hex.EncodeToString(stamp[:])
	if !validXIdentity(identity) || xCredentialStamp(path) != identity.Stamp {
		return worker.VerifiedXIdentity{}, errXIdentityUnverified
	}
	return identity, nil
}

// Legacy registrations have no sidecar yet. Authenticate usable unknown
// sessions before duplicate admission; expired or unverifiable registrations
// cannot silently permit a duplicate identity. This runs outside registry locks.
func verifyRegisteredXIdentities(ctx context.Context, dir string, registry accountFile, exclude string, verify xSessionVerifier) error {
	identities, err := loadXIdentities(dir)
	if err != nil {
		return err
	}
	for _, account := range registry.Accounts {
		if ctx.Err() != nil {
			return errXIdentityUnverified
		}
		if account.Service != "x_read" || account.Path == exclude {
			continue
		}
		// Proxy affinity affects proof readiness, not account identity admission.
		stamp := xCredentialStamp(account.Path)
		if stamp == "" {
			continue
		}
		identity := identities.Identities[filepath.Clean(account.Path)]
		if validXIdentity(identity) && identity.Stamp == stamp {
			continue
		}
		identity, err = verifyXCredential(ctx, account.Path, verify)
		if err != nil {
			return errXIdentityUnverified
		}
		if err := saveXIdentity(dir, account.Path, identity); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Caller holds the account-registry and identity locks. Rechecking the live
// registry and stamps closes concurrent add/reconnect and credential-edit races.
func rejectDuplicateXIdentity(registry accountFile, identities xIdentityFile, candidate providerAccount, identity worker.VerifiedXIdentity) error {
	for _, account := range registry.Accounts {
		if account.Service != "x_read" || account.ID == candidate.ID {
			continue
		}
		stamp := xCredentialStamp(account.Path)
		if stamp == "" {
			continue
		}
		other := identities.Identities[filepath.Clean(account.Path)]
		if !validXIdentity(other) || other.Stamp != stamp {
			return errXIdentityUnverified
		}
		if other.ID == identity.ID {
			return errDuplicateXIdentity
		}
	}
	return nil
}

func xAccountError(output io.Writer, err error) error {
	code := "verification_failed"
	if errors.Is(err, errDuplicateXIdentity) {
		code = "duplicate_account"
	} else if errors.Is(err, errXIdentityMismatch) {
		code = "identity_mismatch"
	}
	if encodeErr := json.NewEncoder(output).Encode(map[string]string{"status": "error", "code": code}); encodeErr != nil {
		return encodeErr
	}
	return errors.New(code)
}

func ensureOwnedAccountDir(path string) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		if err := localfs.CreateDir(path); err != nil && !os.IsExist(err) {
			return err
		}
		if err := localfs.SyncDir(filepath.Dir(path)); err != nil {
			return err
		}
		return localfs.CheckOwnedDir(path)
	} else if err != nil {
		return err
	}
	return localfs.CheckOwnedDir(path)
}

// Reusing a removed nickname must never overwrite the session that an accepted
// job is draining with. The first generation keeps the legacy layout; every
// subsequent generation receives its own exclusively created directory.
func newOwnedXSessionPath(dir, id string) (string, error) {
	path, err := newOwnedAccountDirectory(dir, "x_read", id)
	if err != nil {
		return "", err
	}
	return filepath.Join(path, "session.json"), nil
}

func newOwnedAccountDirectory(dir, service, id string) (string, error) {
	if !validAccountID(id) || service != "x_read" && service != "codex" {
		return "", errors.New("invalid account ID")
	}
	accounts := filepath.Join(dir, "accounts")
	if err := ensureOwnedAccountDir(accounts); err != nil {
		return "", err
	}
	base := filepath.Join(accounts, service+"-"+id)
	if _, err := os.Lstat(base); os.IsNotExist(err) {
		if err := localfs.CreateDir(base); err != nil {
			return "", err
		}
		if err := localfs.SyncDir(accounts); err != nil {
			return "", err
		}
		return base, nil
	}
	if err := localfs.CheckOwnedDir(base); err != nil {
		return "", err
	}
	generation := opaqueLoginID()
	if generation == "" {
		return "", errors.New("cannot create account generation")
	}
	path := filepath.Join(base, "generation-"+generation)
	if err := localfs.CreateDir(path); err != nil {
		return "", err
	}
	if err := localfs.SyncDir(base); err != nil {
		return "", err
	}
	return path, nil
}

func ownedXSessionPath(dir, id, path string) bool {
	base := filepath.Join(dir, "accounts", "x_read-"+id)
	if !validAccountID(id) || path != filepath.Clean(path) || filepath.Base(path) != "session.json" || localfs.CheckOwnedDir(filepath.Join(dir, "accounts")) != nil || localfs.CheckOwnedDir(base) != nil {
		return false
	}
	parent := filepath.Dir(path)
	if parent == base {
		return true
	}
	name := filepath.Base(parent)
	if filepath.Dir(parent) != base || !strings.HasPrefix(name, "generation-") || len(name) != len("generation-")+48 || localfs.CheckOwnedDir(parent) != nil {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, "generation-"))
	return err == nil
}
