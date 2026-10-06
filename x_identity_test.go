package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/worker"
	x "github.com/teslashibe/x-go"
)

// All account tests authenticate through synthetic provider responses. Native
// CLI coverage uses Codex registration or a rejected X session; it never calls X.
func syntheticCLIIdentity(_ context.Context, session x.Session) (worker.VerifiedXIdentity, error) {
	identity := worker.VerifiedXIdentity{ID: "123", Username: "fixture_user"}
	if strings.Contains(session.AuthToken, "external") || strings.Contains(session.AuthToken, "distinct") {
		identity.ID, identity.Username = "456", "other_user"
	}
	return identity, nil
}

func fixtureAccountsCommand(args []string, input io.Reader, output io.Writer) error {
	return accountsCommandWithVerifier(args, input, output, syntheticCLIIdentity)
}

func identityRegistryFixture(t *testing.T) string {
	t.Helper()
	dir := privateTestDir(t)
	t.Setenv("SCARLETT_STATE_DIR", dir)
	t.Setenv("SCARLETT_ACCOUNTS_FILE", "")
	return dir
}

func TestXAccountCLIRejectsSameIdentityWithDifferentCredentials(t *testing.T) {
	dir := identityRegistryFixture(t)
	var output bytes.Buffer
	if err := fixtureAccountsCommand([]string{"connect", "x_read", "first", "1"}, strings.NewReader(`{"auth_token":"synthetic-first","ct0":"csrf"}`), &output); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	err := fixtureAccountsCommand([]string{"connect", "x_read", "alias", "1"}, strings.NewReader(`{"auth_token":"synthetic-second","ct0":"other-csrf","twid":"u%3D456"}`), &output)
	if err == nil || !strings.Contains(output.String(), `"code":"duplicate_account"`) {
		t.Fatal("duplicate provider identity admitted", err)
	}
	registry, err := loadAccounts(accountFilePath(dir))
	if err != nil || len(registry.Accounts) != 1 || registry.Accounts[0].ID != "first" {
		t.Fatal("duplicate rejection changed registration")
	}
	if _, err := os.Stat(filepath.Join(dir, "accounts", "x_read-alias", "session.json")); !os.IsNotExist(err) {
		t.Fatal("rejected alias retained credentials")
	}
	if strings.Contains(output.String(), "synthetic") || strings.Contains(output.String(), dir) || strings.Contains(output.String(), "123") {
		t.Fatal("rejection exposed private metadata")
	}
}

func TestXAccountCLIAuthenticatesLegacyIdentityBeforeDuplicateCheck(t *testing.T) {
	dir := identityRegistryFixture(t)
	session := filepath.Join(dir, "legacy.json")
	writePrivateFixture(session, []byte(`{"auth_token":"synthetic-old","ct0":"csrf","twid":"u%3D999"}`), 0600)
	body, _ := json.Marshal(accountFile{Version: 1, Accounts: []providerAccount{{"legacy-name", "x_read", session, 1}}})
	if err := writeLocalFile(dir, "accounts.json", body); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	calls := 0
	verify := func(ctx context.Context, session x.Session) (worker.VerifiedXIdentity, error) {
		calls++
		return syntheticCLIIdentity(ctx, session)
	}
	err := accountsCommandWithVerifier([]string{"connect", "x_read", "alias", "1"}, strings.NewReader(`{"auth_token":"synthetic-new","ct0":"new-csrf"}`), &output, verify)
	if err == nil || !strings.Contains(output.String(), "duplicate_account") || calls != 2 {
		t.Fatal("legacy cookie identity was trusted or duplicate admitted", calls, err)
	}
	identity, err := verifiedXIdentity(dir, session)
	if err != nil || identity.ID != "123" {
		t.Fatal("authenticated legacy identity not retained", err)
	}
}

func TestXAccountCLIVerificationFailureDoesNotRegisterOrEchoProviderError(t *testing.T) {
	dir := identityRegistryFixture(t)
	var output bytes.Buffer
	err := accountsCommandWithVerifier([]string{"connect", "x_read", "first", "1"}, strings.NewReader(`{"auth_token":"synthetic-secret","ct0":"csrf"}`), &output, func(context.Context, x.Session) (worker.VerifiedXIdentity, error) {
		return worker.VerifiedXIdentity{}, errors.New("synthetic-secret provider request failed")
	})
	if err == nil || output.String() != "{\"code\":\"verification_failed\",\"status\":\"error\"}\n" || strings.Contains(err.Error(), "synthetic") {
		t.Fatal("provider failure was not bounded", err)
	}
	if _, err := os.Stat(accountFilePath(dir)); !os.IsNotExist(err) {
		t.Fatal("failed verification registered account")
	}
}

func TestXAccountCLIRemovalIsIdempotentAndNicknameReuseUsesFreshStorage(t *testing.T) {
	dir := identityRegistryFixture(t)
	var output bytes.Buffer
	call := func(args []string, input string) error {
		output.Reset()
		return fixtureAccountsCommand(args, strings.NewReader(input), &output)
	}
	if err := call([]string{"connect", "x_read", "first", "1"}, `{"auth_token":"synthetic-first","ct0":"csrf"}`); err != nil {
		t.Fatal(err)
	}
	before, _ := loadAccounts(accountFilePath(dir))
	oldPath := before.Accounts[0].Path
	oldRaw, _ := readLocalFile(oldPath, 65536)
	for i := 0; i < 2; i++ {
		if err := call([]string{"remove", "x_read", "first"}, ""); err != nil {
			t.Fatal("removal not idempotent", err)
		}
	}
	if err := call([]string{"connect", "x_read", "first", "1"}, `{"auth_token":"synthetic-distinct","ct0":"new-csrf"}`); err != nil {
		t.Fatal("removed nickname cannot be reused", err)
	}
	after, _ := loadAccounts(accountFilePath(dir))
	if after.Accounts[0].Path == oldPath || !ownedXSessionPath(dir, "first", after.Accounts[0].Path) {
		t.Fatal("reused nickname overwrote drain generation")
	}
	retained, _ := readLocalFile(oldPath, 65536)
	if !bytes.Equal(retained, oldRaw) {
		t.Fatal("removal/reuse changed old credentials")
	}
}

func TestXAccountCLIReconnectRejectsChangedVerifiedIdentityAndKeepsPriorBytes(t *testing.T) {
	dir := identityRegistryFixture(t)
	var output bytes.Buffer
	if err := fixtureAccountsCommand([]string{"connect", "x_read", "first", "1"}, strings.NewReader(`{"auth_token":"synthetic-first","ct0":"csrf"}`), &output); err != nil {
		t.Fatal(err)
	}
	registry, _ := loadAccounts(accountFilePath(dir))
	before, _ := readLocalFile(registry.Accounts[0].Path, 65536)
	output.Reset()
	err := fixtureAccountsCommand([]string{"reconnect", "x_read", "first"}, strings.NewReader(`{"auth_token":"synthetic-distinct","ct0":"new-csrf"}`), &output)
	if err == nil || !strings.Contains(output.String(), "identity_mismatch") {
		t.Fatal("reconnect changed provider identity", err)
	}
	after, _ := readLocalFile(registry.Accounts[0].Path, 65536)
	if !bytes.Equal(before, after) {
		t.Fatal("failed reconnect replaced prior bytes")
	}
}

func TestXAccountCLIConcurrentAddsRecheckIdentityAfterVerification(t *testing.T) {
	dir := identityRegistryFixture(t)
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	verify := func(context.Context, x.Session) (worker.VerifiedXIdentity, error) {
		started <- struct{}{}
		<-release
		return worker.VerifiedXIdentity{ID: "123", Username: "fixture"}, nil
	}
	var outputs [2]bytes.Buffer
	var results [2]error
	var group sync.WaitGroup
	for i, name := range []string{"first", "second"} {
		group.Add(1)
		go func(i int, name string) {
			defer group.Done()
			results[i] = accountsCommandWithVerifier([]string{"connect", "x_read", name, "1"}, strings.NewReader(`{"auth_token":"synthetic","ct0":"csrf"}`), &outputs[i], verify)
		}(i, name)
	}
	<-started
	<-started
	close(release)
	group.Wait()
	success, duplicates := 0, 0
	for i, err := range results {
		if err == nil {
			success++
		} else if strings.Contains(outputs[i].String(), "duplicate_account") {
			duplicates++
		}
	}
	registry, err := loadAccounts(accountFilePath(dir))
	if success != 1 || duplicates != 1 || err != nil || len(registry.Accounts) != 1 {
		t.Fatal("concurrent verification bypassed duplicate admission", success, duplicates, err)
	}
}

func TestXIdentitySidecarIsPrivateBoundedAndStampBound(t *testing.T) {
	dir := identityRegistryFixture(t)
	path := filepath.Join(dir, "session.json")
	writePrivateFixture(path, []byte(`{"auth_token":"synthetic","ct0":"csrf"}`), 0600)
	identity := worker.VerifiedXIdentity{ID: "123", Username: "fixture", Stamp: worker.XSessionStamp(path)}
	if err := saveXIdentity(dir, path, identity); err != nil {
		t.Fatal(err)
	}
	file, err := localfs.OpenPrivate(xIdentitiesPath(dir))
	if err != nil {
		t.Fatal("identity sidecar is not private")
	}
	file.Close()
	if actual, err := verifiedXIdentity(dir, path); err != nil || actual != identity {
		t.Fatal("verified binding missing", err)
	}
	writePrivateFixture(path, []byte(`{"auth_token":"changed","ct0":"csrf"}`), 0600)
	if _, err := verifiedXIdentity(dir, path); !errors.Is(err, errXIdentityUnverified) {
		t.Fatal("stale verified identity survived credential replacement")
	}
	if err := saveXIdentity(dir, path, identity); !errors.Is(err, errXIdentityUnverified) {
		t.Fatal("delayed build rebound replacement credentials")
	}
	for _, raw := range []string{
		`{"version":2,"identities":{}}`,
		`{"version":2,"version":1,"identities":{}}`,
		`{"version":1,"identities":{},"unexpected":"field"}`,
		`{"version":1,"identities":{"relative":{"id":"123","username":"fixture","stamp":"bad"}}}`,
		`{"version":1,"identities":null}`,
		strings.Repeat(" ", maxXIdentitiesBytes+1),
	} {
		if err := writeLocalFile(dir, "x-identities.json", []byte(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadXIdentities(dir); err == nil {
			t.Fatal("malformed identity metadata accepted")
		}
	}
}

func TestXIdentityObserverRebindsOnlyVerifiedChangedCredentials(t *testing.T) {
	dir := identityRegistryFixture(t)
	path := filepath.Join(dir, "session.json")
	writePrivateFixture(path, []byte(`{"auth_token":"synthetic","ct0":"csrf"}`), 0600)
	if err := saveXIdentity(dir, path, worker.VerifiedXIdentity{ID: "123", Username: "fixture", Stamp: worker.XSessionStamp(path)}); err != nil {
		t.Fatal(err)
	}
	err := saveXIdentity(dir, path, worker.VerifiedXIdentity{ID: "456", Username: "different", Stamp: worker.XSessionStamp(path)})
	if !errors.Is(err, errXIdentityMismatch) {
		t.Fatal("same credentials accepted conflicting verified identity")
	}
	writePrivateFixture(path, []byte(`{"auth_token":"distinct","ct0":"csrf"}`), 0600)
	if err := saveXIdentity(dir, path, worker.VerifiedXIdentity{ID: "456", Username: "different", Stamp: worker.XSessionStamp(path)}); err != nil {
		t.Fatal("verified replacement credentials could not change identity", err)
	}
}

func TestXAccountCLIReconnectCannotResurrectRemovedRegistration(t *testing.T) {
	dir := identityRegistryFixture(t)
	var output bytes.Buffer
	if err := fixtureAccountsCommand([]string{"connect", "x_read", "first", "1"}, strings.NewReader(`{"auth_token":"synthetic-first","ct0":"csrf"}`), &output); err != nil {
		t.Fatal(err)
	}
	registry, _ := loadAccounts(accountFilePath(dir))
	before, _ := readLocalFile(registry.Accounts[0].Path, 65536)
	output.Reset()
	err := accountsCommandWithVerifier([]string{"reconnect", "x_read", "first"}, strings.NewReader(`{"auth_token":"synthetic-new","ct0":"new-csrf"}`), &output, func(ctx context.Context, session x.Session) (worker.VerifiedXIdentity, error) {
		if err := fixtureAccountsCommand([]string{"remove", "x_read", "first"}, nil, io.Discard); err != nil {
			t.Fatal(err)
		}
		return syntheticCLIIdentity(ctx, session)
	})
	if err == nil {
		t.Fatal("delayed reconnect resurrected removed account")
	}
	remaining, _ := loadAccounts(accountFilePath(dir))
	after, _ := readLocalFile(registry.Accounts[0].Path, 65536)
	if len(remaining.Accounts) != 0 || !bytes.Equal(before, after) {
		t.Fatal("delayed reconnect replaced retained session or registration")
	}
}

func TestInteractiveXLoginRejectsDuplicateIdentityAndBindsOnce(t *testing.T) {
	o, backend, message := loginFixture(t)
	t.Setenv("SCARLETT_STATE_DIR", o.dir)
	var output bytes.Buffer
	if err := fixtureAccountsCommand([]string{"connect", "x_read", "first", "1"}, strings.NewReader(`{"auth_token":"synthetic-first","ct0":"csrf"}`), &output); err != nil {
		t.Fatal(err)
	}
	backend.start = func(context.Context, x.BrowserLoginRequest) (*x.BrowserLoginResult, error) {
		return candidateResult(), nil
	}
	calls := 0
	o.verify = func(context.Context, x.Session, string, string) (string, error) {
		calls++
		return "123", nil
	}
	result := o.handle(context.Background(), message)
	if result.Code != "duplicate_account" || calls != 1 {
		t.Fatal("interactive login did not reject duplicate authenticated identity", result)
	}
	registry, _ := loadAccounts(accountFilePath(o.dir))
	if len(registry.Accounts) != 1 {
		t.Fatal("duplicate login changed registry")
	}
}

func TestInteractiveXLoginReusesNicknameWithoutOverwritingRetainedSession(t *testing.T) {
	o, backend, message := loginFixture(t)
	t.Setenv("SCARLETT_STATE_DIR", o.dir)
	var output bytes.Buffer
	if err := fixtureAccountsCommand([]string{"connect", "x_read", message.ID, "1"}, strings.NewReader(`{"auth_token":"synthetic-first","ct0":"csrf"}`), &output); err != nil {
		t.Fatal(err)
	}
	prior, _ := loadAccounts(accountFilePath(o.dir))
	oldPath := prior.Accounts[0].Path
	oldRaw, _ := readLocalFile(oldPath, 65536)
	if err := fixtureAccountsCommand([]string{"remove", "x_read", message.ID}, nil, io.Discard); err != nil {
		t.Fatal(err)
	}
	backend.start = func(context.Context, x.BrowserLoginRequest) (*x.BrowserLoginResult, error) {
		return candidateResult(), nil
	}
	if result := o.handle(context.Background(), message); result.Status != "updated" {
		t.Fatal("login could not reuse removed nickname", result)
	}
	current, _ := loadAccounts(accountFilePath(o.dir))
	retained, _ := readLocalFile(oldPath, 65536)
	if current.Accounts[0].Path == oldPath || !bytes.Equal(retained, oldRaw) {
		t.Fatal("new login overwrote removed account's retained session")
	}
	identity, err := verifiedXIdentity(o.dir, current.Accounts[0].Path)
	if err != nil || identity.ID != "123" || identity.Username != message.Username {
		t.Fatal("verified browser login binding missing", err)
	}
}

func TestInteractiveProxyIdentityDoesNotEnableProofExecution(t *testing.T) {
	o, backend, message := loginFixture(t)
	backend.start = func(_ context.Context, request x.BrowserLoginRequest) (*x.BrowserLoginResult, error) {
		o.operation.ProxyURL = "http://127.0.0.1:8888"
		return candidateResult(), nil
	}
	if result := o.handle(context.Background(), message); result.Status != "updated" {
		t.Fatal("verified proxy browser session was not saved", result)
	}
	registry, _ := loadAccounts(accountFilePath(o.dir))
	identity, err := verifiedXIdentity(o.dir, registry.Accounts[0].Path)
	if err != nil || identity.ID != "123" || worker.XSessionStamp(registry.Accounts[0].Path) != "" || worker.XConfigured(registry.Accounts[0].Path) {
		t.Fatal("browser identity loosened proof transport restrictions", err)
	}
}

func TestXAccountCLIRejectsVerifiedProxyIdentityAlias(t *testing.T) {
	o, _, message := loginFixture(t)
	t.Setenv("SCARLETT_STATE_DIR", o.dir)
	message.Reconnect = true
	path := filepath.Join(o.dir, "accounts", "x_read-"+message.ID, "session.json")
	if err := prepareStateDir(filepath.Dir(filepath.Dir(path))); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDir(filepath.Dir(path)); err != nil {
		t.Fatal(err)
	}
	if err := writeLocalFile(filepath.Dir(path), "session.json", []byte(`{"auth_token":"previous","ct0":"previous-csrf","proxy":"http://localhost:8888"}`)); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(accountFile{Version: 1, Accounts: []providerAccount{{ID: message.ID, Service: "x_read", Path: path, Concurrency: 1}}})
	if err := writeLocalFile(o.dir, "accounts.json", body); err != nil {
		t.Fatal(err)
	}
	if result := o.handle(context.Background(), message); result.Status != "updated" {
		t.Fatal("existing proxy session reconnect failed", result)
	}
	if _, err := verifiedXIdentity(o.dir, path); err != nil {
		t.Fatal("verified proxy identity missing", err)
	}
	var output bytes.Buffer
	err := fixtureAccountsCommand([]string{"connect", "x_read", "alias", "1"}, strings.NewReader(`{"auth_token":"synthetic-alias","ct0":"csrf"}`), &output)
	if err == nil || !strings.Contains(output.String(), `"code":"duplicate_account"`) {
		t.Fatal("verified proxy identity admitted an alias", err)
	}
	registry, err := loadAccounts(accountFilePath(o.dir))
	if err != nil || len(registry.Accounts) != 1 || registry.Accounts[0].ID != message.ID {
		t.Fatal("duplicate rejection changed proxy registration", err)
	}
}

func TestXIdentityPreflightIncludesProxyRegistrations(t *testing.T) {
	dir := identityRegistryFixture(t)
	path := filepath.Join(dir, "legacy-proxy.json")
	writePrivateFixture(path, []byte(`{"auth_token":"synthetic","ct0":"csrf","proxy":"http://localhost:8888"}`), 0600)
	registry := accountFile{Version: 1, Accounts: []providerAccount{{"legacy-name", "x_read", path, 1}}}
	body, _ := json.Marshal(registry)
	if err := writeLocalFile(dir, "accounts.json", body); err != nil {
		t.Fatal(err)
	}
	verify := func(context.Context, x.Session) (worker.VerifiedXIdentity, error) {
		t.Fatal("preflight attempted to verify an unsupported proof session")
		return worker.VerifiedXIdentity{}, nil
	}
	if err := verifyRegisteredXIdentities(context.Background(), dir, registry, "", verify); !errors.Is(err, errXIdentityUnverified) {
		t.Fatal("unknown proxy identity silently passed admission", err)
	}
	identity := worker.VerifiedXIdentity{ID: "123", Username: "fixture", Stamp: xCredentialStamp(path)}
	if err := saveXIdentity(dir, path, identity); err != nil {
		t.Fatal(err)
	}
	if err := verifyRegisteredXIdentities(context.Background(), dir, registry, "", verify); err != nil {
		t.Fatal("verified proxy identity failed admission preflight", err)
	}
}

func TestXAccountCLIRegistryLockIsFreeDuringProviderVerification(t *testing.T) {
	dir := identityRegistryFixture(t)
	var output bytes.Buffer
	err := accountsCommandWithVerifier([]string{"connect", "x_read", "first", "1"}, strings.NewReader(`{"auth_token":"synthetic","ct0":"csrf"}`), &output, func(context.Context, x.Session) (worker.VerifiedXIdentity, error) {
		lock, err := localfs.LockPrivate(filepath.Join(dir, ".accounts.lock"))
		if err != nil {
			t.Fatal("provider verification holds registry lock")
		}
		lock.Close()
		return worker.VerifiedXIdentity{ID: "123", Username: "fixture"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestXAccountCLIListShowsOnlyVerifiedHandle(t *testing.T) {
	dir := identityRegistryFixture(t)
	var output bytes.Buffer
	if err := fixtureAccountsCommand([]string{"connect", "x_read", "first", "1"}, strings.NewReader(`{"auth_token":"synthetic","ct0":"csrf"}`), &output); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := fixtureAccountsCommand([]string{"list"}, nil, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"username":"fixture_user"`) || strings.Contains(output.String(), dir) || strings.Contains(output.String(), "123") || strings.Contains(output.String(), "synthetic") {
		t.Fatal("account list identity projection exposed private material")
	}
}

func TestXAccountCLIPreflightSharesOneDeadlineAcrossProviderChecks(t *testing.T) {
	dir := identityRegistryFixture(t)
	path := filepath.Join(dir, "legacy.json")
	writePrivateFixture(path, []byte(`{"auth_token":"synthetic","ct0":"csrf"}`), 0600)
	registry, _ := json.Marshal(accountFile{Version: 1, Accounts: []providerAccount{{"first", "x_read", path, 1}}})
	if err := writeLocalFile(dir, "accounts.json", registry); err != nil {
		t.Fatal(err)
	}
	var deadlines []time.Time
	var output bytes.Buffer
	err := accountsCommandWithVerifier([]string{"connect", "x_read", "second", "1"}, strings.NewReader(`{"auth_token":"synthetic-distinct","ct0":"other-csrf"}`), &output, func(ctx context.Context, session x.Session) (worker.VerifiedXIdentity, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 30*time.Second {
			t.Fatal("provider work has no overall bounded deadline")
		}
		deadlines = append(deadlines, deadline)
		return syntheticCLIIdentity(ctx, session)
	})
	if err != nil || len(deadlines) != 2 || !deadlines[0].Equal(deadlines[1]) {
		t.Fatal("each provider check restarted the overall timeout", err)
	}
}

func TestXCredentialVerificationRejectsLateSuccessAfterCancellation(t *testing.T) {
	dir := identityRegistryFixture(t)
	path := filepath.Join(dir, "session.json")
	writePrivateFixture(path, []byte(`{"auth_token":"synthetic","ct0":"csrf"}`), 0600)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	identity, err := verifyXCredential(ctx, path, func(context.Context, x.Session) (worker.VerifiedXIdentity, error) {
		cancel()
		return worker.VerifiedXIdentity{ID: "123", Username: "fixture"}, nil
	})
	if err == nil || identity.ID != "" {
		t.Fatal("cancelled verification accepted late success")
	}
}

func TestLegacyIdentityPreflightPropagatesDeadlineWithoutRegistryLock(t *testing.T) {
	dir := identityRegistryFixture(t)
	path := filepath.Join(dir, "session.json")
	writePrivateFixture(path, []byte(`{"auth_token":"synthetic","ct0":"csrf"}`), 0600)
	registry := accountFile{Version: 1, Accounts: []providerAccount{{"first", "x_read", path, 1}}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := verifyRegisteredXIdentities(ctx, dir, registry, "", func(ctx context.Context, _ x.Session) (worker.VerifiedXIdentity, error) {
		lock, err := localfs.LockPrivate(filepath.Join(dir, ".accounts.lock"))
		if err != nil {
			t.Fatal("deadline-bound provider work holds registry lock")
		}
		lock.Close()
		<-ctx.Done()
		return worker.VerifiedXIdentity{}, ctx.Err()
	})
	if err == nil || time.Since(started) > time.Second {
		t.Fatal("preflight did not obey inherited deadline", err)
	}
	if _, err := os.Stat(xIdentitiesPath(dir)); !os.IsNotExist(err) {
		t.Fatal("timed-out provider verification wrote identity metadata")
	}
}
