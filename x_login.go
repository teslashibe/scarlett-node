package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/xloginruntime"
	x "github.com/teslashibe/x-go"
	"golang.org/x/term"
)

// Only this process owns the operation and credentials. JSON responses are a
// fixed safe projection; no sidecar response or provider error is forwarded.
type xLoginMessage struct {
	Action      string `json:"action"`
	ID          string `json:"id"`
	Concurrency int    `json:"concurrency,omitempty"`
	Reconnect   bool   `json:"reconnect,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	Code        string `json:"code,omitempty"`
	ChallengeID string `json:"challenge_id,omitempty"`
}

func (xLoginMessage) String() string     { return "x login request [redacted]" }
func (m xLoginMessage) GoString() string { return m.String() }

type xLoginStatus struct {
	Status      string    `json:"status"`
	ID          string    `json:"id,omitempty"`
	Code        string    `json:"code,omitempty"`
	ChallengeID string    `json:"challenge_id,omitempty"`
	Method      string    `json:"method,omitempty"`
	Destination string    `json:"destination,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	RetryAfter  int       `json:"retry_after,omitempty"`
}
type xLoginBackend interface {
	Start(context.Context, x.BrowserLoginRequest) (*x.BrowserLoginResult, error)
	Continue(context.Context, x.BrowserLoginOperation, string, string) (*x.BrowserLoginResult, error)
	Cancel(context.Context, x.BrowserLoginOperation) error
}

// Backend startup waits until browser work is needed; checking a saved session
// never depends on Chrome or launches the local service.
type lazyXLoginBackend struct {
	runtime *xloginruntime.Manager
	client  *x.BrowserLogin
}

// Browser credentials travel only to the explicitly configured local service.
// Browser/account proxy affinity belongs to BrowserLoginOperation, not this RPC.
func newXLoginRPCClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport, Timeout: 180 * time.Second}
}

func (b *lazyXLoginBackend) get(ctx context.Context) (*x.BrowserLogin, error) {
	if b.client != nil {
		return b.client, nil
	}
	endpoint, err := xLoginEndpoint(ctx, b.runtime)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &x.BrowserLoginError{Kind: "service"}
	}
	client, err := x.NewBrowserLogin(x.BrowserLoginConfig{URL: endpoint.URL, BearerToken: endpoint.Bearer, HTTPClient: newXLoginRPCClient()})
	if err != nil {
		return nil, &x.BrowserLoginError{Kind: "service"}
	}
	b.client = client
	return client, nil
}
func (b *lazyXLoginBackend) Start(ctx context.Context, r x.BrowserLoginRequest) (*x.BrowserLoginResult, error) {
	client, err := b.get(ctx)
	if err != nil {
		return nil, err
	}
	return client.Start(ctx, r)
}
func (b *lazyXLoginBackend) Continue(ctx context.Context, o x.BrowserLoginOperation, id, code string) (*x.BrowserLoginResult, error) {
	client, err := b.get(ctx)
	if err != nil {
		return nil, err
	}
	return client.Continue(ctx, o, id, code)
}
func (b *lazyXLoginBackend) Cancel(ctx context.Context, o x.BrowserLoginOperation) error {
	if b.client == nil {
		return nil
	}
	return b.client.Cancel(ctx, o)
}

type xLoginOperation struct {
	dir       string
	backend   xLoginBackend
	verify    func(context.Context, x.Session, string, string) (string, error)
	now       func() time.Time
	request   xLoginMessage // Password/Code are never retained here.
	operation x.BrowserLoginOperation
	pending   *x.BrowserLoginChallenge
	original  *providerAccount
	prior     []byte
	lock      *os.File
}

func opaqueLoginID() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}
func newXLoginOperation(dir string, backend xLoginBackend) *xLoginOperation {
	return &xLoginOperation{dir: dir, backend: backend, verify: verifyXLoginSession, now: time.Now}
}
func verifyXLoginSession(ctx context.Context, s x.Session, username, priorTwid string) (string, error) {
	return verifyXLoginWithOptions(ctx, s, username, priorTwid)
}
func verifyXLoginWithOptions(ctx context.Context, s x.Session, username, priorTwid string, opts ...x.Option) (string, error) {
	opts = append(opts, x.WithRetry(1, time.Second))
	c, err := s.NewClient(ctx, opts...)
	if err != nil {
		return "", err
	}
	viewer, err := c.Me(ctx)
	if err != nil {
		return "", err
	}
	// A partial Viewer profile is insufficient to bind a typed username.
	if viewer == nil || viewer.ID == "" || !strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(username), "@"), viewer.ScreenName) {
		return "", errors.New("account identity mismatch")
	}
	if priorTwid != "" {
		decoded, _ := url.QueryUnescape(priorTwid)
		id := strings.Trim(strings.TrimPrefix(decoded, "u="), "\"")
		if viewer.ID != id {
			return "", errors.New("account identity mismatch")
		}
	}
	return viewer.ID, nil
}
func (o *xLoginOperation) close() {
	if o.lock != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if o.operation.ProfileKey != "" {
			_ = o.backend.Cancel(ctx, o.operation)
		}
		cancel()
		_ = o.lock.Close()
		o.lock = nil
	}
	clear(o.prior)
	o.prior = nil
	o.original = nil
	o.operation = x.BrowserLoginOperation{}
	o.pending = nil
}

// A parked browser may expire before the caller's original operation budget.
// Keep wire identity unchanged while enforcing that earlier local deadline.
func (o *xLoginOperation) deadline() time.Time {
	deadline := o.operation.Budget.DeadlineAt
	if o.pending != nil && o.pending.ExpiresAt.Before(deadline) {
		deadline = o.pending.ExpiresAt
	}
	return deadline
}
func (o *xLoginOperation) expirePending() bool {
	if o.lock == nil || o.now().Before(o.deadline()) {
		return false
	}
	o.close()
	return true
}

func (o *xLoginOperation) handle(ctx context.Context, m xLoginMessage) xLoginStatus {
	fail := func(code string) xLoginStatus { return xLoginStatus{Status: "error", Code: code} }
	if m.Action == "cancel" {
		if o.lock == nil || m.ID != o.request.ID {
			return fail("restart_login")
		}
		o.close()
		return xLoginStatus{Status: "cancelled", ID: m.ID}
	}
	if m.Action == "continue" {
		if o.lock == nil || m.ID != o.request.ID || o.pending == nil || m.ChallengeID != o.pending.ID {
			return fail("restart_login")
		}
		if !o.now().Before(o.pending.ExpiresAt) || !o.now().Before(o.operation.Budget.DeadlineAt) {
			o.close()
			return fail("restart_login")
		}
		if len(m.Code) > 128 || strings.TrimSpace(m.Code) == "" {
			return fail("invalid_input")
		}
		bounded, cancel := context.WithDeadline(ctx, o.deadline())
		defer cancel()
		result, err := o.backend.Continue(bounded, o.operation, m.ChallengeID, m.Code)
		return o.finish(bounded, result, err)
	}
	if m.Action != "start" || !validAccountID(m.ID) || m.Concurrency < 1 || m.Concurrency > 32 || len(m.Username) > 64 || strings.TrimSpace(m.Username) == "" || len(m.Password) > 1024 || m.Password == "" {
		return fail("invalid_input")
	}
	if o.lock != nil {
		return fail("login_busy")
	}
	if err := prepareStateDir(o.dir); err != nil {
		return fail("private_storage_unavailable")
	}
	if err := prepareStateDir(filepath.Join(o.dir, "x-login-locks")); err != nil {
		return fail("private_storage_unavailable")
	}
	lock, err := localfs.LockPrivate(filepath.Join(o.dir, "x-login-locks", m.ID+".lock"))
	if err != nil {
		return fail("login_busy")
	}
	o.lock = lock
	o.request = m
	o.request.Password = ""
	o.request.Code = ""
	o.request.ChallengeID = ""
	path := accountFilePath(o.dir)
	if !filepath.IsAbs(path) || localfs.CheckDir(filepath.Dir(path)) != nil {
		o.close()
		return fail("private_storage_unavailable")
	}
	registry, err := localfs.LockPrivateWait(filepath.Join(filepath.Dir(accountFilePath(o.dir)), ".accounts.lock"))
	if err != nil {
		o.close()
		return fail("accounts_unavailable")
	}
	f, err := loadAccounts(accountFilePath(o.dir))
	if os.IsNotExist(err) {
		err = nil
	}
	if err == nil {
		for _, a := range f.Accounts {
			if a.Service == "x_read" && a.ID == m.ID {
				copy := a
				o.original = &copy
			}
		}
	}
	if err == nil && m.Reconnect {
		if o.original == nil || o.original.Path != filepath.Join(o.dir, "accounts", "x_read-"+m.ID, "session.json") {
			err = errors.New("invalid reconnect")
		} else {
			o.prior, err = readLocalFile(o.original.Path, 65536)
		}
	}
	if err == nil && !m.Reconnect {
		candidate := f
		candidate.Accounts = append(candidate.Accounts, providerAccount{m.ID, "x_read", filepath.Join(o.dir, "accounts", "x_read-"+m.ID, "session.json"), m.Concurrency})
		if !validAccounts(candidate) {
			err = errors.New("duplicate account")
		}
	}
	registry.Close()
	if err != nil {
		o.close()
		return fail("invalid_input")
	}
	if m.Reconnect {
		var prior x.Session
		if json.Unmarshal(o.prior, &prior) != nil {
			o.close()
			return fail("verification_failed")
		}
		checkCtx, done := context.WithTimeout(ctx, 30*time.Second)
		_, check := o.verify(checkCtx, prior, m.Username, prior.Twid)
		done()
		if check == nil {
			id := m.ID
			o.close()
			return xLoginStatus{Status: "updated", ID: id}
		}
		if errors.Is(check, x.ErrRateLimited) {
			o.close()
			return fail("cooldown")
		}
		if !errors.Is(check, x.ErrUnauthorized) && !errors.Is(check, x.ErrInvalidAuth) {
			o.close()
			return fail("verification_failed")
		}
	}
	// Account profiles are opaque and stable for this local state directory.
	hash := sha256.Sum256([]byte(o.dir + "\x00" + m.ID))
	owner := opaqueLoginID()
	if owner == "" {
		o.close()
		return fail("login_failed")
	}
	o.operation = x.BrowserLoginOperation{ProfileKey: hex.EncodeToString(hash[:]), OperationOwner: owner, ConnectionID: owner, Generation: owner, Revision: owner, RecoveryClaim: owner, Budget: x.BrowserLoginBudget{DeadlineAt: o.now().Add(4 * time.Minute), MaxBrowserAttempts: 1, MaxCredentialAttempts: 1, MaxSolverAttempts: 0}}
	if m.Reconnect {
		var prior x.Session
		if json.Unmarshal(o.prior, &prior) == nil && prior.Proxy != "" {
			o.operation.ProxyURL = prior.Proxy
			o.operation.ProxyLease = owner
		}
	}
	bounded, cancel := context.WithDeadline(ctx, o.deadline())
	defer cancel()
	result, err := o.backend.Start(bounded, x.BrowserLoginRequest{Username: m.Username, Password: m.Password, Operation: o.operation})
	return o.finish(bounded, result, err)
}
func (o *xLoginOperation) finish(ctx context.Context, result *x.BrowserLoginResult, err error) xLoginStatus {
	failure := func(code string) xLoginStatus { o.close(); return xLoginStatus{Status: "error", Code: code} }
	if err != nil {
		var e *x.BrowserLoginError
		if errors.As(err, &e) {
			if e.Kind == "challenge_expired" || e.Kind == "owner_mismatch" {
				return failure("restart_login")
			}
			if e.Kind == "service" || e.Kind == "transport" {
				return failure("runtime_unavailable")
			}
			if e.Kind == "rate_limited" {
				delay := int(e.RetryAfter.Seconds())
				o.close()
				return xLoginStatus{Status: "error", Code: "cooldown", RetryAfter: delay}
			}
		}
		return failure("login_failed")
	}
	if result == nil {
		return failure("login_failed")
	}
	if result.Challenge != nil {
		c := result.Challenge
		if c.ID == "" || len(c.ID) > 256 || strings.IndexFunc(c.ID, unicode.IsControl) >= 0 || c.ExpiresAt.IsZero() || !o.now().Before(c.ExpiresAt) || c.ExpiresAt.After(o.operation.Budget.DeadlineAt) {
			return failure("restart_login")
		}
		o.pending = c
		return xLoginStatus{Status: "pending", ID: o.request.ID, ChallengeID: c.ID, Method: safeLoginLabel(c.Method), Destination: safeLoginLabel(c.MaskedDestination), ExpiresAt: c.ExpiresAt}
	}
	if result.Session == nil {
		return failure("login_failed")
	}
	priorTwid := ""
	if o.request.Reconnect {
		var prior x.Session
		if json.Unmarshal(o.prior, &prior) != nil {
			return failure("login_failed")
		}
		priorTwid = prior.Twid
	}
	session := *result.Session
	session.Proxy = o.operation.ProxyURL
	viewerID, err := o.verify(ctx, session, o.request.Username, priorTwid)
	if err != nil || viewerID == "" {
		return failure("verification_failed")
	}
	session.Twid = url.QueryEscape("u=" + viewerID)
	if ctx.Err() != nil {
		return failure("restart_login")
	}
	if err := o.commit(ctx, session); err != nil {
		return failure("account_changed")
	}
	id := o.request.ID
	o.close()
	return xLoginStatus{Status: "updated", ID: id}
}
func safeLoginLabel(s string) string {
	if len(s) > 120 || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return ""
	}
	return s
}
func (o *xLoginOperation) commit(ctx context.Context, s x.Session) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := ctxDeadline(o.now(), o.deadline()); err != nil {
		return err
	}
	path := accountFilePath(o.dir)
	lock, err := localfs.LockPrivateWait(filepath.Join(filepath.Dir(path), ".accounts.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	f, err := loadAccounts(path)
	if os.IsNotExist(err) {
		err = nil
	}
	if err != nil {
		return err
	}
	account := providerAccount{o.request.ID, "x_read", filepath.Join(o.dir, "accounts", "x_read-"+o.request.ID, "session.json"), o.request.Concurrency}
	found := false
	for _, a := range f.Accounts {
		if a.Service == "x_read" && a.ID == account.ID {
			found = true
			if !o.request.Reconnect || o.original == nil || a != *o.original {
				return errors.New("account changed")
			}
			account = a
		}
	}
	if o.request.Reconnect {
		if !found {
			return errors.New("account removed")
		}
		current, err := readLocalFile(account.Path, 65536)
		if err != nil || string(current) != string(o.prior) {
			clear(current)
			return errors.New("session changed")
		}
		clear(current)
	} else {
		if found {
			return errors.New("account added")
		}
		f.Accounts = append(f.Accounts, account)
		if !validAccounts(f) {
			return errors.New("account limit")
		}
	}
	if err := prepareStateDir(filepath.Join(o.dir, "accounts")); err != nil {
		return err
	}
	if err := prepareStateDir(filepath.Dir(account.Path)); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	defer clear(raw)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := localfs.WriteAtomic(account.Path, raw, o.request.Reconnect); err != nil {
		return err
	}
	if !o.request.Reconnect {
		registry, _ := json.Marshal(f)
		if err := writeLocalFile(filepath.Dir(path), filepath.Base(path), registry); err != nil {
			_ = os.Remove(account.Path)
			return err
		}
	}
	return nil
}
func ctxDeadline(now, deadline time.Time) error {
	if !now.Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// Installers expose a launch symlink while resources live beside the versioned
// executable. Resolve the complete executable chain before choosing resources.
func installedXLoginResourceDir(executable string) (string, error) {
	if !filepath.IsAbs(executable) {
		return "", errors.New("invalid installed executable")
	}
	canonical, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return "", errors.New("installed executable unavailable")
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("installed executable unavailable")
	}
	return filepath.Dir(canonical), nil
}

// xLoginCommand is a private JSON-lines conversation. EOF (including app quit)
// cancels the in-flight request, disposes the hold and closes the browser service.
func xLoginCommand(input io.Reader, output io.Writer) error {
	dir := os.Getenv("SCARLETT_STATE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return errors.New("private storage unavailable")
		}
		dir = config.DefaultStateDir(home)
	}
	if !filepath.IsAbs(dir) {
		return errors.New("state directory must be absolute")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resourceDir := os.Getenv("SCARLETT_X_LOGIN_RESOURCE_DIR")
	if resourceDir == "" {
		exe, err := os.Executable()
		if err != nil {
			return errors.New("browser runtime unavailable")
		}
		resourceDir, err = installedXLoginResourceDir(exe)
		if err != nil {
			return errors.New("browser runtime unavailable")
		}
	}
	runtime := xloginruntime.New(xloginruntime.Config{ResourceDir: resourceDir, StateDir: dir, BrowserPath: os.Getenv("SCARLETT_X_LOGIN_BROWSER")})
	defer func() {
		shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		_ = runtime.Close(shutdown)
	}()
	// Startup is lazy so the pipe reader can cancel a missing/hung runtime too.
	messages := make(chan xLoginMessage, 1)
	var active atomic.Value
	active.Store("")
	var cancelled atomic.Value
	cancelled.Store("")
	defer func() {
		if id := cancelled.Load().(string); id != "" {
			_ = json.NewEncoder(output).Encode(xLoginStatus{Status: "cancelled", ID: id})
		}
	}()
	go func() {
		defer close(messages)
		defer cancel()
		scanner := bufio.NewScanner(input)
		scanner.Buffer(make([]byte, 4096), 16384)
		for scanner.Scan() {
			raw := scanner.Bytes()
			var m xLoginMessage
			d := json.NewDecoder(strings.NewReader(string(raw)))
			d.DisallowUnknownFields()
			if d.Decode(&m) != nil || d.Decode(new(any)) != io.EOF {
				m = xLoginMessage{Action: "invalid"}
			}
			if m.Action == "cancel" && validAccountID(m.ID) && active.Load().(string) == m.ID {
				cancelled.Store(m.ID)
				cancel()
				return
			}
			if m.Action == "start" && validAccountID(m.ID) && active.Load().(string) == "" {
				active.Store(m.ID)
			}
			select {
			case messages <- m:
			case <-ctx.Done():
				return
			default:
				return // Reject overlapping queued requests; bounded private owner pipe
			}
		}
	}()
	operation := newXLoginOperation(dir, &lazyXLoginBackend{runtime: runtime})
	defer func() {
		if operation != nil {
			operation.close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
			if operation != nil && operation.expirePending() {
				active.Store("")
				if err := json.NewEncoder(output).Encode(xLoginStatus{Status: "error", Code: "restart_login"}); err != nil {
					return nil
				}
			}
		case m, ok := <-messages:
			if !ok {
				return nil
			}
			result := operation.handle(ctx, m)
			if operation.lock == nil {
				active.Store("")
			} else {
				active.Store(operation.request.ID)
			}
			m.Password = ""
			m.Code = ""
			if ctx.Err() != nil {
				return nil
			}
			if err := json.NewEncoder(output).Encode(result); err != nil {
				return errors.New("login owner unavailable")
			}
		}
	}
}

func xLoginEndpoint(ctx context.Context, runtime *xloginruntime.Manager) (xloginruntime.Endpoint, error) {
	endpoint := os.Getenv("SCARLETT_X_LOGIN_URL")
	if endpoint == "" {
		return runtime.Start(ctx)
	}
	path := os.Getenv("SCARLETT_X_LOGIN_BEARER_FILE")
	if !filepath.IsAbs(path) {
		return xloginruntime.Endpoint{}, errors.New("invalid private bearer path")
	}
	file, err := localfs.OpenPrivate(path)
	if err != nil {
		return xloginruntime.Endpoint{}, errors.New("private bearer unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	defer clear(raw)
	if err != nil || len(raw) > 4096 || len(strings.TrimSpace(string(raw))) < 32 {
		return xloginruntime.Endpoint{}, errors.New("private bearer unavailable")
	}
	return xloginruntime.Endpoint{URL: endpoint, Bearer: strings.TrimSpace(string(raw))}, nil
}

// Native terminal flow keeps credentials off argv and never echoes code input.
func xLoginTerminalCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) != 2 && len(args) != 3 {
		return errors.New("usage: accounts login-x ID CONCURRENCY [reconnect]")
	}
	id := args[0]
	capacity, err := strconv.Atoi(args[1])
	if err != nil || !validAccountID(id) || capacity < 1 || capacity > 32 {
		return errors.New("invalid account selection")
	}
	reconnect := len(args) == 3 && args[2] == "reconnect"
	if len(args) == 3 && !reconnect {
		return errors.New("invalid login mode")
	}
	terminal, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(terminal.Fd())) {
		return errors.New("interactive login requires a terminal; use accounts login-x with no arguments for protected JSON-lines stdin")
	}
	prompt := func(label string) (string, error) {
		fmt.Fprintln(output, label)
		raw, e := term.ReadPassword(int(terminal.Fd()))
		fmt.Fprintln(output)
		defer clear(raw)
		return string(raw), e
	}
	username, err := prompt("X username (hidden):")
	if err != nil {
		return errors.New("login input unavailable")
	}
	password, err := prompt("X password (hidden):")
	if err != nil {
		return errors.New("login input unavailable")
	}
	reader, writer := io.Pipe()
	responsesR, responsesW := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	defer responsesR.Close()
	defer responsesW.Close()
	go func() { _ = xLoginCommand(reader, responsesW); _ = responsesW.Close() }()
	encoder := json.NewEncoder(writer)
	if err := encoder.Encode(xLoginMessage{Action: "start", ID: id, Concurrency: capacity, Reconnect: reconnect, Username: username, Password: password}); err != nil {
		return errors.New("login helper unavailable")
	}
	password = ""
	decoder := json.NewDecoder(responsesR)
	for {
		var result xLoginStatus
		if decoder.Decode(&result) != nil {
			return errors.New("login helper unavailable")
		}
		if result.Status != "pending" {
			return json.NewEncoder(output).Encode(result)
		}
		_ = json.NewEncoder(output).Encode(result)
		code, err := prompt("Verification code (hidden), or type cancel:")
		if err != nil {
			return errors.New("login input unavailable")
		}
		message := xLoginMessage{Action: "continue", ID: id, Code: code, ChallengeID: result.ChallengeID}
		if code == "cancel" {
			message = xLoginMessage{Action: "cancel", ID: id}
		}
		if encoder.Encode(message) != nil {
			return errors.New("login helper unavailable")
		}
	}
}
