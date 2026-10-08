package config

import (
	"encoding/base64"
	"errors"
	"github.com/teslashibe/scarlett-node/internal/attempts"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	ExecutorGateway   = "gateway"
	ExecutorCodexTLSN = "codex-tlsn"
	ExecutorCodex     = "codex"
	ExecutorServices  = "services"
)

type Config struct {
	DiagnosticsDisabled bool // local observations only; never changes the node-v1 wire contract
	JournalLimits       attempts.Limits
	Coordinator         string
	CoordinatorCA       string
	// Executor is "gateway" (reported usage from an HTTP gateway), "codex" (the same
	// Codex client run in-process from this node's own login) or "codex-tlsn"
	// (Codex job proven to a verifier).
	Executor string
	// CodexHome holds this node's `codex login` auth.json; CodexProfile and
	// CodexScaffold are open-agent-api's codex_profile.json and codex_scaffold.json.
	CodexHome, CodexProfile, CodexScaffold string
	// CodexManagedRoot opts into registered app-owned profile renewal only.
	CodexManagedRoot         string
	Verifier                 string
	VerifierCA               string
	VerifierPlaintextFixture bool
	Prover                   string
	Gateway                  string
	Profile                  string
	StateDir                 string
	GatewayKey               string
	Credential               string
	NodeID                   string
	Bid                      int64
	// Concurrency is how many leases the node runs at once. The default matches
	// the local Open Agent API baseline of 20 in-flight requests per account.
	Concurrency       int
	Services          []string
	AccountsFile      string
	AccountsRequired  bool
	AccountCooldown   func(time.Duration) // private provider quota observation
	AccountQuotaReset func(time.Time)     // absolute authoritative provider reset only
	AccountReady      func(string) bool   // final selected-account check before funded acceptance
	LocalAccountID    string              // private attempt identity; never sent to the coordinator
	XSession          string
	// Accepted X leases pin private credentials and verified provider identity.
	// These values never enter coordinator reports or local public status.
	ExpectedXStamp    string
	ExpectedXIdentity string
	// XRelay lets this node take X jobs proven by keyed relay, where the
	// verifier holds the TLS session keys. On by default: relay cuts a node's
	// upload per read from tens of megabytes to tens of kilobytes, and the
	// node already trusts the operator-run verifier with its session (see
	// README). SCARLETT_X_RELAY=0 opts out; the node then serves MPC-TLS only.
	XRelay bool
	// XRefresh is how often a warm X client's transaction-ID material is
	// rebuilt in the background (SCARLETT_X_REFRESH_SECONDS; default 30 min).
	XRefresh         time.Duration
	XPacingMode      string // conservative (default) or opt-in quota_budget
	CodexConcurrency int
	XConcurrency     int
	// Optional per-authenticated-X-account ceiling; zero uses the account
	// registry limit. Desktop pins this to one while allowing distinct accounts.
	XAccountConcurrency int
	// WebConcurrency is how many web pages this node fetches at once
	// (SCARLETT_WEB_CONCURRENCY, 1-32, default 4). Web needs no accounts.
	WebConcurrency int
	// WebEgressProxy, when set, is the local HTTP CONNECT proxy every web
	// target is dialled through (SCARLETT_WEB_EGRESS_PROXY), such as a
	// residential proxy in front of a cloud server. It never leaves this node.
	WebEgressProxy *WebProxy
	// WebBrowser turns on the browser tier for web jobs in browser mode
	// (SCARLETT_WEB_BROWSER on|off). It is on by default with web on macOS
	// and Linux and off by default on Windows in this release.
	WebBrowser bool
	// WebBrowserConcurrency is how many pages the browser renders at once
	// (SCARLETT_WEB_BROWSER_CONCURRENCY, 1-4). Zero means automatic: 1 below
	// 16 GiB of physical memory, else 2. It never exceeds WebConcurrency.
	WebBrowserConcurrency int
	// WebBrowserIdle is how long an idle browser helper stays up
	// (SCARLETT_WEB_BROWSER_IDLE_SECONDS, 30-3600, default 120).
	WebBrowserIdle time.Duration
	// WebSolvers is the operator's own captcha-solver accounts for the
	// browser tier (SCARLETT_WEB_SOLVERS and one key file per provider), or
	// nil. Keys never leave this node except to their provider.
	WebSolvers       *WebSolvers
	LocalFixture     bool
	InferenceTimeout time.Duration
	MaxInputBytes    int
	MaxOutputTokens  int
}

var (
	fixtureHost    = map[string]bool{"agent1-gateway": true, "agent2-gateway": true, "agent3-gateway": true, "agent4-gateway": true}
	fixtureGateway = map[string]bool{
		"http://agent1-gateway:8088": true,
		"http://agent2-gateway:8088": true,
		"http://agent3-gateway:8088": true,
		"http://agent4-gateway:8088": true,
	}
)

func Load() (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, err
	}
	c := Config{Coordinator: os.Getenv("SCARLETT_COORDINATOR"), CoordinatorCA: os.Getenv("SCARLETT_COORDINATOR_CA_FILE"), Executor: os.Getenv("SCARLETT_EXECUTOR"), Verifier: os.Getenv("SCARLETT_VERIFIER"), VerifierCA: os.Getenv("SCARLETT_VERIFIER_CA_FILE"), VerifierPlaintextFixture: os.Getenv("SCARLETT_VERIFIER_PLAINTEXT_FIXTURE") == "1", Prover: os.Getenv("SCARLETT_PROVER"), Gateway: os.Getenv("SCARLETT_GATEWAY"), Profile: os.Getenv("SCARLETT_PROFILE"), StateDir: os.Getenv("SCARLETT_STATE_DIR"), GatewayKey: os.Getenv("SCARLETT_GATEWAY_KEY"), Credential: os.Getenv("SCARLETT_CREDENTIAL"), NodeID: os.Getenv("SCARLETT_NODE_ID"), CodexManagedRoot: os.Getenv("SCARLETT_CODEX_MANAGED_ROOT"), CodexHome: os.Getenv("SCARLETT_CODEX_HOME"), CodexProfile: os.Getenv("SCARLETT_CODEX_PROFILE"), CodexScaffold: os.Getenv("SCARLETT_CODEX_SCAFFOLD"), Bid: 100, LocalFixture: os.Getenv("SCARLETT_LOCAL_FIXTURE") == "1", InferenceTimeout: 45 * time.Second, MaxInputBytes: 32768, MaxOutputTokens: 2048}
	c.JournalLimits = attempts.DefaultLimits()
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SCARLETT_DIAGNOSTICS"))) {
	case "", "1", "true", "on":
	case "0", "false", "off":
		c.DiagnosticsDisabled = true
	default:
		return c, errors.New("invalid SCARLETT_DIAGNOSTICS")
	}
	// An explicit zero is refused: zero terminal limits mean the defaults.
	for name, destination := range map[string]*int{"SCARLETT_JOURNAL_MAX_RECORDS": &c.JournalLimits.MaxRecords, "SCARLETT_JOURNAL_MAX_RECORD_BYTES": &c.JournalLimits.MaxRecordBytes, "SCARLETT_JOURNAL_MAX_TERMINAL_RECORDS": &c.JournalLimits.MaxTerminalRecords} {
		if raw := os.Getenv(name); raw != "" {
			value, err := strconv.Atoi(raw)
			if err != nil || value < 1 {
				return c, errors.New("invalid " + name)
			}
			*destination = value
		}
	}
	for name, destination := range map[string]*int64{"SCARLETT_JOURNAL_MAX_TOTAL_BYTES": &c.JournalLimits.MaxTotalBytes, "SCARLETT_JOURNAL_MAX_TERMINAL_BYTES": &c.JournalLimits.MaxTerminalBytes} {
		if raw := os.Getenv(name); raw != "" {
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || value < 1 {
				return c, errors.New("invalid " + name)
			}
			*destination = value
		}
	}
	if err := c.JournalLimits.Validate(); err != nil {
		return c, err
	}
	if s := os.Getenv("SCARLETT_BID"); s != "" {
		v, e := strconv.ParseInt(s, 10, 64)
		if e != nil || v < 0 || v > 1_000_000_000 {
			return c, errors.New("invalid SCARLETT_BID")
		}
		c.Bid = v
	}
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir(home)
	}
	if c.Executor == "" {
		c.Executor = ExecutorGateway
	}
	if c.Prover == "" {
		c.Prover = proverFilename()
		// Native bundles keep the helper beside the node. Absolute invocation
		// works even before the installation's bin directory is added to PATH.
		if exe, e := os.Executable(); e == nil {
			sibling := filepath.Join(filepath.Dir(exe), proverFilename())
			if info, e := os.Stat(sibling); e == nil && executableFile(info) {
				c.Prover = sibling
			}
		}
	}
	if c.CodexHome == "" {
		c.CodexHome = filepath.Join(home, ".codex")
	}
	if c.Executor == ExecutorServices {
		c.XSession = os.Getenv("SCARLETT_X_SESSION")
		c.XPacingMode = strings.TrimSpace(os.Getenv("SCARLETT_X_PACING_MODE"))
		if c.XPacingMode == "" {
			c.XPacingMode = "conservative"
		}
		if c.XPacingMode != "conservative" && c.XPacingMode != "quota_budget" {
			return c, errors.New("invalid SCARLETT_X_PACING_MODE")
		}
		switch strings.ToLower(strings.TrimSpace(os.Getenv("SCARLETT_X_RELAY"))) {
		case "0", "false", "off", "no":
			c.XRelay = false
		default:
			c.XRelay = true
		}
		c.XRefresh = 30 * time.Minute
		if s := os.Getenv("SCARLETT_X_REFRESH_SECONDS"); s != "" {
			v, e := strconv.Atoi(s)
			if e != nil || v < 60 || v > 86400 {
				return c, errors.New("invalid SCARLETT_X_REFRESH_SECONDS")
			}
			c.XRefresh = time.Duration(v) * time.Second
		}
		c.AccountsFile = os.Getenv("SCARLETT_ACCOUNTS_FILE")
		c.AccountsRequired = c.AccountsFile != ""
		if c.AccountsFile == "" {
			c.AccountsFile = filepath.Join(c.StateDir, "accounts.json")
		}
		c.Services = strings.Split(os.Getenv("SCARLETT_SERVICES"), ",")
		c.CodexConcurrency, c.XConcurrency, c.XAccountConcurrency, c.WebConcurrency = 1, 1, 32, 4
		if raw := os.Getenv("SCARLETT_WEB_EGRESS_PROXY"); raw != "" {
			proxy, err := ParseWebProxy(raw)
			if err != nil {
				return c, err
			}
			c.WebEgressProxy = proxy
		}
		for name, destination := range map[string]*int{"SCARLETT_CODEX_CONCURRENCY": &c.CodexConcurrency, "SCARLETT_X_CONCURRENCY": &c.XConcurrency, "SCARLETT_X_ACCOUNT_CONCURRENCY": &c.XAccountConcurrency, "SCARLETT_WEB_CONCURRENCY": &c.WebConcurrency} {
			if value := os.Getenv(name); value != "" {
				n, e := strconv.Atoi(value)
				if e != nil || n < 1 || n > 32 {
					return c, errors.New("invalid service concurrency")
				}
				*destination = n
			}
		}
		if err := c.loadWebBrowser(runtime.GOOS); err != nil {
			return c, err
		}
		if err := c.loadWebSolvers(); err != nil {
			return c, err
		}
	} else if os.Getenv("SCARLETT_SERVICES") != "" {
		return c, errors.New("SCARLETT_SERVICES requires services executor")
	} else if os.Getenv("SCARLETT_WEB_EGRESS_PROXY") != "" {
		return c, errors.New("SCARLETT_WEB_EGRESS_PROXY requires services executor")
	} else if os.Getenv("SCARLETT_WEB_BROWSER") != "" || os.Getenv("SCARLETT_WEB_BROWSER_CONCURRENCY") != "" || os.Getenv("SCARLETT_WEB_BROWSER_IDLE_SECONDS") != "" {
		return c, errors.New("SCARLETT_WEB_BROWSER settings require services executor")
	} else if anySolverSetting() {
		return c, errors.New("SCARLETT_WEB_SOLVERS settings require services executor")
	}
	if s := os.Getenv("SCARLETT_INFERENCE_TIMEOUT_SECONDS"); s != "" {
		v, e := strconv.Atoi(s)
		if e != nil || v < 1 || v > 300 {
			return c, errors.New("invalid inference timeout")
		}
		c.InferenceTimeout = time.Duration(v) * time.Second
	}
	if s := os.Getenv("SCARLETT_MAX_INPUT_BYTES"); s != "" {
		v, e := strconv.Atoi(s)
		if e != nil || v < 1 || v > 65536 {
			return c, errors.New("invalid max input bytes")
		}
		c.MaxInputBytes = v
	}
	if s := os.Getenv("SCARLETT_MAX_OUTPUT_TOKENS"); s != "" {
		v, e := strconv.Atoi(s)
		if e != nil || v < 1 || v > 8192 {
			return c, errors.New("invalid max output tokens")
		}
		c.MaxOutputTokens = v
	}
	c.Concurrency = 20
	if s := os.Getenv("SCARLETT_CONCURRENCY"); s != "" {
		v, e := strconv.Atoi(s)
		if e != nil || v < 1 || v > 64 {
			return c, errors.New("invalid SCARLETT_CONCURRENCY")
		}
		c.Concurrency = v
	}
	return c, c.Validate()
}

// variants are the gateway alias suffixes that select reasoning effort and the fast tier.
var variants = map[string]bool{
	"low": true, "medium": true, "high": true, "xhigh": true, "max": true,
	"fast": true, "fast-low": true, "fast-medium": true, "fast-high": true, "fast-xhigh": true, "fast-max": true,
}

// Models are reviewed Codex base models retained for historical result validation.
// AvailableModelsAt applies provider retirement dates to new execution and advertising.
var Models = modelIDs()

// Serves returns the base model for a lease model: a base model or its gateway
// effort/fast alias.
func Serves(id string) (string, bool) {
	for _, m := range Models {
		if id == m || legacyGatewayAliases[m] && strings.HasPrefix(id, m+"-") && variants[id[len(m)+1:]] {
			return m, true
		}
	}
	return "", false
}

func (c Config) Validate() error {
	if c.CodexManagedRoot != "" && (c.Executor != ExecutorServices || !filepath.IsAbs(c.CodexManagedRoot) || filepath.Clean(c.CodexManagedRoot) != c.CodexManagedRoot || strings.ContainsAny(c.CodexManagedRoot, "\x00\r\n")) {
		return errors.New("SCARLETT_CODEX_MANAGED_ROOT requires a clean absolute root and services executor")
	}
	if c.JournalLimits != (attempts.Limits{}) {
		if err := c.JournalLimits.Validate(); err != nil {
			return err
		}
	}
	if c.Profile == "" || strings.ContainsAny(c.Profile, " \n\r\t") || len(c.Profile) > 128 {
		return errors.New("SCARLETT_PROFILE required")
	}
	if c.LocalFixture && c.Profile != "local-fixture" {
		return errors.New("local fixture requires local-fixture profile")
	}
	if c.LocalFixture && (c.NodeID == "" || strings.ContainsAny(c.NodeID, " \n\r\t") || len(c.Credential) < 32) {
		return errors.New("local fixture requires SCARLETT_NODE_ID and SCARLETT_CREDENTIAL (at least 32 characters)")
	}
	if c.Executor != ExecutorGateway && c.Executor != ExecutorCodex && c.Executor != ExecutorCodexTLSN && c.Executor != ExecutorServices {
		return errors.New("SCARLETT_EXECUTOR must be gateway, codex, codex-tlsn or services")
	}
	if c.LocalFixture && (c.Coordinator != "http://host.docker.internal:8091" ||
		c.Executor == ExecutorGateway && !fixtureGateway[c.Gateway] ||
		c.Executor == ExecutorCodexTLSN && c.Verifier != "verifier:7047") {
		return errors.New("local fixture requires pinned Docker services")
	}
	if c.InferenceTimeout < time.Second || c.InferenceTimeout > 300*time.Second || c.MaxInputBytes < 1 || c.MaxInputBytes > 65536 || c.MaxOutputTokens < 1 || c.MaxOutputTokens > 8192 {
		return errors.New("invalid limits")
	}
	u, e := url.Parse(c.Coordinator)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("SCARLETT_COORDINATOR must be an origin")
	}
	if u.Scheme != "https" && !(c.LocalFixture && u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "host.docker.internal" || net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback())) {
		return errors.New("SCARLETT_COORDINATOR must be HTTPS or explicit local fixture HTTP")
	}
	if c.CoordinatorCA != "" && (!filepath.IsAbs(c.CoordinatorCA) || u.Scheme != "https") {
		return errors.New("SCARLETT_COORDINATOR_CA_FILE requires an absolute path and HTTPS")
	}
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return errors.New("state directory must be absolute")
	}
	if c.Executor == ExecutorCodex {
		if !filepath.IsAbs(c.CodexHome) || !filepath.IsAbs(c.CodexProfile) || !filepath.IsAbs(c.CodexScaffold) {
			return errors.New("codex executor requires absolute SCARLETT_CODEX_HOME, SCARLETT_CODEX_PROFILE and SCARLETT_CODEX_SCAFFOLD")
		}
		return nil
	}
	if c.Executor == ExecutorServices {
		if c.XPacingMode != "" && c.XPacingMode != "conservative" && c.XPacingMode != "quota_budget" {
			return errors.New("invalid SCARLETT_X_PACING_MODE")
		}
		if c.LocalFixture || len(c.Services) < 1 || len(c.Services) > 3 || c.CodexConcurrency < 1 || c.CodexConcurrency > 32 || c.XConcurrency < 1 || c.XConcurrency > 32 || c.XAccountConcurrency < 0 || c.XAccountConcurrency > 32 || c.WebConcurrency < 0 || c.WebConcurrency > 32 {
			return errors.New("invalid independent service configuration")
		}
		seen := map[string]bool{}
		for _, kind := range c.Services {
			if (kind != "codex" && kind != "x_read" && kind != "web") || seen[kind] {
				return errors.New("SCARLETT_SERVICES must select one or more of codex, x_read and web")
			}
			seen[kind] = true
		}
		if seen["web"] && c.WebConcurrency < 1 {
			return errors.New("invalid independent service configuration")
		}
		if c.WebEgressProxy != nil && !c.WebEgressProxy.valid() {
			return errors.New("invalid SCARLETT_WEB_EGRESS_PROXY")
		}
		if c.WebBrowserConcurrency < 0 || c.WebBrowserConcurrency > 4 || c.WebBrowser && c.WebBrowserConcurrency > c.WebConcurrency || c.WebBrowserIdle != 0 && (c.WebBrowserIdle < 30*time.Second || c.WebBrowserIdle > time.Hour) {
			return errors.New("invalid web browser configuration")
		}
		if c.WebSolvers != nil && (!c.WebBrowser || !c.WebSolvers.valid()) {
			return errors.New("invalid web solver configuration")
		}
		if c.AccountsRequired && c.AccountsFile == "" || !filepath.IsAbs(c.AccountsFile) && c.AccountsFile != "" {
			return errors.New("accounts file must be absolute")
		}
		if c.AccountsFile == "" && (seen["codex"] && !filepath.IsAbs(c.CodexHome) || seen["x_read"] && !filepath.IsAbs(c.XSession)) {
			return errors.New("services need absolute local credential paths")
		}
	}
	if c.VerifierCA != "" && !filepath.IsAbs(c.VerifierCA) {
		return errors.New("SCARLETT_VERIFIER_CA_FILE must be absolute")
	}
	if c.VerifierPlaintextFixture && (!c.LocalFixture || c.Verifier != "verifier:7047" || c.VerifierCA != "") {
		return errors.New("plaintext verifier is restricted to the explicit unpaid Docker fixture")
	}
	if c.Executor == ExecutorCodexTLSN || c.Executor == ExecutorServices {
		host, port, e := net.SplitHostPort(c.Verifier)
		number, portErr := strconv.Atoi(port)
		validHost := host != "" && len(host) <= 253
		if net.ParseIP(host) == nil {
			for _, r := range host {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
					validHost = false
				}
			}
		}
		if e != nil || !validHost || portErr != nil || number < 1 || number > 65535 {
			return errors.New("SCARLETT_VERIFIER must be host:port")
		}
		if c.Prover == "" {
			return errors.New("SCARLETT_PROVER required")
		}
		return nil
	}
	g, e := url.Parse(c.Gateway)
	if e != nil || g.Host == "" || g.User != nil || g.RawQuery != "" || g.Fragment != "" || g.Path != "" {
		return errors.New("SCARLETT_GATEWAY must be a gateway origin")
	}
	if g.Scheme != "https" {
		if g.Scheme != "http" {
			return errors.New("gateway must use HTTP or HTTPS")
		}
		host, _, e := net.SplitHostPort(g.Host)
		if e != nil {
			host = g.Host
		}
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) && !(c.LocalFixture && fixtureHost[host]) {
			return errors.New("HTTP gateway must be loopback or explicit local Docker fixture")
		}
	}
	return nil
}

// WebBrowserDefault is whether the browser tier is on when web is enabled and
// SCARLETT_WEB_BROWSER is unset: on for macOS and Linux, and off for Windows
// until its live test and clean-machine pass are recorded.
func WebBrowserDefault(goos string) bool { return goos != "windows" }

// loadWebBrowser reads the browser tier settings for goos. The tier needs web:
// without it the tier is off whatever SCARLETT_WEB_BROWSER says.
func (c *Config) loadWebBrowser(goos string) error {
	c.WebBrowser = WebBrowserDefault(goos)
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SCARLETT_WEB_BROWSER"))) {
	case "":
	case "on", "1", "true":
		c.WebBrowser = true
	case "off", "0", "false":
		c.WebBrowser = false
	default:
		return errors.New("invalid SCARLETT_WEB_BROWSER; use on or off")
	}
	c.WebBrowser = c.WebBrowser && c.Enabled("web")
	if value := os.Getenv("SCARLETT_WEB_BROWSER_CONCURRENCY"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 4 {
			return errors.New("invalid SCARLETT_WEB_BROWSER_CONCURRENCY; use 1-4")
		}
		c.WebBrowserConcurrency = n
	}
	c.WebBrowserIdle = 120 * time.Second
	if value := os.Getenv("SCARLETT_WEB_BROWSER_IDLE_SECONDS"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 30 || n > 3600 {
			return errors.New("invalid SCARLETT_WEB_BROWSER_IDLE_SECONDS; use 30-3600")
		}
		c.WebBrowserIdle = time.Duration(n) * time.Second
	}
	return nil
}

// WebProxy is a local HTTP CONNECT proxy for web egress. Only
// non-intercepting CONNECT tunnels work: TLS runs end to end between the
// target and the verifier, so the proxy sees only ciphertext.
type WebProxy struct {
	Host string
	Port int
	// Authorization is the exact Proxy-Authorization value, or empty.
	Authorization string
}

// String and GoString keep the proxy and its credentials out of any log line
// or formatted error that prints a configuration.
func (WebProxy) String() string   { return "web egress proxy" }
func (WebProxy) GoString() string { return "config.WebProxy{}" }

// ParseWebProxy reads SCARLETT_WEB_EGRESS_PROXY: http://[user:pass@]host:port,
// with the port required and no path, query or fragment. Errors never repeat
// the value, which may hold credentials.
func ParseWebProxy(raw string) (*WebProxy, error) {
	invalid := errors.New("invalid SCARLETT_WEB_EGRESS_PROXY; use http://[user:pass@]host:port")
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Opaque != "" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return nil, invalid
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || strconv.Itoa(port) != u.Port() {
		return nil, invalid
	}
	p := &WebProxy{Host: u.Hostname(), Port: port}
	if u.User != nil {
		password, _ := u.User.Password()
		if u.User.Username() == "" {
			return nil, invalid
		}
		p.Authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+password))
	}
	if !p.valid() {
		return nil, invalid
	}
	return p, nil
}

func (p WebProxy) valid() bool {
	if p.Port < 1 || p.Port > 65535 || p.Host == "" || len(p.Host) > 253 || len(p.Authorization) > 4096 || strings.ContainsAny(p.Authorization, "\r\n\x00") {
		return false
	}
	if ip := net.ParseIP(p.Host); ip != nil {
		return true
	}
	for _, r := range p.Host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// WebEgress is how this node reaches web targets: "proxy" through
// WebEgressProxy, otherwise "direct". It is reported, never verified.
func (c Config) WebEgress() string {
	if c.WebEgressProxy != nil {
		return "proxy"
	}
	return "direct"
}

func (c Config) Enabled(kind string) bool {
	for _, s := range c.Services {
		if s == kind {
			return true
		}
	}
	return false
}
