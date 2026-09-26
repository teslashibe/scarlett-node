package config

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	ExecutorGateway   = "gateway"
	ExecutorCodexTLSN = "codex-tlsn"
)

type Config struct {
	Coordinator string
	// Executor is "gateway" (reported usage) or "codex-tlsn" (Codex job proven to a verifier).
	Executor string
	Verifier string
	Prover   string
	Gateway  string
	// Models are the base models this node serves. One slot pool is shared across them.
	Models     []string
	Profile    string
	StateDir   string
	GatewayKey string
	Credential string
	NodeID     string
	Bid        int64
	// Concurrency is how many leases the node runs at once. The default matches
	// the local Open Agent API baseline of 20 in-flight requests per account.
	Concurrency      int
	LocalFixture     bool
	InferenceTimeout time.Duration
	MaxInputBytes    int
	MaxOutputTokens  int
}

var (
	fixtureModel   = map[string]bool{"gpt-5.6-luna": true, "gpt-5.6-terra": true, "gpt-5.6-sol": true}
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
	c := Config{Coordinator: os.Getenv("SCARLETT_COORDINATOR"), Executor: os.Getenv("SCARLETT_EXECUTOR"), Verifier: os.Getenv("SCARLETT_VERIFIER"), Prover: os.Getenv("SCARLETT_PROVER"), Gateway: os.Getenv("SCARLETT_GATEWAY"), Profile: os.Getenv("SCARLETT_PROFILE"), StateDir: os.Getenv("SCARLETT_STATE_DIR"), GatewayKey: os.Getenv("SCARLETT_GATEWAY_KEY"), Credential: os.Getenv("SCARLETT_CREDENTIAL"), NodeID: os.Getenv("SCARLETT_NODE_ID"), Bid: 100, LocalFixture: os.Getenv("SCARLETT_LOCAL_FIXTURE") == "1", InferenceTimeout: 45 * time.Second, MaxInputBytes: 32768, MaxOutputTokens: 2048}
	if s := os.Getenv("SCARLETT_MODELS"); s != "" {
		c.Models = strings.Split(s, ",")
	}
	if s := os.Getenv("SCARLETT_BID"); s != "" {
		v, e := strconv.ParseInt(s, 10, 64)
		if e != nil || v < 0 || v > 1_000_000_000 {
			return c, errors.New("invalid SCARLETT_BID")
		}
		c.Bid = v
	}
	if c.StateDir == "" {
		c.StateDir = filepath.Join(home, ".local", "state", "scarlett-node")
	}
	if c.Executor == "" {
		c.Executor = ExecutorGateway
	}
	if c.Prover == "" {
		c.Prover = "scarlett-prover"
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

// Serves returns the served base model for a lease model: a configured model
// or its gateway effort/fast alias.
func (c Config) Serves(id string) (string, bool) {
	for _, m := range c.Models {
		if id == m || strings.HasPrefix(id, m+"-") && variants[id[len(m)+1:]] {
			return m, true
		}
	}
	return "", false
}

func (c Config) Validate() error {
	if len(c.Models) < 1 || len(c.Models) > 16 || c.Profile == "" || strings.ContainsAny(c.Profile, " \n\r\t") || len(c.Profile) > 128 {
		return errors.New("SCARLETT_MODELS (1–16, comma-separated) and SCARLETT_PROFILE required")
	}
	seen := map[string]bool{}
	for _, m := range c.Models {
		if m == "" || strings.ContainsAny(m, " \n\r\t") || len(m) > 128 || seen[m] {
			return errors.New("invalid or duplicate SCARLETT_MODELS entry")
		}
		if c.LocalFixture && !fixtureModel[m] {
			return errors.New("local fixture requires pinned models")
		}
		seen[m] = true
	}
	if c.LocalFixture && c.Profile != "local-fixture" {
		return errors.New("local fixture requires local-fixture profile")
	}
	if c.LocalFixture && (c.NodeID == "" || strings.ContainsAny(c.NodeID, " \n\r\t") || len(c.Credential) < 32) {
		return errors.New("local fixture requires SCARLETT_NODE_ID and SCARLETT_CREDENTIAL (at least 32 characters)")
	}
	if c.Executor != ExecutorGateway && c.Executor != ExecutorCodexTLSN {
		return errors.New("SCARLETT_EXECUTOR must be gateway or codex-tlsn")
	}
	if c.LocalFixture && (c.Coordinator != "http://host.docker.internal:8091" ||
		c.Executor == ExecutorGateway && !fixtureGateway[c.Gateway] ||
		c.Executor == ExecutorCodexTLSN && c.Verifier != "verifier:7047") {
		return errors.New("local fixture requires pinned Docker services and models")
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
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		return errors.New("state directory must be absolute")
	}
	if c.Executor == ExecutorCodexTLSN {
		host, port, e := net.SplitHostPort(c.Verifier)
		if e != nil || host == "" || port == "" {
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
