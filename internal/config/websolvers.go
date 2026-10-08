package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// SolverProviders are the captcha-solver services the browser tier can use,
// in their canonical names. Which one answers a challenge is decided per
// challenge type by the helper's router (CapMonster Cloud first for tokens,
// CapSolver for image and slider recognition, 2Captcha for the widest
// coverage), with fallback to the next configured provider.
var SolverProviders = []string{"capmonster", "capsolver", "2captcha"}

const (
	maxSolverKeyFile = 4096
	// DefaultSolverMaxUSDPerDay caps estimated solver spend per UTC day.
	DefaultSolverMaxUSDPerDay = 1.0
	// DefaultSolverMaxSolvesPerFetch caps paid solves per page.
	DefaultSolverMaxSolvesPerFetch = 2
)

// WebSolvers is the operator's own captcha-solver accounts for the browser
// tier (SCARLETT_WEB_SOLVERS). The operator pays the providers directly. A
// key is read once from its private file and only ever goes to the browser
// helper, which sends it to that provider's API; it is never logged and never
// reported to the coordinator. String and GoString redact the whole value.
type WebSolvers struct {
	// Providers are the configured providers, in SolverProviders order.
	Providers []string
	keys      map[string]string
	// MaxSolvesPerFetch bounds paid solves on one page (1-4).
	MaxSolvesPerFetch int
	// MaxMicroUSDPerDay bounds estimated spend per UTC day, in micro-USD.
	MaxMicroUSDPerDay int64
	// Experimental lets the router take challenge kinds its providers do not
	// document as stable (DataDome's jigsaw slider, Turnstile challenge pages).
	Experimental bool
}

func (WebSolvers) String() string   { return "web solvers [redacted]" }
func (WebSolvers) GoString() string { return "config.WebSolvers{}" }

// Key is a provider's key, or "" when it is not configured.
func (s *WebSolvers) Key(provider string) string {
	if s == nil {
		return ""
	}
	return s.keys[provider]
}

// NewWebSolvers builds a solver configuration from keys already in memory
// (tests, and callers that read keys from a store of their own). Unknown
// providers and empty keys are refused.
func NewWebSolvers(keys map[string]string, maxSolvesPerFetch int, maxMicroUSDPerDay int64, experimental bool) (*WebSolvers, error) {
	s := &WebSolvers{keys: map[string]string{}, MaxSolvesPerFetch: maxSolvesPerFetch, MaxMicroUSDPerDay: maxMicroUSDPerDay, Experimental: experimental}
	for _, name := range SolverProviders {
		if key, ok := keys[name]; ok {
			if !validSolverKey(key) {
				return nil, errors.New("invalid web solver key for " + name)
			}
			s.keys[name] = key
			s.Providers = append(s.Providers, name)
		}
	}
	for name := range keys {
		if !slices.Contains(SolverProviders, name) {
			return nil, errors.New("unknown web solver provider")
		}
	}
	if !s.valid() {
		return nil, errors.New("invalid web solver configuration")
	}
	return s, nil
}

func (s *WebSolvers) valid() bool {
	if s == nil || len(s.Providers) == 0 || len(s.Providers) != len(s.keys) || s.MaxSolvesPerFetch < 1 || s.MaxSolvesPerFetch > 4 ||
		s.MaxMicroUSDPerDay < 1 || s.MaxMicroUSDPerDay > 1_000_000_000 {
		return false
	}
	for _, name := range s.Providers {
		if !validSolverKey(s.keys[name]) {
			return false
		}
	}
	return true
}

// solverEnvName is the provider's part of SCARLETT_WEB_SOLVER_<NAME>_KEY_FILE.
func solverEnvName(provider string) string {
	return "SCARLETT_WEB_SOLVER_" + strings.ToUpper(provider) + "_KEY_FILE"
}

// SolverKeyFileEnv names the variable holding a provider's key file path.
func SolverKeyFileEnv(provider string) string { return solverEnvName(provider) }

// solverSettings are every variable loadWebSolvers reads.
func solverSettings() []string {
	names := []string{"SCARLETT_WEB_SOLVERS", "SCARLETT_WEB_SOLVER_MAX_SOLVES_PER_FETCH", "SCARLETT_WEB_SOLVER_MAX_USD_PER_DAY", "SCARLETT_WEB_SOLVER_EXPERIMENTAL"}
	for _, p := range SolverProviders {
		names = append(names, solverEnvName(p))
	}
	return names
}

// anySolverSetting reports whether any solver variable is set.
func anySolverSetting() bool {
	for _, name := range solverSettings() {
		if os.Getenv(name) != "" {
			return true
		}
	}
	return false
}

// loadWebSolvers reads SCARLETT_WEB_SOLVERS (a comma list of capmonster,
// capsolver and 2captcha), each listed provider's key file
// (SCARLETT_WEB_SOLVER_<PROVIDER>_KEY_FILE: an absolute path to a private
// regular file, mode 0600 on macOS and Linux), and the optional caps. Solvers
// need the browser tier. Errors name the variable, never a path's contents.
func (c *Config) loadWebSolvers() error {
	raw := strings.TrimSpace(os.Getenv("SCARLETT_WEB_SOLVERS"))
	if raw == "" || strings.EqualFold(raw, "off") || raw == "0" {
		for _, name := range solverSettings()[1:] {
			if os.Getenv(name) != "" {
				return errors.New(name + " requires SCARLETT_WEB_SOLVERS")
			}
		}
		return nil
	}
	if !c.WebBrowser {
		return errors.New("SCARLETT_WEB_SOLVERS requires the web browser tier (web in SCARLETT_SERVICES and SCARLETT_WEB_BROWSER on)")
	}
	keys := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "twocaptcha" {
			name = "2captcha"
		}
		if !slices.Contains(SolverProviders, name) {
			return errors.New("invalid SCARLETT_WEB_SOLVERS; use a comma list of capmonster, capsolver and 2captcha")
		}
		if _, seen := keys[name]; seen {
			return errors.New("invalid SCARLETT_WEB_SOLVERS; a provider is listed twice")
		}
		key, err := readSolverKey(solverEnvName(name))
		if err != nil {
			return err
		}
		keys[name] = key
	}
	for _, name := range SolverProviders {
		if _, listed := keys[name]; !listed && os.Getenv(solverEnvName(name)) != "" {
			return errors.New(solverEnvName(name) + " is set but " + name + " is not in SCARLETT_WEB_SOLVERS")
		}
	}
	solves := DefaultSolverMaxSolvesPerFetch
	if value := os.Getenv("SCARLETT_WEB_SOLVER_MAX_SOLVES_PER_FETCH"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 4 {
			return errors.New("invalid SCARLETT_WEB_SOLVER_MAX_SOLVES_PER_FETCH; use 1-4")
		}
		solves = n
	}
	micro := int64(DefaultSolverMaxUSDPerDay * 1e6)
	if value := os.Getenv("SCARLETT_WEB_SOLVER_MAX_USD_PER_DAY"); value != "" {
		n, ok := parseMicroUSD(value)
		if !ok || n < 1 || n > 1_000_000_000 {
			return errors.New("invalid SCARLETT_WEB_SOLVER_MAX_USD_PER_DAY; use 0.000001-1000")
		}
		micro = n
	}
	experimental := false
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SCARLETT_WEB_SOLVER_EXPERIMENTAL"))) {
	case "", "off", "0", "false":
	case "on", "1", "true":
		experimental = true
	default:
		return errors.New("invalid SCARLETT_WEB_SOLVER_EXPERIMENTAL; use on or off")
	}
	solvers, err := NewWebSolvers(keys, solves, micro, experimental)
	if err != nil {
		return err
	}
	c.WebSolvers = solvers
	return nil
}

// readSolverKey reads the key file named by env. The file must be absolute,
// private (only its owner may read it) and regular, at most 4 KiB; the key is
// its content without surrounding whitespace.
func readSolverKey(env string) (string, error) {
	path := os.Getenv(env)
	if path == "" {
		return "", errors.New(env + " is required for a listed solver")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New(env + " must be a clean absolute path")
	}
	f, err := localfs.OpenPrivateInherited(path)
	if err != nil {
		return "", errors.New(env + " must name a private regular file (mode 0600) readable by this user")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxSolverKeyFile+1))
	if err != nil || len(raw) > maxSolverKeyFile {
		return "", errors.New(env + " is unreadable or larger than 4 KiB")
	}
	key := strings.TrimSpace(string(raw))
	if !validSolverKey(key) {
		return "", errors.New(env + " must hold one key of 8-256 printable characters without spaces")
	}
	return key, nil
}

func validSolverKey(key string) bool {
	if len(key) < 8 || len(key) > 256 {
		return false
	}
	for i := 0; i < len(key); i++ {
		if key[i] <= ' ' || key[i] > '~' {
			return false
		}
	}
	return true
}

// parseMicroUSD reads a non-negative decimal dollar amount with at most six
// decimals.
func parseMicroUSD(s string) (int64, bool) {
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" && frac == "" || len(frac) > 6 || len(whole) > 4 {
		return 0, false
	}
	for _, part := range []string{whole, frac} {
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return 0, false
			}
		}
	}
	w := int64(0)
	if whole != "" {
		w, _ = strconv.ParseInt(whole, 10, 64)
	}
	f := int64(0)
	if frac != "" {
		f, _ = strconv.ParseInt(frac+strings.Repeat("0", 6-len(frac)), 10, 64)
	}
	return w*1_000_000 + f, true
}
