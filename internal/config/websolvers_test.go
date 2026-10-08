package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeKey(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWebSolversConfiguration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("key file permissions are checked through ACLs on Windows")
	}
	for _, name := range solverSettings() {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	dir := t.TempDir()
	const capmonster, capsolver, twocaptcha = "cm0123456789abcdef0123456789abcd", "CAP-0123456789ABCDEF0123456789ABCDEF", "2c0123456789abcdef0123456789abcd"
	cmFile := writeKey(t, dir, "capmonster.key", capmonster+"\n", 0o600)
	csFile := writeKey(t, dir, "capsolver.key", "  "+capsolver+"  \n", 0o600)
	tcFile := writeKey(t, dir, "2captcha.key", twocaptcha, 0o600)
	load := func() (Config, error) {
		c := Config{Services: []string{"web"}, WebBrowser: true}
		err := c.loadWebSolvers()
		return c, err
	}

	// Off by default, and no solver variable without the list.
	if c, err := load(); err != nil || c.WebSolvers != nil {
		t.Fatal("default", err, c.WebSolvers)
	}
	t.Setenv("SCARLETT_WEB_SOLVER_CAPMONSTER_KEY_FILE", cmFile)
	if _, err := load(); err == nil || !strings.Contains(err.Error(), "requires SCARLETT_WEB_SOLVERS") {
		t.Fatal("key file without the list", err)
	}

	t.Setenv("SCARLETT_WEB_SOLVERS", "capsolver, CapMonster,twocaptcha")
	t.Setenv("SCARLETT_WEB_SOLVER_CAPSOLVER_KEY_FILE", csFile)
	t.Setenv("SCARLETT_WEB_SOLVER_2CAPTCHA_KEY_FILE", tcFile)
	c, err := load()
	if err != nil || c.WebSolvers == nil || strings.Join(c.WebSolvers.Providers, ",") != "capmonster,capsolver,2captcha" ||
		c.WebSolvers.Key("capmonster") != capmonster || c.WebSolvers.Key("capsolver") != capsolver || c.WebSolvers.Key("2captcha") != twocaptcha ||
		c.WebSolvers.MaxSolvesPerFetch != 2 || c.WebSolvers.MaxMicroUSDPerDay != 1_000_000 || c.WebSolvers.Experimental {
		t.Fatalf("three providers: %v %+v", err, c.WebSolvers)
	}
	// Never printed, whatever the verb.
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, c.WebSolvers); strings.Contains(out, capmonster) || strings.Contains(out, capsolver) {
			t.Fatalf("%s prints a key: %s", verb, out)
		}
		if out := fmt.Sprintf(verb, *c.WebSolvers); strings.Contains(out, capmonster) || strings.Contains(out, capsolver) {
			t.Fatalf("%s prints a key: %s", verb, out)
		}
	}

	// Caps and the experimental switch.
	t.Setenv("SCARLETT_WEB_SOLVER_MAX_SOLVES_PER_FETCH", "4")
	t.Setenv("SCARLETT_WEB_SOLVER_MAX_USD_PER_DAY", "2.5")
	t.Setenv("SCARLETT_WEB_SOLVER_EXPERIMENTAL", "on")
	if c, err := load(); err != nil || c.WebSolvers.MaxSolvesPerFetch != 4 || c.WebSolvers.MaxMicroUSDPerDay != 2_500_000 || !c.WebSolvers.Experimental {
		t.Fatal("caps", err, c.WebSolvers)
	}
	for name, values := range map[string][]string{
		"SCARLETT_WEB_SOLVER_MAX_SOLVES_PER_FETCH": {"0", "5", "two"},
		"SCARLETT_WEB_SOLVER_MAX_USD_PER_DAY":      {"0", "-1", "1e3", "0.0000001", "10000", "1,5", "."},
		"SCARLETT_WEB_SOLVER_EXPERIMENTAL":         {"maybe"},
	} {
		for _, value := range values {
			t.Setenv(name, value)
			if _, err := load(); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("%s=%q: %v", name, value, err)
			}
		}
		os.Unsetenv(name)
	}

	// The list must name known providers once, each with its own file.
	for _, list := range []string{"capmonster,capmonster", "anticaptcha", "capmonster,"} {
		t.Setenv("SCARLETT_WEB_SOLVERS", list)
		if _, err := load(); err == nil {
			t.Errorf("SCARLETT_WEB_SOLVERS=%q accepted", list)
		}
	}
	t.Setenv("SCARLETT_WEB_SOLVERS", "capmonster")
	if _, err := load(); err == nil || !strings.Contains(err.Error(), "SCARLETT_WEB_SOLVER_CAPSOLVER_KEY_FILE is set") {
		t.Fatal("a key file for an unlisted provider", err)
	}
	os.Unsetenv("SCARLETT_WEB_SOLVER_CAPSOLVER_KEY_FILE")
	os.Unsetenv("SCARLETT_WEB_SOLVER_2CAPTCHA_KEY_FILE")
	if c, err := load(); err != nil || strings.Join(c.WebSolvers.Providers, ",") != "capmonster" {
		t.Fatal("one provider", err)
	}

	// Key files: absolute, private, regular, one printable key; errors never
	// carry the key or the path's contents.
	secret := "leaked0123456789secret"
	for name, setup := range map[string]func() string{
		"relative":  func() string { return "capmonster.key" },
		"missing":   func() string { return filepath.Join(dir, "absent.key") },
		"group":     func() string { return writeKey(t, dir, "group.key", secret, 0o640) },
		"world":     func() string { return writeKey(t, dir, "world.key", secret, 0o644) },
		"directory": func() string { p := filepath.Join(dir, "d"); _ = os.Mkdir(p, 0o700); return p },
		"empty":     func() string { return writeKey(t, dir, "empty.key", "\n", 0o600) },
		"short":     func() string { return writeKey(t, dir, "short.key", "abc", 0o600) },
		"two words": func() string { return writeKey(t, dir, "words.key", secret+" "+secret, 0o600) },
		"too large": func() string { return writeKey(t, dir, "large.key", strings.Repeat("a", 5000), 0o600) },
		"control":   func() string { return writeKey(t, dir, "control.key", secret+"\x00x", 0o600) },
		"symlink": func() string {
			p := filepath.Join(dir, "link.key")
			_ = os.Symlink(cmFile, p)
			return p
		},
	} {
		t.Setenv("SCARLETT_WEB_SOLVER_CAPMONSTER_KEY_FILE", setup())
		_, err := load()
		if err == nil {
			t.Errorf("%s key file accepted", name)
			continue
		}
		if strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "SCARLETT_WEB_SOLVER_CAPMONSTER_KEY_FILE") {
			t.Errorf("%s: %v", name, err)
		}
	}
	t.Setenv("SCARLETT_WEB_SOLVER_CAPMONSTER_KEY_FILE", cmFile)

	// Solvers need the browser tier.
	c = Config{Services: []string{"web"}, WebBrowser: false}
	if err := c.loadWebSolvers(); err == nil || !strings.Contains(err.Error(), "browser tier") {
		t.Fatal("solvers without the browser", err)
	}

	// Through Load: only with the services executor.
	t.Setenv("SCARLETT_COORDINATOR", "https://example.org")
	t.Setenv("SCARLETT_PROFILE", "synthetic")
	t.Setenv("SCARLETT_EXECUTOR", ExecutorServices)
	t.Setenv("SCARLETT_VERIFIER", "127.0.0.1:7047")
	t.Setenv("SCARLETT_PROVER", "scarlett-prover")
	t.Setenv("SCARLETT_SERVICES", "web")
	t.Setenv("SCARLETT_WEB_BROWSER", "on")
	if c, err := Load(); err != nil || c.WebSolvers == nil || c.WebSolvers.Key("capmonster") != capmonster {
		t.Fatal("loaded solvers", err)
	}
	t.Setenv("SCARLETT_WEB_BROWSER", "off")
	if _, err := Load(); err == nil {
		t.Fatal("solvers accepted with the browser off")
	}
	t.Setenv("SCARLETT_EXECUTOR", ExecutorGateway)
	t.Setenv("SCARLETT_SERVICES", "")
	t.Setenv("SCARLETT_WEB_BROWSER", "")
	t.Setenv("SCARLETT_GATEWAY", "http://127.0.0.1:8088")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SCARLETT_WEB_SOLVERS") {
		t.Fatal("solver settings accepted without the services executor", err)
	}
}

func TestNewWebSolvers(t *testing.T) {
	if _, err := NewWebSolvers(map[string]string{"capmonster": "0123456789abcdef"}, 2, 1_000_000, false); err != nil {
		t.Fatal(err)
	}
	for name, keys := range map[string]map[string]string{
		"none":    {},
		"unknown": {"anticaptcha": "0123456789abcdef"},
		"short":   {"capsolver": "abc"},
	} {
		if _, err := NewWebSolvers(keys, 2, 1_000_000, false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := NewWebSolvers(map[string]string{"capmonster": "0123456789abcdef"}, 0, 1_000_000, false); err == nil {
		t.Error("zero solves per fetch accepted")
	}
	if _, err := NewWebSolvers(map[string]string{"capmonster": "0123456789abcdef"}, 2, 0, false); err == nil {
		t.Error("zero daily cap accepted")
	}
	for value, want := range map[string]int64{"1": 1_000_000, "0.5": 500_000, ".25": 250_000, "1000": 1_000_000_000, "0.000001": 1, "12.": 12_000_000} {
		if got, ok := parseMicroUSD(value); !ok || got != want {
			t.Errorf("parseMicroUSD(%q) = %d %v", value, got, ok)
		}
	}
}
