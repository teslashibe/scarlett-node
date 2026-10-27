package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

func TestDesktopPrivateHelpersUseRealPrivateStorageAndStableBearer(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	var out bytes.Buffer
	if err := desktopCommand([]string{"private-dir", root}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if err := localfs.CheckDir(root); err != nil {
		t.Fatal(err)
	}
	if out.String() != "{\"ok\":true}\n" {
		t.Fatal("unexpected directory response")
	}
	path := filepath.Join(root, "bearer")
	out.Reset()
	if err := desktopCommand([]string{"bearer", path}, strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(out.Bytes(), &response); err != nil || len(response.Key) != 64 {
		t.Fatal("invalid private bearer response")
	}
	original := response.Key
	file, err := localfs.OpenPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	key, err := desktopBearer(path)
	if err != nil || key != original {
		t.Fatal("bearer changed")
	}
	lock, err := localfs.LockPrivate(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = desktopBearer(path); err == nil {
		t.Fatal("concurrent key access acquired owned lock")
	}
	lock.Close()
	if err = localfs.WriteAtomic(path, []byte(strings.Repeat("!", 64)), true); err != nil {
		t.Fatal(err)
	}
	if _, err = desktopBearer(path); err == nil {
		t.Fatal("corrupted bearer accepted")
	}
}

// The desktop reserves each Codex login profile with private-dir-new and then
// checks it with private-dir, exactly as this test does. A name already taken
// by any entry, including an older inherited-ACL directory, is reported for the
// caller to skip and is never adopted or repaired.
func TestDesktopPrivateDirNewReservesProtectedProfilesExclusively(t *testing.T) {
	root := filepath.Join(t.TempDir(), "codex-logins")
	if err := desktopCommand([]string{"private-dir", root}, strings.NewReader(""), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	reserve := func(path string) string {
		t.Helper()
		var out bytes.Buffer
		if err := desktopCommand([]string{"private-dir-new", path}, strings.NewReader(""), &out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	home := filepath.Join(root, "codex-1")
	if got := reserve(home); got != "{\"status\":\"created\"}\n" {
		t.Fatal("unexpected reservation response")
	}
	var out bytes.Buffer
	if err := desktopCommand([]string{"private-dir", home}, strings.NewReader(""), &out); err != nil || out.String() != "{\"ok\":true}\n" {
		t.Fatal("reserved profile failed the private directory check", err)
	}
	if got := reserve(home); got != "{\"status\":\"exists\"}\n" {
		t.Fatal("reserved profile was claimed twice")
	}
	orphan := filepath.Join(root, "codex-2")
	if err := os.Mkdir(orphan, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(orphan, 0755); err != nil {
		t.Fatal(err)
	}
	if got := reserve(orphan); got != "{\"status\":\"exists\"}\n" {
		t.Fatal("existing unprotected directory was not reported as taken")
	}
	if err := desktopCommand([]string{"private-dir", orphan}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("existing unprotected directory was adopted or repaired")
	}
	// Shared on Unix; inherited-only ACL on Windows.
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", filepath.Join(root, "missing", "codex-3"), filepath.Join(shared, "codex-4")} {
		if err := desktopCommand([]string{"private-dir-new", path}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatal("reservation accepted an invalid or unprotected parent")
		}
	}
}

func TestDesktopHelpersRejectPathsPortsAndUnknownCommands(t *testing.T) {
	for _, args := range [][]string{{"private-dir", "relative"}, {"private-dir-new", "relative"}, {"private-dir-new"}, {"bearer", "relative"}, {"api", "80"}, {"api", "65536"}, {"api", "localhost:8088"}, {"api", "8088", "extra"}, {"delete", "anything"}} {
		if err := desktopCommand(args, strings.NewReader(""), &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted invalid command %q", args[0])
		}
	}
	if err := desktopCommand([]string{"api", "8088"}, nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing owner accepted")
	}
	root := t.TempDir()
	file := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := desktopCommand([]string{"private-dir", file}, strings.NewReader(""), &bytes.Buffer{}); err == nil {
		t.Fatal("regular file treated as private directory")
	}
}

const syntheticStartProxy = `{"provider":"webshare","username":"synthetic0user","password":"synthetic-secret","country":"us","port":80,"use":"limited_sites"}`

// The start line is read a byte at a time, so the owner commands after it
// stay in the pipe for readOwner.
func TestDesktopStartLine(t *testing.T) {
	owner := strings.NewReader("{}\nsleep\nwake\n")
	if p, err := readDesktopStart(owner); err != nil || p != nil {
		t.Fatal("empty start line", p, err)
	}
	if rest, _ := io.ReadAll(owner); string(rest) != "sleep\nwake\n" {
		t.Fatalf("start line took %q", rest)
	}
	owner = strings.NewReader(`{"web_egress_proxy":` + syntheticStartProxy + "}\r\nwake\n")
	p, err := readDesktopStart(owner)
	if err != nil || p == nil || p.Provider != config.ProxyWebshare || p.Use != config.ProxyUseLimitedSites {
		t.Fatal("proxy start line", err)
	}
	if rest, _ := io.ReadAll(owner); string(rest) != "wake\n" {
		t.Fatalf("start line took %q", rest)
	}
	long := `{"web_egress_proxy":` + strings.Replace(syntheticStartProxy, `"use"`, `"pad":"`+strings.Repeat("a", 4096)+`","use"`, 1) + "}\n"
	for _, line := range []string{"", "{}", "sleep\n", `{"web_egress_proxy":` + strings.Replace(syntheticStartProxy, "webshare", "http", 1) + "}\n", long, "{\"web_egress_proxy\":" + syntheticStartProxy + "}"} {
		_, err := readDesktopStart(strings.NewReader(line))
		if err == nil {
			t.Errorf("%.40q accepted", line)
		} else if strings.Contains(err.Error(), "synthetic") {
			t.Errorf("error repeats the line: %v", err)
		}
	}
	// A proxy start line belongs to the services executor; the merge is
	// checked before anything runs.
	t.Setenv("SCARLETT_COORDINATOR", "https://example.org")
	t.Setenv("SCARLETT_PROFILE", "standard")
	t.Setenv("SCARLETT_EXECUTOR", "gateway")
	t.Setenv("SCARLETT_GATEWAY", "http://127.0.0.1:8080")
	t.Setenv("SCARLETT_STATE_DIR", filepath.Join(t.TempDir(), "state"))
	err = desktopCommand([]string{"run"}, strings.NewReader(`{"web_egress_proxy":`+syntheticStartProxy+"}\n"), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "services executor") || strings.Contains(err.Error(), "synthetic") {
		t.Fatal("proxy start line outside services mode", err)
	}
	if err := desktopCommand([]string{"run"}, strings.NewReader("sleep\n"), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "start line") {
		t.Fatal("run without a start line", err)
	}
}

func TestDesktopProxyTest(t *testing.T) {
	previous := probeDesktopProxy
	t.Cleanup(func() { probeDesktopProxy = previous })
	var probed []*config.WebProxy
	answer := func(exit netip.Addr, class string) {
		probeDesktopProxy = func(_ context.Context, p *config.WebProxy) (netip.Addr, string) {
			probed = append(probed, p)
			return exit, class
		}
	}
	run := func(input string) string {
		t.Helper()
		var out bytes.Buffer
		if err := desktopCommand([]string{"proxy-test"}, strings.NewReader(input), &out); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "synthetic") {
			t.Fatal("proxy test prints the settings", out.String())
		}
		return out.String()
	}
	answer(netip.MustParseAddr("93.184.216.34"), "")
	if out := run(syntheticStartProxy); out != `{"ok":true,"exit":"93.184.216.34"}`+"\n" || len(probed) != 1 || probed[0].Username != "synthetic0user" {
		t.Fatal(out)
	}
	if out := run(syntheticStartProxy + "\n"); out != `{"ok":true,"exit":"93.184.216.34"}`+"\n" {
		t.Fatal(out)
	}
	for _, class := range []string{"proxy_unreachable", "proxy_auth", "proxy_quota", "proxy_busy", "proxy_refused", "proxy_exit"} {
		answer(netip.Addr{}, class)
		if out := run(syntheticStartProxy); out != `{"ok":false,"class":"`+class+`"}`+"\n" {
			t.Fatal(class, out)
		}
	}
	probed = nil
	for _, input := range []string{"", "{}", `{"web_egress_proxy":` + syntheticStartProxy + `}`, strings.Replace(syntheticStartProxy, `"port":80`, `"port":8080`, 1), `{"provider":"http","host":"127.0.0.1","port":3128,"use":"all"}`} {
		if out := run(input); out != `{"ok":false,"class":"invalid"}`+"\n" {
			t.Fatalf("%q: %s", input, out)
		}
	}
	if len(probed) != 0 {
		t.Fatal("an invalid proxy was probed")
	}
}
