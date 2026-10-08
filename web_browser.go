package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

// startBrowserTier starts this node's browser tier for web jobs in browser
// mode and returns it with its stop function. The runtime-backed version
// (web_browser_runtime.go) prepares the bundled runtime and the pinned
// browser in the background and never blocks here; tests replace it.
var startBrowserTier = func(ctx context.Context, c config.Config) (worker.BrowserTier, func()) {
	return unavailableBrowser{reason: "runtime_missing"}, func() {}
}

// checkWebRuntime verifies a web runtime the way `scarlett-node web-runtime
// check` does: the archive, its extraction and the helper's self-check, and
// with withBrowser the browser download and a launch probe too. The runtime
// wiring sets it; tests replace it.
var checkWebRuntime = func(ctx context.Context, resources, state string, withBrowser bool) error {
	return errors.New("web runtime is not part of this build")
}

// unavailableBrowser is a browser tier that never runs: it reports one closed
// reason and refuses every fetch.
type unavailableBrowser struct{ reason string }

func (u unavailableBrowser) Status() worker.BrowserStatus {
	return worker.BrowserStatus{Reason: u.reason}
}
func (unavailableBrowser) Prewarm() {}
func (unavailableBrowser) Fetch(context.Context, worker.BrowserFetchRequest) (worker.BrowserFetchResult, error) {
	return worker.BrowserFetchResult{}, worker.ErrBrowserUnavailable
}

// webRuntimeResourceDir finds the directory holding web-runtime-*.tar.gz and
// x-login-runtime/, in the same order as the X login runtime:
// SCARLETT_X_LOGIN_RESOURCE_DIR when set (the desktop sets it), else the
// installed layout beside this executable.
func webRuntimeResourceDir() (string, error) {
	if dir := os.Getenv("SCARLETT_X_LOGIN_RESOURCE_DIR"); dir != "" {
		if !filepath.IsAbs(dir) {
			return "", errors.New("SCARLETT_X_LOGIN_RESOURCE_DIR must be absolute")
		}
		return dir, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", errors.New("installed runtime unavailable")
	}
	return installedXLoginResourceDir(exe)
}

// xLoginNode is the Node binary of the x-login runtime, which the browser
// helper's driver reuses.
func xLoginNode(resources string) string {
	name := "node"
	if runtime.GOOS == "windows" {
		name = "node.exe"
	}
	return filepath.Join(resources, "x-login-runtime", name)
}

// lookupWebHost is the resolver the browser's egress proxy uses.
func lookupWebHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// upstreamProxyURL is SCARLETT_WEB_EGRESS_PROXY's address for the browser's
// egress proxy, which then sends CONNECT <checked-ip>:<port> through it as
// the relay does. Its Proxy-Authorization travels apart, exactly as configured.
func upstreamProxyURL(p *config.WebProxy) *url.URL {
	if p == nil {
		return nil
	}
	return &url.URL{Scheme: "http", Host: net.JoinHostPort(p.Host, strconv.Itoa(p.Port))}
}

// webRuntimeCommand is `scarlett-node web-runtime check [--resources DIR]
// [--with-browser]`: release checks verify a bundled web runtime without
// pairing or running a node. It prints {"webRuntime":"passed"} on success.
func webRuntimeCommand(args []string, out io.Writer) error {
	usage := errors.New("usage: scarlett-node web-runtime check [--resources DIR] [--with-browser]")
	if len(args) < 1 || args[0] != "check" {
		return usage
	}
	flags := flag.NewFlagSet("web-runtime check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	resources := flags.String("resources", "", "directory holding the web runtime archive and x-login-runtime/")
	withBrowser := flags.Bool("with-browser", false, "also download and verify the pinned browser and run a launch probe")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return usage
	}
	dir := *resources
	if dir == "" {
		found, err := webRuntimeResourceDir()
		if err != nil {
			return err
		}
		dir = found
	}
	state := os.Getenv("SCARLETT_STATE_DIR")
	if state == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return errors.New("private storage unavailable")
		}
		state = config.DefaultStateDir(home)
	}
	if !filepath.IsAbs(dir) || !filepath.IsAbs(state) {
		return errors.New("web runtime and state directories must be absolute")
	}
	if err := checkWebRuntime(context.Background(), dir, state, *withBrowser); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"webRuntime": "passed"})
}
