package webruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CheckOptions are `scarlett-node web-runtime check` inputs.
type CheckOptions struct {
	ResourceDir string
	StateDir    string
	// WithBrowser also downloads (or reuses) the pinned browser and runs one
	// launch-and-close probe. Bundle checks leave it off.
	WithBrowser bool
}

type denyAll struct{}

func (denyAll) Allowed(context.Context, netip.Addr) bool { return false }

// Check proves a packaged runtime works on this host: extraction and full
// verification, the helper's --self-check (imports and the exact option set)
// and the Playwright driver on the x-login runtime's Node; with WithBrowser,
// the pinned browser and a launch-and-close probe.
func Check(ctx context.Context, opts CheckOptions) error {
	cfg := Config{ResourceDir: opts.ResourceDir, StateDir: opts.StateDir, Guard: denyAll{}, Capacity: 1}.withDefaults()
	root, err := Ensure(cfg)
	if err != nil {
		return err
	}
	if err = Verify(root); err != nil {
		return err
	}
	state := filepath.Join(cfg.StateDir, "web-browser")
	for _, dir := range []string{state, filepath.Join(state, "home"), filepath.Join(state, "none")} {
		if err = privateDir(dir); err != nil {
			return fail(ReasonRuntimeInvalid, "private browser state inaccessible")
		}
	}
	if err = wipeDir(filepath.Join(state, "tmp")); err != nil {
		return fail(ReasonRuntimeInvalid, "private browser state inaccessible")
	}
	m := New(cfg)
	env := m.helperEnv(state, strings.Repeat("0", 64), 1, Browser{}, "http://127.0.0.1:9", "http://127.0.0.1:9", 1)
	run := func(args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, root.Python(), args...)
		cmd.Dir = filepath.Join(state, "home")
		cmd.Env = env
		var out bytes.Buffer
		cmd.Stdout = &limitedWriter{buf: &out, max: 64 << 10}
		err := cmd.Run()
		return out.Bytes(), err
	}
	out, err := run("-I", "-B", "-X", "utf8", "-m", "scarlett_web_helper", "--self-check")
	var report struct {
		SelfCheck  string `json:"self_check"`
		Python     string `json:"python"`
		Scrapling  string `json:"scrapling"`
		Patchright string `json:"patchright"`
		Playwright string `json:"playwright"`
	}
	if err != nil || json.Unmarshal(out, &report) != nil || report.SelfCheck != "passed" || report.Python != pythonVersion ||
		report.Scrapling != scraplingVersion || report.Patchright != "1.63.0" || report.Playwright != "1.63.0" {
		return fail(ReasonRuntimeInvalid, "runtime self-check failed")
	}
	out, err = run("-I", "-B", "-m", "patchright", "--version")
	if err != nil || strings.TrimSpace(string(out)) != "Version 1.63.0" {
		return fail(ReasonRuntimeInvalid, "browser driver check failed")
	}
	if !opts.WithBrowser {
		return nil
	}
	err = m.prepare(ctx)
	if cerr := m.Close(context.Background()); err == nil && cerr != nil {
		err = errors.New("browser probe did not stop")
	}
	return err
}

type limitedWriter struct {
	buf *bytes.Buffer
	max int
}

func (w *limitedWriter) Write(b []byte) (int, error) {
	if room := w.max - w.buf.Len(); room > 0 {
		w.buf.Write(b[:min(len(b), room)])
	}
	return len(b), nil
}
