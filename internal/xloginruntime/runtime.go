// Package xloginruntime supervises the packaged, local browser-login helper.
// It does not download software, locate executables through PATH, or log credentials.
package xloginruntime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

var ErrUnavailable = errors.New("browser login runtime unavailable")

type Config struct{ ResourceDir, StateDir, BrowserPath string }
type Endpoint struct{ URL, Bearer string }

func (e Endpoint) String() string   { return "browser login endpoint [redacted]" }
func (e Endpoint) GoString() string { return e.String() }

type Manager struct {
	mu       sync.Mutex
	config   Config
	cmd      *exec.Cmd
	stdin    io.WriteCloser
	done     chan struct{}
	endpoint Endpoint
	lockFile *os.File
}

func New(c Config) *Manager { return &Manager{config: c} }

type Manifest struct {
	SchemaVersion int        `json:"schemaVersion"`
	Platform      string     `json:"platform"`
	NodeVersion   string     `json:"nodeVersion"`
	Files         []Resource `json:"files"`
}
type Resource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Verify checks the complete package inventory, including dependencies. Symlinks,
// traversal, duplicate paths, missing files and unlisted resources fail closed.
func Verify(root string) error {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: packaged resources missing", ErrUnavailable)
	}
	// Inspect every resource before any reads, so symlinks and FIFOs cannot
	// redirect or block manifest/resource verification.
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink resource")
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return errors.New("nonregular resource")
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: resource tree invalid", ErrUnavailable)
	}
	manifestInfo, err := os.Lstat(filepath.Join(root, "manifest.json"))
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() > 1048576 {
		return fmt.Errorf("%w: manifest invalid", ErrUnavailable)
	}
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return fmt.Errorf("%w: manifest missing", ErrUnavailable)
	}
	var manifest Manifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.SchemaVersion != 1 || manifest.Platform != runtime.GOOS+"-"+runtime.GOARCH || manifest.NodeVersion != "22.23.3" {
		return fmt.Errorf("%w: resource manifest incompatible", ErrUnavailable)
	}
	required := map[string]bool{nodeName(): false, "social-login/src/server.js": false, "social-login/node_modules/playwright/package.json": false, "social-login/UPSTREAM.json": false}
	inventory := map[string]bool{}
	for _, f := range manifest.Files {
		if f.Path == "" || f.Path == "manifest.json" || strings.Contains(f.Path, "\\") || strings.Contains(f.Path, ":") || filepath.IsAbs(f.Path) || filepath.ToSlash(filepath.Clean(f.Path)) != f.Path || strings.HasPrefix(f.Path, "../") || inventory[f.Path] {
			return fmt.Errorf("%w: invalid resource inventory", ErrUnavailable)
		}
		inventory[f.Path] = true
		if _, ok := required[f.Path]; ok {
			required[f.Path] = true
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.Path)))
		if err != nil {
			return fmt.Errorf("%w: resource missing", ErrUnavailable)
		}
		hash := sha256.Sum256(data)
		if hex.EncodeToString(hash[:]) != f.SHA256 {
			return fmt.Errorf("%w: resource checksum mismatch", ErrUnavailable)
		}
	}
	for _, found := range required {
		if !found {
			return fmt.Errorf("%w: required resource absent", ErrUnavailable)
		}
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink")
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("nonregular resource")
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel != "manifest.json" && !inventory[rel] {
			return errors.New("unlisted resource")
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: resource inventory invalid", ErrUnavailable)
	}
	return nil
}
func nodeName() string {
	if runtime.GOOS == "windows" {
		return "node.exe"
	}
	return "node"
}
func defaultBrowser() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	case "linux":
		return "/opt/google/chrome/chrome"
	case "windows":
		return `C:\Program Files\Google\Chrome\Application\chrome.exe`
	}
	return ""
}
func privateDir(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return localfs.CheckDir(path)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := privateDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := localfs.CreateDir(path); err != nil && !os.IsExist(err) {
		return err
	}
	return localfs.CheckDir(path)
}
func token(path string) (string, error) {
	f, err := localfs.OpenPrivate(path)
	if os.IsNotExist(err) {
		bytes := make([]byte, 32)
		if _, err = rand.Read(bytes); err != nil {
			return "", err
		}
		if err = localfs.WriteAtomic(path, []byte(hex.EncodeToString(bytes)), false); err != nil && !os.IsExist(err) {
			return "", err
		}
		f, err = localfs.OpenPrivate(path)
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil || len(raw) != 64 {
		return "", errors.New("bearer file invalid")
	}
	if _, err = hex.DecodeString(string(raw)); err != nil {
		return "", errors.New("bearer file invalid")
	}
	return string(raw), nil
}
func (m *Manager) Start(ctx context.Context) (Endpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil {
		select {
		case <-m.done:
			m.stopLocked(context.Background())
		default:
			if m.endpoint.URL == "" {
				return Endpoint{}, fmt.Errorf("%w: previous helper is still stopping", ErrUnavailable)
			}
			return m.endpoint, nil
		}
	}
	if !filepath.IsAbs(m.config.ResourceDir) || !filepath.IsAbs(m.config.StateDir) {
		return Endpoint{}, fmt.Errorf("%w: fixed absolute resource and state paths required", ErrUnavailable)
	}
	root := filepath.Join(m.config.ResourceDir, "x-login-runtime")
	if err := Verify(root); err != nil {
		return Endpoint{}, err
	}
	// Node resolves module filenames through OS aliases (for example /tmp on
	// macOS). Use the same canonical fixed path for its entrypoint argv.
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: resource path inaccessible", ErrUnavailable)
	}
	browser := m.config.BrowserPath
	if browser == "" {
		browser = defaultBrowser()
	}
	info, err := os.Stat(browser)
	if !filepath.IsAbs(browser) || err != nil || !info.Mode().IsRegular() {
		return Endpoint{}, fmt.Errorf("%w: Google Chrome must be installed at the configured absolute path", ErrUnavailable)
	}
	if _, err = os.Lstat(m.config.StateDir); os.IsNotExist(err) {
		err = localfs.EnsureDir(m.config.StateDir)
	} else if err == nil {
		err = localfs.CheckDir(m.config.StateDir)
	}
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: private node state inaccessible", ErrUnavailable)
	}
	state := filepath.Join(m.config.StateDir, "x-browser")
	if err = privateDir(state); err != nil {
		return Endpoint{}, fmt.Errorf("%w: private state inaccessible", ErrUnavailable)
	}
	profiles := filepath.Join(state, "profiles")
	if err = privateDir(profiles); err != nil {
		return Endpoint{}, fmt.Errorf("%w: private profiles inaccessible", ErrUnavailable)
	}
	bearer, err := token(filepath.Join(state, "bearer"))
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: private bearer unavailable", ErrUnavailable)
	}
	lock, err := localfs.LockPrivate(filepath.Join(state, "runtime.lock"))
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: browser login already active for this installation", ErrUnavailable)
	}
	started := false
	defer func() {
		if !started {
			lock.Close()
		}
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return Endpoint{}, fmt.Errorf("%w: loopback unavailable", ErrUnavailable)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cmd := exec.Command(filepath.Join(root, nodeName()), filepath.Join(root, "social-login", "src", "server.js"))
	cmd.Dir = filepath.Join(root, "social-login")
	// Allow only operating-system essentials. Inherited NODE_OPTIONS, helper and
	// solver configuration must not override the packaged lifecycle or identity.
	for _, key := range []string{"SystemRoot", "WINDIR", "TEMP", "TMP", "TMPDIR", "DISPLAY", "HOME", "USERPROFILE"} {
		if value := os.Getenv(key); value != "" {
			cmd.Env = append(cmd.Env, key+"="+value)
		}
	}
	cmd.Env = append(cmd.Env, "HOST=127.0.0.1", fmt.Sprintf("PORT=%d", port), "SOCIAL_LOGIN_BEARER_TOKEN="+bearer, "SOCIAL_LOGIN_MANAGED=1", "CAP_PROFILE_BASE="+profiles, "CAP_BROWSER_EXECUTABLE_PATH="+browser, "CAP_HEADLESS=false", "CAP_WEBGL_SPOOF=false", "SOCIAL_LOGIN_MAX_CONCURRENCY=1", "CAP_MAX_PROCESSES=4096", "CAP_NO_SANDBOX=false", "CAP_SHUTDOWN_GRACE_MS=5000", "SOCIAL_LOGIN_SHUTDOWN_TIMEOUT_MS=5000")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Endpoint{}, ErrUnavailable
	}
	configureProcess(cmd)
	if err = cmd.Start(); err != nil {
		stdin.Close()
		return Endpoint{}, fmt.Errorf("%w: helper could not start", ErrUnavailable)
	}
	cleanup, err := containProcess(cmd)
	if err != nil {
		stdin.Close()
		killProcess(cmd)
		_ = cmd.Wait()
		return Endpoint{}, fmt.Errorf("%w: helper process containment unavailable", ErrUnavailable)
	}
	m.lockFile = lock
	started = true
	m.cmd = cmd
	m.stdin = stdin
	m.done = make(chan struct{})
	done := m.done
	go func() { _ = cmd.Wait(); cleanup(); close(done) }()
	endpoint := Endpoint{URL: fmt.Sprintf("http://127.0.0.1:%d", port), Bearer: bearer}
	startup, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for {
		select {
		case <-m.done:
			m.stopLocked(context.Background())
			return Endpoint{}, fmt.Errorf("%w: helper exited before readiness", ErrUnavailable)
		case <-startup.Done():
			m.stopLocked(context.Background())
			return Endpoint{}, fmt.Errorf("%w: helper readiness cancelled or timed out", ErrUnavailable)
		default:
		}
		req, _ := http.NewRequestWithContext(startup, http.MethodGet, endpoint.URL+"/v1/ready", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		response, requestErr := client.Do(req)
		if requestErr == nil {
			var ready struct {
				Data struct {
					Status string `json:"status"`
				} `json:"data"`
			}
			readyErr := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&ready)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && readyErr == nil && ready.Data.Status == "ready" {
				capReq, _ := http.NewRequestWithContext(startup, http.MethodGet, endpoint.URL+"/v1/capabilities", nil)
				capReq.Header.Set("Authorization", "Bearer "+bearer)
				capResponse, capErr := client.Do(capReq)
				if capErr == nil {
					var capabilities struct {
						Data struct {
							InteractiveX int `json:"interactive_x"`
						} `json:"data"`
					}
					decodeErr := json.NewDecoder(io.LimitReader(capResponse.Body, 4096)).Decode(&capabilities)
					capResponse.Body.Close()
					if capResponse.StatusCode == http.StatusOK && decodeErr == nil && capabilities.Data.InteractiveX == 1 {
						m.endpoint = endpoint
						return endpoint, nil
					}
				}
			}
		}
		select {
		case <-startup.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
}
func (m *Manager) stopLocked(ctx context.Context) error {
	if m.cmd == nil {
		return nil
	}
	if m.stdin != nil {
		m.stdin.Close()
	}
	timeout, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	select {
	case <-m.done:
	case <-timeout.Done():
		killProcess(m.cmd)
		select {
		case <-m.done:
		case <-time.After(2 * time.Second):
			return fmt.Errorf("%w: helper shutdown did not complete", ErrUnavailable)
		}
	}
	m.cmd = nil
	m.stdin = nil
	m.endpoint = Endpoint{}
	if m.lockFile != nil {
		m.lockFile.Close()
		m.lockFile = nil
	}
	return nil
}
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked(ctx)
}
