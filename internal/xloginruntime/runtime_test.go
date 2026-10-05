package xloginruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A local subprocess fixture stands in for Node; no Chrome or provider calls.
func init() {
	if len(os.Args) != 2 || filepath.Base(os.Args[1]) != "server.js" {
		return
	}
	raw, _ := os.ReadFile(os.Args[1])
	if string(raw) != "synthetic-local-runtime" {
		return
	}
	listener, err := net.Listen("tcp4", os.Getenv("HOST")+":"+os.Getenv("PORT"))
	if err != nil {
		os.Exit(3)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/ready" {
			io.WriteString(w, `{"data":{"status":"ready"}}`)
			return
		}
		if r.URL.Path == "/v1/health" {
			w.WriteHeader(200)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+os.Getenv("SOCIAL_LOGIN_BEARER_TOKEN") {
			w.WriteHeader(401)
			return
		}
		if os.Getenv("NODE_OPTIONS") != "" || os.Getenv("CAP_HEADLESS") != "false" {
			w.WriteHeader(500)
			return
		}
		if r.URL.Path == "/v1/capabilities" {
			io.WriteString(w, `{"data":{"interactive_x":1}}`)
			return
		}
		w.WriteHeader(200)
	})}
	go func() { _, _ = io.Copy(io.Discard, os.Stdin); _ = server.Close() }()
	_ = server.Serve(listener)
	os.Exit(0)
}
func fixture(t *testing.T) (Config, string) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "resources", "x-login-runtime")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{nodeName(): binary, "social-login/src/server.js": []byte("synthetic-local-runtime"), "social-login/node_modules/playwright/package.json": []byte("{}"), "social-login/UPSTREAM.json": []byte("{}")}
	manifest := Manifest{SchemaVersion: 1, Platform: runtime.GOOS + "-" + runtime.GOARCH, NodeVersion: "22.23.3"}
	for path, data := range files {
		file := filepath.Join(root, filepath.FromSlash(path))
		if err = os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(file, data, 0700); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(data)
		manifest.Files = append(manifest.Files, Resource{Path: path, SHA256: hex.EncodeToString(hash[:])})
	}
	raw, _ := json.Marshal(manifest)
	if err = os.WriteFile(filepath.Join(root, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return Config{ResourceDir: filepath.Dir(root), StateDir: filepath.Join(dir, "state"), BrowserPath: executable}, root
}
func TestManagedLifecycleAndPrivateIdentity(t *testing.T) {
	config, _ := fixture(t)
	t.Setenv("NODE_OPTIONS", "untrusted-runtime-override")
	manager := New(config)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint, err := manager.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	if !strings.HasPrefix(endpoint.URL, "http://127.0.0.1:") || len(endpoint.Bearer) != 64 {
		t.Fatal("invalid loopback identity")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", endpoint, endpoint), endpoint.Bearer) {
		t.Fatal("endpoint formatting leaked bearer")
	}
	req, _ := http.NewRequest(http.MethodGet, endpoint.URL+"/private", nil)
	client := &http.Client{Timeout: time.Second}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("helper did not require bearer")
	}
	req.Header.Set("Authorization", "Bearer "+endpoint.Bearer)
	response, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("private request or sanitized environment failed")
	}
	if _, err := New(config).Start(ctx); err == nil {
		t.Fatal("second helper accepted same installation")
	}
	if again, err := manager.Start(ctx); err != nil || again != endpoint {
		t.Fatal("idempotent start failed")
	}
	if err = manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()
	if _, err = client.Get(endpoint.URL + "/v1/health"); err == nil {
		t.Fatal("helper survived shutdown")
	}
	next, err := manager.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if next.Bearer != endpoint.Bearer {
		t.Fatal("restart changed per-install identity")
	}
	if err = manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{config.StateDir + "/x-browser", config.StateDir + "/x-browser/profiles", config.StateDir + "/x-browser/bearer"} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm()&0077 != 0 {
				t.Fatal("state readable by another user")
			}
		}
	}
}
func TestInventoryAndPrerequisitesFailClosed(t *testing.T) {
	config, root := fixture(t)
	if err := Verify(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "social-login", "src", "server.js")
	if err := os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Verify(root); err == nil {
		t.Fatal("tampered source accepted")
	}
	os.WriteFile(path, []byte("synthetic-local-runtime"), 0600)
	os.WriteFile(filepath.Join(root, "extra"), []byte("unlisted"), 0600)
	if err := Verify(root); err == nil {
		t.Fatal("unlisted resource accepted")
	}
	os.Remove(filepath.Join(root, "extra"))
	config.BrowserPath = filepath.Join(t.TempDir(), "missing-chrome")
	if _, err := New(config).Start(context.Background()); err == nil {
		t.Fatal("missing browser accepted")
	}
}
func TestStartupCancellationReapsHelper(t *testing.T) {
	config, _ := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manager := New(config)
	if _, err := manager.Start(ctx); err == nil {
		t.Fatal("cancelled startup accepted")
	}
	if manager.cmd != nil {
		t.Fatal("cancelled helper retained")
	}
}

// Explicit local release smoke: starts the pinned helper and verifies its HTTP
// contract without launching Chrome or making any provider requests.
func TestPackagedRuntimeLoopbackOptIn(t *testing.T) {
	resources := os.Getenv("SCARLETT_TEST_X_LOGIN_RESOURCES")
	if resources == "" {
		t.Skip("set fixed packaged resource path for native helper smoke")
	}
	manager := New(Config{ResourceDir: resources, StateDir: filepath.Join(t.TempDir(), "state"), BrowserPath: os.Getenv("SCARLETT_TEST_X_LOGIN_BROWSER")})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	endpoint, err := manager.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close(context.Background())
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get(endpoint.URL + "/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("unauthenticated private route status %d", response.StatusCode)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL+"/v1/health", nil)
	req.Header.Set("Authorization", "Bearer "+endpoint.Bearer)
	response, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("packaged helper not healthy")
	}
	if err = manager.Close(ctx); err != nil {
		t.Fatal(err)
	}
	client.CloseIdleConnections()
	if _, err = client.Get(endpoint.URL + "/v1/health"); err == nil {
		t.Fatal("packaged helper survived shutdown")
	}
}

// Container packaging smoke uses a synthetic Docker secret, private-file rules
// and the real companion API. It performs capability reads only.
func TestExternalEndpointPrivateBearerOptIn(t *testing.T) {
	endpoint := os.Getenv("SCARLETT_TEST_X_LOGIN_EXTERNAL_URL")
	if endpoint == "" {
		t.Skip("set local synthetic companion endpoint for container packaging smoke")
	}
	file, err := localfs.OpenPrivate(os.Getenv("SCARLETT_X_LOGIN_BEARER_FILE"))
	if err != nil {
		t.Fatal("container private bearer inaccessible")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4096))
	if err != nil || len(raw) < 32 {
		t.Fatal("container private bearer invalid")
	}
	request, _ := http.NewRequest(http.MethodGet, endpoint+"/v1/capabilities", nil)
	request.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(raw)))
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal("companion unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("companion capability status %d", response.StatusCode)
	}
	var capabilities struct {
		Data struct {
			InteractiveX int `json:"interactive_x"`
		} `json:"data"`
	}
	if json.NewDecoder(response.Body).Decode(&capabilities) != nil || capabilities.Data.InteractiveX != 1 {
		t.Fatal("interactive companion capability unavailable")
	}
}
