package update

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// releaseServer serves one manifest and its files like the download host.
func releaseServer(t *testing.T, manifest []byte, files map[string][]byte) (*Client, *atomic.Int64) {
	t.Helper()
	var ranged atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/downloads/manifest.json" {
			w.Write(manifest)
			return
		}
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://evil.example/", http.StatusFound)
			return
		}
		name := filepath.Base(r.URL.Path)
		data, ok := files[name]
		if !ok || r.URL.Path != "/downloads/v"+strings.Split(strings.TrimPrefix(r.URL.Path, "/downloads/v"), "/")[0]+"/"+name {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Range") != "" {
			ranged.Add(1)
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	}))
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	return client, &ranged
}

func TestDownloadResumesAndVerifiesBeforeTheFinalName(t *testing.T) {
	k := newTestKey(t)
	data := bytes.Repeat([]byte("scarlett"), 100000)
	name := HeadlessFilename("0.1.13", "linux-amd64")
	manifest := encode(t, manifestFixture(t, k, "0.1.13", map[string][]byte{name: data}))
	client, ranged := releaseServer(t, manifest, map[string][]byte{name: data})
	m, err := client.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	target, err := m.Headless("linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// A partial download from an interrupted run resumes with Range.
	if err = os.WriteFile(filepath.Join(dir, name+".part"), data[:12345], 0o600); err != nil {
		t.Fatal(err)
	}
	var seen int64
	path, err := client.Download(context.Background(), target, dir, []PublicKey{k.pub}, true, DownloadOptions{Progress: func(received, total int64) { seen = received }})
	if err != nil {
		t.Fatal(err)
	}
	if ranged.Load() != 1 || seen != int64(len(data)) || path != filepath.Join(dir, name) {
		t.Fatalf("resume %d progress %d path %s", ranged.Load(), seen, path)
	}
	if _, err = os.Stat(path + ".part"); !os.IsNotExist(err) {
		t.Fatal("partial file left behind")
	}
	// A second call reuses the verified file.
	if again, err := client.Download(context.Background(), target, dir, []PublicKey{k.pub}, true, DownloadOptions{}); err != nil || again != path {
		t.Fatal("verified file was not reused")
	}
}

func TestDownloadRefusesWrongBytesKeysAndRedirects(t *testing.T) {
	k := newTestKey(t)
	data := []byte("the real bundle")
	name := HeadlessFilename("0.1.13", "linux-amd64")
	manifest := encode(t, manifestFixture(t, k, "0.1.13", map[string][]byte{name: data}))
	client, _ := releaseServer(t, manifest, map[string][]byte{name: []byte("the evil bundle")})
	m, _ := client.Manifest(context.Background())
	target, _ := m.Headless("linux-amd64")
	dir := t.TempDir()
	_, err := client.Download(context.Background(), target, dir, []PublicKey{k.pub}, true, DownloadOptions{})
	if CodeOf(err) != CodeSignatureInvalid {
		t.Fatalf("changed bytes: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatal("unverified file took its final name")
	}
	// Right bytes, but a key this build does not trust.
	client, _ = releaseServer(t, manifest, map[string][]byte{name: data})
	other := newTestKey(t)
	if _, err = client.Download(context.Background(), target, t.TempDir(), []PublicKey{other.pub}, true, DownloadOptions{}); CodeOf(err) != CodeSignatureInvalid {
		t.Fatalf("untrusted key: %v", err)
	}
	if _, err = client.Download(context.Background(), target, t.TempDir(), nil, true, DownloadOptions{}); CodeOf(err) != CodeNoKey {
		t.Fatalf("no key: %v", err)
	}
	if _, err = client.get(context.Background(), "/redirect", nil); err != nil {
		t.Fatal(err)
	}
	if _, err = client.manifest(context.Background(), "/redirect"); err == nil {
		t.Fatal("redirect followed")
	}
	for _, origin := range []string{"http://network.scarlett.ai", "https://network.scarlett.ai/downloads", "https://user@network.scarlett.ai", "https://network.scarlett.ai?x=1"} {
		if _, err := NewClient(origin, ""); err == nil {
			t.Errorf("%s accepted", origin)
		}
	}
}

func TestRateLimitedDownloadIsPaced(t *testing.T) {
	k := newTestKey(t)
	data := bytes.Repeat([]byte{1}, 300<<10)
	name := HeadlessFilename("0.1.13", "linux-amd64")
	client, _ := releaseServer(t, encode(t, manifestFixture(t, k, "0.1.13", map[string][]byte{name: data})), map[string][]byte{name: data})
	m, _ := client.Manifest(context.Background())
	target, _ := m.Headless("linux-amd64")
	started := time.Now()
	if _, err := client.Download(context.Background(), target, t.TempDir(), []PublicKey{k.pub}, true, DownloadOptions{RateLimit: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 200*time.Millisecond {
		t.Fatal("rate limit not applied")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Download(ctx, target, t.TempDir(), []PublicKey{k.pub}, true, DownloadOptions{}); err == nil || !errors.Is(err, context.Canceled) && CodeOf(err) != CodeNetwork {
		t.Fatalf("cancelled download: %v", err)
	}
}
