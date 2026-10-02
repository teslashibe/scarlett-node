package coordinator

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoordinatorPrivateCATrustKeepsHostnameVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-node-credential" {
			t.Error("missing scoped credential")
		}
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewWithCA(server.URL, "synthetic-node-credential", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Post(context.Background(), "/test", struct{}{}, nil); err != nil {
		t.Fatal("configured CA not trusted", err)
	}
	plain := New(server.URL, "synthetic-node-credential")
	if _, err = plain.Post(context.Background(), "/test", struct{}{}, nil); err == nil {
		t.Fatal("untrusted self-signed coordinator accepted")
	}
	wrongHost, err := NewWithCA(strings.Replace(server.URL, "127.0.0.1", "localhost", 1), "synthetic-node-credential", bundle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongHost.Post(context.Background(), "/test", struct{}{}, nil); err == nil {
		t.Fatal("CA bundle disabled hostname verification")
	}
}

func TestCoordinatorCARejectsInvalidBundlesAndHTTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ origin, path string }{{"https://example.invalid", path}, {"http://127.0.0.1", path}, {"https://example.invalid", path + "-missing"}, {"https://example.invalid", filepath.Dir(path)}} {
		if _, err := NewWithCA(tc.origin, "", tc.path); err == nil {
			t.Fatal("invalid private CA configuration accepted")
		}
	}
}
