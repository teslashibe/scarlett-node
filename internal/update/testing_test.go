package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

// testKey is a throwaway minisign key that signs like `tauri signer sign`.
type testKey struct {
	id   [8]byte
	priv ed25519.PrivateKey
	pub  PublicKey
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var k testKey
	_, _ = rand.Read(k.id[:])
	k.priv = priv
	k.pub = PublicKey{ID: k.id, Key: pub}
	return k
}

// line is the bare minisign public key line ("RWQ...").
func (k testKey) line() string {
	return base64.StdEncoding.EncodeToString(append(append([]byte("Ed"), k.id[:]...), k.pub.Key...))
}

func (k testKey) signComment(data []byte, comment string) string {
	h := NewPrehash()
	h.Write(data)
	sig := ed25519.Sign(k.priv, h.Sum(nil))
	global := ed25519.Sign(k.priv, append(append([]byte{}, sig...), comment...))
	text := fmt.Sprintf("untrusted comment: signature from tauri secret key\n%s\ntrusted comment: %s\n%s\n",
		base64.StdEncoding.EncodeToString(append(append([]byte("ED"), k.id[:]...), sig...)), comment, base64.StdEncoding.EncodeToString(global))
	return base64.StdEncoding.EncodeToString([]byte(text))
}

func (k testKey) sign(data []byte, file, version string) string {
	return k.signComment(data, "timestamp:1791480419\tfile:"+file+"\tversion:"+version)
}

func sum(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}
