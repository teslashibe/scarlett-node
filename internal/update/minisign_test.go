package update

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// The vector was produced by the pinned @tauri-apps/cli 2.12.1:
// `tauri signer generate` then `tauri signer sign --app-version 0.1.13`.
func TestTauriSignerVectorVerifies(t *testing.T) {
	data, _ := os.ReadFile("testdata/tauri-vector.bin")
	sig, _ := os.ReadFile("testdata/tauri-vector.bin.sig")
	pub, _ := os.ReadFile("testdata/tauri-vector.key.pub")
	key, err := ParsePublicKey(string(pub))
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyID() != "00935881B7A69521" {
		t.Fatalf("key id %s", key.KeyID())
	}
	s, err := ParseSignature(string(sig))
	if err != nil {
		t.Fatal(err)
	}
	h := NewPrehash()
	h.Write(data)
	if err = s.Verify([]PublicKey{key}, h.Sum(nil), "Scarlett-Node-0.1.13-darwin-arm64.dmg", "0.1.13"); err != nil {
		t.Fatal(err)
	}
	// The same signature cannot vouch for another file name or version.
	for _, c := range [][2]string{{"Scarlett-Node-0.1.13-darwin-amd64.dmg", "0.1.13"}, {"Scarlett-Node-0.1.13-darwin-arm64.dmg", "0.1.14"}} {
		if s.Verify([]PublicKey{key}, h.Sum(nil), c[0], c[1]) == nil {
			t.Fatalf("signature accepted for %v", c)
		}
	}
	tampered := NewPrehash()
	tampered.Write(append(data, 'x'))
	if s.Verify([]PublicKey{key}, tampered.Sum(nil), "Scarlett-Node-0.1.13-darwin-arm64.dmg", "0.1.13") == nil {
		t.Fatal("changed bytes verified")
	}
	other := newTestKey(t)
	if s.Verify([]PublicKey{other.pub}, h.Sum(nil), "Scarlett-Node-0.1.13-darwin-arm64.dmg", "0.1.13") == nil {
		t.Fatal("untrusted key accepted")
	}
	if s.Verify(nil, h.Sum(nil), "Scarlett-Node-0.1.13-darwin-arm64.dmg", "0.1.13") == nil {
		t.Fatal("no trusted keys accepted a signature")
	}
	// The bare key line parses to the same key.
	raw, _ := base64.StdEncoding.DecodeString(string(pub))
	line := strings.Split(string(raw), "\n")[1]
	if k2, err := ParsePublicKey(line); err != nil || k2.ID != key.ID || !k2.Key.Equal(key.Key) {
		t.Fatal("bare key line did not parse")
	}
}

func TestSignatureRejectsForgedCommentsAndLegacyFormat(t *testing.T) {
	k := newTestKey(t)
	data := []byte("bundle")
	h := NewPrehash()
	h.Write(data)
	good := k.sign(data, "a.tar.gz", "1.0.0")
	s, err := ParseSignature(good)
	if err != nil || s.Verify([]PublicKey{k.pub}, h.Sum(nil), "a.tar.gz", "1.0.0") != nil {
		t.Fatal("valid signature refused", err)
	}
	// Replace the trusted comment without re-signing it.
	raw, _ := base64.StdEncoding.DecodeString(good)
	forged := strings.Replace(string(raw), "version:1.0.0", "version:9.0.0", 1)
	s, err = ParseSignature(base64.StdEncoding.EncodeToString([]byte(forged)))
	if err != nil || s.Verify([]PublicKey{k.pub}, h.Sum(nil), "a.tar.gz", "9.0.0") == nil {
		t.Fatal("forged trusted comment accepted")
	}
	lines := strings.Split(string(raw), "\n")
	box, _ := base64.StdEncoding.DecodeString(lines[1])
	box[1] = 'd' // "Ed": a legacy signature over the whole file, not its BLAKE2b hash
	lines[1] = base64.StdEncoding.EncodeToString(box)
	if _, err = ParseSignature(base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))); err == nil {
		t.Fatal("non-prehashed signature accepted")
	}
	for _, comment := range []string{"timestamp:1\tfile:a.tar.gz", "file:a.tar.gz\tversion:1.0.0", "timestamp:x\tfile:a\tversion:1", "timestamp:1\tfile:a\tversion:1\textra:1"} {
		if _, err = ParseSignature(k.signComment(data, comment)); err == nil {
			t.Fatalf("comment %q accepted", comment)
		}
	}
	for _, bad := range []string{"", "!!", base64.StdEncoding.EncodeToString([]byte("untrusted comment: x\n")), strings.Repeat("A", 5000)} {
		if _, err = ParseSignature(bad); err == nil {
			t.Fatalf("%q parsed", bad)
		}
	}
	for _, bad := range []string{"", "RWQ", base64.StdEncoding.EncodeToString(make([]byte, 42))} {
		if _, err = ParsePublicKey(bad); err == nil {
			t.Fatalf("public key %q parsed", bad)
		}
	}
}
