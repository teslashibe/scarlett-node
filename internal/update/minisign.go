package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Minisign signatures in the format `tauri signer sign` writes: base64 of the
// minisign signature file. Only prehashed (BLAKE2b-512, "ED") signatures are
// accepted; the trusted comment must be exactly
// "timestamp:<n>\tfile:<name>\tversion:<v>", which binds the signature to one
// file name and one release version.

var (
	errKey       = errors.New("invalid minisign public key")
	errSignature = errors.New("invalid minisign signature")
)

// PublicKey is one Ed25519 minisign key.
type PublicKey struct {
	ID  [8]byte
	Key ed25519.PublicKey
}

// KeyID is minisign's display form: the key number as a little-endian
// integer in uppercase hex.
func (k PublicKey) KeyID() string {
	var id [8]byte
	for i := range id {
		id[i] = k.ID[7-i]
	}
	return strings.ToUpper(hex.EncodeToString(id[:]))
}

// ParsePublicKey accepts the bare minisign key line ("RWQ...") or the whole
// base64-wrapped public key file that `tauri signer generate` writes.
func ParsePublicKey(text string) (PublicKey, error) {
	text = strings.TrimSpace(text)
	if len(text) == 0 || len(text) > 1024 {
		return PublicKey{}, errKey
	}
	if raw, err := base64.StdEncoding.DecodeString(text); err == nil && len(raw) != 42 {
		lines := boxLines(string(raw))
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "untrusted comment: ") {
			return PublicKey{}, errKey
		}
		text = lines[1]
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil || len(raw) != 42 || raw[0] != 'E' || raw[1] != 'd' {
		return PublicKey{}, errKey
	}
	var key PublicKey
	copy(key.ID[:], raw[2:10])
	key.Key = ed25519.PublicKey(bytes.Clone(raw[10:]))
	return key, nil
}

// Signature is a decoded minisign signature.
type Signature struct {
	KeyNum  [8]byte
	Sig     []byte
	Trusted string
	Global  []byte
	File    string
	Version string
}

func boxLines(text string) []string {
	text = strings.TrimSuffix(text, "\n")
	if strings.ContainsRune(text, '\r') {
		return nil
	}
	return strings.Split(text, "\n")
}

// ParseSignature decodes a Tauri .sig value.
func ParseSignature(encoded string) (Signature, error) {
	var s Signature
	encoded = strings.TrimSpace(encoded)
	if len(encoded) == 0 || len(encoded) > 4096 {
		return s, errSignature
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return s, errSignature
	}
	lines := boxLines(string(raw))
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "untrusted comment: ") || !strings.HasPrefix(lines[2], "trusted comment: ") {
		return s, errSignature
	}
	sig, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(sig) != 74 || string(sig[:2]) != "ED" {
		return s, errSignature
	}
	global, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil || len(global) != ed25519.SignatureSize {
		return s, errSignature
	}
	copy(s.KeyNum[:], sig[2:10])
	s.Sig, s.Global = sig[10:], global
	s.Trusted = strings.TrimPrefix(lines[2], "trusted comment: ")
	fields := strings.Split(s.Trusted, "\t")
	if len(fields) != 3 || !strings.HasPrefix(fields[0], "timestamp:") || !strings.HasPrefix(fields[1], "file:") || !strings.HasPrefix(fields[2], "version:") {
		return s, errSignature
	}
	stamp := strings.TrimPrefix(fields[0], "timestamp:")
	if stamp == "" || len(stamp) > 20 || strings.Trim(stamp, "0123456789") != "" {
		return s, errSignature
	}
	s.File, s.Version = strings.TrimPrefix(fields[1], "file:"), strings.TrimPrefix(fields[2], "version:")
	if s.File == "" || s.Version == "" {
		return s, errSignature
	}
	return s, nil
}

// NewPrehash returns the BLAKE2b-512 hash a prehashed signature covers.
func NewPrehash() hash.Hash {
	h, _ := blake2b.New512(nil)
	return h
}

// Verify checks the signature over prehash (BLAKE2b-512 of the file) with the
// one trusted key whose ID it names, then the trusted comment's global
// signature, then that the comment names exactly file and version.
func (s Signature) Verify(keys []PublicKey, prehash []byte, file, version string) error {
	for _, key := range keys {
		if key.ID != s.KeyNum {
			continue
		}
		if len(prehash) != blake2b.Size || !ed25519.Verify(key.Key, prehash, s.Sig) {
			return errors.New("minisign signature does not match the file")
		}
		if !ed25519.Verify(key.Key, append(bytes.Clone(s.Sig), s.Trusted...), s.Global) {
			return errors.New("minisign trusted comment signature is invalid")
		}
		if s.File != file || s.Version != version {
			return errors.New("minisign signature belongs to another file or version")
		}
		return nil
	}
	return errors.New("minisign signature is not from a trusted key")
}
