package webruntime

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// cleanRel reports whether p is a relative, slash-separated path that stays
// inside its root: no empty, "." or ".." part, no backslash, colon or NUL.
func cleanRel(p string) bool {
	if p == "" || len(p) > 1024 || strings.ContainsAny(p, "\\:\x00") || path.IsAbs(p) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func hex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// privateDir creates path and any missing parents as private directories, or
// checks an existing one, as xloginruntime does.
func privateDir(p string) error {
	if _, err := os.Lstat(p); err == nil {
		return localfs.CheckDir(p)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := privateDir(filepath.Dir(p)); err != nil {
		return err
	}
	if err := localfs.CreateDir(p); err != nil && !os.IsExist(err) {
		return err
	}
	return localfs.CheckDir(p)
}

// stateDir checks or creates the node state directory itself.
func stateDir(p string) error {
	if !filepath.IsAbs(p) {
		return errors.New("state directory must be absolute")
	}
	if _, err := os.Lstat(p); os.IsNotExist(err) {
		return localfs.EnsureDir(p)
	} else if err != nil {
		return err
	}
	return localfs.CheckDir(p)
}

// removeTree deletes a tree written read-only by this package. Directories
// and files are made writable first (Windows refuses to delete read-only
// files); symlinks are removed, never followed.
func removeTree(p string) error {
	_ = filepath.WalkDir(p, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			_ = os.Chmod(name, 0o700)
		} else {
			_ = os.Chmod(name, 0o600)
		}
		return nil
	})
	return os.RemoveAll(p)
}

// wipeDir empties and recreates a private directory.
func wipeDir(p string) error {
	if err := removeTree(p); err != nil {
		return err
	}
	return privateDir(p)
}

func token(p string) (string, error) {
	f, err := localfs.OpenPrivate(p)
	if os.IsNotExist(err) {
		raw := make([]byte, 32)
		if _, err = rand.Read(raw); err != nil {
			return "", err
		}
		if err = localfs.WriteAtomic(p, []byte(hex.EncodeToString(raw)), false); err != nil && !os.IsExist(err) {
			return "", err
		}
		f, err = localfs.OpenPrivate(p)
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 65))
	if err != nil || len(raw) != 64 || !hex64(string(raw)) {
		return "", errors.New("bearer file invalid")
	}
	return string(raw), nil
}

func fileSHA256(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// randomHex is n random bytes as lowercase hex.
func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
