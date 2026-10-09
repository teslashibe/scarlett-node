//go:build rehearsal

package update

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// A rehearsal build (go build -tags rehearsal: PR CI and local end-to-end
// tests only, never a release) replaces every pin with a throwaway trust file
// named by SCARLETT_UPDATER_REHEARSAL_TRUST while SCARLETT_SIGNING_REHEARSAL=1.
func rehearsalTrust() (Trust, bool, error) {
	if os.Getenv("SCARLETT_SIGNING_REHEARSAL") != "1" {
		return Trust{}, false, nil
	}
	path := os.Getenv("SCARLETT_UPDATER_REHEARSAL_TRUST")
	if !filepath.IsAbs(path) {
		return Trust{}, true, errors.New("rehearsal trust requires an absolute SCARLETT_UPDATER_REHEARSAL_TRUST")
	}
	f, err := os.Open(path)
	if err != nil {
		return Trust{}, true, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return Trust{}, true, errors.New("invalid rehearsal trust")
	}
	var file struct {
		Minisign []string `json:"minisign"`
		MacOS    struct {
			SHA1   string `json:"sha1"`
			SHA256 string `json:"sha256"`
		} `json:"macos"`
		Windows struct {
			SHA256 string `json:"sha256"`
		} `json:"windows"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&file); err != nil {
		return Trust{}, true, errors.New("invalid rehearsal trust")
	}
	t, err := newTrust(file.Minisign, file.MacOS.SHA1, file.MacOS.SHA256, file.Windows.SHA256)
	t.Rehearsal = true
	return t, true, err
}
