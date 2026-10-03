package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// Preferences never contain account credentials or execution admission settings.
type desktopPreferences struct {
	Schema       int  `json:"schema"`
	LocalAPIPort int  `json:"local_api_port"`
	Background   bool `json:"background"`
}

func (p desktopPreferences) valid() bool {
	return p.Schema == 1 && p.LocalAPIPort >= 1024 && p.LocalAPIPort <= 65535
}

func desktopPreferencesCommand(action, path string, input io.Reader, out io.Writer) error {
	fail := errors.New("desktop preferences unavailable")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "preferences.json" || localfs.CheckDir(filepath.Dir(path)) != nil {
		return fail
	}
	lock, err := localfs.LockPrivate(path + ".lock")
	if err != nil {
		return fail
	}
	defer lock.Close()
	p := desktopPreferences{Schema: 1, LocalAPIPort: 8088}
	switch action {
	case "preferences-get":
		f, err := localfs.OpenPrivate(path)
		if err == nil {
			defer f.Close()
			if !decodeDesktopPreferences(f, &p) {
				return fail
			}
		} else if !os.IsNotExist(err) {
			return fail
		}
	case "preferences-set":
		if input == nil || !decodeDesktopPreferences(input, &p) {
			return fail
		}
		raw, err := json.Marshal(p)
		if err != nil || localfs.WriteAtomic(path, raw, true) != nil {
			return fail
		}
	default:
		return fail
	}
	return json.NewEncoder(out).Encode(p)
}

func decodeDesktopPreferences(input io.Reader, p *desktopPreferences) bool {
	raw, err := io.ReadAll(io.LimitReader(input, 1025))
	if err != nil || len(raw) > 1024 {
		return false
	}
	*p = desktopPreferences{}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(p) == nil && p.valid() && d.Decode(&struct{}{}) == io.EOF
}
