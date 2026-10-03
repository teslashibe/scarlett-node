// Package browserx imports only X session cookies from an explicitly selected
// local browser profile. It never returns credentials to the desktop renderer.
package browserx

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	Protected   Error = "browser_protected"
	Busy        Error = "browser_busy"
	Invalid     Error = "browser_invalid"
	Missing     Error = "browser_no_x_session"
	Ambiguous   Error = "browser_ambiguous"
	Unsupported Error = "browser_unsupported"
)

func Code(err error) string {
	var e Error
	if errors.As(err, &e) {
		return string(e)
	}
	return string(Invalid)
}

type session struct{ token, csrf string }
type selection map[string]session

func (s selection) add(group, name, value string) error {
	max := 64
	if name == "ct0" {
		max = 160
	} else if name != "auth_token" {
		return Invalid
	}
	if value == "" || len(value) > max {
		return Invalid
	}
	for _, c := range []byte(value) {
		if c < 33 || c > 126 || strings.ContainsRune(";=\\\"", rune(c)) {
			return Invalid
		}
	}
	pair := s[group]
	previous := pair.token
	if name == "ct0" {
		previous = pair.csrf
	}
	if previous != "" && previous != value {
		return Ambiguous
	}
	if name == "ct0" {
		pair.csrf = value
	} else {
		pair.token = value
	}
	s[group] = pair
	return nil
}

func (s selection) encode() ([]byte, error) {
	var found session
	for _, pair := range s {
		if pair.token == "" || pair.csrf == "" {
			continue
		}
		if found.token != "" && found != pair {
			return nil, Ambiguous
		}
		found = pair
	}
	if found.token == "" {
		return nil, Missing
	}
	return json.Marshal(map[string]string{"auth_token": found.token, "ct0": found.csrf})
}

func domain(raw string) string {
	switch strings.ToLower(raw) {
	case "x.com", ".x.com":
		return "x.com"
	case "twitter.com", ".twitter.com":
		return "twitter.com"
	}
	return ""
}

func cookieName(name string) bool { return name == "auth_token" || name == "ct0" }

// ReadSession returns credential JSON solely for the private account writer.
// All errors are fixed codes, never paths, cookie values or OS command output.
func ReadSession(ctx context.Context, browser, path string) (raw []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	name := "Cookies"
	switch browser {
	case "chrome":
		if runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
			return nil, Unsupported
		}
	case "firefox":
		name = "cookies.sqlite"
	case "safari":
		if runtime.GOOS != "darwin" {
			return nil, Unsupported
		}
		name = "Cookies.binarycookies"
	default:
		return nil, Unsupported
	}
	if filepath.Base(path) != name {
		return nil, Invalid
	}
	f, before, err := openStore(path, 64<<20)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	selected := selection{}
	if browser == "safari" {
		err = readSafari(ctx, f, before.Size(), selected)
	} else {
		err = readSQLite(ctx, browser, path, selected)
	}
	if err != nil {
		return nil, err
	}
	after, e := os.Stat(path)
	if e != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, Busy
	}
	if browser != "safari" {
		if err = checkJournals(path); err != nil {
			return nil, err
		}
	}
	return selected.encode()
}

func openStore(path string, limit int64) (*os.File, os.FileInfo, error) {
	if len(path) > 4096 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, Invalid
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || pathProtected(p) {
			return nil, nil, Protected
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < 8 || info.Size() > limit {
		return nil, nil, Invalid
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, Protected
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		f.Close()
		return nil, nil, Protected
	}
	return f, opened, nil
}

func checkJournals(path string) error {
	// Immutable SQLite reads never create or update browser files. A populated
	// journal means that snapshot may be stale: ask the operator to close the
	// selected browser, rather than silently ignoring its committed WAL data.
	for _, suffix := range []string{"-wal", "-journal"} {
		info, err := os.Lstat(path + suffix)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
			return Busy
		}
	}
	return nil
}
