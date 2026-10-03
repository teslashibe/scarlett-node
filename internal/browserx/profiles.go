package browserx

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode"
)

// Paths remain in the local helper. Listing reads directory/file metadata only,
// never a browser cookie, account identity, Local State or Keychain item.
type Profile struct {
	ID      string `json:"id"`
	Browser string `json:"browser"`
	Label   string `json:"label"`
	path    string
}

func Profiles() ([]Profile, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return nil, Protected
	}
	roots := map[string]string{}
	switch runtime.GOOS {
	case "darwin":
		roots["chrome"] = filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
		roots["firefox"] = filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
		roots["safari"] = filepath.Join(home, "Library", "Containers", "com.apple.Safari", "Data", "Library", "Cookies")
		roots["safari-legacy"] = filepath.Join(home, "Library", "Cookies")
	case "windows":
		local, roaming := os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA")
		if !filepath.IsAbs(local) {
			local = filepath.Join(home, "AppData", "Local")
		}
		if !filepath.IsAbs(roaming) {
			roaming = filepath.Join(home, "AppData", "Roaming")
		}
		roots["chrome"] = filepath.Join(local, "Google", "Chrome", "User Data")
		roots["firefox"] = filepath.Join(roaming, "Mozilla", "Firefox", "Profiles")
	default:
		roots["firefox"] = filepath.Join(home, ".mozilla", "firefox")
	}
	return discover(roots), nil
}

func discover(roots map[string]string) []Profile {
	out := []Profile{}
	add := func(browser, label, path string) {
		if len(out) >= 48 {
			return
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return
		}
		digest := sha256.Sum256([]byte(browser + "\x00" + filepath.Clean(path)))
		out = append(out, Profile{ID: browser + "_" + hex.EncodeToString(digest[:16]), Browser: browser, Label: label, path: path})
	}
	for _, browser := range []string{"chrome", "firefox", "safari", "safari-legacy"} {
		root := roots[browser]
		if root == "" {
			continue
		}
		if browser == "safari" || browser == "safari-legacy" {
			label := "Safari / Default"
			if browser == "safari-legacy" {
				label = "Safari / Legacy"
			}
			add("safari", label, filepath.Join(root, "Cookies.binarycookies"))
			continue
		}
		dir, err := os.Open(root)
		if err != nil {
			continue
		}
		entries, _ := dir.ReadDir(256)
		dir.Close()
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			name := entry.Name()
			if !entry.IsDir() || len(name) > 80 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
				continue
			}
			if browser == "chrome" && name != "Default" && !strings.HasPrefix(name, "Profile ") {
				continue
			}
			path := filepath.Join(root, name, "cookies.sqlite")
			label := "Firefox / " + name
			if browser == "chrome" {
				label = "Chrome / " + name
				path = filepath.Join(root, name, "Network", "Cookies")
				if _, err := os.Lstat(path); os.IsNotExist(err) {
					path = filepath.Join(root, name, "Cookies")
				}
			}
			add(browser, label, path)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Label < out[j].Label || out[i].Label == out[j].Label && out[i].ID < out[j].ID
	})
	return out
}

func Resolve(id string) (string, string, error) {
	if len(id) > 64 {
		return "", "", Invalid
	}
	profiles, err := Profiles()
	if err != nil {
		return "", "", err
	}
	for _, p := range profiles {
		if p.ID == id {
			return p.Browser, p.path, nil
		}
	}
	return "", "", Missing
}
