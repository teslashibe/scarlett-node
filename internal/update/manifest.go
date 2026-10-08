package update

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"unicode"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// The download manifest (https://network.scarlett.ai/downloads/manifest.json,
// schemaVersion 1). Only the fields the updater uses are read; the publisher
// validates the rest. Every URL is derived from the version and a fixed file
// name, so a manifest can never point a client at another path or origin.

const (
	// MaxManifestBytes bounds the manifest read; the publisher allows 16 KiB.
	MaxManifestBytes = 64 << 10
	// MaxArtifactBytes bounds any download.
	MaxArtifactBytes = 1 << 30
	// ChangelogURL is the public node changelog; entries are #v<version>.
	ChangelogURL = "https://network.scarlett.ai/changelog/"
	releaseURL   = "https://github.com/teslashibe/scarlett-node/releases/tag/v"
)

// Desktop and headless platforms this updater knows.
var (
	desktopExtensions = map[string]string{"darwin-arm64": ".dmg", "darwin-amd64": ".dmg", "windows-amd64": ".exe"}
	headlessPlatforms = map[string]bool{"linux-amd64": true, "darwin-arm64": true, "darwin-amd64": true}
	sha256Hex         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	keyIDHex          = regexp.MustCompile(`^[0-9A-F]{16}$`)
	isoDate           = regexp.MustCompile(`^20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$`)
)

// Platform is this process's platform name, such as darwin-arm64.
func Platform() string {
	return runtime.GOOS + "-" + runtime.GOARCH
}

// Notes are one release's short public notes.
type Notes struct {
	Title      string   `json:"title"`
	Date       string   `json:"date"`
	Highlights []string `json:"highlights"`
	Changelog  string   `json:"changelog"`
	Release    string   `json:"release"`
}

// ChangelogFor is the public changelog entry for a version.
func ChangelogFor(version string) string { return ChangelogURL + "#v" + version }

// ReleaseFor is the GitHub release page for a version.
func ReleaseFor(version string) string { return releaseURL + version }

func plainText(s string, max int) bool {
	if s == "" || len(s) > max || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '<' || r == '>' || r == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

// Valid reports whether notes follow release-notes/README.md for version.
func (n *Notes) Valid(version string) bool {
	if n == nil || !plainText(n.Title, 80) || !isoDate.MatchString(n.Date) || len(n.Highlights) < 1 || len(n.Highlights) > 3 {
		return false
	}
	for _, h := range n.Highlights {
		if !plainText(h, 160) {
			return false
		}
	}
	return n.Changelog == ChangelogFor(version) && n.Release == ReleaseFor(version)
}

// Target is one verified-to-be artifact to download.
type Target struct {
	Version   string `json:"version"`
	Platform  string `json:"platform"`
	Kind      string `json:"kind"` // desktop or headless
	Filename  string `json:"filename"`
	Path      string `json:"path"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Signature string `json:"-"`
}

// Manifest is the validated subset of the download manifest.
type Manifest struct {
	Version string
	Notes   *Notes
	// KeyID names the primary signing key, when the release carries updates.
	KeyID    string
	desktop  map[string]Target
	headless map[string]Target
	// installers are the published desktop installers, signed or not.
	installers map[string]Target
}

type rawManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Version       string `json:"version"`
	Artifacts     []struct {
		Platform string `json:"platform"`
		Filename string `json:"filename"`
		Path     string `json:"path"`
		Bytes    int64  `json:"bytes"`
		SHA256   string `json:"sha256"`
	} `json:"artifacts"`
	Notes   *Notes `json:"notes"`
	Updates *struct {
		SchemaVersion int    `json:"schemaVersion"`
		KeyID         string `json:"keyId"`
		Desktop       map[string]struct {
			Filename  string `json:"filename"`
			Signature string `json:"signature"`
		} `json:"desktop"`
		Headless map[string]struct {
			Filename  string `json:"filename"`
			Path      string `json:"path"`
			Bytes     int64  `json:"bytes"`
			SHA256    string `json:"sha256"`
			Signature string `json:"signature"`
		} `json:"headless"`
	} `json:"updates"`
}

// DesktopFilename is the published installer name for a version and platform.
func DesktopFilename(version, platform string) string {
	return "Scarlett-Node-" + version + "-" + platform + desktopExtensions[platform]
}

// HeadlessFilename is the published bundle name for a version and platform.
func HeadlessFilename(version, platform string) string {
	return "scarlett-node-" + version + "-" + platform + ".tar.gz"
}

func versionedPath(version, filename string) string {
	return "/downloads/v" + version + "/" + filename
}

func validFile(t Target) bool {
	return t.Bytes > 0 && t.Bytes <= MaxArtifactBytes && sha256Hex.MatchString(t.SHA256) && t.Path == versionedPath(t.Version, t.Filename)
}

// ParseManifest validates the fields the updater relies on. Notes that break
// the rules are dropped rather than failing the release.
func ParseManifest(raw []byte) (*Manifest, error) {
	if len(raw) > MaxManifestBytes {
		return nil, errors.New("manifest too large")
	}
	var m rawManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errors.New("invalid manifest")
	}
	if m.SchemaVersion != 1 || !coordinator.ValidVersion(m.Version) || len(m.Artifacts) > 3 {
		return nil, errors.New("unsupported manifest")
	}
	out := &Manifest{Version: m.Version, desktop: map[string]Target{}, headless: map[string]Target{}, installers: map[string]Target{}}
	if m.Notes.Valid(m.Version) {
		out.Notes = m.Notes
	}
	for _, a := range m.Artifacts {
		if _, ok := desktopExtensions[a.Platform]; !ok {
			return nil, errors.New("unknown manifest platform")
		}
		t := Target{Version: m.Version, Platform: a.Platform, Kind: "desktop", Filename: a.Filename, Path: a.Path, Bytes: a.Bytes, SHA256: a.SHA256}
		if _, dup := out.installers[a.Platform]; dup || a.Filename != DesktopFilename(m.Version, a.Platform) || !validFile(t) {
			return nil, errors.New("invalid manifest artifact")
		}
		out.installers[a.Platform] = t
	}
	if m.Updates == nil {
		return out, nil
	}
	u := m.Updates
	if u.SchemaVersion != 1 || !keyIDHex.MatchString(u.KeyID) || len(u.Desktop) > 3 || len(u.Headless) > 3 {
		return nil, errors.New("invalid manifest updates")
	}
	out.KeyID = u.KeyID
	for platform, entry := range u.Desktop {
		installer, ok := out.installers[platform]
		if !ok || entry.Filename != installer.Filename || entry.Signature == "" || len(entry.Signature) > 4096 {
			return nil, errors.New("invalid desktop update")
		}
		installer.Signature = entry.Signature
		out.desktop[platform] = installer
	}
	for platform, entry := range u.Headless {
		t := Target{Version: m.Version, Platform: platform, Kind: "headless", Filename: entry.Filename, Path: entry.Path, Bytes: entry.Bytes, SHA256: entry.SHA256, Signature: entry.Signature}
		if !headlessPlatforms[platform] || entry.Filename != HeadlessFilename(m.Version, platform) || !validFile(t) || entry.Signature == "" || len(entry.Signature) > 4096 {
			return nil, errors.New("invalid headless update")
		}
		out.headless[platform] = t
	}
	return out, nil
}

// Desktop returns the signed desktop installer for platform.
func (m *Manifest) Desktop(platform string) (Target, error) {
	t, ok := m.desktop[platform]
	if !ok {
		return t, fmt.Errorf("release %s has no signed %s update", m.Version, platform)
	}
	return t, nil
}

// Installer returns a published desktop installer, signed for the updater or
// not; rollback sources use it with OS signature verification.
func (m *Manifest) Installer(platform string) (Target, bool) {
	t, ok := m.installers[platform]
	if s, signed := m.desktop[platform]; signed {
		t = s
	}
	return t, ok
}

// Headless returns the signed headless bundle for platform.
func (m *Manifest) Headless(platform string) (Target, error) {
	t, ok := m.headless[platform]
	if !ok {
		return t, fmt.Errorf("release %s has no signed %s bundle", m.Version, platform)
	}
	return t, nil
}
