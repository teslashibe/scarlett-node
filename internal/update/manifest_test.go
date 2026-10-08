package update

import (
	"encoding/json"
	"strings"
	"testing"
)

func manifestFixture(t *testing.T, k testKey, version string, files map[string][]byte) map[string]any {
	t.Helper()
	artifacts := []any{}
	desktop := map[string]any{}
	headless := map[string]any{}
	for platform := range desktopExtensions {
		name := DesktopFilename(version, platform)
		data := files[name]
		if data == nil {
			data = []byte("installer " + platform)
		}
		artifacts = append(artifacts, map[string]any{"platform": platform, "filename": name, "path": "/downloads/v" + version + "/" + name,
			"bytes": len(data), "sha256": sum(data), "nativeValidated": true, "components": []string{"desktop"},
			"signature": map[string]any{"status": "self-signed-stable"}})
		desktop[platform] = map[string]any{"filename": name, "signature": k.sign(data, name, version)}
	}
	for platform := range headlessPlatforms {
		name := HeadlessFilename(version, platform)
		data := files[name]
		if data == nil {
			data = []byte("bundle " + platform)
		}
		headless[platform] = map[string]any{"filename": name, "path": "/downloads/v" + version + "/" + name, "bytes": len(data), "sha256": sum(data), "signature": k.sign(data, name, version)}
	}
	return map[string]any{"schemaVersion": 1, "version": version, "channel": "stable", "source": map[string]any{"node": strings.Repeat("a", 40)},
		"artifacts": artifacts,
		"notes": map[string]any{"title": "Automatic updates", "date": "2026-10-09", "highlights": []string{"One", "Two"},
			"changelog": ChangelogFor(version), "release": ReleaseFor(version)},
		"updates": map[string]any{"schemaVersion": 1, "keyId": k.pub.KeyID(), "desktop": desktop, "headless": headless}}
}

func encode(t *testing.T, v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestManifestDerivesEveryPathAndKeepsUnknownKeysHarmless(t *testing.T) {
	k := newTestKey(t)
	m, err := ParseManifest(encode(t, manifestFixture(t, k, "0.1.13", nil)))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "0.1.13" || m.Notes == nil || m.KeyID != k.pub.KeyID() {
		t.Fatal("manifest fields missing")
	}
	d, err := m.Desktop("darwin-arm64")
	if err != nil || d.Path != "/downloads/v0.1.13/Scarlett-Node-0.1.13-darwin-arm64.dmg" || d.Signature == "" {
		t.Fatalf("desktop target %+v %v", d, err)
	}
	h, err := m.Headless("linux-amd64")
	if err != nil || h.Filename != "scarlett-node-0.1.13-linux-amd64.tar.gz" {
		t.Fatalf("headless target %+v %v", h, err)
	}
	if _, err = m.Headless("windows-amd64"); err == nil {
		t.Fatal("unknown headless platform returned")
	}
	// The 0.1.12 manifest shape (no notes, no updates) still parses.
	old := manifestFixture(t, k, "0.1.12", nil)
	delete(old, "notes")
	delete(old, "updates")
	m, err = ParseManifest(encode(t, old))
	if err != nil || m.Notes != nil {
		t.Fatal("pre-updater manifest refused", err)
	}
	if _, err = m.Desktop("darwin-arm64"); err == nil {
		t.Fatal("unsigned release offered as an update")
	}
	if inst, ok := m.Installer("windows-amd64"); !ok || inst.Signature != "" {
		t.Fatal("unsigned installer missing for rollback")
	}
}

func TestManifestRefusesForeignPathsAndDropsUnsafeNotes(t *testing.T) {
	k := newTestKey(t)
	mutate := func(change func(map[string]any)) error {
		v := manifestFixture(t, k, "0.1.13", nil)
		change(v)
		_, err := ParseManifest(encode(t, v))
		return err
	}
	artifact := func(v map[string]any) map[string]any { return v["artifacts"].([]any)[0].(map[string]any) }
	updates := func(v map[string]any) map[string]any { return v["updates"].(map[string]any) }
	for name, change := range map[string]func(map[string]any){
		"schema":        func(v map[string]any) { v["schemaVersion"] = 2 },
		"version":       func(v map[string]any) { v["version"] = "0.1.13/../x" },
		"foreign path":  func(v map[string]any) { artifact(v)["path"] = "https://evil.example/x.dmg" },
		"other version": func(v map[string]any) { artifact(v)["path"] = "/downloads/v0.1.12/" + artifact(v)["filename"].(string) },
		"filename":      func(v map[string]any) { artifact(v)["filename"] = "evil.dmg" },
		"size":          func(v map[string]any) { artifact(v)["bytes"] = MaxArtifactBytes + 1 },
		"sha":           func(v map[string]any) { artifact(v)["sha256"] = "AB" },
		"platform":      func(v map[string]any) { artifact(v)["platform"] = "linux-arm64" },
		"key id":        func(v map[string]any) { updates(v)["keyId"] = "short" },
		"desktop filename": func(v map[string]any) {
			updates(v)["desktop"].(map[string]any)["darwin-arm64"].(map[string]any)["filename"] = "x.dmg"
		},
		"headless path": func(v map[string]any) {
			updates(v)["headless"].(map[string]any)["linux-amd64"].(map[string]any)["path"] = "/downloads/x"
		},
		"headless platform": func(v map[string]any) {
			updates(v)["headless"].(map[string]any)["windows-amd64"] = updates(v)["headless"].(map[string]any)["linux-amd64"]
		},
	} {
		if mutate(change) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for name, notes := range map[string]map[string]any{
		"markup":     {"title": "<b>x</b>", "date": "2026-10-09", "highlights": []string{"a"}, "changelog": ChangelogFor("0.1.13"), "release": ReleaseFor("0.1.13")},
		"link":       {"title": "x", "date": "2026-10-09", "highlights": []string{"a"}, "changelog": "https://evil.example/", "release": ReleaseFor("0.1.13")},
		"too many":   {"title": "x", "date": "2026-10-09", "highlights": []string{"a", "b", "c", "d"}, "changelog": ChangelogFor("0.1.13"), "release": ReleaseFor("0.1.13")},
		"control":    {"title": "x\u0007", "date": "2026-10-09", "highlights": []string{"a"}, "changelog": ChangelogFor("0.1.13"), "release": ReleaseFor("0.1.13")},
		"date":       {"title": "x", "date": "09/10/2026", "highlights": []string{"a"}, "changelog": ChangelogFor("0.1.13"), "release": ReleaseFor("0.1.13")},
		"long title": {"title": strings.Repeat("x", 81), "date": "2026-10-09", "highlights": []string{"a"}, "changelog": ChangelogFor("0.1.13"), "release": ReleaseFor("0.1.13")},
	} {
		v := manifestFixture(t, k, "0.1.13", nil)
		v["notes"] = notes
		m, err := ParseManifest(encode(t, v))
		if err != nil || m.Notes != nil {
			t.Errorf("%s notes kept (%v)", name, err)
		}
	}
	if _, err := ParseManifest(make([]byte, MaxManifestBytes+1)); err == nil {
		t.Fatal("oversized manifest accepted")
	}
}
