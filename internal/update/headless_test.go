//go:build unix

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// A stand-in for the bundle's install.sh: copy the bundle into versions/ and
// flip current, as the real one does after its checks.
const fakeInstall = `#!/bin/sh
set -eu
bundle=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$1
version=$(cat "$bundle/VERSION")
target="$root/versions/$version-PLATFORM"
[ -d "$target" ] || cp -R "$bundle" "$target"
ln -sfn "versions/$version-PLATFORM" "$root/current"
`

func bundleFiles(version, reports string) map[string]string {
	return map[string]string{
		"install.sh":    fakeInstall,
		"VERSION":       version + "\n",
		"scarlett-node": "#!/bin/sh\nprintf '{\"release\":\"" + reports + "\"}\\n'\n",
	}
}

func tarBundle(t *testing.T, version string, files map[string]string, extra func(*tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	top := "scarlett-node-" + version + "-" + Platform()
	tw.WriteHeader(&tar.Header{Name: top + "/", Typeflag: tar.TypeDir, Mode: 0o755})
	for name, content := range files {
		content = string(bytes.ReplaceAll([]byte(content), []byte("PLATFORM"), []byte(Platform())))
		tw.WriteHeader(&tar.Header{Name: top + "/" + name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(content))})
		tw.Write([]byte(content))
	}
	if extra != nil {
		extra(tw)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

type headlessFixture struct {
	h        *Headless
	root     string
	status   atomic.Value
	drained  atomic.Bool
	drains   atomic.Int32
	resumes  atomic.Int32
	restarts atomic.Int32
	inFlight atomic.Int32
}

func newHeadlessFixture(t *testing.T, newReports string) *headlessFixture {
	t.Helper()
	if !headlessPlatforms[Platform()] {
		t.Skip("headless updates run on Linux amd64 and macOS")
	}
	k := newTestKey(t)
	root := filepath.Join(t.TempDir(), "root")
	if err := localfs.EnsureDir(root); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(root, "versions", "0.1.12-"+Platform())
	os.MkdirAll(current, 0o700)
	for name, content := range bundleFiles("0.1.12", "0.1.12") {
		content = string(bytes.ReplaceAll([]byte(content), []byte("PLATFORM"), []byte(Platform())))
		os.WriteFile(filepath.Join(current, name), []byte(content), 0o755)
	}
	if err := os.Symlink("versions/0.1.12-"+Platform(), filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	name := HeadlessFilename("0.1.13", Platform())
	archive := tarBundle(t, "0.1.13", bundleFiles("0.1.13", newReports), nil)
	client, _ := releaseServer(t, encode(t, manifestFixture(t, k, "0.1.13", map[string][]byte{name: archive})), map[string][]byte{name: archive})
	f := &headlessFixture{root: root}
	f.inFlight.Store(2)
	f.status.Store(NodeStatus{State: "running", UpdatedAt: time.Now(), InFlight: 2, Release: "0.1.12", NodeID: "node-a"})
	f.h = &Headless{
		Layout: Layout{Root: root, Current: current, Version: "0.1.12", Platform: Platform()}, Bin: filepath.Join(root, "bin"),
		Client: client, Trust: Trust{Keys: []PublicKey{k.pub}}, Out: &bytes.Buffer{}, Running: "0.1.12", Platform: Platform(),
		State: StateFile{Path: filepath.Join(root, "update-state.json")},
		Status: func() (NodeStatus, error) {
			s := f.status.Load().(NodeStatus)
			// Accepted work finishes on its own while new work is paused,
			// and the node's next status reports the pause.
			if f.drained.Load() {
				if f.inFlight.Load() > 0 {
					f.inFlight.Add(-1)
				}
				if s.State == "running" {
					s.State, s.UpdatedAt = "draining", time.Now()
				}
			}
			s.InFlight = int(f.inFlight.Load())
			return s, nil
		},
		Drained:       func() (bool, error) { return f.drained.Load(), nil },
		Drain:         func() error { f.drains.Add(1); f.drained.Store(true); return nil },
		Resume:        func() error { f.resumes.Add(1); f.drained.Store(false); return nil },
		ServiceActive: func() bool { return true },
		RestartService: func() error {
			f.restarts.Add(1)
			link, _ := os.Readlink(filepath.Join(root, "current"))
			release := "0.1.12"
			if link == "versions/0.1.13-"+Platform() {
				release = newReports
			}
			time.Sleep(5 * time.Millisecond)
			f.status.Store(NodeStatus{State: "draining", UpdatedAt: time.Now(), Release: release, NodeID: "node-a"})
			return nil
		},
		DrainTimeout: time.Second, HealthWait: 300 * time.Millisecond, Poll: 5 * time.Millisecond, Now: time.Now,
	}
	return f
}

func (f *headlessFixture) current(t *testing.T) string {
	link, err := os.Readlink(filepath.Join(f.root, "current"))
	if err != nil {
		t.Fatal(err)
	}
	return link
}

func TestHeadlessApplyDrainsSwapsRestartsAndResumes(t *testing.T) {
	f := newHeadlessFixture(t, "0.1.13")
	if err := f.h.Apply(context.Background(), ApplyOptions{}); err != nil {
		t.Fatal(err, f.h.Out)
	}
	s, _ := f.h.State.Read()
	if f.current(t) != "versions/0.1.13-"+Platform() || s.Installed != "0.1.13" || s.HighWater != "0.1.13" || s.Pending != nil {
		t.Fatalf("current %s state %+v", f.current(t), s)
	}
	if f.drains.Load() != 1 || f.resumes.Load() != 1 || f.restarts.Load() != 1 || f.inFlight.Load() != 0 {
		t.Fatalf("drains %d resumes %d restarts %d", f.drains.Load(), f.resumes.Load(), f.restarts.Load())
	}
	// Nothing newer: a second run changes nothing.
	f.h.Running = "0.1.13"
	if err := f.h.Apply(context.Background(), ApplyOptions{}); err != nil || f.restarts.Load() != 1 {
		t.Fatal("up-to-date node was restarted", err)
	}
}

func TestHeadlessApplyRollsBackABundleThatFailsItsChecks(t *testing.T) {
	f := newHeadlessFixture(t, "0.1.12") // the new binary reports the wrong release
	if err := f.h.Apply(context.Background(), ApplyOptions{}); err == nil {
		t.Fatal("failed update reported success")
	}
	s, _ := f.h.State.Read()
	if f.current(t) != "versions/0.1.12-"+Platform() || !s.HasFailed("0.1.13") || s.Pending.Phase != PhaseRolledBack || f.resumes.Load() != 1 {
		t.Fatalf("current %s state %+v resumes %d", f.current(t), s.Pending, f.resumes.Load())
	}
	// Automatic mode skips the failed version; an explicit apply may retry.
	f.drained.Store(false)
	before := f.restarts.Load()
	if err := f.h.Apply(context.Background(), ApplyOptions{Auto: true}); err != nil || f.restarts.Load() != before {
		t.Fatal("automatic mode retried a failed version", err)
	}
}

func TestHeadlessAutoWaitsForItsRolloutSlotUnlessRequired(t *testing.T) {
	f := newHeadlessFixture(t, "0.1.13")
	// Seen just now: an optional update waits for this node's slot.
	offset := RolloutOffset("node-a", "0.1.13")
	if offset < time.Second {
		t.Skip("this node's slot is immediate")
	}
	if err := f.h.Apply(context.Background(), ApplyOptions{Auto: true}); err != nil || f.current(t) != "versions/0.1.12-"+Platform() {
		t.Fatal("optional update installed before its slot", err)
	}
	// Required: the coordinator offers 0.1.12 no new jobs, so it installs now.
	s := f.status.Load().(NodeStatus)
	s.UpdateRequired = true
	f.status.Store(s)
	if err := f.h.Apply(context.Background(), ApplyOptions{Auto: true}); err != nil || f.current(t) != "versions/0.1.13-"+Platform() {
		t.Fatal("required update did not install", err)
	}
}

func TestHeadlessDrainNeverKillsAcceptedWork(t *testing.T) {
	f := newHeadlessFixture(t, "0.1.13")
	f.h.Status = func() (NodeStatus, error) {
		return NodeStatus{State: "draining", UpdatedAt: time.Now(), InFlight: 1, Release: "0.1.12"}, nil
	}
	f.h.DrainTimeout = 50 * time.Millisecond
	err := f.h.Apply(context.Background(), ApplyOptions{})
	if CodeOf(err) != CodeBusy || f.current(t) != "versions/0.1.12-"+Platform() || f.resumes.Load() != 1 || f.restarts.Load() != 0 {
		t.Fatalf("err %v resumes %d restarts %d", err, f.resumes.Load(), f.restarts.Load())
	}
}

func TestBundleExtractionStaysInsideTheBundle(t *testing.T) {
	if !headlessPlatforms[Platform()] {
		t.Skip()
	}
	name := HeadlessFilename("0.1.13", Platform())
	top := "scarlett-node-0.1.13-" + Platform()
	for label, extra := range map[string]func(*tar.Writer){
		"traversal": func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: top + "/../evil", Typeflag: tar.TypeReg, Size: 1})
			tw.Write([]byte("x"))
		},
		"outside": func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "other/evil", Typeflag: tar.TypeReg, Size: 1})
			tw.Write([]byte("x"))
		},
		"link": func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: top + "/link", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"})
		},
		"link inside": func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: top + "/lib/link", Typeflag: tar.TypeSymlink, Linkname: "../VERSION"})
		},
		"chained links": func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: top + "/here", Typeflag: tar.TypeSymlink, Linkname: "."})
			tw.WriteHeader(&tar.Header{Name: top + "/up", Typeflag: tar.TypeSymlink, Linkname: "here/.."})
			tw.WriteHeader(&tar.Header{Name: top + "/up/evil", Typeflag: tar.TypeReg, Size: 1})
			tw.Write([]byte("x"))
		},
		"hard link": func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: top + "/hard", Typeflag: tar.TypeLink, Linkname: top + "/VERSION"})
		},
		"absolute link": func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: top + "/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
		},
		"device": func(tw *tar.Writer) { tw.WriteHeader(&tar.Header{Name: top + "/dev", Typeflag: tar.TypeChar}) },
	} {
		dir := t.TempDir()
		archive := filepath.Join(dir, name)
		os.WriteFile(archive, tarBundle(t, "0.1.13", bundleFiles("0.1.13", "0.1.13"), extra), 0o600)
		if _, _, err := extractBundle(archive, dir, Target{Version: "0.1.13", Filename: name}); err == nil {
			t.Errorf("%s extracted", label)
		}
	}
	dir := t.TempDir()
	archive := filepath.Join(dir, name)
	os.WriteFile(archive, tarBundle(t, "0.1.13", bundleFiles("0.1.13", "0.1.13"), func(tw *tar.Writer) {
		tw.WriteHeader(&tar.Header{Name: top + "/._VERSION", Typeflag: tar.TypeReg, Size: 1})
		tw.Write([]byte("x"))
	}), 0o600)
	bundle, cleanup, err := extractBundle(archive, dir, Target{Version: "0.1.13", Filename: name})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := os.Lstat(filepath.Join(bundle, "._VERSION")); !os.IsNotExist(err) {
		t.Fatal("AppleDouble metadata extracted")
	}
	if _, _, err := extractBundle(archive, dir, Target{Version: "0.1.14", Filename: HeadlessFilename("0.1.14", Platform())}); err == nil {
		t.Fatal("bundle for another version accepted")
	}
}

func TestDetectLayoutAcceptsOnlyAnInstallShLayout(t *testing.T) {
	if !headlessPlatforms[Platform()] {
		t.Skip()
	}
	root := filepath.Join(t.TempDir(), "lib")
	localfs.EnsureDir(root)
	dir := filepath.Join(root, "versions", "0.1.13-"+Platform())
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "scarlett-node"), []byte("x"), 0o755)
	os.WriteFile(filepath.Join(dir, "VERSION"), []byte("0.1.13\n"), 0o600)
	os.Symlink("versions/0.1.13-"+Platform(), filepath.Join(root, "current"))
	bin := filepath.Join(t.TempDir(), "bin")
	os.MkdirAll(bin, 0o700)
	os.Symlink(filepath.Join(root, "current", "scarlett-node"), filepath.Join(bin, "scarlett-node"))
	l, err := DetectLayout(filepath.Join(bin, "scarlett-node"))
	if err != nil || l.Version != "0.1.13" {
		t.Fatalf("layout %+v %v", l, err)
	}
	if _, err = DetectLayout(filepath.Join(t.TempDir(), "scarlett-node")); CodeOf(err) != CodeNotInstalledLayout {
		t.Fatal("binary outside a layout accepted")
	}
	os.Chmod(root, 0o755)
	if _, err = DetectLayout(filepath.Join(bin, "scarlett-node")); err == nil {
		t.Fatal("shared installation root accepted")
	}
}

func TestHeadlessDrainTrustsOnlyAStatusWrittenAfterThePause(t *testing.T) {
	f := newHeadlessFixture(t, "0.1.13")
	// The node has not written a status since the pause: its last one says
	// running with nothing in flight, but a job accepted in that instant may
	// not be counted yet. The updater waits for the node's own report.
	f.inFlight.Store(0)
	stale := NodeStatus{State: "running", UpdatedAt: time.Now(), Release: "0.1.12", NodeID: "node-a"}
	f.h.Status = func() (NodeStatus, error) { return stale, nil }
	f.h.DrainTimeout = 50 * time.Millisecond
	err := f.h.Apply(context.Background(), ApplyOptions{})
	if CodeOf(err) != CodeBusy || f.current(t) != "versions/0.1.12-"+Platform() || f.restarts.Load() != 0 || f.resumes.Load() != 1 {
		t.Fatalf("err %v restarts %d resumes %d", err, f.restarts.Load(), f.resumes.Load())
	}
}

func TestHeadlessRollbackDrainsFirstAndResumes(t *testing.T) {
	f := newHeadlessFixture(t, "0.1.13")
	if err := f.h.Apply(context.Background(), ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	f.h.Running = "0.1.13"
	f.h.Layout.Current = filepath.Join(f.root, "versions", "0.1.13-"+Platform())
	f.h.Layout.Version = "0.1.13"
	f.inFlight.Store(2)
	f.status.Store(NodeStatus{State: "running", UpdatedAt: time.Now(), Release: "0.1.13", NodeID: "node-a"})
	drains, resumes := f.drains.Load(), f.resumes.Load()
	if err := f.h.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	s, _ := f.h.State.Read()
	if f.current(t) != "versions/0.1.12-"+Platform() || f.inFlight.Load() != 0 || f.drains.Load() != drains+1 || f.resumes.Load() != resumes+1 || !s.HasFailed("0.1.13") || s.Installed != "0.1.12" {
		t.Fatalf("current %s in flight %d drains %d resumes %d state %+v", f.current(t), f.inFlight.Load(), f.drains.Load()-drains, f.resumes.Load()-resumes, s)
	}
}
