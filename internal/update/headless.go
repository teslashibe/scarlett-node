package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
)

// Layout is an installation made by the bundle's install.sh:
// <root>/versions/<version>-<platform>/scarlett-node with <root>/current
// linking to the active version directory.
type Layout struct {
	Root     string
	Current  string
	Version  string
	Platform string
}

// DetectLayout refuses anything but a binary inside an install.sh layout,
// such as a desktop bundle, a container or a development build.
func DetectLayout(exe string) (Layout, error) {
	notLayout := fail(CodeNotInstalledLayout, errors.New("scarlett-node update works only for nodes installed with the bundle's install.sh"))
	if !headlessPlatforms[Platform()] {
		return Layout{}, notLayout
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil || filepath.Base(resolved) != "scarlett-node" {
		return Layout{}, notLayout
	}
	dir := filepath.Dir(resolved)
	versions := filepath.Dir(dir)
	root := filepath.Dir(versions)
	name := filepath.Base(dir)
	version, ok := strings.CutSuffix(name, "-"+Platform())
	if filepath.Base(versions) != "versions" || !ok || version == "" {
		return Layout{}, notLayout
	}
	link, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || link != "versions/"+name {
		return Layout{}, notLayout
	}
	if err = localfs.CheckDir(root); err != nil {
		return Layout{}, notLayout
	}
	raw, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil || strings.TrimSpace(string(raw)) != version {
		return Layout{}, notLayout
	}
	return Layout{Root: root, Current: dir, Version: version, Platform: Platform()}, nil
}

// NodeStatus is the part of the node's status.json the updater reads.
type NodeStatus struct {
	State          string    `json:"state"`
	UpdatedAt      time.Time `json:"updated_at"`
	InFlight       int       `json:"in_flight"`
	Release        string    `json:"release"`
	LatestRelease  string    `json:"latest_release"`
	UpdateRequired bool      `json:"update_required"`
	NodeID         string    `json:"node_id"`
}

// Headless updates an install.sh installation.
type Headless struct {
	Layout   Layout
	Bin      string
	Client   *Client
	Trust    Trust
	Out      io.Writer
	State    StateFile
	Running  string
	Platform string
	// Node hooks, supplied by the CLI from the node's own local commands.
	Status         func() (NodeStatus, error)
	Drained        func() (bool, error)
	Drain          func() error
	Resume         func() error
	ServiceActive  func() bool
	RestartService func() error
	DrainTimeout   time.Duration
	HealthWait     time.Duration
	Poll           time.Duration
	Now            func() time.Time
}

func (h *Headless) printf(format string, args ...any) { fmt.Fprintf(h.Out, format+"\n", args...) }

// CheckResult is what `scarlett-node update check` reports.
type CheckResult struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	Required  bool   `json:"required"`
	Signed    bool   `json:"signed"`
	Failed    bool   `json:"failed,omitempty"`
	Notes     *Notes `json:"notes,omitempty"`
	Changelog string `json:"changelog"`
}

// Check reads the manifest and the node's last release notice.
func (h *Headless) Check(ctx context.Context) (CheckResult, *Manifest, error) {
	m, err := h.Client.Manifest(ctx)
	if err != nil {
		return CheckResult{}, nil, err
	}
	r := CheckResult{Current: h.Running, Latest: m.Version, Notes: m.Notes, Changelog: ChangelogFor(m.Version)}
	r.Available = coordinator.CompareVersions(m.Version, h.Running) > 0
	_, signedErr := m.Headless(h.Platform)
	r.Signed = signedErr == nil
	if st, err := h.Status(); err == nil && st.UpdateRequired && st.Release == h.Running {
		r.Required = r.Available
	}
	if s, err := h.State.Read(); err == nil {
		r.Failed = s.HasFailed(m.Version)
	}
	return r, m, nil
}

// ApplyOptions select an automatic or an explicit install.
type ApplyOptions struct {
	// Auto applies the rollout window and skips failed versions.
	Auto bool
}

// Apply downloads, verifies, drains, installs, restarts and checks one update,
// rolling back to the previous version when the new one fails its checks.
func (h *Headless) Apply(ctx context.Context, opts ApplyOptions) error {
	lock, err := localfs.LockPrivate(filepath.Join(h.Layout.Root, ".update-lock"))
	if err != nil {
		return fail(CodeBusy, errors.New("another update is running"))
	}
	defer lock.Close()
	if !h.Trust.CanVerify() {
		return fail(CodeNoKey, errors.New("this build trusts no update signing key; install the next release by hand"))
	}
	result, m, err := h.Check(ctx)
	if err != nil {
		return err
	}
	if !result.Available {
		h.printf("Scarlett Node %s is up to date", h.Running)
		return nil
	}
	state, err := h.State.Read()
	if err != nil {
		return err
	}
	if state.HighWater != "" && coordinator.CompareVersions(m.Version, state.HighWater) < 0 {
		return fail(CodeSignatureInvalid, errors.New("refusing to install a version below one already installed"))
	}
	if opts.Auto && state.HasFailed(m.Version) {
		h.printf("Skipping %s: it failed its checks on this machine before. Run scarlett-node update apply to retry", m.Version)
		return nil
	}
	if opts.Auto && !result.Required {
		due, err := h.due(m.Version)
		if err != nil {
			return err
		}
		if h.Now().Before(due) {
			h.printf("Scarlett Node %s is available; this node installs it after %s", m.Version, due.Format(time.RFC3339))
			return nil
		}
	}
	target, err := m.Headless(h.Platform)
	if err != nil {
		return fail(CodeUnsupported, err)
	}
	downloads := filepath.Join(h.Layout.Root, "updates")
	if err = localfs.EnsureDir(downloads); err != nil {
		return err
	}
	h.printf("Downloading Scarlett Node %s", target.Version)
	archive, err := h.Client.Download(ctx, target, downloads, h.Trust.Keys, true, DownloadOptions{})
	if err != nil {
		return err
	}
	h.printf("Verified %s (SHA-256 and signature)", target.Filename)
	bundle, cleanup, err := extractBundle(archive, downloads, target)
	if err != nil {
		return err
	}
	defer cleanup()
	owner, err := h.drainIdle(ctx)
	if err != nil {
		return err
	}
	previous := h.Layout.Current
	if _, err = h.State.Update(func(s *State) error {
		s.Pending = &Pending{Phase: PhaseHandoff, From: h.Running, To: target.Version, Kind: "headless", Staged: bundle, App: h.Layout.Root, Previous: previous, DrainOwner: owner, StartedAt: h.Now().Unix()}
		return nil
	}); err != nil {
		return err
	}
	if err = runInstall(ctx, filepath.Join(bundle, "install.sh"), h.Layout.Root, h.Bin); err != nil {
		h.printf("The new bundle did not install: %v", err)
		return h.finish(owner, PhaseFailed, "install_failed", target.Version, false)
	}
	h.printf("Installed %s; checking it", target.Version)
	if err = h.health(ctx, target.Version); err != nil {
		h.printf("Scarlett Node %s failed its checks (%v); restoring %s", target.Version, err, h.Running)
		if rbErr := h.restore(ctx, previous); rbErr != nil {
			h.printf("Rollback failed: %v. Rerun %s to restore the previous version", rbErr, filepath.Join(previous, "install.sh"))
		}
		return errors.Join(err, h.finish(owner, PhaseRolledBack, "unhealthy", target.Version, true))
	}
	if err = h.finish(owner, PhaseHealthy, "", target.Version, false); err != nil {
		return err
	}
	h.printf("Updated to Scarlett Node %s. What's new: %s", target.Version, ChangelogFor(target.Version))
	_ = os.Remove(archive)
	return nil
}

// due is when an optional update installs on this node: its first sighting
// plus this node's fixed place in the rollout window.
func (h *Headless) due(version string) (time.Time, error) {
	nodeID := ""
	if st, err := h.Status(); err == nil {
		nodeID = st.NodeID
	}
	s, err := h.State.Update(func(s *State) error {
		if s.FirstSeen == nil || s.FirstSeen.Version != version {
			s.FirstSeen = &Seen{Version: version, At: h.Now().Unix()}
		}
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(s.FirstSeen.At, 0).Add(RolloutOffset(nodeID, version)), nil
}

func (h *Headless) finish(owner, phase, reason, version string, failed bool) error {
	_, err := h.State.Update(func(s *State) error {
		if s.Pending != nil {
			s.Pending.Phase, s.Pending.Reason = phase, reason
		}
		if failed || phase == PhaseFailed {
			s.MarkFailed(version)
		}
		if phase == PhaseHealthy {
			s.Installed, s.HighWater, s.Pending, s.FirstSeen = version, version, nil, nil
		}
		return nil
	})
	if owner == "updater" {
		if resumeErr := h.Resume(); resumeErr != nil {
			h.printf("Run scarlett-node resume: the update paused new work and could not resume it")
			err = errors.Join(err, resumeErr)
		} else {
			h.printf("New work resumed")
		}
	}
	return err
}

// drainIdle pauses new work and waits until no accepted job is in flight. It
// never stops or kills accepted work: after the timeout it resumes and gives up.
// The in-flight count is trusted only from a status the node wrote after it
// saw the pause ("draining"): a job accepted in the instant before the pause
// is counted there, while an older status may not show it yet.
func (h *Headless) drainIdle(ctx context.Context) (string, error) {
	st, err := h.Status()
	if err != nil || (st.State != "running" && st.State != "draining") || time.Since(st.UpdatedAt) > 2*time.Minute {
		return "none", nil
	}
	owner := "operator"
	drained, err := h.Drained()
	if err != nil {
		return "", err
	}
	paused := time.Time{}
	if !drained {
		paused = time.Now()
		if err = h.Drain(); err != nil {
			return "", err
		}
		owner = "updater"
	}
	deadline := h.Now().Add(h.DrainTimeout)
	for {
		st, err = h.Status()
		settled := err == nil && (st.State == "draining" || st.State == "stopped") && !st.UpdatedAt.Before(paused)
		if settled && st.InFlight == 0 {
			return owner, nil
		}
		if err == nil && st.InFlight > 0 {
			h.printf("Waiting for %d accepted jobs to finish before updating; new jobs are paused", st.InFlight)
		}
		if h.Now().After(deadline) {
			if owner == "updater" {
				_ = h.Resume()
			}
			return "", fail(CodeBusy, errors.New("accepted jobs are still running; try again later"))
		}
		select {
		case <-ctx.Done():
			if owner == "updater" {
				_ = h.Resume()
			}
			return "", ctx.Err()
		case <-time.After(h.Poll * 5):
		}
	}
}

// health requires the new binary to start and report its release and, when
// the user service runs the node, a fresh running status from that release.
func (h *Headless) health(ctx context.Context, version string) error {
	out, err := exec.CommandContext(ctx, filepath.Join(h.Layout.Root, "current", "scarlett-node"), "update", "version").Output()
	var reported struct {
		Release string `json:"release"`
	}
	if err != nil || json.Unmarshal(bytes.TrimSpace(out), &reported) != nil || reported.Release != version {
		return errors.New("the new binary did not report its release")
	}
	if !h.ServiceActive() {
		h.printf("Restart your node to run %s (no active scarlett-node user service was found)", version)
		return nil
	}
	restarted := h.Now()
	if err = h.RestartService(); err != nil {
		return fmt.Errorf("restart failed: %w", err)
	}
	deadline := restarted.Add(h.HealthWait)
	for h.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(h.Poll):
		}
		st, err := h.Status()
		if err == nil && st.Release == version && st.UpdatedAt.After(restarted) && (st.State == "running" || st.State == "draining") {
			return nil
		}
	}
	return errors.New("the restarted node did not report running")
}

func (h *Headless) restore(ctx context.Context, previous string) error {
	if err := runInstall(ctx, filepath.Join(previous, "install.sh"), h.Layout.Root, h.Bin); err != nil {
		return err
	}
	if h.ServiceActive() {
		return h.RestartService()
	}
	return nil
}

// Rollback reinstalls the version that was active before the last update.
// Like an update, it waits for accepted jobs to finish before restarting.
func (h *Headless) Rollback(ctx context.Context) error {
	lock, err := localfs.LockPrivate(filepath.Join(h.Layout.Root, ".update-lock"))
	if err != nil {
		return fail(CodeBusy, errors.New("another update is running"))
	}
	defer lock.Close()
	s, err := h.State.Read()
	if err != nil {
		return err
	}
	previous := ""
	if s.Pending != nil && s.Pending.Previous != "" && s.Pending.Previous != h.Layout.Current {
		previous = s.Pending.Previous
	} else {
		previous, err = previousVersion(h.Layout)
		if err != nil {
			return err
		}
	}
	owner, err := h.drainIdle(ctx)
	if err != nil {
		return err
	}
	h.printf("Restoring %s", filepath.Base(previous))
	err = h.restore(ctx, previous)
	if err == nil {
		_, err = h.State.Update(func(s *State) error {
			s.MarkFailed(h.Running)
			s.Pending = nil
			if v, ok := strings.CutSuffix(filepath.Base(previous), "-"+h.Layout.Platform); ok && coordinator.ValidVersion(v) {
				s.Installed = v
			}
			return nil
		})
	}
	if owner == "updater" {
		if resumeErr := h.Resume(); resumeErr != nil {
			h.printf("Run scarlett-node resume: the rollback paused new work and could not resume it")
			err = errors.Join(err, resumeErr)
		}
	}
	return err
}

// previousVersion is the highest installed version below the active one.
func previousVersion(l Layout) (string, error) {
	entries, err := os.ReadDir(filepath.Join(l.Root, "versions"))
	if err != nil {
		return "", err
	}
	best, bestVersion := "", ""
	for _, e := range entries {
		v, ok := strings.CutSuffix(e.Name(), "-"+l.Platform)
		if !ok || !e.IsDir() || !coordinator.ValidVersion(v) || coordinator.CompareVersions(v, l.Version) >= 0 {
			continue
		}
		if bestVersion == "" || coordinator.CompareVersions(v, bestVersion) > 0 {
			best, bestVersion = filepath.Join(l.Root, "versions", e.Name()), v
		}
	}
	if best == "" {
		return "", errors.New("no earlier installed version to restore")
	}
	return best, nil
}

func runInstall(ctx context.Context, script, root, bin string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", script, root, bin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %s", filepath.Base(filepath.Dir(script)), strings.TrimSpace(lastLine(out.String())))
	}
	return nil
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// extractBundle unpacks a verified bundle into a private directory. Entries
// must be directories or regular files inside the bundle's single top
// directory.
func extractBundle(archive, dir string, t Target) (string, func(), error) {
	work, err := os.MkdirTemp(dir, "extract-"+t.Version+"-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(work) }
	top := strings.TrimSuffix(t.Filename, ".tar.gz")
	bad := func(reason string) (string, func(), error) {
		cleanup()
		return "", nil, fail(CodeSignatureInvalid, errors.New("bundle archive "+reason))
	}
	f, err := os.Open(archive)
	if err != nil {
		cleanup()
		return "", nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return bad("is not gzip")
	}
	tr := tar.NewReader(gz)
	var total int64
	for entries := 0; ; entries++ {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || entries > 200000 {
			return bad("is invalid")
		}
		if strings.HasPrefix(filepath.Base(hdr.Name), "._") {
			continue // AppleDouble metadata from a Mac tar, never bundle content
		}
		name := filepath.FromSlash(strings.TrimSuffix(hdr.Name, "/"))
		if name != top && !strings.HasPrefix(name, top+string(filepath.Separator)) || filepath.Clean(name) != name || strings.Contains(hdr.Name, "..") {
			return bad("has an entry outside its bundle")
		}
		path := filepath.Join(work, name)
		mode := os.FileMode(hdr.Mode).Perm() & 0o755
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err = os.MkdirAll(path, 0o700); err != nil {
				return bad("could not be extracted")
			}
		case tar.TypeReg:
			total += hdr.Size
			if total > 4*MaxArtifactBytes {
				return bad("is too large")
			}
			if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return bad("could not be extracted")
			}
			out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode|0o600)
			if err != nil {
				return bad("could not be extracted")
			}
			_, err = io.Copy(out, io.LimitReader(tr, hdr.Size))
			if closeErr := out.Close(); err != nil || closeErr != nil {
				return bad("could not be extracted")
			}
		case tar.TypeSymlink, tar.TypeLink:
			// Bundles hold only regular files (install.sh refuses links too).
			// A link could also chain through another link out of the bundle.
			return bad("has a link")
		default:
			return bad("has an unsupported entry")
		}
	}
	bundle := filepath.Join(work, top)
	if info, err := os.Lstat(filepath.Join(bundle, "install.sh")); err != nil || !info.Mode().IsRegular() {
		return bad("has no installer")
	}
	raw, err := os.ReadFile(filepath.Join(bundle, "VERSION"))
	if err != nil || strings.TrimSpace(string(raw)) != t.Version {
		return bad("names another version")
	}
	if runtime.GOOS == "windows" {
		return bad("is not for this platform")
	}
	return bundle, cleanup, nil
}
