package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// AppName is the installed bundle's name.
const AppName = "Scarlett Node.app"

var sidecars = []string{"scarlett-node", "scarlett-prover", "open-agent-api"}

func run(ctx context.Context, name string, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// verifyMacCode proves Scarlett's own signature on one file or bundle: the
// pinned requirement, the pinned designated requirement, exactly the pinned
// certificate embedded, and no team.
func verifyMacCode(ctx context.Context, path, identifier string, trust Trust, deep bool) error {
	requirement := trust.MacRequirement(identifier)
	args := []string{"--verify", "--strict"}
	if deep {
		args = append(args, "--deep")
	}
	if _, _, err := run(ctx, "/usr/bin/codesign", append(args, "-R="+requirement, path)...); err != nil {
		return fail(CodeIdentityMismatch, fmt.Errorf("%s is not signed with the pinned certificate", filepath.Base(path)))
	}
	out, _, err := run(ctx, "/usr/bin/codesign", "--display", "-r-", path)
	if err != nil || strings.TrimSpace(out) != "designated => "+requirement {
		return fail(CodeIdentityMismatch, fmt.Errorf("%s does not carry the pinned designated requirement", filepath.Base(path)))
	}
	dir, err := os.MkdirTemp("", "scarlett-update-certificates-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if _, _, err = run(ctx, "/usr/bin/codesign", "--display", "--extract-certificates="+filepath.Join(dir, "certificate"), path); err != nil {
		return fail(CodeIdentityMismatch, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "certificate0" {
		return fail(CodeIdentityMismatch, errors.New("signed code must embed only the pinned certificate"))
	}
	der, err := os.ReadFile(filepath.Join(dir, "certificate0"))
	sum := sha256.Sum256(der)
	if err != nil || hex.EncodeToString(sum[:]) != trust.MacSHA256 {
		return fail(CodeIdentityMismatch, errors.New("embedded certificate differs from the pinned certificate"))
	}
	_, detail, err := run(ctx, "/usr/bin/codesign", "--display", "--verbose=4", path)
	lines := strings.Split(detail, "\n")
	if err != nil || !contains(lines, "Identifier="+identifier) || !contains(lines, "TeamIdentifier=not set") {
		return fail(CodeIdentityMismatch, errors.New("signed code must have its fixed identifier and no team"))
	}
	return nil
}

func contains(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}

func verifyMacApp(ctx context.Context, app string, trust Trust) error {
	if err := verifyMacCode(ctx, app, "ai.scarlett.node", trust, true); err != nil {
		return err
	}
	for _, name := range sidecars {
		if err := verifyMacCode(ctx, filepath.Join(app, "Contents", "MacOS", name), "ai.scarlett.node."+name, trust, false); err != nil {
			return err
		}
	}
	return nil
}

// DesignatedRequirement returns an app's "designated => ..." line.
func DesignatedRequirement(ctx context.Context, app string) (string, error) {
	out, _, err := run(ctx, "/usr/bin/codesign", "--display", "-r-", app)
	return strings.TrimSpace(out), err
}

// InstalledApp returns the .app bundle that contains the running executable.
func InstalledApp(exe string) (string, error) {
	app := filepath.Dir(filepath.Dir(filepath.Dir(exe)))
	if filepath.Base(app) != AppName || filepath.Base(filepath.Dir(exe)) != "MacOS" {
		return "", fail(CodeUnsupported, errors.New("not running from an app bundle"))
	}
	return app, nil
}

// CheckInstallable refuses locations Scarlett cannot replace by itself.
func CheckInstallable(app string) error {
	if strings.Contains(app, "/AppTranslocation/") {
		return fail(CodeTranslocated, errors.New("move Scarlett Node to Applications to enable updates"))
	}
	parent := filepath.Dir(app)
	var fs unix.Statfs_t
	if err := unix.Statfs(app, &fs); err == nil && fs.Flags&unix.MNT_RDONLY != 0 {
		return fail(CodeTranslocated, errors.New("Scarlett Node runs from a read-only volume"))
	}
	if unix.Access(parent, unix.W_OK) != nil {
		return fail(CodeNotWritable, errors.New("Scarlett Node can't replace itself in this folder"))
	}
	return nil
}

func sameVolume(a, b string) bool {
	var x, y syscall.Stat_t
	return syscall.Stat(a, &x) == nil && syscall.Stat(b, &y) == nil && x.Dev == y.Dev
}

// StagingRoot is a private directory on the installed app's volume, so the
// swap is one rename.
func StagingRoot(app, updates string) (string, error) {
	if sameVolume(updates, filepath.Dir(app)) {
		return updates, nil
	}
	root := besideAppStagingRoot(app)
	if err := os.Mkdir(root, 0o700); err != nil && !os.IsExist(err) {
		return "", fail(CodeNotWritable, err)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return "", fail(CodeNotWritable, errors.New("invalid staging directory"))
	}
	return root, nil
}

// StageMacApp verifies a downloaded DMG and the app inside it against the
// pins and the running app, and copies the app beside the installed one.
func StageMacApp(ctx context.Context, dmg string, t Target, trust Trust, app, updates string) (string, error) {
	if err := CheckInstallable(app); err != nil {
		return "", err
	}
	if err := verifyMacCode(ctx, dmg, "ai.scarlett.node.dmg", trust, false); err != nil {
		return "", err
	}
	running, err := DesignatedRequirement(ctx, app)
	if err != nil || running != "designated => "+trust.MacRequirement("ai.scarlett.node") {
		return "", fail(CodeRequirement, errors.New("the installed app's signing identity differs from the update's"))
	}
	root, err := StagingRoot(app, updates)
	if err != nil {
		return "", err
	}
	work := filepath.Join(root, "stage-"+t.Version+"-"+randomSuffix())
	if err = os.Mkdir(work, 0o700); err != nil {
		return "", err
	}
	mount := filepath.Join(work, "mount")
	if err = os.Mkdir(mount, 0o700); err != nil {
		return "", err
	}
	if _, _, err = run(ctx, "/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount, dmg); err != nil {
		os.RemoveAll(work)
		return "", fail(CodeSignatureInvalid, errors.New("the disk image could not be opened"))
	}
	attached := true
	detach := func() {
		if attached {
			_, _, _ = run(context.Background(), "/usr/bin/hdiutil", "detach", "-force", mount)
			attached = false
		}
	}
	defer detach()
	source := filepath.Join(mount, AppName)
	if err = verifyMacApp(ctx, source, trust); err != nil {
		os.RemoveAll(work)
		return "", err
	}
	version, _, err := run(ctx, "/usr/bin/plutil", "-extract", "CFBundleShortVersionString", "raw", "-o", "-", filepath.Join(source, "Contents", "Info.plist"))
	if err != nil || strings.TrimSpace(version) != t.Version {
		os.RemoveAll(work)
		return "", fail(CodeSignatureInvalid, errors.New("the app version differs from the manifest"))
	}
	staged := filepath.Join(work, AppName)
	if _, _, err = run(ctx, "/usr/bin/ditto", source, staged); err != nil {
		os.RemoveAll(work)
		return "", fail(CodeDiskFull, errors.New("the app could not be copied out of the disk image"))
	}
	detach()
	_ = os.Remove(mount)
	if err = verifyMacApp(ctx, staged, trust); err != nil {
		os.RemoveAll(work)
		return "", err
	}
	return staged, nil
}

// SwapApp exchanges the staged and installed bundles in one rename. The
// previous bundle is left at the staged path.
func SwapApp(staged, app string) error {
	err := unix.RenamexNp(staged, app, unix.RENAME_SWAP)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.EPERM) {
		return fail(CodeAppManagement, err)
	}
	if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EROFS) {
		return fail(CodeNotWritable, err)
	}
	if !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EINVAL) {
		return fail(CodeInstallFailed, err)
	}
	// No swap support on this volume: two renames, restoring on failure.
	aside := staged + ".previous"
	if err = os.Rename(app, aside); err != nil {
		return fail(CodeNotWritable, err)
	}
	if err = os.Rename(staged, app); err != nil {
		_ = os.Rename(aside, app)
		return fail(CodeNotWritable, err)
	}
	return os.Rename(aside, staged)
}

// LaunchApp opens the installed app through LaunchServices.
func LaunchApp(app string) error {
	cmd := exec.Command("/usr/bin/open", "-n", app)
	return cmd.Run()
}
