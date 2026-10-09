package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/update"
)

// installedTarget is the desktop executable beside this helper, in a
// per-user install directory the updater can replace without elevation.
func installedTarget(exe string) (string, error) {
	return update.InstalledExecutable(filepath.Join(filepath.Dir(exe), "scarlett-node-desktop.exe"))
}

func stageMacApp(context.Context, string, update.Target, update.Trust, string, string) (string, error) {
	return "", &update.Error{Code: update.CodeUnsupported}
}

// stageWindowsInstaller checks the new installer's pinned Authenticode
// signature and keeps the running version's installer as the rollback
// source, fetching it from its retained release when it is not cached yet.
func stageWindowsInstaller(ctx context.Context, client *update.Client, file string, t update.Target, trust update.Trust, updates string) (string, string, error) {
	if err := update.VerifyWindowsInstaller(file, t.Version, trust); err != nil {
		return "", "", err
	}
	from := coordinator.NodeRelease
	installed := filepath.Join(updates, "installed")
	if err := localfs.EnsureDir(installed); err != nil {
		return "", "", err
	}
	cached := filepath.Join(installed, from+".exe")
	if update.VerifyWindowsInstaller(cached, from, trust) == nil {
		return file, cached, nil
	}
	_ = os.Remove(cached)
	// Earlier releases carry no updater signature; their retained manifest's
	// SHA-256 and the pinned Authenticode check verify the rollback source.
	previous := ""
	if m, err := client.VersionedManifest(ctx, from); err == nil {
		if target, ok := m.Installer(update.Platform()); ok {
			if path, err := client.Download(ctx, target, installed, trust.Keys, false, update.DownloadOptions{}); err == nil {
				if update.VerifyWindowsInstaller(path, from, trust) == nil && os.Rename(path, cached) == nil {
					previous = cached
				} else {
					_ = os.Remove(path)
				}
			}
		}
	}
	// Without a rollback source the update still installs; a failed start
	// then offers the download page instead of restoring automatically.
	return file, previous, nil
}
