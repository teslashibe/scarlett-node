package main

import (
	"context"

	"github.com/teslashibe/scarlett-node/internal/update"
)

// installedTarget is the app bundle that contains this helper.
func installedTarget(exe string) (string, error) {
	app, err := update.InstalledApp(exe)
	if err != nil {
		return "", err
	}
	return app, update.CheckInstallable(app)
}

func stageMacApp(ctx context.Context, dmg string, t update.Target, trust update.Trust, app, updates string) (string, error) {
	return update.StageMacApp(ctx, dmg, t, trust, app, updates)
}

func stageWindowsInstaller(context.Context, *update.Client, string, update.Target, update.Trust, string) (string, string, error) {
	return "", "", &update.Error{Code: update.CodeUnsupported}
}
