//go:build !darwin && !windows

package main

import (
	"context"

	"github.com/teslashibe/scarlett-node/internal/update"
)

func installedTarget(string) (string, error) { return "", &update.Error{Code: update.CodeUnsupported} }

func stageMacApp(context.Context, string, update.Target, update.Trust, string, string) (string, error) {
	return "", &update.Error{Code: update.CodeUnsupported}
}

func stageWindowsInstaller(context.Context, *update.Client, string, update.Target, update.Trust, string) (string, string, error) {
	return "", "", &update.Error{Code: update.CodeUnsupported}
}
