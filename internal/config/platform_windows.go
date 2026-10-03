package config

import (
	"os"
	"path/filepath"
)

func DefaultStateDir(home string) string {
	if cache, err := os.UserCacheDir(); err == nil && filepath.IsAbs(cache) {
		return filepath.Join(cache, "Scarlett", "node")
	}
	return filepath.Join(home, "AppData", "Local", "Scarlett", "node")
}
func proverFilename() string               { return "scarlett-prover.exe" }
func executableFile(info os.FileInfo) bool { return info.Mode().IsRegular() }
