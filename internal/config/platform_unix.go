//go:build unix

package config

import (
	"os"
	"path/filepath"
)

func DefaultStateDir(home string) string {
	return filepath.Join(home, ".local", "state", "scarlett-node")
}
func proverFilename() string { return "scarlett-prover" }
func executableFile(info os.FileInfo) bool {
	return info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0
}
