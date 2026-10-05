//go:build unix

package localfs

import (
	"errors"
	"os"
	"syscall"
)

// CheckOwnedDir validates without changing existing directory ownership or mode.
func CheckOwnedDir(path string) error {
	if err := CheckDir(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("directory must belong to this user")
	}
	return nil
}
