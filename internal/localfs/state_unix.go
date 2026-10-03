//go:build unix

package localfs

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func CheckDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("directory must be private and regular")
	}
	return nil
}

func EnsureDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("directory must be regular, not a symlink")
	}
	return os.Chmod(path, 0700)
}

// CreateDir claims exactly one new 0700 directory below an existing private
// parent. Any existing entry, including a link, reports fs.ErrExist and is
// never adopted or repaired.
func CreateDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == path {
		return errors.New("private directory requires a clean absolute path")
	}
	if err := CheckDir(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	// The umask can only remove owner bits here; restore exactly 0700.
	if err := os.Chmod(path, 0700); err != nil {
		return err
	}
	return CheckDir(path)
}

func SyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func LockPrivateWait(path string) (*os.File, error) {
	f, err := privateFile(path, true)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// WriteAtomic publishes a synced complete private inode. replace=false claims a
// new name exclusively; pairing must never replace an existing identity.
func WriteAtomic(path string, raw []byte, replace bool) error {
	dir := filepath.Dir(path)
	if err := CheckDir(dir); err != nil {
		return err
	}
	if replace {
		f, err := OpenPrivate(path)
		if err == nil {
			f.Close()
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	f, err := os.CreateTemp(dir, ".write-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if replace {
		err = os.Rename(f.Name(), path)
	} else {
		err = os.Link(f.Name(), path)
	}
	if err != nil {
		return err
	}
	return SyncDir(dir)
}
