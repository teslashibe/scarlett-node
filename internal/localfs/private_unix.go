//go:build unix

// Package localfs owns platform-specific private file opens and process locks.
package localfs

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func OpenPrivate(path string) (*os.File, error) {
	return privateFile(path, false)
}

func privateFile(path string, create bool) (*os.File, error) {
	flags := os.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if create {
		flags = os.O_CREATE | os.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, errors.New("file must be private and regular")
	}
	return f, nil
}

// LockPrivate holds exclusive process ownership until the returned file closes.
func LockPrivate(path string) (*os.File, error) {
	f, err := privateFile(path, true)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("another process owns the private lock")
	}
	return f, nil
}
