//go:build unix

package webruntime

import "golang.org/x/sys/unix"

// freeBytes is the space available to this user on the volume holding dir.
func freeBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}
