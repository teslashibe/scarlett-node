package webruntime

import "golang.org/x/sys/windows"

// freeBytes is the space available to this user on the volume holding dir.
func freeBytes(dir string) (uint64, error) {
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var free uint64
	if err = windows.GetDiskFreeSpaceEx(name, &free, nil, nil); err != nil {
		return 0, err
	}
	return free, nil
}
