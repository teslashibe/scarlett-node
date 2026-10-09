package update

import "golang.org/x/sys/windows"

func freeBytes(dir string) (uint64, error) {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var free, total, all uint64
	if err = windows.GetDiskFreeSpaceEx(path, &free, &total, &all); err != nil {
		return 0, err
	}
	return free, nil
}
