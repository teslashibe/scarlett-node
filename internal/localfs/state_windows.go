package localfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func directorySecurity() (*windows.SecurityAttributes, *windows.SID, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + u.User.Sid.String() + "D:P(A;OICI;FA;;;" + u.User.Sid.String() + ")(A;OICI;FA;;;SY)")
	if err != nil {
		return nil, nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, u.User.Sid, nil
}

func CheckDir(path string) error {
	var filesystem [32]uint16
	root, err := windows.UTF16PtrFromString(filepath.VolumeName(path) + "\\")
	if err != nil {
		return err
	}
	if err = windows.GetVolumeInformation(root, nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))); err != nil {
		return err
	}
	if windows.UTF16ToString(filesystem[:]) != "NTFS" {
		return errors.New("private node state requires local NTFS")
	}
	// The final directory is included in the pinned ancestry walk.
	handles, err := parentHandles(filepath.Join(path, ".directory-check"))
	if err != nil {
		return err
	}
	defer closeHandles(handles)
	_, user, err := directorySecurity()
	if err != nil {
		return err
	}
	return validateACL(handles[len(handles)-1], user)
}

// EnsureDir creates missing components with protected ACLs at creation. It
// never repairs an existing broad ACL or follows a reparse-point ancestor.
func EnsureDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(filepath.VolumeName(path)) != 2 || strings.Contains(path[2:], ":") {
		return errors.New("private directory requires a clean local absolute path")
	}
	sa, _, err := directorySecurity()
	if err != nil {
		return err
	}
	var paths []string
	for p := path; filepath.Dir(p) != p; p = filepath.Dir(p) {
		paths = append(paths, p)
	}
	for i := len(paths) - 1; i >= 0; i-- {
		parents, err := parentHandles(filepath.Join(filepath.Dir(paths[i]), ".directory-check"))
		if err != nil {
			return err
		}
		name, err := windows.UTF16PtrFromString(paths[i])
		if err == nil {
			err = windows.CreateDirectory(name, sa)
		}
		closeHandles(parents)
		if err != nil && err != windows.ERROR_ALREADY_EXISTS {
			return err
		}
		// Validate every component's actual handle even when already present.
		checked, err := parentHandles(filepath.Join(paths[i], ".directory-check"))
		if err != nil {
			return err
		}
		closeHandles(checked)
	}
	return CheckDir(path)
}

// CreateDir claims exactly one new directory below an existing private parent.
// The protected ACL is applied by CreateDirectory itself, so the directory is
// never observable with an inherited ACL. Any existing entry, including an
// older inherited-ACL directory, file or link, reports fs.ErrExist and is never
// adopted or repaired.
func CreateDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(filepath.VolumeName(path)) != 2 || strings.Contains(path[2:], ":") || filepath.Dir(path) == path {
		return errors.New("private directory requires a clean local absolute path")
	}
	if err := CheckDir(filepath.Dir(path)); err != nil {
		return err
	}
	sa, _, err := directorySecurity()
	if err != nil {
		return err
	}
	parents, err := parentHandles(path)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err == nil {
		err = windows.CreateDirectory(name, sa)
	}
	closeHandles(parents)
	if errors.Is(err, fs.ErrExist) {
		return &os.PathError{Op: "mkdir", Path: path, Err: fs.ErrExist}
	}
	if err != nil {
		return err
	}
	return CheckDir(path)
}

// Windows does not expose Unix directory fsync to a non-admin node. State
// publications use a flushed file and same-volume WRITE_THROUGH rename instead.
// Removal can reappear after power loss; callers only remove terminal history
// or a drain marker, whose reappearance pauses work rather than repeating it.
func SyncDir(path string) error { return CheckDir(path) }

func WriteAtomic(path string, raw []byte, replace bool) error {
	dir := filepath.Dir(path)
	if err := CheckDir(dir); err != nil {
		return err
	}
	parents, err := parentHandles(path)
	if err != nil {
		return err
	}
	defer closeHandles(parents)
	if replace {
		f, err := OpenPrivate(path)
		if err == nil {
			f.Close()
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + u.User.Sid.String() + "D:P(A;;FA;;;" + u.User.Sid.String() + ")(A;;FA;;;SY)")
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	var f *os.File
	for i := 0; i < 10; i++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return err
		}
		tmp := filepath.Join(dir, ".write-"+hex.EncodeToString(nonce[:]))
		name, err := windows.UTF16PtrFromString(tmp)
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, 0, &sa, windows.CREATE_NEW, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
		if err == windows.ERROR_FILE_EXISTS {
			continue
		}
		if err != nil {
			return err
		}
		f = os.NewFile(uintptr(h), tmp)
		break
	}
	if f == nil {
		return errors.New("cannot allocate private temporary file")
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
	from, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	return windows.MoveFileEx(from, to, flags)
}
