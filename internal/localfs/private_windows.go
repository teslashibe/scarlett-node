package localfs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func OpenPrivate(path string) (*os.File, error) { return privateFile(path, false, false) }

// OpenPrivateInherited reads a provider credential that another local program
// rewrites, such as Codex auth.json from codex-cli or open-agent-api. Both
// create the file without a security descriptor, so it carries only ACEs
// inherited from its directory and no SE_DACL_PROTECTED. Such a DACL is
// accepted only below a pinned parent whose own DACL passes the protected
// private-directory check, and the file must still belong to the current user
// and grant only the current user and SYSTEM. Node-owned state keeps
// OpenPrivate, which also guards WriteAtomic replacement. Neither open repairs
// an ACL.
func OpenPrivateInherited(path string) (*os.File, error) { return privateFile(path, false, true) }

// Parent handles deny delete/rename while resolving the final file. No component
// may be a reparse point. Device/UNC paths and alternate data streams are closed.
func parentHandles(path string) ([]windows.Handle, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(filepath.VolumeName(path)) != 2 || strings.Contains(path[2:], ":") {
		return nil, errors.New("private files require a clean local absolute path")
	}
	var handles []windows.Handle
	var directories []string
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		directories = append(directories, directory)
		if filepath.Dir(directory) == directory {
			break
		}
	}
	// Pin from the volume root downward, before a child path is resolved.
	for i := len(directories) - 1; i >= 0; i-- {
		directory := directories[i]
		name, err := windows.UTF16PtrFromString(directory)
		if err != nil {
			closeHandles(handles)
			return nil, err
		}
		handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			closeHandles(handles)
			return nil, err
		}
		handles = append(handles, handle)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			closeHandles(handles)
			return nil, errors.New("private file parent must be a regular directory")
		}
	}
	return handles, nil
}

func closeHandles(handles []windows.Handle) {
	for _, h := range handles {
		windows.CloseHandle(h)
	}
}

func privateFile(path string, create, inherited bool) (*os.File, error) {
	parents, err := parentHandles(path)
	if err != nil {
		return nil, err
	}
	defer closeHandles(parents)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)")
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	access, disposition := uint32(windows.GENERIC_READ|windows.READ_CONTROL), uint32(windows.OPEN_EXISTING)
	if create {
		access |= windows.GENERIC_WRITE
		disposition = windows.OPEN_ALWAYS
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
	if !create {
		share |= windows.FILE_SHARE_DELETE
	}
	h, err := windows.CreateFile(name, access, share, &sa, disposition, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)
	// An inherited DACL is only as private as the directory it came from. The
	// parent stays pinned by a handle that denies its rename or delete.
	inherited = inherited && validateACL(parents[len(parents)-1], user.User.Sid, false) == nil
	if err = validatePrivate(h, user.User.Sid, inherited); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func validatePrivate(h windows.Handle, user *windows.SID, inherited bool) error {
	var info windows.ByHandleFileInformation
	kind, err := windows.GetFileType(h)
	if err != nil || kind != windows.FILE_TYPE_DISK || windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return errors.New("private file must be regular without a reparse point")
	}
	return validateACL(h, user, inherited)
}

// validateACL requires the current user as owner and only ACCESS_ALLOWED ACEs,
// explicit or inherited, for the current user or SYSTEM. inherited only waives
// SE_DACL_PROTECTED; every ACE is still checked.
func validateACL(h windows.Handle, user *windows.SID, inherited bool) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(user) {
		return errors.New("private file must belong to the current user")
	}
	control, _, err := sd.Control()
	if err != nil || !inherited && control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("private file requires a protected ACL")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return errors.New("private file requires an explicit ACL")
	}
	system, err := windows.StringToSid("S-1-5-18")
	if err != nil {
		return err
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported private file ACL")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user) && !sid.Equals(system) {
			return errors.New("private file ACL grants another identity")
		}
	}
	return nil
}

func LockPrivate(path string) (*os.File, error) {
	return lockPrivate(path, true)
}

func LockPrivateWait(path string) (*os.File, error) {
	return lockPrivate(path, false)
}

func lockPrivate(path string, nonblocking bool) (*os.File, error) {
	f, err := privateFile(path, true, false)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if nonblocking {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	if err = windows.LockFileEx(windows.Handle(f.Fd()), flags, 0, 1, 0, new(windows.Overlapped)); err != nil {
		f.Close()
		return nil, errors.New("another process owns the private lock")
	}
	return f, nil
}
