package localfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPrivateWindowsACLRejectsAnotherIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private file")
	f, err := LockPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	f, err = OpenPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if f, err := OpenPrivate(path); err == nil {
		f.Close()
		t.Fatal("Everyone ACL accepted")
	}
}

func TestPrivateWindowsRejectsStreamsAndDeviceNamespaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	for _, invalid := range []string{path + ":stream", `\\?\C:\private`, `\\server\share\private`, "relative", path + `\..\other`} {
		if f, err := OpenPrivate(invalid); err == nil {
			f.Close()
			t.Fatalf("unsafe path accepted")
		}
	}
}

func TestPrivateWindowsRejectsReparsePoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private")
	f, err := LockPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("native reparse test requires unprivileged symlink support or a prepared Windows test host")
	}
	if f, err := OpenPrivate(link); err == nil {
		f.Close()
		t.Fatal("reparse point accepted")
	}
}

// Desktop profile reservation previously used CreateDirectoryW(path, NULL),
// as os.Mkdir does here: the directory only inherits ACEs, so every later
// CheckDir rejected it and Connect Codex failed on Windows.
func TestCreateDirWindowsProtectsAtCreationAndNeverAdoptsInheritedDirectories(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "codex-logins")
	if err := EnsureDir(parent); err != nil {
		t.Fatal(err)
	}
	inherited := filepath.Join(parent, "codex-1")
	if err := os.Mkdir(inherited, 0700); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(inherited); err == nil {
		t.Fatal("inherited-only ACL accepted as private")
	}
	if err := CreateDir(inherited); !errors.Is(err, fs.ErrExist) {
		t.Fatal("inherited directory was not reported as taken", err)
	}
	if err := CheckDir(inherited); err == nil {
		t.Fatal("inherited directory was adopted or repaired")
	}
	path := filepath.Join(parent, "codex-2")
	if err := CreateDir(path); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if control, _, err := sd.Control(); err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("new directory DACL was not protected at creation", err)
	}
	if err := CheckDir(path); err != nil {
		t.Fatal(err)
	}
	if err := CreateDir(path); !errors.Is(err, fs.ErrExist) {
		t.Fatal("protected directory was claimed twice", err)
	}
	if err := WriteAtomic(filepath.Join(path, "synthetic.json"), []byte("{}"), false); err != nil {
		t.Fatal("new directory cannot hold private files", err)
	}
	// An inherited-ACL parent, such as a plain temporary directory, is not a
	// private root for new profiles.
	if err := CreateDir(filepath.Join(t.TempDir(), "codex-3")); err == nil || errors.Is(err, fs.ErrExist) {
		t.Fatal("profile created below an unprotected parent", err)
	}
}
