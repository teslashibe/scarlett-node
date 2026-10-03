package localfs

import (
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
