package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func createFIFOFixture(t *testing.T, _ string) error {
	t.Skip("POSIX FIFO fixture; Windows reparse fixtures run in localfs")
	return nil
}
func installFixtureHelper(path string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(exe)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0700)
}

func fixtureHelperPath(dir string) string  { return filepath.Join(dir, "synthetic-prover.exe") }
func makeHelperUnusable(path string) error { return os.Mkdir(path, 0700) }
func restoreFixtureHelper(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return installFixtureHelper(path)
}

func makeFixturePublic(path string) error { return setFixtureACL(path, "D:P(A;;FA;;;WD)") }
func makeFixturePrivate(path string) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return setFixtureACL(path, "D:P(A;;FA;;;"+u.User.Sid.String()+")(A;;FA;;;SY)")
}
func setFixtureACL(path, descriptor string) error {
	sd, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
