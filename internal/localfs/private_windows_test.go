package localfs

import (
	"errors"
	"io"
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
	for _, open := range []func(string) (*os.File, error){OpenPrivate, OpenPrivateInherited} {
		for _, invalid := range []string{path + ":stream", `\\?\C:\private`, `\\server\share\private`, "relative", path + `\..\other`} {
			if f, err := open(invalid); err == nil {
				f.Close()
				t.Fatalf("unsafe path accepted")
			}
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

func currentUserSID(t *testing.T) *windows.SID {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid
}

// A non-elevated desktop's codex-cli owns its files as the user. An elevated
// administrator on Windows Server, as on hosted runners, may create them owned
// by BUILTIN\Administrators instead, so fixtures reassign only the owner and
// leave the DACL exactly as created.
func ownAsCurrentUser(t *testing.T, path string) {
	t.Helper()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, currentUserSID(t), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func requireInheritedDACL(t *testing.T, path string) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if control, _, err := sd.Control(); err != nil || control&windows.SE_DACL_PROTECTED != 0 {
		t.Fatal("fixture DACL is protected, unlike a codex-cli file", err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		t.Fatal("fixture has no inherited DACL", err)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			t.Fatal("fixture has an explicit ACE, unlike a codex-cli file", err)
		}
	}
}

// codex-cli (Rust OpenOptions) creates auth.json with CreateFileW and no
// security descriptor, so its DACL holds only ACEs inherited from CODEX_HOME.
func writeLikeCodexCLI(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ownAsCurrentUser(t, path)
	requireInheritedDACL(t, path)
}

// open-agent-api v0.1.31 persists a renewal through os.CreateTemp in the same
// directory, Chmod(0600) and a rename, which keeps the inherited DACL.
func replaceLikeOpenAgentAPI(t *testing.T, path string, raw []byte) {
	t.Helper()
	temp, err := os.CreateTemp(filepath.Dir(path), ".codex-auth-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp.Name())
	err = temp.Chmod(0600)
	if err == nil {
		_, err = temp.Write(raw)
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temp.Name(), path)
	}
	if err != nil {
		t.Fatal(err)
	}
	ownAsCurrentUser(t, path)
	requireInheritedDACL(t, path)
}

// privateProfile reserves CODEX_HOME as desktop Connect Codex does.
func privateProfile(t *testing.T) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "codex-logins")
	if err := EnsureDir(parent); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(parent, "codex-1")
	if err := CreateDir(home); err != nil {
		t.Fatal(err)
	}
	return home
}

func readInherited(t *testing.T, path, want string) {
	t.Helper()
	f, err := OpenPrivateInherited(path)
	if err != nil {
		t.Fatal("private credential rejected", err)
	}
	defer f.Close()
	if raw, err := io.ReadAll(f); err != nil || string(raw) != want {
		t.Fatal("private credential unreadable", err)
	}
}

func rejectInherited(t *testing.T, path, message string) {
	t.Helper()
	if f, err := OpenPrivateInherited(path); err == nil {
		f.Close()
		t.Fatal(message)
	}
}

func setUnprotectedACE(t *testing.T, path, ace string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString("D:" + ace)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	// The explicit ACE joins the inherited ones; the DACL stays unprotected.
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

// Desktop Connect Codex reserves CODEX_HOME with CreateDir. codex-cli writes
// auth.json there and open-agent-api renewals replace it, both with only
// inherited ACEs. Strict OpenPrivate rejects that file, which left every
// Windows desktop Codex account auth_required.
func TestOpenPrivateInheritedAcceptsCodexCLIFileInPrivateProfile(t *testing.T) {
	path := filepath.Join(privateProfile(t), "auth.json")
	writeLikeCodexCLI(t, path, []byte("synthetic codex-cli login"))
	if f, err := OpenPrivate(path); err == nil {
		f.Close()
		t.Fatal("strict OpenPrivate accepted an inherited DACL")
	}
	readInherited(t, path, "synthetic codex-cli login")
	replaceLikeOpenAgentAPI(t, path, []byte("synthetic renewed login"))
	readInherited(t, path, "synthetic renewed login")
	// Protected files stay readable wherever OpenPrivate reads them.
	protected := filepath.Join(t.TempDir(), "protected")
	f, err := LockPrivate(protected)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	readInherited(t, protected, "")
}

func TestOpenPrivateInheritedRejectsBroadOrForeignACLs(t *testing.T) {
	for _, sid := range []string{"WD", "AU", "BU", "BA"} {
		t.Run(sid, func(t *testing.T) {
			path := filepath.Join(privateProfile(t), "auth.json")
			writeLikeCodexCLI(t, path, []byte("synthetic"))
			readInherited(t, path, "synthetic")
			setUnprotectedACE(t, path, "(A;;FR;;;"+sid+")")
			rejectInherited(t, path, "inherited credential with a broader ACE accepted")
		})
	}
	t.Run("owner", func(t *testing.T) {
		path := filepath.Join(privateProfile(t), "auth.json")
		writeLikeCodexCLI(t, path, []byte("synthetic"))
		readInherited(t, path, "synthetic")
		admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err != nil {
			t.Fatal(err)
		}
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
			t.Skip("assigning another owner needs an elevated administrator token; hosted Windows runners have one")
		}
		requireInheritedDACL(t, path)
		rejectInherited(t, path, "inherited credential owned by another SID accepted")
	})
	// Waiving SE_DACL_PROTECTED never waives the DACL: a NULL DACL grants
	// everyone full access, so the file opens and only the ACL check refuses it.
	t.Run("null DACL", func(t *testing.T) {
		path := filepath.Join(privateProfile(t), "auth.json")
		writeLikeCodexCLI(t, path, []byte("synthetic"))
		readInherited(t, path, "synthetic")
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		// Windows reports either a present NULL DACL or none; both grant everyone.
		if acl, _, err := sd.DACL(); err == nil && acl != nil {
			t.Fatal("fixture still has a DACL")
		}
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal("NULL DACL fixture unreadable", err)
		}
		rejectInherited(t, path, "inherited credential with a NULL DACL accepted")
	})
	// Only ACCESS_ALLOWED ACEs are understood. A deny ACE that leaves the file
	// readable still fails closed.
	t.Run("deny ACE", func(t *testing.T) {
		path := filepath.Join(privateProfile(t), "auth.json")
		writeLikeCodexCLI(t, path, []byte("synthetic"))
		readInherited(t, path, "synthetic")
		setUnprotectedACE(t, path, "(D;;0x2;;;WD)")
		if _, err := os.ReadFile(path); err != nil {
			t.Fatal("deny-ACE fixture unreadable", err)
		}
		rejectInherited(t, path, "inherited credential with a deny ACE accepted")
	})
}

// An inherited DACL is only as private as its directory. A directory that only
// inherits ACEs (os.Mkdir, std::fs::DirBuilder) or a default one such as %TEMP%
// or a stock ~/.codex is never a private parent.
func TestOpenPrivateInheritedRequiresProtectedPrivateParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private")
	if err := EnsureDir(parent); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "inherited")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ownAsCurrentUser(t, dir)
	requireInheritedDACL(t, dir)
	if err := CheckDir(dir); err == nil {
		t.Fatal("inherited-only directory passed the private-directory check")
	}
	path := filepath.Join(dir, "auth.json")
	writeLikeCodexCLI(t, path, []byte("synthetic"))
	// Owner and every ACE are private; only the parent's protection is missing.
	rejectInherited(t, path, "credential below an unprotected parent accepted")
	user := currentUserSID(t).String()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user + ")(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(dir); err != nil {
		t.Fatal(err)
	}
	requireInheritedDACL(t, path)
	readInherited(t, path, "synthetic")
	plain := filepath.Join(t.TempDir(), "auth.json")
	writeLikeCodexCLI(t, plain, []byte("synthetic"))
	rejectInherited(t, plain, "credential below a default temporary directory accepted")
}

func TestOpenPrivateInheritedRejectsReparsePoints(t *testing.T) {
	home := privateProfile(t)
	path := filepath.Join(home, "auth.json")
	writeLikeCodexCLI(t, path, []byte("synthetic"))
	readInherited(t, path, "synthetic")
	link := filepath.Join(home, "linked-auth.json")
	if err := os.Symlink(path, link); err != nil {
		t.Skip("native reparse test requires unprivileged symlink support or a prepared Windows test host")
	}
	rejectInherited(t, link, "credential reparse point accepted")
	linkedHome := filepath.Join(filepath.Dir(home), "linked-home")
	if err := os.Symlink(home, linkedHome); err != nil {
		t.Fatal(err)
	}
	rejectInherited(t, filepath.Join(linkedHome, "auth.json"), "credential below a reparse-point parent accepted")
}
