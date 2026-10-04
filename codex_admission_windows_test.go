package main

import (
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The inherited-ACL allowance covers only private ACEs: a desktop login that
// also grants Everyone is never admitted or advertised.
func TestWindowsDesktopCodexLoginWithBroadACEStaysAuthRequired(t *testing.T) {
	p := poolFixture(t, "codex")
	home := desktopCodexAccount(t, p)
	if healthKind(t, p, "codex").State != "configured" {
		t.Fatal("private codex-cli login was not configured")
	}
	sd, err := windows.SecurityDescriptorFromString("D:(A;;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	// The explicit ACE joins the inherited ones; the DACL stays unprotected.
	if err := windows.SetNamedSecurityInfo(filepath.Join(home, "auth.json"), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if codexAdmissionValid(home, codexAdmissionWindow(time.Now())) {
		t.Fatal("Everyone-readable Codex login admitted")
	}
	if h := healthKind(t, p, "codex"); h.State != "auth_required" || h.Capacity != 0 {
		t.Fatal("Everyone-readable Codex login advertised capacity", h.State)
	}
}
