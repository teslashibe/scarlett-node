package browserx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsChromeKeyUsesCurrentUserDPAPIWithoutBrowserOrElevation(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	input := windows.DataBlob{Size: uint32(len(key)), Data: &key[0]}
	var protected windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &protected); err != nil {
		t.Fatal("isolated DPAPI fixture unavailable")
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(protected.Data))))
	body := bytes.Clone(unsafe.Slice(protected.Data, int(protected.Size)))
	defer clear(body)
	dir := t.TempDir()
	profile := filepath.Join(dir, "Default", "Network")
	if err := os.MkdirAll(profile, 0700); err != nil {
		t.Fatal(err)
	}
	state, _ := json.Marshal(map[string]any{"os_crypt": map[string]string{"encrypted_key": base64.StdEncoding.EncodeToString(append([]byte("DPAPI"), body...))}})
	if err := os.WriteFile(filepath.Join(dir, "Local State"), state, 0600); err != nil {
		t.Fatal(err)
	}
	read, err := nativeChromeKey(context.Background(), filepath.Join(profile, "Cookies"))
	if err != nil || !bytes.Equal(read, key) {
		t.Fatal("native synthetic Chrome key did not round trip", err)
	}
	clear(read)
	if err := os.WriteFile(filepath.Join(dir, "Local State"), []byte(`{"os_crypt":{"encrypted_key":"QVBQQnByb3RlY3RlZA=="}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := nativeChromeKey(context.Background(), filepath.Join(profile, "Cookies")); err != Protected || raw != nil {
		t.Fatal("unsupported app-bound key accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if raw, err := nativeChromeKey(ctx, filepath.Join(profile, "Cookies")); err != Protected || raw != nil {
		t.Fatal("cancelled native import returned a key")
	}
}
