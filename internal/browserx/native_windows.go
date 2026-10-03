package browserx

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func pathProtected(path string) bool {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || strings.HasPrefix(path, `\\`) {
		return true
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return true
	}
	attributes, err := windows.GetFileAttributes(p)
	return err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
func nativeChromeKey(ctx context.Context, path string) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, Protected
	}
	profile := filepath.Dir(path)
	if strings.EqualFold(filepath.Base(profile), "Network") {
		profile = filepath.Dir(profile)
	}
	f, _, err := openStore(filepath.Join(filepath.Dir(profile), "Local State"), 4<<20)
	if err != nil {
		return nil, Protected
	}
	defer f.Close()
	var state struct {
		Crypto struct {
			Key string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if json.NewDecoder(io.LimitReader(f, 4<<20)).Decode(&state) != nil || len(state.Crypto.Key) > 16384 {
		return nil, Protected
	}
	wrapped, err := base64.StdEncoding.DecodeString(state.Crypto.Key)
	defer clear(wrapped)
	if err != nil || len(wrapped) <= 5 || !bytes.HasPrefix(wrapped, []byte("DPAPI")) {
		return nil, Protected
	}
	body := wrapped[5:]
	input := windows.DataBlob{Size: uint32(len(body)), Data: &body[0]}
	var output windows.DataBlob
	if windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output) != nil {
		return nil, Protected
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data))))
	if output.Size != 32 || output.Data == nil {
		return nil, Protected
	}
	decrypted := unsafe.Slice(output.Data, int(output.Size))
	key := bytes.Clone(decrypted)
	clear(decrypted)
	return key, nil
}
