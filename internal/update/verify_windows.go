package update

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// certEUntrustedRoot is CERT_E_UNTRUSTEDROOT: the digest and signature
// verified but the self-signed root is not trusted, which is exactly what a
// self-signed-stable installer reports (check-windows-signatures.ps1). A
// different result means a bad digest, no signature, or a trusted chain
// someone added.
const certEUntrustedRoot = 0x800B0109

var (
	crypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = crypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = crypt32.NewProc("CryptMsgClose")
)

const cmsgSignerCertInfoParam = 7

func winVerifyTrust(path string) (uint32, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	file := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: name}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(file),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	result := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if result == nil {
		return 0, nil
	}
	var errno windows.Errno
	if errors.As(result, &errno) {
		return uint32(errno), nil
	}
	return 0, result
}

// signerCertificate returns the DER certificate that signed path.
func signerCertificate(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var encoding, content, format uint32
	var store, msg windows.Handle
	if err = windows.CryptQueryObject(windows.CERT_QUERY_OBJECT_FILE, unsafe.Pointer(name), windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, &content, &format, &store, &msg, nil); err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))
	var size uint32
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); r == 0 || size == 0 {
		return nil, fmt.Errorf("signer information unavailable: %v", e)
	}
	info := make([]byte, size)
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, uintptr(unsafe.Pointer(&info[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return nil, fmt.Errorf("signer information unavailable: %v", e)
	}
	cert, err := windows.CertFindCertificateInStore(store, windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING, 0, windows.CERT_FIND_SUBJECT_CERT, unsafe.Pointer(&info[0]), nil)
	if err != nil {
		return nil, err
	}
	defer windows.CertFreeCertificateContext(cert)
	return append([]byte(nil), unsafe.Slice(cert.EncodedCert, cert.Length)...), nil
}

func fileVersion(path string) (string, error) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return "", errors.New("no version resource")
	}
	buf := make([]byte, size)
	if err = windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return "", err
	}
	var fixed *windows.VS_FIXEDFILEINFO
	var length uint32
	if err = windows.VerQueryValue(unsafe.Pointer(&buf[0]), `\`, unsafe.Pointer(&fixed), &length); err != nil || fixed == nil {
		return "", errors.New("no fixed version")
	}
	return fmt.Sprintf("%d.%d.%d", fixed.ProductVersionMS>>16, fixed.ProductVersionMS&0xffff, fixed.ProductVersionLS>>16), nil
}

// VerifyWindowsInstaller proves an installer carries the pinned self-signed
// Authenticode signature and the expected product version.
func VerifyWindowsInstaller(path, version string, trust Trust) error {
	result, err := winVerifyTrust(path)
	if err != nil || result != certEUntrustedRoot {
		return fail(CodeIdentityMismatch, fmt.Errorf("installer signature check returned 0x%08X", result))
	}
	der, err := signerCertificate(path)
	if err != nil {
		return fail(CodeIdentityMismatch, err)
	}
	sum := sha256.Sum256(der)
	cert, err := x509.ParseCertificate(der)
	if err != nil || hex.EncodeToString(sum[:]) != trust.WindowsSHA256 || cert.Subject.String() != cert.Issuer.String() {
		return fail(CodeIdentityMismatch, errors.New("installer is not signed with the pinned certificate"))
	}
	core, _, _ := strings.Cut(version, "-")
	got, err := fileVersion(path)
	if err != nil || got != core {
		return fail(CodeSignatureInvalid, errors.New("installer version differs from the manifest"))
	}
	return nil
}

// InstalledExecutable returns the running app's executable when it lives in
// a per-user install directory Scarlett can write.
func InstalledExecutable(exe string) (string, error) {
	dir := filepath.Dir(exe)
	probe := filepath.Join(dir, ".scarlett-update-probe-"+randomSuffix())
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fail(CodeNotWritable, err)
	}
	f.Close()
	_ = os.Remove(probe)
	return exe, nil
}
