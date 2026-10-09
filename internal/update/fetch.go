package update

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Error codes shown to operators. Raw tool output is never shown.
const (
	CodeNetwork            = "network"
	CodeSignatureInvalid   = "signature_invalid"
	CodeIdentityMismatch   = "identity_mismatch"
	CodeRequirement        = "requirement_changed"
	CodeDiskFull           = "disk_full"
	CodeNotWritable        = "not_writable"
	CodeTranslocated       = "translocated"
	CodeUnsupported        = "unsupported"
	CodeNoKey              = "no_update_key"
	CodeBusy               = "busy"
	CodeInstallFailed      = "install_failed"
	CodeAppManagement      = "app_management"
	CodeNotInstalledLayout = "not_installed_layout"
)

// Error is a refusal with a fixed operator-facing code.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return e.Code + ": " + e.Err.Error()
}
func (e *Error) Unwrap() error { return e.Err }

func fail(code string, err error) error { return &Error{Code: code, Err: err} }

// CodeOf returns an error's fixed code, or install_failed.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeInstallFailed
}

// DefaultOrigin is the release download origin.
const DefaultOrigin = "https://network.scarlett.ai"

// Client reads the manifest and artifacts from one HTTPS origin.
type Client struct {
	origin string
	http   *http.Client
}

// NewClient accepts only an https origin without path, query or credentials.
// caFile adds a private CA (loopback rehearsals); empty uses system roots.
func NewClient(origin, caFile string) (*Client, error) {
	u, err := url.Parse(strings.TrimSuffix(origin, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("update origin must be an https origin")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		if !filepath.IsAbs(caFile) {
			return nil, errors.New("update CA must be an absolute path")
		}
		raw, err := os.ReadFile(caFile)
		if err != nil || len(raw) > 1<<20 {
			return nil, errors.New("invalid update CA bundle")
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(raw) {
			return nil, errors.New("invalid update CA bundle")
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	transport.ResponseHeaderTimeout = 30 * time.Second
	return &Client{
		origin: u.Scheme + "://" + u.Host,
		// Redirects are refused: every path is derived and same-origin.
		http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// Origin is the client's origin.
func (c *Client) Origin() string { return c.origin }

func (c *Client) get(ctx context.Context, path string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.Header.Set("Cache-Control", "no-cache")
	return c.http.Do(req)
}

// Manifest reads the selected manifest.
func (c *Client) Manifest(ctx context.Context) (*Manifest, error) {
	return c.manifest(ctx, "/downloads/manifest.json")
}

// VersionedManifest reads one retained release's immutable manifest.
func (c *Client) VersionedManifest(ctx context.Context, version string) (*Manifest, error) {
	m, err := c.manifest(ctx, "/downloads/v"+version+"/manifest.json")
	if err == nil && m.Version != version {
		err = fail(CodeNetwork, errors.New("retained manifest names another version"))
	}
	return m, err
}

func (c *Client) manifest(ctx context.Context, path string) (*Manifest, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := c.get(ctx, path, nil)
	if err != nil {
		return nil, fail(CodeNetwork, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fail(CodeNetwork, fmt.Errorf("manifest status %d", resp.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxManifestBytes+1))
	if err != nil {
		return nil, fail(CodeNetwork, err)
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, fail(CodeNetwork, err)
	}
	return m, nil
}

// Progress reports downloaded bytes.
type Progress func(received, total int64)

// DownloadOptions tune one download.
type DownloadOptions struct {
	// RateLimit caps bytes per second; zero is unlimited.
	RateLimit int64
	Progress  Progress
}

// Download fetches t into dir (a private directory) with resume, then checks
// length, SHA-256 and, when signed, the minisign signature from one of keys
// before the file takes its final name. It returns the verified file's path.
// Unsigned downloads are only rollback sources that the OS signature check
// verifies again.
func (c *Client) Download(ctx context.Context, t Target, dir string, keys []PublicKey, signed bool, opts DownloadOptions) (string, error) {
	if t.Filename == "" || strings.ContainsAny(t.Filename, `/\`) || t.Path != versionedPath(t.Version, t.Filename) {
		return "", fail(CodeNetwork, errors.New("invalid download target"))
	}
	final := filepath.Join(dir, t.Filename)
	if err := VerifyFile(final, t, keys, signed); err == nil {
		return final, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(final)
	}
	if free, err := freeBytes(dir); err == nil && free < uint64(3*t.Bytes) {
		return "", fail(CodeDiskFull, errors.New("not enough free disk space for the update"))
	}
	part := final + ".part"
	for attempt := 0; ; attempt++ {
		err := c.fetch(ctx, t, part, opts)
		if err == nil {
			break
		}
		if ctx.Err() != nil || attempt >= 4 {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Duration(attempt+1) * 5 * time.Second):
		}
	}
	if err := VerifyFile(part, t, keys, signed); err != nil {
		_ = os.Remove(part)
		return "", err
	}
	if err := os.Rename(part, final); err != nil {
		return "", err
	}
	return final, nil
}

func (c *Client) fetch(ctx context.Context, t Target, part string, opts DownloadOptions) error {
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("partial download must be a regular file")
	}
	offset := info.Size()
	if offset > t.Bytes {
		offset = 0
	}
	if offset == t.Bytes {
		return nil
	}
	header := http.Header{}
	if offset > 0 {
		header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	resp, err := c.get(ctx, t.Path, header)
	if err != nil {
		return fail(CodeNetwork, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusPartialContent && offset > 0 && strings.HasPrefix(resp.Header.Get("Content-Range"), "bytes "+strconv.FormatInt(offset, 10)+"-"):
	case resp.StatusCode == http.StatusOK:
		offset = 0
	default:
		return fail(CodeNetwork, fmt.Errorf("download status %d", resp.StatusCode))
	}
	if err = f.Truncate(offset); err != nil {
		return err
	}
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	received := offset
	buf := make([]byte, 256<<10)
	started, base := time.Now(), offset
	body := io.LimitReader(resp.Body, t.Bytes-offset+1)
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			if received+int64(n) > t.Bytes {
				return fail(CodeNetwork, errors.New("download is larger than the manifest says"))
			}
			if _, err = f.Write(buf[:n]); err != nil {
				return err
			}
			received += int64(n)
			if opts.Progress != nil {
				opts.Progress(received, t.Bytes)
			}
			if opts.RateLimit > 0 {
				ahead := time.Duration(float64(received-base)/float64(opts.RateLimit)*float64(time.Second)) - time.Since(started)
				if ahead > 0 {
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(ahead):
					}
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fail(CodeNetwork, readErr)
		}
	}
	if received != t.Bytes {
		return fail(CodeNetwork, errors.New("download ended early"))
	}
	return f.Sync()
}

// VerifyFile checks a file's length and SHA-256 against t and, when signed,
// its minisign signature from one of keys, bound to t's file name and version.
func VerifyFile(path string, t Target, keys []PublicKey, signed bool) error {
	if signed && len(keys) == 0 {
		return fail(CodeNoKey, errors.New("this build trusts no update key"))
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != t.Bytes {
		return fail(CodeSignatureInvalid, errors.New("download length does not match the manifest"))
	}
	sum, pre := sha256.New(), NewPrehash()
	if _, err = io.Copy(io.MultiWriter(sum, pre), f); err != nil {
		return err
	}
	if hex.EncodeToString(sum.Sum(nil)) != t.SHA256 {
		return fail(CodeSignatureInvalid, errors.New("download SHA-256 does not match the manifest"))
	}
	if !signed {
		return nil
	}
	sig, err := ParseSignature(t.Signature)
	if err != nil {
		return fail(CodeSignatureInvalid, err)
	}
	if err = sig.Verify(keys, pre.Sum(nil), t.Filename, t.Version); err != nil {
		return fail(CodeSignatureInvalid, err)
	}
	return nil
}
