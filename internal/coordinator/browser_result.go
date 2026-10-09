package coordinator

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// BrowserResult is the body of POST /api/node/v1/jobs/{job_id}/browser-result:
// the manifest of what the node's hidden browser rendered for a browser web
// job. The DOM itself travels as gzip parts (PUT …/browser-result/parts/{n})
// and is never cut: DOM says whether it was uploaded ("ok"), was over the
// page ceiling ("too_large", HTMLBytes is its size) or never existed because
// the node killed its browser for memory ("memory", TreePeakBytes is the
// tree size it reached). Scarlett did not see these bytes on the wire, so the
// coordinator labels anything served from them as not TLS-verified. Cookie
// values never appear here; set_cookie_names carries names only.
type BrowserResult struct {
	Version        string      `json:"version"`
	Attempt        string      `json:"attempt"`
	Fence          string      `json:"fence"`
	RequestSHA256  string      `json:"request_sha256"`
	URL            string      `json:"url"`
	FinalURL       string      `json:"final_url"`
	StatusCode     int         `json:"status_code"`
	Headers        [][2]string `json:"headers"`
	SetCookieNames []string    `json:"set_cookie_names"`
	ContentType    string      `json:"content_type"`
	DOM            string      `json:"dom"`
	HTMLBytes      int64       `json:"html_bytes"`
	// HTMLSHA256, UploadSHA256 and Parts describe the uploaded DOM and are
	// set exactly when DOM is "ok"; GzipBytes is 0 otherwise.
	HTMLSHA256    string   `json:"html_sha256,omitempty"`
	GzipBytes     int64    `json:"gzip_bytes"`
	UploadSHA256  string   `json:"upload_sha256,omitempty"`
	Parts         []string `json:"parts"`
	TreePeakBytes int64    `json:"tree_peak_bytes,omitempty"`
	// Challenge, Redirects and the rest are today's metadata.
	Challenge   string            `json:"challenge"`
	Redirects   []BrowserRedirect `json:"redirects"`
	Browser     BrowserInfo       `json:"browser"`
	StartedAtMS int64             `json:"started_at_ms"`
	DurationMS  int64             `json:"duration_ms"`
	// Solver is "used" when the operator's captcha solver cleared the page
	// and "needed" when the page stopped at a captcha that takes one; absent
	// otherwise. The coordinator remembers such domains and sends their
	// browser jobs to nodes that report solvers first.
	Solver string `json:"solver,omitempty"`
}

// BrowserRedirect is one main-frame redirect the browser followed.
type BrowserRedirect struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

// BrowserInfo names the engine, the Chrome for Testing version and the exact
// User-Agent the browser sent.
type BrowserInfo struct {
	Engine    string `json:"engine"`
	Version   string `json:"version"`
	UserAgent string `json:"user_agent"`
}

// BrowserResultParts is GET …/browser-result/parts: the stored part set.
type BrowserResultParts struct {
	UploadSHA256 string        `json:"upload_sha256,omitempty"`
	Parts        []BrowserPart `json:"parts"`
}

// BrowserPart is one stored part.
type BrowserPart struct {
	N      int    `json:"n"`
	SHA256 string `json:"sha256"`
}

// The browser-result DOM states.
const (
	DOMOK       = "ok"
	DOMTooLarge = "too_large"
	DOMMemory   = "memory"
)

const (
	// PageMax is the page ceiling: a web hop's entity bytes, and the
	// browser's DOM in UTF-8 bytes.
	PageMax = 67108864
	// MaxBrowserHTMLBytes caps the rendered document, in UTF-8 bytes.
	MaxBrowserHTMLBytes = PageMax
	// BrowserPartBytes is the size of every upload part but the last.
	BrowserPartBytes = 2 << 20
	// MaxBrowserParts bounds the parts of one upload: a DOM of PageMax bytes
	// that does not compress still fits.
	MaxBrowserParts = 33
	// MaxBrowserGzipBytes caps the gzip stream.
	MaxBrowserGzipBytes = MaxBrowserParts * BrowserPartBytes
	// maxBrowserManifestBytes bounds the manifest JSON.
	maxBrowserManifestBytes = 256 << 10
	// maxBrowserPartsReply bounds GET …/parts.
	maxBrowserPartsReply = 16 << 10
	// browserUploadRate is the slowest uplink a part try is planned for, in
	// bytes per second.
	browserUploadRate = 250_000
	// browserUploadTries bounds the tries of one part or of the manifest.
	browserUploadTries = 3
	// browserPartMinimum is the least time before the report deadline in
	// which a part try may start; browserManifestReserve is kept after a
	// part for the manifest.
	browserPartMinimum     = 10 * time.Second
	browserManifestReserve = 5 * time.Second
	// browserManifestMinimum is the least time before the report deadline in
	// which a manifest try may start.
	browserManifestMinimum = 3 * time.Second
)

// browserUploadBackoff is the wait before each retry of a part or manifest.
var browserUploadBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// ErrBrowserUploadTooLate means a part or the manifest could not start with
// enough time left before the report deadline.
var ErrBrowserUploadTooLate = errors.New("browser result upload: not enough time before the report deadline")

// ErrDOMTooLarge is a DOM over PageMax bytes.
var ErrDOMTooLarge = errors.New("browser DOM is larger than the page ceiling")

// BrowserUpload is a DOM file compressed for upload: the gzip stream at Path
// and what the manifest says about it.
type BrowserUpload struct {
	Path         string
	HTMLBytes    int64
	HTMLSHA256   string
	GzipBytes    int64
	UploadSHA256 string
	Parts        []string
}

// partWriter writes the gzip stream to a file and hashes it whole and per
// 2 MiB part as it goes.
type partWriter struct {
	file  *os.File
	whole hash.Hash
	part  hash.Hash
	fill  int
	total int64
	parts []string
}

func (w *partWriter) Write(b []byte) (int, error) {
	if w.total+int64(len(b)) > MaxBrowserGzipBytes {
		return 0, errors.New("browser DOM gzip stream exceeds the upload limit")
	}
	n, err := w.file.Write(b)
	w.total += int64(n)
	w.whole.Write(b[:n])
	for rest := b[:n]; len(rest) > 0; {
		take := min(len(rest), BrowserPartBytes-w.fill)
		w.part.Write(rest[:take])
		w.fill += take
		rest = rest[take:]
		if w.fill == BrowserPartBytes {
			w.closePart()
		}
	}
	return n, err
}

func (w *partWriter) closePart() {
	w.parts = append(w.parts, hex.EncodeToString(w.part.Sum(nil)))
	w.part.Reset()
	w.fill = 0
}

// PrepareBrowserUpload compresses the DOM at htmlPath (UTF-8, at most PageMax
// bytes) with gzip level 6 into gzipPath, created exclusively and private, and
// returns the hashes the manifest carries. The DOM is read once and never held
// in memory; on failure gzipPath is removed.
func PrepareBrowserUpload(htmlPath, gzipPath string) (up BrowserUpload, err error) {
	in, err := os.Open(htmlPath)
	if err != nil {
		return up, errors.New("browser DOM unreadable")
	}
	defer in.Close()
	out, err := os.OpenFile(gzipPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return up, errors.New("browser DOM gzip file unavailable")
	}
	defer func() {
		if cerr := out.Close(); err == nil && cerr != nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(gzipPath)
		}
	}()
	pw := &partWriter{file: out, whole: sha256.New(), part: sha256.New()}
	zw, err := gzip.NewWriterLevel(pw, 6)
	if err != nil {
		return up, err
	}
	html := sha256.New()
	n, err := io.Copy(io.MultiWriter(zw, html), io.LimitReader(in, MaxBrowserHTMLBytes+1))
	if err != nil {
		return up, err
	}
	if n > MaxBrowserHTMLBytes {
		return up, ErrDOMTooLarge
	}
	if err = zw.Close(); err != nil {
		return up, err
	}
	if pw.fill > 0 {
		pw.closePart()
	}
	if err = out.Sync(); err != nil {
		return up, err
	}
	return BrowserUpload{Path: gzipPath, HTMLBytes: n, HTMLSHA256: hex.EncodeToString(html.Sum(nil)), GzipBytes: pw.total,
		UploadSHA256: hex.EncodeToString(pw.whole.Sum(nil)), Parts: pw.parts}, nil
}

// EncodeBrowserResult fills r's empty lists and returns its JSON (HTML
// escaping off), checking that the DOM fields agree with r.DOM.
func EncodeBrowserResult(r BrowserResult) (BrowserResult, []byte, error) {
	if r.Headers == nil {
		r.Headers = [][2]string{}
	}
	if r.SetCookieNames == nil {
		r.SetCookieNames = []string{}
	}
	if r.Redirects == nil {
		r.Redirects = []BrowserRedirect{}
	}
	if r.Parts == nil {
		r.Parts = []string{}
	}
	switch r.DOM {
	case DOMOK:
		if r.HTMLBytes < 0 || r.HTMLBytes > MaxBrowserHTMLBytes || !digest(r.HTMLSHA256) || !digest(r.UploadSHA256) || r.GzipBytes < 1 || r.GzipBytes > MaxBrowserGzipBytes ||
			int64(len(r.Parts)) != (r.GzipBytes+BrowserPartBytes-1)/BrowserPartBytes || r.TreePeakBytes < 0 {
			return r, nil, errors.New("browser result: inconsistent DOM upload")
		}
		for _, part := range r.Parts {
			if !digest(part) {
				return r, nil, errors.New("browser result: invalid part digest")
			}
		}
	case DOMTooLarge:
		if r.HTMLBytes <= MaxBrowserHTMLBytes || r.HTMLSHA256 != "" || r.UploadSHA256 != "" || r.GzipBytes != 0 || len(r.Parts) != 0 || r.TreePeakBytes < 0 {
			return r, nil, errors.New("browser result: inconsistent too_large")
		}
	case DOMMemory:
		if r.HTMLBytes != 0 || r.HTMLSHA256 != "" || r.UploadSHA256 != "" || r.GzipBytes != 0 || len(r.Parts) != 0 || r.TreePeakBytes < 1 {
			return r, nil, errors.New("browser result: inconsistent memory")
		}
	default:
		return r, nil, errors.New("browser result: unknown dom state")
	}
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(r); err != nil {
		return r, nil, err
	}
	raw := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(raw) > maxBrowserManifestBytes {
		return r, nil, errors.New("browser result manifest too large")
	}
	return r, raw, nil
}

// UploadStats counts what one UploadBrowserResult sent, for the node's log.
type UploadStats struct {
	PartsSent, PartsSkipped, Retries int
}

// UploadBrowserResult stores the browser's result for jobID: with r.DOM "ok"
// the parts of the gzip stream at gzipPath first, then the manifest r. It
// uses the client's transport, roots and version headers but not its
// 10-second timeout: every request runs under the report deadline. It reads
// the stored part set first and skips parts already stored under the same
// upload sha256 (the coordinator replaces a set with a different one). Each
// part is held in memory alone, and each part or manifest is tried at most
// three times, after 1, 2 and 4 seconds or the coordinator's Retry-After;
// only a transport failure, 429 or 5xx is retried. A part try starts only
// while max(10 s, size / 250 kB/s + 5 s) is left before report, a manifest
// try while 3 s is. A manifest answered 409 parts_incomplete sends the
// missing parts once more and posts again.
func (c *Client) UploadBrowserResult(ctx context.Context, jobID string, r BrowserResult, gzipPath string, report time.Time) (UploadStats, error) {
	var stats UploadStats
	base, err := JobPath(jobID, "browser-result")
	if err != nil {
		return stats, err
	}
	r, manifest, err := EncodeBrowserResult(r)
	if err != nil {
		return stats, err
	}
	client := *c.HTTP
	client.Timeout = 0
	u := browserUploader{c: c, client: &client, base: base, r: r, report: report, stats: &stats}
	if r.DOM == DOMOK {
		file, err := os.Open(gzipPath)
		if err != nil {
			return stats, errors.New("browser DOM gzip file unreadable")
		}
		defer file.Close()
		if info, err := file.Stat(); err != nil || info.Size() != r.GzipBytes {
			return stats, errors.New("browser DOM gzip file does not match the manifest")
		}
		u.file = file
		if err := u.sendParts(ctx); err != nil {
			return stats, err
		}
	}
	for round := 0; ; round++ {
		status, err := u.send(ctx, http.MethodPost, base, manifest, "application/json", nil, browserManifestMinimum)
		if err == nil {
			return stats, nil
		}
		var se *StatusError
		if round > 0 || r.DOM != DOMOK || !errors.As(err, &se) || status != http.StatusConflict || se.Code != "parts_incomplete" {
			return stats, err
		}
		if err := u.sendParts(ctx); err != nil {
			return stats, err
		}
	}
}

type browserUploader struct {
	c      *Client
	client *http.Client
	base   string
	r      BrowserResult
	file   *os.File
	report time.Time
	stats  *UploadStats
}

// sendParts sends every part the coordinator does not hold yet.
func (u *browserUploader) sendParts(ctx context.Context) error {
	have := u.storedParts(ctx)
	buf := make([]byte, BrowserPartBytes)
	for i, want := range u.r.Parts {
		n := i + 1
		if have[n] == want {
			u.stats.PartsSkipped++
			continue
		}
		size := min(int64(BrowserPartBytes), u.r.GzipBytes-int64(i)*BrowserPartBytes)
		part := buf[:size]
		if _, err := u.file.ReadAt(part, int64(i)*BrowserPartBytes); err != nil {
			return errors.New("browser DOM gzip file unreadable")
		}
		sum := sha256.Sum256(part)
		if hex.EncodeToString(sum[:]) != want {
			return errors.New("browser DOM gzip file changed")
		}
		need := max(browserPartMinimum, time.Duration(size)*time.Second/browserUploadRate+browserManifestReserve)
		headers := map[string]string{"X-Scarlett-Part-SHA256": want}
		if _, err := u.send(ctx, http.MethodPut, u.base+"/parts/"+strconv.Itoa(n), part, "application/octet-stream", headers, need); err != nil {
			return err
		}
		u.stats.PartsSent++
	}
	return nil
}

// storedParts reads GET …/parts once and returns the part digests stored
// under this upload's sha256. Any failure reads as nothing stored.
func (u *browserUploader) storedParts(ctx context.Context) map[int]string {
	have := map[int]string{}
	if time.Until(u.report) < browserPartMinimum {
		return have
	}
	tryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := u.request(tryCtx, http.MethodGet, u.base+"/parts", nil, "")
	if err != nil {
		return have
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return have
	}
	defer resp.Body.Close()
	u.c.observeRelease(resp.Header)
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBrowserPartsReply+1))
	var stored BrowserResultParts
	if resp.StatusCode != http.StatusOK || err != nil || len(data) > maxBrowserPartsReply || json.Unmarshal(data, &stored) != nil || stored.UploadSHA256 != u.r.UploadSHA256 {
		return have
	}
	for _, p := range stored.Parts {
		if p.N >= 1 && p.N <= MaxBrowserParts && digest(p.SHA256) {
			have[p.N] = p.SHA256
		}
	}
	return have
}

func (u *browserUploader) request(ctx context.Context, method, path string, body []byte, contentType string) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.c.Origin+path, reader)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(NodeVersionHeader, NodeRelease)
	req.Header.Set("X-Scarlett-Attempt", u.r.Attempt)
	req.Header.Set("X-Scarlett-Fence", u.r.Fence)
	req.Header.Set("X-Scarlett-Request-SHA256", u.r.RequestSHA256)
	if u.r.UploadSHA256 != "" {
		req.Header.Set("X-Scarlett-Upload-SHA256", u.r.UploadSHA256)
	}
	if u.c.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+u.c.Credential)
	}
	return req, nil
}

// send makes one request with the upload's retry rule and returns its last
// status. need is the least time before the report deadline for a try.
func (u *browserUploader) send(ctx context.Context, method, path string, body []byte, contentType string, headers map[string]string, need time.Duration) (int, error) {
	backoff := browserUploadBackoff
	if u.c.uploadBackoff != nil {
		backoff = u.c.uploadBackoff
	}
	var last error = ErrBrowserUploadTooLate
	status := 0
	for try := 0; try < browserUploadTries; try++ {
		if try > 0 {
			wait := backoff[min(try-1, len(backoff)-1)]
			var se *StatusError
			if errors.As(last, &se) && se.RetryAfter > wait {
				wait = se.RetryAfter
			}
			if time.Until(u.report)-wait < need {
				return status, last
			}
			u.stats.Retries++
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return status, last
			case <-timer.C:
			}
		}
		if time.Until(u.report) < need {
			return status, last
		}
		var retry bool
		status, retry, last = u.once(ctx, method, path, body, contentType, headers)
		if last == nil || !retry {
			return status, last
		}
	}
	return status, last
}

func (u *browserUploader) once(ctx context.Context, method, path string, body []byte, contentType string, headers map[string]string) (int, bool, error) {
	tryCtx, cancel := context.WithDeadline(ctx, u.report)
	defer cancel()
	req, err := u.request(tryCtx, method, path, body, contentType)
	if err != nil {
		return 0, false, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return 0, ctx.Err() == nil, errors.New("coordinator unavailable")
	}
	defer resp.Body.Close()
	u.c.observeRelease(resp.Header)
	if resp.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBytes))
		return resp.StatusCode, false, nil
	}
	err = statusError(resp)
	return resp.StatusCode, resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500, fmt.Errorf("%s %s: %w", method, browserRoute(path), err)
}

// browserRoute names a browser-result route for errors without the job ID.
func browserRoute(path string) string {
	switch {
	case strings.HasSuffix(path, "/parts"):
		return "parts"
	case strings.Contains(path, "/parts/"):
		return "part"
	}
	return "manifest"
}
