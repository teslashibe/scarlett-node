package coordinator

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"
	"unicode/utf8"
)

// BrowserResult is the decompressed body of POST
// /api/node/v1/jobs/{job_id}/browser-result: the page as the node's hidden
// browser rendered it for a browser web job. Scarlett did not see these bytes
// on the wire, so the coordinator labels anything served from them as not
// TLS-verified. Cookie values never appear here; set_cookie_names carries
// names only.
type BrowserResult struct {
	Version        string            `json:"version"`
	Attempt        string            `json:"attempt"`
	Fence          string            `json:"fence"`
	RequestSHA256  string            `json:"request_sha256"`
	URL            string            `json:"url"`
	FinalURL       string            `json:"final_url"`
	StatusCode     int               `json:"status_code"`
	Headers        [][2]string       `json:"headers"`
	SetCookieNames []string          `json:"set_cookie_names"`
	ContentType    string            `json:"content_type"`
	HTML           string            `json:"html"`
	HTMLBytes      int               `json:"html_bytes"`
	HTMLSHA256     string            `json:"html_sha256"`
	HTMLTruncated  bool              `json:"html_truncated"`
	Challenge      string            `json:"challenge"`
	Redirects      []BrowserRedirect `json:"redirects"`
	Browser        BrowserInfo       `json:"browser"`
	StartedAtMS    int64             `json:"started_at_ms"`
	DurationMS     int64             `json:"duration_ms"`
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

const (
	// MaxBrowserHTMLBytes caps the rendered document, in UTF-8 bytes.
	MaxBrowserHTMLBytes = 10485760
	// MaxBrowserResultGzipBytes caps the compressed upload.
	MaxBrowserResultGzipBytes = 12582912
	// MaxBrowserResultBytes is the coordinator's limit on the decompressed body.
	MaxBrowserResultBytes = 16777216
	// BrowserResultTarget is the decompressed size the node shrinks html to,
	// 64 KiB under the coordinator's limit.
	BrowserResultTarget = MaxBrowserResultBytes - 64<<10
	// browserUploadRate is the slowest uplink an upload try is planned for,
	// in bytes per second.
	browserUploadRate = 250_000
	// browserUploadTries bounds the tries of one upload.
	browserUploadTries = 3
	// browserUploadMinimum is the least time before the report deadline in
	// which a try may start, whatever the body size.
	browserUploadMinimum = 15 * time.Second
)

// browserUploadBackoff is the wait before each retry of an upload.
var browserUploadBackoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// ErrBrowserUploadTooLate means no upload try could start with enough time
// left before the report deadline.
var ErrBrowserUploadTooLate = errors.New("browser result upload: not enough time before the report deadline")

// EncodeBrowserResult fixes up r and returns its gzip body. html is first
// capped at MaxBrowserHTMLBytes, then cut further until the JSON body (HTML
// escaping off) fits BrowserResultTarget and its gzip fits
// MaxBrowserResultGzipBytes. Every cut lands on a UTF-8 code point boundary
// and sets html_truncated. html_bytes and html_sha256 are computed here, on
// the final string, so they always describe the bytes sent.
func EncodeBrowserResult(r BrowserResult) (BrowserResult, []byte, error) {
	if !utf8.ValidString(r.HTML) {
		return r, nil, errors.New("browser result html is not UTF-8")
	}
	if r.Headers == nil {
		r.Headers = [][2]string{}
	}
	if r.SetCookieNames == nil {
		r.SetCookieNames = []string{}
	}
	if r.Redirects == nil {
		r.Redirects = []BrowserRedirect{}
	}
	if len(r.HTML) > MaxBrowserHTMLBytes {
		r.HTML, r.HTMLTruncated = cutUTF8(r.HTML, MaxBrowserHTMLBytes), true
	}
	target := BrowserResultTarget
	for range 64 {
		raw, err := encodeBrowserJSON(&r)
		if err != nil {
			return r, nil, err
		}
		if len(raw) > target {
			// Cut html to what fits next to the rest of the body, counting
			// each code point at its escaped size.
			overhead := len(raw) - escapedJSONLen(r.HTML)
			r.HTML, r.HTMLTruncated = fitEscaped(r.HTML, target-overhead), true
			continue
		}
		var buf bytes.Buffer
		zw, err := gzip.NewWriterLevel(&buf, 6)
		if err != nil {
			return r, nil, err
		}
		if _, err := zw.Write(raw); err != nil {
			return r, nil, err
		}
		if err := zw.Close(); err != nil {
			return r, nil, err
		}
		if buf.Len() <= MaxBrowserResultGzipBytes {
			return r, buf.Bytes(), nil
		}
		if r.HTML == "" {
			break
		}
		// Barely compressible content: shrink the decompressed target by the
		// overshoot and try again.
		target = int(int64(target) * MaxBrowserResultGzipBytes / int64(buf.Len()) * 15 / 16)
	}
	return r, nil, errors.New("browser result cannot fit the upload limits")
}

func encodeBrowserJSON(r *BrowserResult) ([]byte, error) {
	sum := sha256.Sum256([]byte(r.HTML))
	r.HTMLBytes, r.HTMLSHA256 = len(r.HTML), hex.EncodeToString(sum[:])
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(false)
	if err := e.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// cutUTF8 returns the longest prefix of s within limit bytes that ends on a
// code point boundary.
func cutUTF8(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(s) <= limit {
		return s
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit]
}

// escapedRuneLen is how many bytes encoding/json writes for r inside a string
// with HTML escaping off.
func escapedRuneLen(r rune, size int) int {
	switch {
	case r == '"' || r == '\\' || r == '\n' || r == '\r' || r == '\t' || r == '\b' || r == '\f':
		return 2
	case r < 0x20 || r == '\u2028' || r == '\u2029' || r == utf8.RuneError && size == 1:
		return 6
	}
	return size
}

func escapedJSONLen(s string) int {
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		n += escapedRuneLen(r, size)
		i += size
	}
	return n
}

// fitEscaped returns the longest code point prefix of s whose escaped size is
// within limit.
func fitEscaped(s string, limit int) string {
	n := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		n += escapedRuneLen(r, size)
		if n > limit {
			return s[:i]
		}
		i += size
	}
	return s
}

// UploadBrowserResult posts one gzip browser result for jobID and returns nil
// once the coordinator stored it (200). It uses the client's transport, roots
// and version headers but not its 10-second timeout: every try runs under the
// report deadline instead, starts only while max(15 s, size / 250 kB/s) is
// left before it, and at most three tries are made, the retries after 1 and
// 2 seconds or the coordinator's Retry-After. Only a transport failure, 429
// or 5xx is retried; the coordinator stores one body per attempt and answers
// a repeat of the same body with 200.
func (c *Client) UploadBrowserResult(ctx context.Context, jobID string, gzipBody []byte, report time.Time) error {
	path, err := JobPath(jobID, "browser-result")
	if err != nil {
		return err
	}
	if len(gzipBody) == 0 || len(gzipBody) > MaxBrowserResultGzipBytes {
		return errors.New("browser result upload: invalid body size")
	}
	need := max(browserUploadMinimum, time.Duration(int64(len(gzipBody))*int64(time.Second)/browserUploadRate))
	backoff := browserUploadBackoff
	if c.uploadBackoff != nil {
		backoff = c.uploadBackoff
	}
	client := *c.HTTP
	client.Timeout = 0
	var last error = ErrBrowserUploadTooLate
	for try := 0; try < browserUploadTries; try++ {
		if try > 0 {
			wait := backoff[min(try-1, len(backoff)-1)]
			var status *StatusError
			if errors.As(last, &status) && status.RetryAfter > wait {
				wait = status.RetryAfter
			}
			if time.Until(report)-wait < need {
				return last
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return last
			case <-timer.C:
			}
		}
		if time.Until(report) < need {
			return last
		}
		var retry bool
		retry, last = c.uploadBrowserResultOnce(ctx, &client, path, gzipBody, report)
		if last == nil || !retry {
			return last
		}
	}
	return last
}

func (c *Client) uploadBrowserResultOnce(ctx context.Context, client *http.Client, path string, body []byte, report time.Time) (bool, error) {
	tryCtx, cancel := context.WithDeadline(ctx, report)
	defer cancel()
	req, err := http.NewRequestWithContext(tryCtx, http.MethodPost, c.Origin+path, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set(NodeVersionHeader, NodeRelease)
	if c.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.Credential)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ctx.Err() == nil, errors.New("coordinator unavailable")
	}
	defer resp.Body.Close()
	c.observeRelease(resp.Header)
	if resp.StatusCode == http.StatusOK {
		return false, nil
	}
	err = statusError(resp)
	return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500, err
}
