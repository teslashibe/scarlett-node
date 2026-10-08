package coordinator

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func browserResultFixture(t *testing.T) BrowserResult {
	t.Helper()
	raw, err := os.ReadFile("../../api/fixtures/browser-result.json")
	if err != nil {
		t.Fatal(err)
	}
	var r BrowserResult
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

func gunzip(t *testing.T, body []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func hexSHA(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestBrowserResultFixtureDigests(t *testing.T) {
	r := browserResultFixture(t)
	if r.HTMLBytes != len(r.HTML) || r.HTMLSHA256 != hexSHA(r.HTML) || r.RequestSHA256 != "f24ba0094ed03be33c287a26997889217a0e6aebf62ca0b278f34dbecf0a175e" || r.Browser.Engine != "scrapling/0.4.15+scarlett.2" {
		t.Fatal("fixture digests")
	}
	encoded, body, err := EncodeBrowserResult(r)
	if err != nil || encoded.HTMLSHA256 != r.HTMLSHA256 || encoded.HTMLTruncated {
		t.Fatal(err)
	}
	var again BrowserResult
	if err := json.Unmarshal(gunzip(t, body), &again); err != nil || again.HTML != r.HTML || again.HTMLSHA256 != r.HTMLSHA256 {
		t.Fatal("encoded fixture differs", err)
	}
}

// Escaping is off, so an HTML-heavy page is not inflated: 3 MiB of <>&" stays
// well under the target and is sent whole.
func TestEncodeBrowserResultHTMLEscapingOff(t *testing.T) {
	r := browserResultFixture(t)
	r.HTML = strings.Repeat(`<>&"`, 3<<20/4)
	encoded, body, err := EncodeBrowserResult(r)
	if err != nil {
		t.Fatal(err)
	}
	raw := gunzip(t, body)
	if len(raw) > BrowserResultTarget || encoded.HTMLTruncated || encoded.HTML != r.HTML || bytes.Contains(raw, []byte(`\u003c`)) || len(body) > MaxBrowserResultGzipBytes {
		t.Fatal("escaped or cut", len(raw), encoded.HTMLTruncated)
	}
}

// A body over the target is cut on a code point boundary; html_bytes and
// html_sha256 describe the string actually sent.
func TestEncodeBrowserResultCutsOnACodePoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		html string
	}{
		{"quotes", strings.Repeat(`"é`, 4<<20)},             // 12 MiB of HTML, 16 MiB escaped
		{"controls", strings.Repeat("\x01€", 2<<20)},        // 8 MiB of HTML, 18 MiB escaped
		{"over the html cap", strings.Repeat("ab€", 4<<20)}, // 20 MiB of HTML
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := browserResultFixture(t)
			r.HTML = tc.html
			encoded, body, err := EncodeBrowserResult(r)
			if err != nil {
				t.Fatal(err)
			}
			raw := gunzip(t, body)
			var sent BrowserResult
			if err := json.Unmarshal(raw, &sent); err != nil {
				t.Fatal(err)
			}
			if !encoded.HTMLTruncated || !sent.HTMLTruncated || len(raw) > BrowserResultTarget || len(sent.HTML) > MaxBrowserHTMLBytes || !utf8.ValidString(sent.HTML) || !strings.HasPrefix(tc.html, sent.HTML) {
				t.Fatal("cut", len(raw), len(sent.HTML))
			}
			if sent.HTMLBytes != len(sent.HTML) || sent.HTMLSHA256 != hexSHA(sent.HTML) || encoded.HTMLSHA256 != sent.HTMLSHA256 {
				t.Fatal("digests describe another string")
			}
			// Nothing much was cut beyond what was needed.
			if len(raw) < BrowserResultTarget-64 && len(sent.HTML) < MaxBrowserHTMLBytes-4 {
				t.Fatal("cut too much", len(raw), len(sent.HTML))
			}
		})
	}
	// Incompressible content is cut further until the gzip body fits.
	random := make([]byte, 9<<20)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	r := browserResultFixture(t)
	r.HTML = strings.ToValidUTF8(hex.EncodeToString(random[:6<<20])+string(random[6<<20:]), "")
	if !utf8.ValidString(r.HTML) {
		t.Fatal("fixture")
	}
	encoded, body, err := EncodeBrowserResult(r)
	if err != nil || len(body) > MaxBrowserResultGzipBytes || !utf8.ValidString(encoded.HTML) || encoded.HTMLSHA256 != hexSHA(encoded.HTML) {
		t.Fatal("incompressible body", err, len(body))
	}
	if _, _, err := EncodeBrowserResult(BrowserResult{HTML: "\xff"}); err == nil {
		t.Fatal("invalid UTF-8 encoded")
	}
}

func TestEscapedJSONLenMatchesEncodingJSON(t *testing.T) {
	var all strings.Builder
	for r := rune(0); r < 0x80; r++ {
		all.WriteRune(r)
	}
	all.WriteString("é€😀\u2028\u2029\uFFFD")
	for _, s := range []string{all.String(), "", `<script>"x"&\</script>`} {
		var buf bytes.Buffer
		e := json.NewEncoder(&buf)
		e.SetEscapeHTML(false)
		if err := e.Encode(s); err != nil {
			t.Fatal(err)
		}
		if got, want := escapedJSONLen(s), buf.Len()-3; got != want {
			t.Fatalf("escaped length %d, encoding/json %d", got, want)
		}
	}
}

type uploadServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
	answer   func(n int, w http.ResponseWriter)
	throttle time.Duration
}

func newUploadServer(t *testing.T, answer func(n int, w http.ResponseWriter)) *uploadServer {
	s := &uploadServer{answer: answer}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body bytes.Buffer
		chunk := make([]byte, 256<<10)
		for {
			n, err := r.Body.Read(chunk)
			body.Write(chunk[:n])
			if err != nil {
				break
			}
			if s.throttle > 0 {
				time.Sleep(s.throttle)
			}
		}
		s.mu.Lock()
		s.requests = append(s.requests, r)
		s.bodies = append(s.bodies, body.Bytes())
		n := len(s.requests)
		s.mu.Unlock()
		s.answer(n, w)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *uploadServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func stored(_ int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"status":"stored"}`)
}

func uploadClient(origin string) *Client {
	c := New(origin, "synthetic-credential")
	c.uploadBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	return c
}

// A maximal 12 MiB body goes through a throttled server when the report
// deadline leaves room for it at 250 kB/s, and is never started otherwise.
func TestUploadBrowserResultSizeAndTime(t *testing.T) {
	body := make([]byte, MaxBrowserResultGzipBytes)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	server := newUploadServer(t, stored)
	server.throttle = time.Millisecond
	c := uploadClient(server.URL)
	if err := c.UploadBrowserResult(context.Background(), "11111111-1111-4111-8111-111111111111", body, time.Now().Add(60*time.Second)); err != nil {
		t.Fatal(err)
	}
	if server.count() != 1 || !bytes.Equal(server.bodies[0], body) {
		t.Fatal("upload body", server.count())
	}
	r := server.requests[0]
	if r.Method != http.MethodPost || r.URL.Path != "/api/node/v1/jobs/11111111-1111-4111-8111-111111111111/browser-result" || r.Header.Get("Content-Encoding") != "gzip" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get(NodeVersionHeader) != NodeRelease || r.Header.Get("Authorization") != "Bearer synthetic-credential" {
		t.Fatalf("upload request %s %s %v", r.Method, r.URL.Path, r.Header)
	}
	// 12 MiB at 250 kB/s needs 50 s: with 45 s left no try starts.
	if err := c.UploadBrowserResult(context.Background(), "11111111-1111-4111-8111-111111111111", body, time.Now().Add(45*time.Second)); !errors.Is(err, ErrBrowserUploadTooLate) || server.count() != 1 {
		t.Fatal("late upload started", err, server.count())
	}
	// Any body needs at least 15 s.
	if err := c.UploadBrowserResult(context.Background(), "11111111-1111-4111-8111-111111111111", []byte("x"), time.Now().Add(14*time.Second)); !errors.Is(err, ErrBrowserUploadTooLate) || server.count() != 1 {
		t.Fatal("upload started under the 15 s minimum", err)
	}
	for _, bad := range [][]byte{nil, make([]byte, MaxBrowserResultGzipBytes+1)} {
		if err := c.UploadBrowserResult(context.Background(), "11111111-1111-4111-8111-111111111111", bad, time.Now().Add(time.Minute)); err == nil || server.count() != 1 {
			t.Fatal("bad body size sent", len(bad))
		}
	}
	if err := c.UploadBrowserResult(context.Background(), "../x", []byte("x"), time.Now().Add(time.Minute)); err == nil || server.count() != 1 {
		t.Fatal("bad job ID sent")
	}
}

func TestUploadBrowserResultRetries(t *testing.T) {
	report := func() time.Time { return time.Now().Add(time.Minute) }
	job := "11111111-1111-4111-8111-111111111111"
	t.Run("transient failures are retried", func(t *testing.T) {
		server := newUploadServer(t, func(n int, w http.ResponseWriter) {
			if n < 3 {
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusServiceUnavailable)
				io.WriteString(w, `{"error":{"code":"network_unavailable","message":"x"}}`)
				return
			}
			stored(n, w)
		})
		c := New(server.URL, "synthetic-credential")
		c.uploadBackoff = []time.Duration{10 * time.Millisecond}
		started := time.Now()
		if err := c.UploadBrowserResult(context.Background(), job, []byte("gz"), report()); err != nil || server.count() != 3 {
			t.Fatal(err, server.count())
		}
		// Retry-After (1 s, clamped) outranks the shorter backoff.
		if time.Since(started) < 2*time.Second {
			t.Fatal("Retry-After not honoured", time.Since(started))
		}
		for _, body := range server.bodies {
			if string(body) != "gz" {
				t.Fatal("retry changed the body")
			}
		}
	})
	t.Run("three tries at most", func(t *testing.T) {
		server := newUploadServer(t, func(n int, w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) })
		var status *StatusError
		if err := uploadClient(server.URL).UploadBrowserResult(context.Background(), job, []byte("gz"), report()); !errors.As(err, &status) || status.Status != http.StatusBadGateway || server.count() != 3 {
			t.Fatal(err, server.count())
		}
	})
	for _, final := range []struct {
		status int
		code   string
	}{{409, "result_conflict"}, {409, "fenced"}, {409, "expired"}, {409, "already_reported"}, {400, "invalid_result"}, {401, ""}, {404, ""}, {413, ""}, {415, ""}} {
		t.Run("final "+final.code, func(t *testing.T) {
			server := newUploadServer(t, func(n int, w http.ResponseWriter) {
				w.WriteHeader(final.status)
				if final.code != "" {
					io.WriteString(w, `{"error":{"code":"`+final.code+`","message":"x"}}`)
				}
			})
			var status *StatusError
			if err := uploadClient(server.URL).UploadBrowserResult(context.Background(), job, []byte("gz"), report()); !errors.As(err, &status) || status.Status != final.status || status.Code != final.code || server.count() != 1 {
				t.Fatal(err, server.count())
			}
		})
	}
	t.Run("no retry once too little time is left", func(t *testing.T) {
		server := newUploadServer(t, func(n int, w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) })
		c := New(server.URL, "synthetic-credential")
		c.uploadBackoff = []time.Duration{time.Second}
		if err := c.UploadBrowserResult(context.Background(), job, []byte("gz"), time.Now().Add(15500*time.Millisecond)); err == nil || server.count() != 1 {
			t.Fatal(err, server.count())
		}
	})
	t.Run("a hung try ends with its context", func(t *testing.T) {
		release := make(chan struct{})
		var entered atomic.Bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			entered.Store(true)
			<-release
		}))
		t.Cleanup(func() { close(release); server.Close() })
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		started := time.Now()
		if err := uploadClient(server.URL).UploadBrowserResult(ctx, job, []byte("gz"), report()); err == nil || time.Since(started) > 5*time.Second || !entered.Load() {
			t.Fatal("hung upload", err, time.Since(started))
		}
	})
}
