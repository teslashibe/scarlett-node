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
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const testJob = "11111111-1111-4111-8111-111111111111"

func decodeStrict(t *testing.T, raw []byte, out any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		t.Fatal(err)
	}
}

func browserResultFixture(t *testing.T, name string) BrowserResult {
	t.Helper()
	raw, err := os.ReadFile("../../api/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var r BrowserResult
	decodeStrict(t, raw, &r)
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

func hexSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// The manifest fixtures are self-consistent: the dom ok one's part file
// hashes to its part and upload sha256 and gunzips to the DOM it describes;
// every fixture passes the node's own manifest checks.
func TestBrowserResultFixtures(t *testing.T) {
	ok := browserResultFixture(t, "browser-result.json")
	part, err := os.ReadFile("../../api/fixtures/browser-result-part-1.gz")
	if err != nil {
		t.Fatal(err)
	}
	html := gunzip(t, part)
	if ok.DOM != DOMOK || len(ok.Parts) != 1 || ok.Parts[0] != hexSHA(part) || ok.UploadSHA256 != hexSHA(part) || ok.GzipBytes != int64(len(part)) ||
		ok.HTMLBytes != int64(len(html)) || ok.HTMLSHA256 != hexSHA(html) || !bytes.Contains(html, []byte("<title>Example Domain</title>")) ||
		ok.RequestSHA256 != "964f55b17be3ad0fb55ae96c3a1cdd36883b9a2f4833da2946c1eeefcdd62ba7" || ok.Browser.Engine != "scrapling/0.4.15+scarlett.2" {
		t.Fatalf("dom ok fixture: %+v", ok)
	}
	for _, name := range []string{"browser-result.json", "browser-result-too-large.json", "browser-result-memory.json"} {
		if _, _, err := EncodeBrowserResult(browserResultFixture(t, name)); err != nil {
			t.Fatal(name, err)
		}
	}
	if r := browserResultFixture(t, "browser-result-too-large.json"); r.DOM != DOMTooLarge || r.HTMLBytes <= PageMax {
		t.Fatal("too_large fixture", r.DOM, r.HTMLBytes)
	}
	if r := browserResultFixture(t, "browser-result-memory.json"); r.DOM != DOMMemory || r.TreePeakBytes < 1 || r.StatusCode != 0 || r.FinalURL != "" {
		t.Fatal("memory fixture", r.DOM)
	}
	raw, err := os.ReadFile("../../api/fixtures/browser-result-parts.json")
	if err != nil {
		t.Fatal(err)
	}
	var parts BrowserResultParts
	decodeStrict(t, raw, &parts)
	if parts.UploadSHA256 != ok.UploadSHA256 || len(parts.Parts) != 1 || parts.Parts[0] != (BrowserPart{1, ok.Parts[0]}) {
		t.Fatalf("parts fixture %+v", parts)
	}
}

func writeDOM(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dom-test.html")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// incompressible is n bytes of valid UTF-8 that gzip cannot shrink much.
func incompressible(t *testing.T, n int) []byte {
	t.Helper()
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<>/=\" "
	b := randomBytes(t, n)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return b
}

// PrepareBrowserUpload: 2 MiB parts with per-part hashes, the upload sha256
// over the whole stream, the DOM's own hash, and a gzip stream that
// decompresses to the DOM exactly. A DOM at the ceiling that does not
// compress fits 33 parts; one byte over is refused and leaves no file.
func TestPrepareBrowserUpload(t *testing.T) {
	for _, size := range []int{0, 1, 5 << 20, PageMax} {
		html := incompressible(t, size)
		if size == PageMax {
			html = randomBytes(t, size) // gzip cannot shrink it at all
		}
		dir := t.TempDir()
		up, err := PrepareBrowserUpload(writeDOM(t, html), filepath.Join(dir, "dom.gz"))
		if err != nil {
			t.Fatal(size, err)
		}
		stream, err := os.ReadFile(up.Path)
		if err != nil {
			t.Fatal(err)
		}
		want := (len(stream) + BrowserPartBytes - 1) / BrowserPartBytes
		if up.HTMLBytes != int64(size) || up.HTMLSHA256 != hexSHA(html) || up.GzipBytes != int64(len(stream)) || up.UploadSHA256 != hexSHA(stream) || len(up.Parts) != want || want > MaxBrowserParts {
			t.Fatalf("size %d: %+v (%d parts)", size, up, want)
		}
		for i, sum := range up.Parts {
			part := stream[i*BrowserPartBytes : min(len(stream), (i+1)*BrowserPartBytes)]
			if hexSHA(part) != sum {
				t.Fatalf("size %d: part %d hash", size, i+1)
			}
		}
		if !bytes.Equal(gunzip(t, stream), html) {
			t.Fatal("stream does not decompress to the DOM", size)
		}
		if info, _ := os.Stat(up.Path); info.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
			t.Fatal("gzip file not private", info.Mode())
		}
		if size == PageMax && want != MaxBrowserParts {
			t.Fatal("the incompressible ceiling case compressed", want)
		}
	}
	dir := t.TempDir()
	gz := filepath.Join(dir, "over.gz")
	if _, err := PrepareBrowserUpload(writeDOM(t, incompressible(t, PageMax+1)), gz); !errors.Is(err, ErrDOMTooLarge) {
		t.Fatal("over the ceiling", err)
	}
	if _, err := os.Stat(gz); !os.IsNotExist(err) {
		t.Fatal("a refused DOM left its gzip file")
	}
	existing := filepath.Join(dir, "exists.gz")
	os.WriteFile(existing, []byte("x"), 0o600)
	if _, err := PrepareBrowserUpload(writeDOM(t, []byte("<p>x</p>")), existing); err == nil {
		t.Fatal("an existing gzip path was reused")
	}
}

func TestEncodeBrowserResultChecksTheDOMFields(t *testing.T) {
	ok := browserResultFixture(t, "browser-result.json")
	_, raw, err := EncodeBrowserResult(ok)
	if err != nil || bytes.Contains(raw, []byte(`<`)) {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*BrowserResult){
		"unknown dom":      func(r *BrowserResult) { r.DOM = "partial" },
		"ok without parts": func(r *BrowserResult) { r.Parts = nil },
		"ok part count":    func(r *BrowserResult) { r.GzipBytes = BrowserPartBytes + 1 },
		"ok over ceiling":  func(r *BrowserResult) { r.HTMLBytes = PageMax + 1 },
		"ok bad digest":    func(r *BrowserResult) { r.Parts = []string{"x"} },
		"ok no upload sha": func(r *BrowserResult) { r.UploadSHA256 = "" },
		"too_large under": func(r *BrowserResult) {
			*r = browserResultFixture(t, "browser-result-too-large.json")
			r.HTMLBytes = PageMax
		},
		"too_large parts": func(r *BrowserResult) {
			*r = browserResultFixture(t, "browser-result-too-large.json")
			r.Parts = ok.Parts
		},
		"memory no peak": func(r *BrowserResult) {
			*r = browserResultFixture(t, "browser-result-memory.json")
			r.TreePeakBytes = 0
		},
		"memory with a size": func(r *BrowserResult) { *r = browserResultFixture(t, "browser-result-memory.json"); r.HTMLBytes = 1 },
	} {
		r := ok
		mutate(&r)
		if _, _, err := EncodeBrowserResult(r); err == nil {
			t.Error(name, "accepted")
		}
	}
}

// fakeBrowserCoordinator is the coordinator side of the parts protocol, as
// the node contract states it: bound to the lease headers, one uncommitted
// part set per attempt replaced by a new upload sha256, a manifest that
// checks every part, the stream hash and the gunzipped DOM.
type fakeBrowserCoordinator struct {
	*httptest.Server
	t        *testing.T
	mu       sync.Mutex
	upload   string
	parts    map[int][]byte
	manifest []byte
	log      []string
	// fail answers a request instead of handling it when it returns true.
	fail func(method, route string, n int, w http.ResponseWriter) bool
}

var partPath = regexp.MustCompile(`^/api/node/v1/jobs/` + testJob + `/browser-result/parts/([0-9]+)$`)

func newFakeBrowserCoordinator(t *testing.T, lease BrowserResult) *fakeBrowserCoordinator {
	f := &fakeBrowserCoordinator{t: t, parts: map[int][]byte{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		route, n := "manifest", 0
		if m := partPath.FindStringSubmatch(r.URL.Path); m != nil {
			route = "part"
			n, _ = strconv.Atoi(m[1])
		} else if r.URL.Path == "/api/node/v1/jobs/"+testJob+"/browser-result/parts" {
			route = "parts"
		} else if r.URL.Path != "/api/node/v1/jobs/"+testJob+"/browser-result" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.log = append(f.log, r.Method+" "+route+" "+strconv.Itoa(n))
		if f.fail != nil && f.fail(r.Method, route, n, w) {
			return
		}
		if r.Header.Get("Authorization") != "Bearer synthetic-credential" || r.Header.Get(NodeVersionHeader) != NodeRelease ||
			r.Header.Get("X-Scarlett-Attempt") != lease.Attempt || r.Header.Get("X-Scarlett-Fence") != lease.Fence || r.Header.Get("X-Scarlett-Request-SHA256") != lease.RequestSHA256 {
			writeError(w, http.StatusConflict, "fenced")
			return
		}
		switch {
		case route == "part" && r.Method == http.MethodPut:
			upload := r.Header.Get("X-Scarlett-Upload-SHA256")
			if f.manifest != nil {
				writeError(w, http.StatusConflict, "result_conflict")
				return
			}
			if n < 1 || n > MaxBrowserParts || len(body) < 1 || len(body) > BrowserPartBytes || hexSHA(body) != r.Header.Get("X-Scarlett-Part-SHA256") || !digest(upload) || r.Header.Get("Content-Type") != "application/octet-stream" {
				writeError(w, http.StatusBadRequest, "invalid_part")
				return
			}
			if upload != f.upload {
				f.upload, f.parts = upload, map[int][]byte{}
			}
			f.parts[n] = body
			io.WriteString(w, `{"status":"stored"}`)
		case route == "parts" && r.Method == http.MethodGet:
			out := BrowserResultParts{UploadSHA256: f.upload, Parts: []BrowserPart{}}
			for i := 1; i <= MaxBrowserParts; i++ {
				if p, ok := f.parts[i]; ok {
					out.Parts = append(out.Parts, BrowserPart{i, hexSHA(p)})
				}
			}
			json.NewEncoder(w).Encode(out)
		case route == "manifest" && r.Method == http.MethodPost:
			var m BrowserResult
			d := json.NewDecoder(bytes.NewReader(body))
			d.DisallowUnknownFields()
			if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Content-Encoding") != "" || d.Decode(&m) != nil {
				writeError(w, http.StatusBadRequest, "invalid_result")
				return
			}
			if f.manifest != nil {
				if !bytes.Equal(f.manifest, body) {
					writeError(w, http.StatusConflict, "result_conflict")
					return
				}
				io.WriteString(w, `{"status":"stored"}`)
				return
			}
			if m.DOM == DOMOK {
				var stream []byte
				for i, sum := range m.Parts {
					p, ok := f.parts[i+1]
					if !ok || f.upload != m.UploadSHA256 || hexSHA(p) != sum {
						writeError(w, http.StatusConflict, "parts_incomplete")
						return
					}
					stream = append(stream, p...)
				}
				zr, err := gzip.NewReader(bytes.NewReader(stream))
				if err != nil || hexSHA(stream) != m.UploadSHA256 || int64(len(stream)) != m.GzipBytes {
					writeError(w, http.StatusBadRequest, "invalid_result")
					return
				}
				html, err := io.ReadAll(io.LimitReader(zr, PageMax+1))
				if err != nil || int64(len(html)) != m.HTMLBytes || hexSHA(html) != m.HTMLSHA256 {
					writeError(w, http.StatusBadRequest, "invalid_result")
					return
				}
			}
			f.manifest = body
			io.WriteString(w, `{"status":"stored"}`)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	io.WriteString(w, `{"error":{"code":"`+code+`","message":"x"}}`)
}

func (f *fakeBrowserCoordinator) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *fakeBrowserCoordinator) stream() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []byte
	for i := 1; i <= len(f.parts); i++ {
		out = append(out, f.parts[i]...)
	}
	return out
}

func uploadClient(origin string) *Client {
	c := New(origin, "synthetic-credential")
	c.uploadBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	return c
}

// preparedManifest compresses html and returns the manifest for it and its
// gzip file.
func preparedManifest(t *testing.T, html []byte) (BrowserResult, string) {
	t.Helper()
	up, err := PrepareBrowserUpload(writeDOM(t, html), filepath.Join(t.TempDir(), "dom.gz"))
	if err != nil {
		t.Fatal(err)
	}
	m := browserResultFixture(t, "browser-result.json")
	m.HTMLBytes, m.HTMLSHA256, m.GzipBytes, m.UploadSHA256, m.Parts = up.HTMLBytes, up.HTMLSHA256, up.GzipBytes, up.UploadSHA256, up.Parts
	return m, up.Path
}

func report() time.Time { return time.Now().Add(time.Minute) }

// A multi-part DOM goes up part by part, in order, then the manifest; the
// coordinator reassembles exactly the stream the node hashed.
func TestUploadBrowserResultSendsPartsThenTheManifest(t *testing.T) {
	m, gz := preparedManifest(t, randomBytes(t, 5<<20))
	f := newFakeBrowserCoordinator(t, m)
	stats, err := uploadClient(f.URL).UploadBrowserResult(context.Background(), testJob, m, gz, report())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"GET parts 0", "PUT part 1", "PUT part 2", "PUT part 3", "POST manifest 0"}
	if got := f.requests(); strings.Join(got, ",") != strings.Join(want, ",") || stats != (UploadStats{PartsSent: 3}) {
		t.Fatalf("requests %v stats %+v", got, stats)
	}
	stream, _ := os.ReadFile(gz)
	if !bytes.Equal(f.stream(), stream) {
		t.Fatal("reassembled stream differs")
	}
	// The same upload again sends no part and replays the manifest.
	stats, err = uploadClient(f.URL).UploadBrowserResult(context.Background(), testJob, m, gz, report())
	if err != nil || stats != (UploadStats{PartsSkipped: 3}) {
		t.Fatal("replay", err, stats)
	}
}

// Transient failures (503 with Retry-After, 502, a transport error) are
// retried per part; a later upload resumes from the stored set and skips
// what is already there under the same upload sha256.
func TestUploadBrowserResultRetriesAndResumes(t *testing.T) {
	m, gz := preparedManifest(t, randomBytes(t, 5<<20))
	f := newFakeBrowserCoordinator(t, m)
	failed := map[string]bool{}
	f.fail = func(method, route string, n int, w http.ResponseWriter) bool {
		key := method + route + strconv.Itoa(n)
		if route == "part" && n == 2 && !failed[key] {
			failed[key] = true
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusServiceUnavailable, "network_unavailable")
			return true
		}
		if route == "part" && n == 3 {
			// Part 3 fails every time: the upload stops after three tries.
			w.WriteHeader(http.StatusBadGateway)
			return true
		}
		return false
	}
	c := uploadClient(f.URL)
	started := time.Now()
	stats, err := c.UploadBrowserResult(context.Background(), testJob, m, gz, report())
	var status *StatusError
	if !errors.As(err, &status) || status.Status != http.StatusBadGateway || stats.PartsSent != 2 || stats.Retries != 3 {
		t.Fatalf("err %v stats %+v log %v", err, stats, f.requests())
	}
	if time.Since(started) < time.Second {
		t.Fatal("Retry-After not honoured")
	}
	f.mu.Lock()
	f.fail, f.log = nil, nil
	f.mu.Unlock()
	stats, err = c.UploadBrowserResult(context.Background(), testJob, m, gz, report())
	if err != nil || stats != (UploadStats{PartsSent: 1, PartsSkipped: 2}) {
		t.Fatalf("resume: %v %+v", err, stats)
	}
	if got := strings.Join(f.requests(), ","); got != "GET parts 0,PUT part 3,POST manifest 0" {
		t.Fatal("resume sent", got)
	}
}

// A node that rebuilt its gzip stream (a different upload sha256) sends
// every part again and the coordinator replaces the old set.
func TestUploadBrowserResultReplacesAnOldSet(t *testing.T) {
	old, oldGz := preparedManifest(t, randomBytes(t, 3<<20))
	f := newFakeBrowserCoordinator(t, old)
	f.fail = func(method, route string, n int, w http.ResponseWriter) bool {
		if route == "manifest" {
			writeError(w, http.StatusServiceUnavailable, "network_unavailable")
			return true
		}
		return false
	}
	c := uploadClient(f.URL)
	if _, err := c.UploadBrowserResult(context.Background(), testJob, old, oldGz, report()); err == nil {
		t.Fatal("manifest stored despite 503s")
	}
	f.mu.Lock()
	f.fail, f.log = nil, nil
	f.mu.Unlock()
	m, gz := preparedManifest(t, randomBytes(t, 3<<20))
	stats, err := c.UploadBrowserResult(context.Background(), testJob, m, gz, report())
	if err != nil || stats.PartsSent != 2 || stats.PartsSkipped != 0 {
		t.Fatalf("%v %+v %v", err, stats, f.requests())
	}
	stream, _ := os.ReadFile(gz)
	if !bytes.Equal(f.stream(), stream) || f.upload != m.UploadSHA256 {
		t.Fatal("the new set did not replace the old one")
	}
}

// A manifest answered 409 parts_incomplete sends the missing parts once
// more and posts again.
func TestUploadBrowserResultRefillsMissingParts(t *testing.T) {
	m, gz := preparedManifest(t, randomBytes(t, 3<<20))
	f := newFakeBrowserCoordinator(t, m)
	dropped := false
	f.fail = func(method, route string, n int, w http.ResponseWriter) bool {
		if route == "manifest" && !dropped {
			dropped = true
			delete(f.parts, 1) // lost on the coordinator's side
		}
		return false
	}
	stats, err := uploadClient(f.URL).UploadBrowserResult(context.Background(), testJob, m, gz, report())
	want := "GET parts 0,PUT part 1,PUT part 2,POST manifest 0,GET parts 0,PUT part 1,POST manifest 0"
	if err != nil || strings.Join(f.requests(), ",") != want || stats != (UploadStats{PartsSent: 3, PartsSkipped: 1}) {
		t.Fatalf("%v %+v %v", err, stats, f.requests())
	}
}

// dom too_large and dom memory send the manifest alone.
func TestUploadBrowserResultWithoutADOM(t *testing.T) {
	for _, name := range []string{"browser-result-too-large.json", "browser-result-memory.json"} {
		m := browserResultFixture(t, name)
		f := newFakeBrowserCoordinator(t, m)
		if _, err := uploadClient(f.URL).UploadBrowserResult(context.Background(), testJob, m, "", report()); err != nil {
			t.Fatal(name, err)
		}
		if got := strings.Join(f.requests(), ","); got != "POST manifest 0" {
			t.Fatal(name, got)
		}
	}
}

func TestUploadBrowserResultFinalAnswersAndTime(t *testing.T) {
	m, gz := preparedManifest(t, randomBytes(t, 3<<20))
	for _, final := range []struct {
		status int
		code   string
	}{{409, "result_conflict"}, {409, "fenced"}, {409, "expired"}, {409, "already_reported"}, {400, "invalid_part"}, {401, ""}, {404, ""}, {413, ""}} {
		f := newFakeBrowserCoordinator(t, m)
		f.fail = func(method, route string, n int, w http.ResponseWriter) bool {
			if route != "part" {
				return false
			}
			if final.code == "" {
				w.WriteHeader(final.status)
			} else {
				writeError(w, final.status, final.code)
			}
			return true
		}
		var status *StatusError
		_, err := uploadClient(f.URL).UploadBrowserResult(context.Background(), testJob, m, gz, report())
		if !errors.As(err, &status) || status.Status != final.status || status.Code != final.code || strings.Join(f.requests(), ",") != "GET parts 0,PUT part 1" {
			t.Fatal(final, err, f.requests())
		}
	}
	// A 2 MiB part needs max(10 s, 8.4 s + 5 s): with 12 s left none starts.
	f := newFakeBrowserCoordinator(t, m)
	if _, err := uploadClient(f.URL).UploadBrowserResult(context.Background(), testJob, m, gz, time.Now().Add(12*time.Second)); !errors.Is(err, ErrBrowserUploadTooLate) || len(f.requests()) != 1 {
		t.Fatal("late part started", err, f.requests())
	}
	// A gzip file that does not match the manifest is never sent.
	other, _ := preparedManifest(t, []byte("<p>other</p>"))
	if _, err := uploadClient(f.URL).UploadBrowserResult(context.Background(), testJob, other, gz, report()); err == nil {
		t.Fatal("mismatched gzip file sent")
	}
	if _, err := uploadClient(f.URL).UploadBrowserResult(context.Background(), "../x", m, gz, report()); err == nil {
		t.Fatal("bad job ID sent")
	}
}

func TestUploadBrowserResultHungTryEndsWithItsContext(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		<-release
	}))
	t.Cleanup(func() { close(release); server.Close() })
	m := browserResultFixture(t, "browser-result-memory.json")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := uploadClient(server.URL).UploadBrowserResult(ctx, testJob, m, "", report()); err == nil || time.Since(started) > 5*time.Second {
		t.Fatal("hung upload", err, time.Since(started))
	}
}
