package worker

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

const darwinUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"

// fakeBrowser stands in for the browser tier: a fixed status and one answer.
type fakeBrowser struct {
	mu       sync.Mutex
	status   BrowserStatus
	result   BrowserFetchResult
	err      error
	requests []BrowserFetchRequest
	prewarms int
}

func (f *fakeBrowser) Status() BrowserStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeBrowser) Prewarm() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prewarms++
}

func (f *fakeBrowser) Fetch(ctx context.Context, req BrowserFetchRequest) (BrowserFetchResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	return f.result, f.err
}

func (f *fakeBrowser) prewarmCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.prewarms
}

func readyStatus() BrowserStatus {
	return BrowserStatus{Ready: true, Capacity: 2, Version: "155.0.8059.39", Engine: "scrapling/0.4.15+scarlett.2", UserAgent: darwinUA}
}

const secretCookie = "synthetic-clearance-value"

func renderedPage() BrowserFetchResult {
	return BrowserFetchResult{
		Outcome: "ok", FinalURL: "https://example.com/", StatusCode: 200,
		Headers:        [][2]string{{"Content-Type", "text/html; charset=utf-8"}, {"set-cookie", "cf_clearance=" + secretCookie}, {"cookie", "x=y"}, {"x-bad", "a\nb"}},
		SetCookieNames: []string{"cf_clearance", "__cf_bm"}, ContentType: "text/html; charset=utf-8",
		HTML: "<!doctype html><title>Example</title><p>rendered</p>",
		Cookies: []BrowserCookie{
			{Name: "cf_clearance", Value: secretCookie, Domain: ".example.com", Path: "/", Expires: -1, Secure: true},
			{Name: "session", Value: "synthetic-session-value", Domain: ".example.com", Path: "/", Expires: -1},
			{Name: "__cf_bm", Value: "synthetic-bm-value", Domain: "www.example.com", Path: "/", Expires: -1},
		},
		Challenge: "solved", Redirects: []coordinator.BrowserRedirect{{URL: "https://example.com/", StatusCode: 301}},
	}
}

func webBrowserFixtureLease(t *testing.T) coordinator.Lease {
	t.Helper()
	raw, err := os.ReadFile("../../api/fixtures/lease-web-browser.json")
	if err != nil {
		t.Fatal(err)
	}
	var l coordinator.Lease
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	l.LeaseDeadline = time.Now().Add(118 * time.Second)
	l.SettlementDeadline = l.LeaseDeadline
	return l
}

func browserConfig() config.Config {
	c := webConfig()
	c.WebBrowser = true
	return c
}

// browserWebLease rebuilds a browser lease around a changed request and
// payload, keeping its digests consistent.
func browserWebLease(t *testing.T, request func(*coordinator.WebRequest), payload func(*webPlan)) coordinator.Lease {
	t.Helper()
	l := webBrowserFixtureLease(t)
	plan, ok := decodeWebPlan(l.WebPayload)
	if !ok {
		t.Fatal("browser fixture payload refused")
	}
	if payload != nil {
		payload(&plan)
		raw, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		l.WebPayload = raw
	}
	options := *l.WebRequest.Browser
	r := *l.WebRequest
	r.Browser = &options
	if request != nil {
		request(&r)
	}
	l.WebRequest = &r
	encoded, _ := json.Marshal(l.WebRequest)
	l.InputSHA256 = SHA(string(encoded))
	return l
}

func TestValidateBrowserWebLease(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	c := browserConfig()
	l := webBrowserFixtureLease(t)
	plan, deadline, code := validateWebLease(c, l)
	if code != "" || plan.ProofPolicy != webBrowserPolicy || len(plan.Headers) != 2 || len(plan.NodeHeaders) != 2 || !deadline.Equal(l.LeaseDeadline.Add(-webReportMargin)) {
		t.Fatal("browser fixture refused", code)
	}
	if limit := ProofSampleLimit(c, l); limit != 6 {
		t.Fatal("browser proof sample limit", limit)
	}
	relayPayload := webFixtureLease(t).WebPayload
	for name, mutate := range map[string]func(*coordinator.Lease){
		"mode without browser": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Browser = nil }, nil)
		},
		"browser without mode": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Mode = "" }, nil)
		},
		"unknown mode": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Mode = "render" }, nil)
		},
		"relay payload on a browser job": func(l *coordinator.Lease) {
			*l = browserWebLease(t, nil, nil)
			l.WebPayload = relayPayload
		},
		"browser payload on a relay job": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Mode, r.Browser = "", nil }, nil)
		},
		"user-agent header": func(l *coordinator.Lease) {
			*l = browserWebLease(t, nil, func(p *webPlan) {
				p.Headers = append([]webHeader{{"user-agent", darwinUA}}, p.Headers...)
			})
		},
		"one default header": func(l *coordinator.Lease) {
			*l = browserWebLease(t, nil, func(p *webPlan) { p.Headers = p.Headers[:1] })
		},
		"changed accept": func(l *coordinator.Lease) {
			*l = browserWebLease(t, nil, func(p *webPlan) { p.Headers[0].Value = "*/*" })
		},
		"node headers reversed": func(l *coordinator.Lease) {
			*l = browserWebLease(t, nil, func(p *webPlan) { p.NodeHeaders = []string{"cookie", "user-agent"} })
		},
		"node headers without cookie": func(l *coordinator.Lease) {
			*l = browserWebLease(t, nil, func(p *webPlan) { p.NodeHeaders = []string{"user-agent"} })
		},
		"node headers on relay policy": func(l *coordinator.Lease) {
			*l = browserWebLease(t, nil, func(p *webPlan) { p.ProofPolicy = webRelayPolicy })
		},
		"max redirects": func(l *coordinator.Lease) {
			*l = browserWebLease(t, nil, func(p *webPlan) { p.MaxRedirects = 4 })
		},
		"max response bytes": func(l *coordinator.Lease) {
			*l = browserWebLease(t, nil, func(p *webPlan) { p.MaxResponseBytes = 1 << 20 })
		},
		"wait": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Browser.Wait = "domcontentloaded" }, nil)
		},
		"wait_ms": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Browser.WaitMS = 15001 }, nil)
		},
		"negative wait_ms": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Browser.WaitMS = -1 }, nil)
		},
		"short timeout": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Browser.TimeoutMS = 4999 }, nil)
		},
		"long timeout": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Browser.TimeoutMS = 45001 }, nil)
		},
		"long selector": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Browser.WaitSelector = strings.Repeat("a", 257) }, nil)
		},
		"selector line break": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Browser.WaitSelector = "#main\n" }, nil)
		},
		"selector non-ASCII": func(l *coordinator.Lease) {
			*l = browserWebLease(t, func(r *coordinator.WebRequest) { r.Browser.WaitSelector = "#é" }, nil)
		},
		"pre-warm hint on a browser job": func(l *coordinator.Lease) {
			*l = browserWebLease(t, nil, nil)
			l.WebPrewarmBrowser = true
		},
	} {
		m := webBrowserFixtureLease(t)
		mutate(&m)
		if _, _, code := validateWebLease(c, m); code != "invalid_lease" {
			t.Errorf("%s: code %q, want invalid_lease", name, code)
		}
	}
	for _, selector := range []string{"#main", strings.Repeat("a", 256), "div[data-x='1'] > p"} {
		m := browserWebLease(t, func(r *coordinator.WebRequest) { r.Browser.WaitSelector = selector; r.Browser.Wait = "load" }, nil)
		if _, _, code := validateWebLease(c, m); code != "" {
			t.Errorf("selector %q refused: %s", selector, code)
		}
	}
	hinted := webFixtureLease(t)
	hinted.WebPrewarmBrowser = true
	if _, _, code := validateWebLease(c, hinted); code != "" {
		t.Fatal("relay lease with the pre-warm hint refused", code)
	}
}

func TestWebOfferServableBrowser(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	c := browserConfig()
	offer := webBrowserFixtureLease(t)
	eventually := func(f *fakeBrowser, want int) {
		t.Helper()
		for start := time.Now(); f.prewarmCount() != want; time.Sleep(5 * time.Millisecond) {
			if time.Since(start) > 2*time.Second {
				t.Fatalf("prewarms %d, want %d", f.prewarmCount(), want)
			}
		}
	}
	ready := &fakeBrowser{status: readyStatus()}
	if !WebOfferServable(c, offer, ready) {
		t.Fatal("browser offer refused with a ready browser")
	}
	eventually(ready, 1)
	for name, browser := range map[string]BrowserTier{"no tier": nil, "downloading": &fakeBrowser{status: BrowserStatus{Reason: "browser_downloading"}}} {
		if WebOfferServable(c, offer, browser) {
			t.Fatal("browser offer servable:", name)
		}
	}
	off := c
	off.WebBrowser = false
	if WebOfferServable(off, offer, ready) {
		t.Fatal("browser offer servable with the browser off")
	}
	hinted := offer
	hinted.WebPrewarmBrowser = true
	if WebOfferServable(c, hinted, ready) {
		t.Fatal("browser offer with the pre-warm hint servable")
	}
	// A relay offer is servable whatever the browser does; the hint only
	// starts a ready browser.
	relay := webFixtureLease(t)
	relay.WebPrewarmBrowser = true
	hint := &fakeBrowser{status: readyStatus()}
	if !WebOfferServable(c, relay, hint) {
		t.Fatal("hinted relay offer refused")
	}
	eventually(hint, 1)
	cold := &fakeBrowser{status: BrowserStatus{Reason: "browser_downloading"}}
	if !WebOfferServable(c, relay, cold) || !WebOfferServable(c, relay, nil) || !WebOfferServable(off, relay, hint) {
		t.Fatal("relay offer refused for its browser")
	}
	relay.WebPrewarmBrowser = false
	plain := &fakeBrowser{status: readyStatus()}
	if !WebOfferServable(c, relay, plain) {
		t.Fatal("relay offer refused")
	}
	time.Sleep(50 * time.Millisecond)
	if cold.prewarmCount() != 0 || plain.prewarmCount() != 0 || hint.prewarmCount() != 1 {
		t.Fatal("pre-warm without a ready browser and the hint")
	}
	HaltRelay("test")
	if WebOfferServable(c, offer, ready) {
		t.Fatal("halted relay serves browser jobs")
	}
}

type uploadCall struct {
	jobID  string
	body   BrowserUploadBody
	raw    []byte
	report time.Time
}

// BrowserUploadBody is the decompressed upload, decoded strictly.
type BrowserUploadBody = coordinator.BrowserResult

type fakeUpload struct {
	mu    sync.Mutex
	calls []uploadCall
	fn    func(ctx context.Context) error
}

func (u *fakeUpload) upload(ctx context.Context, jobID string, gz []byte, report time.Time) error {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return err
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		return err
	}
	var body BrowserUploadBody
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&body); err != nil {
		return err
	}
	u.mu.Lock()
	u.calls = append(u.calls, uploadCall{jobID, body, raw, report})
	u.mu.Unlock()
	if u.fn != nil {
		return u.fn(ctx)
	}
	return nil
}

func (u *fakeUpload) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.calls)
}

type browserRun struct {
	webRun
	browser *fakeBrowser
	upload  *fakeUpload
	output  string
	took    time.Duration
}

// runBrowserJob runs one browser lease with the fake prover in mode, the fake
// browser and the fake upload, capturing everything the process printed.
func runBrowserJob(t *testing.T, mode string, l coordinator.Lease, browser *fakeBrowser, upload *fakeUpload, answers map[string][]netip.Addr) browserRun {
	t.Helper()
	log := filepath.Join(t.TempDir(), "relay-web.log")
	t.Setenv("SCARLETT_FAKE_PROVER", mode)
	t.Setenv("SCARLETT_FAKE_WEB_LOG", log)
	r := &fakeResolver{answers: answers}
	w := Web{Config: browserConfig(), Resolver: r.resolve, Egress: staticEgress(), Upload: upload.upload}
	if browser != nil {
		w.Browser = browser
	}
	started := time.Now()
	var code string
	output := captureOutput(t, func() { code = w.Run(context.Background(), l) })
	run := browserRun{webRun: webRun{code: code, asked: r.asked}, browser: browser, upload: upload, output: output, took: time.Since(started)}
	raw, err := os.ReadFile(log)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var in webHopInput
		if err := json.Unmarshal(line, &in); err != nil {
			t.Fatal(err)
		}
		run.inputs = append(run.inputs, in)
	}
	return run
}

// captureOutput runs f with this process's stdout and stderr sent to a file
// and returns what was written.
func captureOutput(t *testing.T, f func()) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = file, file
	defer func() { os.Stdout, os.Stderr = stdout, stderr }()
	f()
	raw, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func browserWith(mutate func(*fakeBrowser)) *fakeBrowser {
	f := &fakeBrowser{status: readyStatus(), result: renderedPage()}
	if mutate != nil {
		mutate(f)
	}
	return f
}

func TestRunBrowserUploadsAndRefetches(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	l := webBrowserFixtureLease(t)
	log := ""
	// The upload waits until the re-fetch's helper has started and then takes
	// a while more: both run at once, and the report waits for both.
	upload := &fakeUpload{}
	upload.fn = func(ctx context.Context) error {
		for start := time.Now(); ; time.Sleep(10 * time.Millisecond) {
			if raw, _ := os.ReadFile(log); len(raw) > 0 {
				break
			}
			if time.Since(start) > 5*time.Second {
				return errors.New("re-fetch never started while uploading")
			}
		}
		time.Sleep(300 * time.Millisecond)
		return nil
	}
	browser := browserWith(nil)
	logDir := t.TempDir()
	log = filepath.Join(logDir, "relay-web.log")
	t.Setenv("SCARLETT_FAKE_PROVER", "web-chain")
	t.Setenv("SCARLETT_FAKE_WEB_LOG", log)
	r := &fakeResolver{answers: publicAnswers}
	w := Web{Config: browserConfig(), Resolver: r.resolve, Egress: staticEgress(), Browser: browser, Upload: upload.upload}
	started := time.Now()
	var code string
	output := captureOutput(t, func() { code = w.Run(context.Background(), l) })
	took := time.Since(started)
	if code != "" || upload.count() != 1 || took < 300*time.Millisecond {
		t.Fatal("concurrent upload and re-fetch", code, upload.count(), took)
	}
	// The browser got the job's options, bounded by the time left.
	if len(browser.requests) != 1 || browser.requests[0] != (BrowserFetchRequest{URL: "https://example.com/", Wait: "networkidle", TimeoutMS: 30000, SolveChallenge: true}) {
		t.Fatalf("browser request %+v", browser.requests)
	}
	// Each re-fetch hop carried the pinned User-Agent and only the clearance
	// cookies that match that hop.
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []webHopInput{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var in webHopInput
		if err := json.Unmarshal(line, &in); err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, in)
	}
	want := []struct{ url, cookie string }{
		{"https://example.com/", "cf_clearance=" + secretCookie},
		{"https://www.example.com/a", "cf_clearance=" + secretCookie + "; __cf_bm=synthetic-bm-value"},
		{"https://cdn.example.net/b", ""},
	}
	if len(inputs) != len(want) {
		t.Fatal("re-fetch hops", len(inputs))
	}
	for i, in := range inputs {
		if in.URL != want[i].url || in.NodeHeaders == nil || in.NodeHeaders.UserAgent != darwinUA || in.NodeHeaders.Cookie != want[i].cookie || !bytes.Equal(in.Payload, l.WebPayload) || in.Token != l.VerifierToken {
			t.Fatalf("hop %d input %s", i, in.URL)
		}
	}
	// Without a matching cookie the hop sends no cookie key at all.
	if lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n")); !bytes.Contains(lines[0], []byte(`"node_headers":{"user_agent":"`)) || bytes.Contains(lines[2], []byte(`"cookie":"`)) {
		t.Fatal("node_headers shape on stdin")
	}
	// The upload is the browser's copy, bound to this attempt, with header
	// names lowercased and cookies, set-cookie and bad values dropped.
	call := upload.calls[0]
	body := call.body
	if call.jobID != l.JobID || !call.report.Equal(l.LeaseDeadline.Add(-webReportMargin)) || body.Version != "node-v1" || body.Attempt != l.Attempt || body.Fence != l.Fence || body.RequestSHA256 != l.RequestSHA256 || body.URL != l.WebRequest.URL || body.FinalURL != "https://example.com/" || body.StatusCode != 200 || body.HTML != renderedPage().HTML || body.HTMLBytes != len(body.HTML) || body.HTMLSHA256 != SHA(body.HTML) || body.HTMLTruncated || body.Challenge != "solved" {
		t.Fatalf("upload body %+v", body)
	}
	if len(body.Headers) != 1 || body.Headers[0] != [2]string{"content-type", "text/html; charset=utf-8"} || strings.Join(body.SetCookieNames, ",") != "cf_clearance,__cf_bm" || len(body.Redirects) != 1 {
		t.Fatalf("upload headers %v %v", body.Headers, body.SetCookieNames)
	}
	if body.Browser != (coordinator.BrowserInfo{Engine: "scrapling/0.4.15+scarlett.2", Version: "155.0.8059.39", UserAgent: darwinUA}) || body.StartedAtMS < started.UnixMilli() || body.StartedAtMS > time.Now().UnixMilli() || body.DurationMS < 0 || body.DurationMS > took.Milliseconds() {
		t.Fatalf("upload browser %+v %d %d", body.Browser, body.StartedAtMS, body.DurationMS)
	}
	// No cookie value is ever uploaded or printed.
	for _, secret := range []string{secretCookie, "synthetic-session-value", "synthetic-bm-value"} {
		if strings.Contains(string(call.raw), secret) || strings.Contains(output, secret) {
			t.Fatal("cookie value leaked:", secret)
		}
	}
}

func TestRunBrowserOutcomes(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	failUpload := func(ctx context.Context) error { return errors.New("synthetic upload failure") }
	conflict := func(ctx context.Context) error {
		return &coordinator.StatusError{Status: 409, Code: "result_conflict"}
	}
	for _, tc := range []struct {
		name     string
		mode     string
		browser  func(*fakeBrowser)
		upload   func(context.Context) error
		code     string
		uploads  int
		hops     int
		answers  map[string][]netip.Addr
		noFetch  bool
		nilTier  bool
		relayOff bool
	}{
		{name: "upload stored, re-fetch failed", mode: "web-fetch", code: "", uploads: 1, hops: 1},
		{name: "re-fetch proven, upload failed", mode: "web-final", upload: failUpload, code: "", uploads: 1, hops: 1},
		{name: "no upload, re-fetch hop 0 fails", mode: "web-connect", upload: failUpload, code: "web_connect_failed", uploads: 1, hops: 1},
		{name: "upload conflict, re-fetch proven", mode: "web-final", upload: conflict, code: "", uploads: 1, hops: 1},
		{name: "upload conflict, re-fetch fails", mode: "web-fetch", upload: conflict, code: "web_fetch_failed", uploads: 1, hops: 1},
		{name: "later re-fetch hop fails", mode: "web-later-fails", upload: failUpload, code: "", uploads: 1, hops: 2},
		{name: "unsolved challenge: no re-fetch", mode: "web-final", browser: func(f *fakeBrowser) { f.result.Challenge = "unsolved" }, code: "", uploads: 1, hops: 0},
		{name: "unsolved challenge, upload failed", mode: "web-final", browser: func(f *fakeBrowser) { f.result.Challenge = "unsolved" }, upload: failUpload, code: "web_browser_failed", uploads: 1, hops: 0},
		{name: "x host final URL: no upload", mode: "web-final", browser: func(f *fakeBrowser) { f.result.FinalURL = "https://x.com/home" }, code: "", uploads: 0, hops: 1},
		{name: "x host final URL, re-fetch fails", mode: "web-fetch", browser: func(f *fakeBrowser) { f.result.FinalURL = "https://mobile.twitter.com/a" }, code: "web_browser_failed", uploads: 0, hops: 1},
		{name: "relative final URL", mode: "web-fetch", browser: func(f *fakeBrowser) { f.result.FinalURL = "/home" }, code: "web_browser_failed", uploads: 0, hops: 1},
		{name: "no document", mode: "web-final", browser: func(f *fakeBrowser) { f.result.StatusCode = 0 }, code: "", uploads: 0, hops: 1},
		{name: "browser failed, re-fetch proven", mode: "web-final", browser: func(f *fakeBrowser) { f.result = BrowserFetchResult{Outcome: "failed", Error: "tls"} }, code: "", uploads: 0, hops: 1},
		{name: "browser failed, re-fetch fails", mode: "web-fetch", browser: func(f *fakeBrowser) { f.result = BrowserFetchResult{Outcome: "failed", Error: "tls"} }, code: "web_browser_failed", uploads: 0, hops: 1},
		{name: "browser timed out", mode: "web-fetch", browser: func(f *fakeBrowser) { f.result.Outcome = "timeout" }, code: "web_browser_failed", uploads: 0, hops: 1},
		{name: "helper transport error", mode: "web-fetch", browser: func(f *fakeBrowser) { f.err = errors.New("helper exited") }, code: "web_browser_failed", uploads: 0, hops: 1},
		{name: "helper could not start", mode: "web-final", browser: func(f *fakeBrowser) { f.err = ErrBrowserUnavailable }, code: "web_browser_unavailable", uploads: 0, hops: 0},
		{name: "browser not ready", mode: "web-final", browser: func(f *fakeBrowser) { f.status = BrowserStatus{Reason: "browser_downloading"} }, code: "web_browser_unavailable", uploads: 0, hops: 0, noFetch: true},
		{name: "no browser tier", mode: "web-final", code: "web_browser_unavailable", uploads: 0, hops: 0, noFetch: true, nilTier: true},
		{name: "page host does not resolve", mode: "web-final", answers: map[string][]netip.Addr{}, code: "web_dns_failed", noFetch: true},
		{name: "page host is private", mode: "web-final", answers: map[string][]netip.Addr{"example.com": addrs("10.0.0.7")}, code: "web_egress_denied", noFetch: true},
		{name: "relay misuse in the re-fetch", mode: "web-misuse", code: "relay_misuse", uploads: 1, hops: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ResetRelayHaltForTests()
			browser := browserWith(tc.browser)
			if tc.nilTier {
				browser = nil
			}
			answers := tc.answers
			if answers == nil {
				answers = publicAnswers
			}
			run := runBrowserJob(t, tc.mode, webBrowserFixtureLease(t), browser, &fakeUpload{fn: tc.upload}, answers)
			if run.code != tc.code || run.upload.count() != tc.uploads || len(run.inputs) != tc.hops {
				t.Fatalf("code %q uploads %d hops %d", run.code, run.upload.count(), len(run.inputs))
			}
			if tc.noFetch && browser != nil && len(browser.requests) != 0 {
				t.Fatal("browser ran")
			}
			if tc.code == "relay_misuse" && !RelayHalted() {
				t.Fatal("misuse did not halt relay")
			}
		})
	}
}

func TestRunBrowserBudget(t *testing.T) {
	ResetRelayHaltForTests()
	l := webBrowserFixtureLease(t)
	// Under 5 s left for the browser once the re-fetch reserve is kept.
	l.LeaseDeadline = time.Now().Add(webReportMargin + webRefetchReserve + 4*time.Second)
	l.SettlementDeadline = l.LeaseDeadline
	browser := browserWith(nil)
	run := runBrowserJob(t, "web-final", l, browser, &fakeUpload{}, publicAnswers)
	if run.code != "expired" || len(browser.requests) != 0 || len(run.asked) != 0 || len(run.inputs) != 0 {
		t.Fatal("browser phase started without its minimum budget", run.code)
	}
	// With little time left the browser gets what remains, not timeout_ms.
	l.LeaseDeadline = time.Now().Add(webReportMargin + webRefetchReserve + 8*time.Second)
	l.SettlementDeadline = l.LeaseDeadline
	browser = browserWith(nil)
	if run = runBrowserJob(t, "web-final", l, browser, &fakeUpload{}, publicAnswers); run.code != "" || len(browser.requests) != 1 || browser.requests[0].TimeoutMS > 8000 || browser.requests[0].TimeoutMS < 7000 {
		t.Fatal("browser budget", run.code, browser.requests)
	}
}

// The upload and the re-fetch end with the report deadline: an upload that
// never answers does not hold the report back.
func TestRunBrowserReportsAtTheDeadline(t *testing.T) {
	t.Parallel()
	l := webBrowserFixtureLease(t)
	l.LeaseDeadline = time.Now().Add(webReportMargin + webRefetchReserve + 5500*time.Millisecond)
	l.SettlementDeadline = l.LeaseDeadline
	report := l.LeaseDeadline.Add(-webReportMargin)
	browser := browserWith(func(f *fakeBrowser) { f.result.Challenge = "unsolved" })
	upload := &fakeUpload{fn: func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }}
	w := Web{Config: browserConfig(), Resolver: (&fakeResolver{answers: publicAnswers}).resolve, Egress: staticEgress(), Browser: browser, Upload: upload.upload}
	code := w.Run(context.Background(), l)
	if late := time.Since(report); code != "expired" || late < 0 || late > 3*time.Second || upload.count() != 1 {
		t.Fatal("report deadline", code, late)
	}
}

// The upload keeps only what the coordinator's D.1 validation accepts, so one
// odd redirect or content type never costs the whole browser copy.
func TestBrowserUploadSanitizersMatchTheCoordinator(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://example.com/a?b=c":                      true,
		"http://example.com:8080/":                       true,
		"https://user:pass@example.com/":                 false,
		"https://example.com/café":                       false,
		"ftp://example.com/":                             false,
		"https://x.com/home":                             false,
		"https://mobile.twitter.com/":                    false,
		"about:blank":                                    false,
		"https://" + strings.Repeat("a", 2048) + ".com/": false,
	} {
		if got := browserFinalURLAllowed(raw); got != want {
			t.Errorf("browserFinalURLAllowed(%q) = %v, want %v", raw, got, want)
		}
	}
	redirects := browserRedirects([]coordinator.BrowserRedirect{
		{URL: "https://example.com/", StatusCode: 301},
		{URL: "https://user@example.com/", StatusCode: 302},
		{URL: "chrome-error://chromewebdata/", StatusCode: 302},
		{URL: "https://x.com/", StatusCode: 302},
		{URL: "https://example.com/next", StatusCode: 99},
	})
	if len(redirects) != 1 || redirects[0].URL != "https://example.com/" {
		t.Fatalf("redirects = %+v", redirects)
	}
	if got := browserContentType("text/html; charset=utf-8"); got != "text/html; charset=utf-8" {
		t.Fatalf("content type = %q", got)
	}
	for _, bad := range []string{"text/html; name=é", "text/html\r\nx: y", strings.Repeat("a", 1025)} {
		if got := browserContentType(bad); got != "" {
			t.Fatalf("content type %q kept as %q", bad, got)
		}
	}
}

// The upload says whether the operator's captcha solver cleared the page or
// would have been needed; nothing else, and nothing when neither.
func TestRunBrowserUploadNamesTheSolver(t *testing.T) {
	ResetRelayHaltForTests()
	t.Cleanup(ResetRelayHaltForTests)
	for solver, want := range map[string]string{"used": "used", "needed": "needed", "": "", "capmonster": ""} {
		browser := browserWith(func(f *fakeBrowser) { f.result.Solver = solver })
		upload := &fakeUpload{}
		run := runBrowserJob(t, "web-final", webBrowserFixtureLease(t), browser, upload, publicAnswers)
		if run.code != "" || upload.count() != 1 || upload.calls[0].body.Solver != want {
			t.Fatalf("%q: code %q uploads %d", solver, run.code, upload.count())
		}
		if want == "" && bytes.Contains(upload.calls[0].raw, []byte(`"solver"`)) {
			t.Fatalf("%q: empty solver sent", solver)
		}
	}
}
