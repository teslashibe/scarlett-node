package worker

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
)

// BrowserTier is the node's hidden browser for web jobs in browser mode: the
// bundled Scrapling helper driving the node's own verified Chrome for Testing
// (internal/webruntime). main adapts the runtime's manager to it; tests use a
// fake.
type BrowserTier interface {
	// Status is the tier's readiness now. It never blocks on the browser.
	Status() BrowserStatus
	// Prewarm starts the helper in the background if it is not running. It
	// returns at once.
	Prewarm()
	// Fetch renders one page in a fresh browser context. ErrBrowserUnavailable
	// means the page was never loaded: the tier was not ready or its helper
	// could not start. Any other error is a failed fetch.
	Fetch(ctx context.Context, req BrowserFetchRequest) (BrowserFetchResult, error)
}

// ErrBrowserUnavailable is a browser fetch that never ran.
var ErrBrowserUnavailable = errors.New("browser tier unavailable")

// BrowserStatus is the readiness of a BrowserTier. Ready means verified and
// probed, not that a browser is running. Reason is one of the closed
// heartbeat reasons when not ready.
type BrowserStatus struct {
	Ready    bool
	Reason   string
	Capacity int
	// Version is the Chrome for Testing version, Engine the helper engine
	// ("scrapling/0.4.15") and UserAgent the pinned User-Agent the browser
	// sends, which the proven re-fetch repeats.
	Version, Engine, UserAgent string
}

// BrowserFetchRequest is one page for the helper (POST /v1/fetch).
type BrowserFetchRequest struct {
	URL            string `json:"url"`
	Wait           string `json:"wait"`
	WaitMS         int    `json:"wait_ms"`
	WaitSelector   string `json:"wait_selector"`
	TimeoutMS      int    `json:"timeout_ms"`
	BlockResources bool   `json:"block_resources"`
	SolveChallenge bool   `json:"solve_challenge"`
}

// BrowserFetchResult is the helper's answer for one page. Cookies carry
// values; everything else is safe to upload.
type BrowserFetchResult struct {
	Outcome        string                        `json:"outcome"` // ok, timeout or failed
	Error          string                        `json:"error"`
	FinalURL       string                        `json:"final_url"`
	StatusCode     int                           `json:"status_code"`
	Headers        [][2]string                   `json:"headers"`
	SetCookieNames []string                      `json:"set_cookie_names"`
	ContentType    string                        `json:"content_type"`
	HTML           string                        `json:"html"`
	HTMLTruncated  bool                          `json:"html_truncated"`
	Cookies        []BrowserCookie               `json:"cookies"`
	Challenge      string                        `json:"challenge"` // none, solved or unsolved
	Redirects      []coordinator.BrowserRedirect `json:"redirects"`
	StartedAtMS    int64                         `json:"started_at_ms"`
}

const (
	// webRefetchReserve is the part of a browser job kept after the browser
	// phase for the proven re-fetch and the upload.
	webRefetchReserve = 15 * time.Second
	// webBrowserMinBudget is the shortest browser phase worth starting.
	webBrowserMinBudget = 5 * time.Second
	// webBrowserOverrun is how long past its own budget Go waits for the
	// helper's answer before it gives up on the fetch.
	webBrowserOverrun = time.Second
	// webBrowserSettle bounds the wait for the upload and re-fetch to clean
	// up once the report deadline has passed.
	webBrowserSettle   = 2 * time.Second
	maxBrowserFinalURL = 2048
)

// Upload bounds the coordinator validates; the node drops what would make it
// refuse the whole copy.
const (
	maxBrowserHeaders     = 128
	maxBrowserHeaderName  = 64
	maxBrowserHeaderValue = 4096
	maxBrowserHeaderTotal = 65536
	maxBrowserCookieNames = 50
	maxBrowserRedirects   = 20
	maxBrowserRedirectURL = 2048
	maxBrowserContentType = 1024
)

// runBrowser serves a browser job (contract C.7). report is the deadline for
// the job's report. The browser phase ends 15 s before it; then the upload of
// the browser's copy and the proven re-fetch run together, and the job is
// proven if either the upload was stored or the verifier holds a hop.
func (w Web) runBrowser(ctx context.Context, l coordinator.Lease, plan webPlan, report time.Time) string {
	opts := *l.WebRequest.Browser
	budget := min(time.Duration(opts.TimeoutMS)*time.Millisecond, time.Until(report.Add(-webRefetchReserve)))
	if budget < webBrowserMinBudget {
		return "expired"
	}
	// The page's own host passes the egress guard before any browser work, so
	// the browser is never started for a page the node would refuse.
	_, host, err := canonicalWebURL(plan.URL)
	if err != nil {
		return "web_egress_denied"
	}
	lookupCtx, cancel := context.WithTimeout(ctx, webLookupLimit)
	addrs, err := w.resolver()(lookupCtx, host)
	cancel()
	if ctx.Err() != nil {
		return "expired"
	}
	if err != nil || len(addrs) == 0 {
		return "web_dns_failed"
	}
	if _, ok := w.egress().pickWebAddr(ctx, addrs); !ok {
		return "web_egress_denied"
	}
	if w.Browser == nil {
		return "web_browser_unavailable"
	}
	status := w.Browser.Status()
	if !status.Ready || status.UserAgent == "" {
		return "web_browser_unavailable"
	}

	started := time.Now()
	fetchCtx, cancel := context.WithTimeout(ctx, budget+webBrowserOverrun)
	end := diagnostics.Start(ctx, "browser_fetch", 0)
	res, err := w.Browser.Fetch(fetchCtx, BrowserFetchRequest{URL: plan.URL, Wait: opts.Wait, WaitMS: opts.WaitMS, WaitSelector: opts.WaitSelector, TimeoutMS: int(budget.Milliseconds()), BlockResources: opts.BlockResources, SolveChallenge: opts.SolveChallenge})
	cancel()
	duration := time.Since(started)
	if errors.Is(err, ErrBrowserUnavailable) {
		end("web_browser_unavailable")
		return "web_browser_unavailable"
	}
	browserCode := ""
	if err != nil || res.Outcome != "ok" {
		browserCode = "web_browser_failed"
	}
	end(webDiagnosticOutcome(ctx, browserCode))
	// The main document must be a public web page; otherwise the browser copy
	// is dropped. The re-fetch still runs: the verifier authorizes its hops.
	upload := browserCode == "" && res.StatusCode >= 100 && res.StatusCode <= 999
	if browserCode == "" && !browserFinalURLAllowed(res.FinalURL) {
		browserCode, upload = "web_browser_failed", false
	}
	refetch := res.Challenge != "unsolved"

	var (
		mu          sync.Mutex
		stored      bool
		refetchCode string
		verified    int
		wg          sync.WaitGroup
	)
	if upload {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok := w.uploadBrowserResult(ctx, l, res, status, started, duration, report)
			mu.Lock()
			stored = ok
			mu.Unlock()
		}()
	}
	if refetch {
		cookies := res.Cookies
		userAgent := status.UserAgent
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, hops := w.relay(ctx, plan, l.VerifierToken, func(hopURL string) *webNodeHeaders {
				return &webNodeHeaders{UserAgent: userAgent, Cookie: CookieHeader(cookies, hopURL, time.Now())}
			})
			mu.Lock()
			refetchCode, verified = code, hops
			mu.Unlock()
		}()
	}
	// Report once both are done, or at the report deadline: both run under
	// it, so they end with it, and only their cleanup is waited for.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		select {
		case <-done:
		case <-time.After(webBrowserSettle):
		}
	}
	mu.Lock()
	defer mu.Unlock()
	switch {
	case refetchCode == "relay_misuse":
		return refetchCode
	case stored || verified > 0:
		return ""
	case browserCode != "":
		return browserCode
	case refetch && refetchCode != "":
		return refetchCode
	case ctx.Err() != nil:
		return "expired"
	}
	return "web_browser_failed"
}

// uploadBrowserResult builds, encodes and sends the browser's copy and
// reports whether the coordinator stored it.
func (w Web) uploadBrowserResult(ctx context.Context, l coordinator.Lease, res BrowserFetchResult, status BrowserStatus, started time.Time, duration time.Duration, report time.Time) bool {
	if w.Upload == nil {
		return false
	}
	end := diagnostics.Start(ctx, "browser_upload", 0)
	result := coordinator.BrowserResult{
		Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence, RequestSHA256: l.RequestSHA256, URL: l.WebRequest.URL,
		FinalURL: res.FinalURL, StatusCode: res.StatusCode, Headers: browserHeaders(res.Headers), SetCookieNames: browserCookieNames(res.SetCookieNames),
		ContentType: browserContentType(res.ContentType), HTML: strings.ToValidUTF8(res.HTML, "\uFFFD"), HTMLTruncated: res.HTMLTruncated, Challenge: res.Challenge,
		Redirects: browserRedirects(res.Redirects), Browser: coordinator.BrowserInfo{Engine: status.Engine, Version: status.Version, UserAgent: status.UserAgent},
		// Go's own clock bounds the browser phase: the start precedes the
		// helper's and the duration covers it.
		StartedAtMS: started.UnixMilli(), DurationMS: duration.Milliseconds(),
	}
	if result.Challenge != "solved" && result.Challenge != "unsolved" {
		result.Challenge = "none"
	}
	_, body, err := coordinator.EncodeBrowserResult(result)
	if err == nil {
		err = w.Upload(ctx, l.JobID, body, report)
	}
	if err != nil {
		end(webDiagnosticOutcome(ctx, "web_browser_failed"))
		return false
	}
	end("success")
	return true
}

// browserFinalURLAllowed is the main-document rule: an absolute http or https
// URL of at most 2048 bytes of printable ASCII, without userinfo, whose host
// is not an X host. The coordinator applies the same rule to the final URL
// and every redirect.
func browserFinalURLAllowed(raw string) bool {
	if len(raw) > maxBrowserFinalURL || !printableASCII(raw) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" && u.Scheme != "http" || u.Host == "" || u.Opaque != "" || u.User != nil {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	return host != "" && !webHostUnder(host, webXHosts)
}

// browserHeaders keeps the response headers the coordinator accepts: token
// names of at most 64 bytes, lowercased, printable ASCII values of at most
// 4096 bytes, never set-cookie or cookie, at most 128 pairs and 65536 bytes.
func browserHeaders(in [][2]string) [][2]string {
	out := [][2]string{}
	total := 0
	for _, h := range in {
		name, value := strings.ToLower(h[0]), h[1]
		if len(out) == maxBrowserHeaders || name == "set-cookie" || name == "cookie" || len(name) > maxBrowserHeaderName || !validCookieName(name) || len(value) > maxBrowserHeaderValue || !printableASCII(value) || total+len(name)+len(value) > maxBrowserHeaderTotal {
			continue
		}
		out = append(out, [2]string{name, value})
		total += len(name) + len(value)
	}
	return out
}

func browserCookieNames(in []string) []string {
	out := []string{}
	for _, name := range in {
		if len(out) < maxBrowserCookieNames && validCookieName(name) {
			out = append(out, name)
		}
	}
	return out
}

func browserRedirects(in []coordinator.BrowserRedirect) []coordinator.BrowserRedirect {
	out := []coordinator.BrowserRedirect{}
	for _, r := range in {
		if len(out) < maxBrowserRedirects && len(r.URL) <= maxBrowserRedirectURL && browserFinalURLAllowed(r.URL) && r.StatusCode >= 100 && r.StatusCode <= 999 {
			out = append(out, r)
		}
	}
	return out
}

// browserContentType keeps a content type the coordinator accepts: printable
// ASCII of at most 1024 bytes; anything else is sent empty.
func browserContentType(s string) string {
	if len(s) > maxBrowserContentType || !printableASCII(s) {
		return ""
	}
	return s
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
