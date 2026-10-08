package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/webruntime"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

func init() {
	startBrowserTier = startRuntimeBrowser
	checkWebRuntime = func(ctx context.Context, resources, state string, withBrowser bool) error {
		return webruntime.Check(ctx, webruntime.CheckOptions{ResourceDir: resources, StateDir: state, WithBrowser: withBrowser})
	}
}

// startRuntimeBrowser builds the runtime manager and runs it in the
// background: memory check, runtime extraction and verification, browser
// download and verification, launch probe, then supervision. The tier
// reports browser_downloading and the like until that is done.
func startRuntimeBrowser(ctx context.Context, c config.Config) (worker.BrowserTier, func()) {
	resources, err := webRuntimeResourceDir()
	if err != nil {
		return unavailableBrowser{reason: "runtime_missing"}, func() {}
	}
	cfg := webruntime.Config{
		ResourceDir: resources,
		StateDir:    c.StateDir,
		XLoginNode:  xLoginNode(resources),
		// The same guard as every relay hop.
		Guard:       worker.DefaultWebEgress(),
		Resolver:    lookupWebHost,
		Capacity:    c.WebBrowserConcurrency, // 0: chosen from physical memory
		IdleTimeout: c.WebBrowserIdle,
		// State transitions and closed reasons only.
		Logf: func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) },
	}
	if p := c.WebEgressProxy; p != nil {
		cfg.UpstreamProxy, cfg.UpstreamAuthorization = upstreamProxyURL(p), p.Authorization
	}
	cfg.Solvers = runtimeSolvers(c.WebSolvers)
	m := webruntime.New(cfg)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); m.Run(runCtx) }()
	return runtimeBrowser{m}, func() {
		cancel()
		shutdown, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = m.Close(shutdown)
		select {
		case <-done:
		case <-shutdown.Done():
		}
	}
}

// runtimeBrowser adapts the runtime manager to the worker's BrowserTier.
type runtimeBrowser struct{ m *webruntime.Manager }

func (r runtimeBrowser) Status() worker.BrowserStatus {
	h := r.m.Health()
	return worker.BrowserStatus{Ready: h.State == "ready", Reason: string(h.Reason), Capacity: h.Capacity, Version: h.Version, Engine: webruntime.Engine, UserAgent: r.m.UserAgent(), Solvers: h.Solvers}
}

func (r runtimeBrowser) Prewarm() { r.m.Prewarm() }

// Fetch maps the runtime's errors to the worker's: ErrUnavailable (not ready,
// busy, or the helper could not start) is web_browser_unavailable, and any
// other error a failed render.
func (r runtimeBrowser) Fetch(ctx context.Context, req worker.BrowserFetchRequest) (worker.BrowserFetchResult, error) {
	res, err := r.m.Fetch(ctx, webruntime.FetchRequest(req))
	if errors.Is(err, webruntime.ErrUnavailable) {
		return worker.BrowserFetchResult{}, worker.ErrBrowserUnavailable
	}
	if err != nil {
		return worker.BrowserFetchResult{}, err
	}
	out := worker.BrowserFetchResult{Outcome: res.Outcome, Error: res.Error, FinalURL: res.FinalURL, StatusCode: res.StatusCode, Headers: res.Headers, SetCookieNames: res.SetCookieNames, ContentType: res.ContentType, HTML: res.HTML, HTMLTruncated: res.HTMLTruncated, Challenge: res.Challenge, StartedAtMS: res.StartedAtMS, Solver: res.Solver}
	for _, c := range res.Cookies {
		out.Cookies = append(out.Cookies, worker.BrowserCookie(c))
	}
	for _, redirect := range res.Redirects {
		out.Redirects = append(out.Redirects, coordinator.BrowserRedirect(redirect))
	}
	return out, nil
}

// runtimeSolvers hands the operator's solver accounts to the runtime, or nil.
func runtimeSolvers(s *config.WebSolvers) *webruntime.Solvers {
	if s == nil || len(s.Providers) == 0 {
		return nil
	}
	out := &webruntime.Solvers{Keys: map[string]string{}, MaxSolvesPerFetch: s.MaxSolvesPerFetch, MaxMicroUSDPerDay: s.MaxMicroUSDPerDay, Experimental: s.Experimental}
	for _, name := range s.Providers {
		out.Keys[name] = s.Key(name)
	}
	return out
}
