package x

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequestJitterPreservesGapAndCancellation(t *testing.T) {
	for _, configured := range []time.Duration{-time.Second, 0, 250 * time.Millisecond} {
		t.Run(configured.String(), func(t *testing.T) {
			prior := time.Now().Add(time.Hour)
			pacing := &RequestPacing{lastReqAt: prior}
			var requests atomic.Int32
			c := &Client{pacing: pacing, minGap: time.Second, httpClient: &http.Client{Transport: observerFixtureTransport(func(*http.Request) (*http.Response, error) {
				requests.Add(1)
				return nil, errors.New("unexpected provider request")
			})}}
			WithRequestJitter(configured)(c)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			for range 16 {
				_, err := c.doGraphQLGET(ctx, "synthetic-id", "synthetic-operation", []byte(`{}`), []byte(`{}`))
				if !errors.Is(err, context.Canceled) || requests.Load() != 0 {
					t.Fatal("cancelled request reached the provider", err, requests.Load())
				}
				next := pacing.LastRequestAt()
				added := next.Sub(prior) - c.minGap
				if configured <= 0 && added != 0 || configured > 0 && (added <= 0 || added > configured) {
					t.Fatal("reservation violated jitter bounds", configured, added)
				}
				prior = next
			}
		})
	}
}

func TestRequestJitterAppliesAfterIdle(t *testing.T) {
	for _, prior := range []time.Time{{}, time.Now().Add(-time.Hour)} {
		pacing := &RequestPacing{lastReqAt: prior}
		c := &Client{pacing: pacing, minGap: time.Second}
		// A single-nanosecond bound gives a deterministic positive draw.
		WithRequestJitter(time.Nanosecond)(c)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		before := time.Now()
		c.waitForGap(ctx)
		after := time.Now()
		if got := pacing.LastRequestAt(); got.Before(before.Add(time.Nanosecond)) || got.After(after.Add(time.Nanosecond)) {
			t.Fatal("idle reservation did not include bounded jitter", got, before, after)
		}
	}
}

func TestRequestJitterSharesConcurrentReservations(t *testing.T) {
	const count = 64
	const gap, jitter = time.Second, 250 * time.Millisecond
	prior := time.Now().Add(time.Hour)
	pacing := &RequestPacing{lastReqAt: prior}
	first, second := &Client{pacing: pacing, minGap: gap}, &Client{pacing: pacing, minGap: gap}
	WithRequestJitter(jitter)(first)
	WithRequestJitter(jitter)(second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	for i := range count {
		c := first
		if i%2 != 0 {
			c = second
		}
		wg.Go(func() { c.waitForGap(ctx) })
	}
	wg.Wait()
	elapsed := pacing.LastRequestAt().Sub(prior)
	if elapsed <= count*gap || elapsed > count*(gap+jitter) {
		t.Fatal("shared clients lost or exceeded their reserved slots", elapsed)
	}
}

func TestRequestJitterPreservesQuotaWait(t *testing.T) {
	now := time.Now()
	quota := RateLimitState{Remaining: 0, Reset: now.Add(time.Minute), RetryAfter: time.Minute}
	prior := now.Add(time.Hour)
	pacing := &RequestPacing{lastReqAt: prior, rlState: quota}
	c := &Client{pacing: pacing, minGap: time.Second}
	WithRequestJitter(250 * time.Millisecond)(c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.waitForGap(ctx)
	minimum, _ := c.adaptiveGapReason()
	if pacing.RateLimit() != quota || pacing.LastRequestAt().Sub(prior) < minimum {
		t.Fatal("jitter relaxed the existing quota wait", pacing.RateLimit(), pacing.LastRequestAt())
	}
}
