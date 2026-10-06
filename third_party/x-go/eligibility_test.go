package x

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestQuotaBudgetRequiresSameCompleteOperationAndHeadroom(t *testing.T) {
	now := time.Now()
	quota := RateLimitState{Limit: 100, Remaining: 21, Reset: now.Add(15 * time.Minute)}
	for _, observed := range []struct {
		remaining, reset bool
		operation        string
		burst            bool
		want             string
	}{
		{true, true, "SearchTimeline", true, "gap"},
		{false, true, "SearchTimeline", true, "reset"},
		{true, false, "SearchTimeline", true, "gap"}, // no known window: ordinary minimum only
		{true, true, "UserByScreenName", true, "spread"},
		{true, true, "", true, "spread"},
		{true, true, "SearchTimeline", false, "spread"},
	} {
		p := &RequestPacing{lastReqAt: now.Add(-time.Second), burst: observed.burst}
		p.observe(quota, true, observed.remaining, observed.reset, observed.operation)
		before := p.RateLimit()
		for range 16 {
			e := p.Eligibility(time.Second, now, "SearchTimeline")
			if e.Reason != observed.want {
				t.Fatalf("%+v: got %+v", observed, e)
			}
		}
		if p.RateLimit() != before || p.LastRequestAt() != now.Add(-time.Second) {
			t.Fatal("inspection consumed a slot")
		}
	}
	p := &RequestPacing{lastReqAt: now.Add(-time.Second), burst: true}
	p.observe(RateLimitState{Limit: 100, Remaining: 20, Reset: quota.Reset}, true, true, true, "SearchTimeline")
	if e := p.Eligibility(time.Second, now, "SearchTimeline"); e.Reason != "spread" || !e.At.After(now) {
		t.Fatal("reserve floor was burstable", e)
	}
	p.observe(RateLimitState{Limit: 100, Remaining: 99, Reset: quota.Reset}, true, true, true, "SearchTimeline")
	if p.RateLimit().Remaining != 20 {
		t.Fatal("stale higher headers renewed budget")
	}
	p.observe(RateLimitState{Limit: 100, Remaining: 99, Reset: quota.Reset.Add(-time.Second)}, true, true, true, "SearchTimeline")
	if p.RateLimit().Remaining != 20 || p.RateLimit().Reset != quota.Reset {
		t.Fatal("older window replaced stricter state")
	}
}

func TestAtomicDispatchCannotSpendBurstReserveConcurrently(t *testing.T) {
	now := time.Now()
	p := &RequestPacing{burst: true}
	p.observe(RateLimitState{Limit: 100, Remaining: 21, Reset: now.Add(10 * time.Second)}, true, true, true, "SearchTimeline")
	var calls atomic.Int32
	c := &Client{pacing: p, minGap: time.Millisecond, httpClient: &http.Client{Transport: observerFixtureTransport(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(nilReader{})}, nil
	})}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://fixture.invalid", nil)
			response, _ := c.dispatch(req, "SearchTimeline")
			if response != nil {
				response.Body.Close()
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 || p.RateLimit().Remaining != 20 {
		t.Fatal("concurrent calls spent the reserve", calls.Load(), p.RateLimit())
	}
}

func TestPartialAfterCompleteRevokesChangedBurstAuthority(t *testing.T) {
	now := time.Now()
	initial := RateLimitState{Limit: 50, Remaining: 30, Reset: now.Add(time.Minute)}
	for _, tc := range []struct {
		name                    string
		partial                 RateLimitState
		limit, remaining, reset bool
		operation               string
	}{
		{"later-reset", RateLimitState{Reset: initial.Reset.Add(time.Second)}, false, false, true, "SearchTimeline"},
		{"lower-remaining", RateLimitState{Remaining: 29}, false, true, false, "SearchTimeline"},
		{"lower-limit", RateLimitState{Limit: 40}, true, false, false, "SearchTimeline"},
		{"inconsistent-lower-limit", RateLimitState{Limit: 10}, true, false, false, "SearchTimeline"},
		{"other-operation", RateLimitState{Remaining: 28}, false, true, false, "UserByScreenName"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &RequestPacing{burst: true, lastReqAt: now}
			p.observe(initial, true, true, true, "SearchTimeline")
			if e := p.Eligibility(time.Millisecond, now, "SearchTimeline"); !e.Complete || e.Reason != "gap" {
				t.Fatal("fixture lacks complete burst authority", e)
			}
			p.observe(tc.partial, tc.limit, tc.remaining, tc.reset, tc.operation)
			e := p.Eligibility(time.Millisecond, now, "SearchTimeline")
			if e.Complete || e.Reason != "spread" || !e.At.After(now.Add(time.Second)) || e.Quota.Remaining > initial.Remaining || e.Quota.Reset.Before(initial.Reset) {
				t.Fatal("partial response retained complete burst authority or relaxed quota", e)
			}
			// A later complete triplet can restore same-operation authority but
			// cannot renew the stricter remaining budget within this window.
			p.observe(RateLimitState{Limit: 50, Remaining: 30, Reset: e.Quota.Reset}, true, true, true, "SearchTimeline")
			if got := p.Eligibility(time.Millisecond, now, "SearchTimeline"); got.Complete != (e.Quota.Remaining <= e.Quota.Limit) || got.Quota.Remaining != e.Quota.Remaining {
				t.Fatal("complete evidence renewed budget", got)
			}
			if e.Quota.Remaining > e.Quota.Limit {
				p.observe(RateLimitState{Limit: 10, Remaining: 9, Reset: e.Quota.Reset}, true, true, true, "SearchTimeline")
				if got := p.Eligibility(time.Millisecond, now, "SearchTimeline"); !got.Complete || got.Quota.Limit != 10 || got.Quota.Remaining != 9 {
					t.Fatal("consistent stricter complete triplet failed to restore authority", got)
				}
			}
		})
	}
	p := &RequestPacing{burst: true}
	p.observe(initial, true, true, true, "SearchTimeline")
	observedAt := p.observedAt
	p.observe(RateLimitState{Remaining: 99}, false, true, false, "SearchTimeline")
	if e := p.Eligibility(time.Millisecond, now, "SearchTimeline"); !e.Complete || e.Quota != initial || p.observedAt != observedAt {
		t.Fatal("ignored stale partial changed retained evidence", e)
	}
	p.observe(RateLimitState{Remaining: 0}, false, true, false, "SearchTimeline")
	if e := p.Eligibility(time.Millisecond, now, "SearchTimeline"); e.Complete || e.At != initial.Reset.Add(50*time.Millisecond) || !e.Authoritative {
		t.Fatal("partial exhaustion weakened explicit reset floor", e)
	}
}

type nilReader struct{}

func (nilReader) Read([]byte) (int, error) { return 0, io.EOF }

func TestCancelledDispatchPreservesBudgetAndDoesNoHTTP(t *testing.T) {
	p := &RequestPacing{burst: true}
	p.observe(RateLimitState{Limit: 100, Remaining: 21, Reset: time.Now().Add(time.Minute)}, true, true, true, "SearchTimeline")
	before := p.RateLimit()
	var calls int
	c := &Client{pacing: p, httpClient: &http.Client{Transport: observerFixtureTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected fixture HTTP")
	})}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://fixture.invalid", nil)
	if _, err := c.dispatch(req, "SearchTimeline"); !errors.Is(err, context.Canceled) || calls != 0 || p.RateLimit() != before {
		t.Fatal("cancelled dispatch spent provider budget", err, calls, p.RateLimit())
	}
}

func TestResetFloorAndStableSpreadEligibility(t *testing.T) {
	now := time.Now()
	p := &RequestPacing{lastReqAt: now.Add(-10 * time.Second)}
	reset := now.Add(time.Minute)
	p.observe(RateLimitState{Remaining: 0, Reset: reset}, false, true, true)
	if got := p.Eligibility(time.Second, now); got.At != reset.Add(50*time.Millisecond) || !got.Authoritative {
		t.Fatal("reset floor is not absolute", got)
	}
	p = &RequestPacing{lastReqAt: now, rlState: RateLimitState{Limit: 100, Remaining: 10, Reset: reset}}
	first := p.Eligibility(time.Second, now)
	second := p.Eligibility(time.Second, now.Add(time.Second))
	if first.At != second.At || first.Reason != "spread" {
		t.Fatal("unchanged quota emitted a moving heartbeat deadline", first, second)
	}
	if e := p.Eligibility(time.Second, reset.Add(time.Second), "SearchTimeline"); e.Reason != "gap" || e.At.After(reset.Add(time.Second)) {
		t.Fatal("expired evidence authorized a new window", e)
	}
}

func TestProviderResetDistinguishesExplicitAndSyntheticWaits(t *testing.T) {
	for _, tc := range []struct {
		header  http.Header
		known   bool
		minimum time.Duration
	}{
		{http.Header{}, false, time.Minute},
		{http.Header{"Retry-After": []string{"garbage"}}, false, time.Minute},
		{http.Header{"Retry-After": []string{"2"}}, true, 1900 * time.Millisecond},
		{http.Header{"Retry-After": []string{"2"}, "X-Rate-Limit-Reset": []string{"5"}}, true, 4900 * time.Millisecond},
	} {
		wait, reset := providerReset(tc.header)
		if !reset.IsZero() != tc.known || wait < tc.minimum {
			t.Fatal("wrong reset provenance", tc, wait, reset)
		}
	}
}

func TestDeterministicIdleJitterSlotArithmetic(t *testing.T) {
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	for _, last := range []time.Time{{}, now.Add(-time.Hour)} {
		base, at := requestSlot(last, now, time.Second, time.Nanosecond, time.Time{})
		if base != now || at != now.Add(time.Nanosecond) {
			t.Fatal("idle jitter can pass without adding the actual draw", base, at)
		}
	}
	base, at := requestSlot(now, now, time.Second, 250*time.Millisecond, now.Add(time.Minute))
	if base != now.Add(time.Minute) || at != base.Add(250*time.Millisecond) {
		t.Fatal("jitter weakened the reset floor", base, at)
	}
}

func TestSecondPageRechecksBudgetAndObserverCannotAuthorizeHTTP(t *testing.T) {
	now := time.Now()
	p := &RequestPacing{burst: true}
	p.observe(RateLimitState{Limit: 100, Remaining: 21, Reset: now.Add(10 * time.Second)}, true, true, true, "SearchTimeline")
	var calls atomic.Int32
	c := &Client{pacing: p, minGap: time.Millisecond, httpClient: &http.Client{Transport: observerFixtureTransport(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(nilReader{})}, nil
	})}}
	var observation QuotaObservation
	ctx := WithQuotaObserver(context.Background(), func(q QuotaObservation) { observation = q; panic("optional observer failure") })
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://fixture.invalid", nil)
	response, err := c.dispatch(req, "SearchTimeline")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if !observation.Complete || observation.Remaining != 21 || observation.ObservedAt.IsZero() || observation.NextEligibleAt.Sub(observation.CapturedAt) < 400*time.Millisecond {
		t.Fatal("snapshot did not project following-page reserve wait", observation)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, "https://fixture.invalid", nil)
	if _, err := c.dispatch(req, "SearchTimeline"); !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 || p.RateLimit().Remaining != 20 {
		t.Fatal("second page bypassed aggregate reserve", err, calls.Load(), p.RateLimit())
	}
}

func TestRemovedDomainRetentionIncludesActualDispatchAndOriginalObservation(t *testing.T) {
	now := time.Now()
	local := &RequestPacing{lastReqAt: now.Add(-time.Second), lastSentAt: now}
	local.observe(RateLimitState{Limit: 100, Remaining: 30, Reset: now.Add(500 * time.Millisecond)}, true, true, true, "SearchTimeline")
	local.observedAt = now.Add(-5 * time.Second)
	p := &RequestPacing{}
	p.merge(local)
	if got := p.RetainUntil(time.Second); got != now.Add(time.Second) || p.observedAt != local.observedAt {
		t.Fatal("merge lost sent floor or refreshed header age", got, p.observedAt)
	}
}

func TestValidationMergePreservesPartialPresenceAndNoInventedZero(t *testing.T) {
	now := time.Now()
	initial := RateLimitState{Limit: 100, Remaining: 80, Reset: now.Add(time.Minute)}
	for _, tc := range []struct {
		name                    string
		partial                 RateLimitState
		limit, remaining, reset bool
		wantRemaining           int
		wantReset               time.Time
	}{
		{"explicit-zero-without-reset", RateLimitState{Remaining: 0}, false, true, false, 0, initial.Reset},
		{"reset-without-remaining", RateLimitState{Reset: initial.Reset.Add(time.Second)}, false, false, true, 80, initial.Reset.Add(time.Second)},
		{"stricter-limit-without-remaining", RateLimitState{Limit: 50}, true, false, false, 80, initial.Reset},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shared := &RequestPacing{burst: true}
			shared.observe(initial, true, true, true, "SearchTimeline")
			local := &RequestPacing{}
			local.observe(tc.partial, tc.limit, tc.remaining, tc.reset, "UserByScreenName")
			shared.merge(local)
			e := shared.Eligibility(time.Millisecond, now, "SearchTimeline")
			if e.Complete || e.Quota.Remaining != tc.wantRemaining || e.Quota.Reset != tc.wantReset {
				t.Fatal("merge dropped partial floor or invented absent zero", e)
			}
			if tc.wantRemaining == 0 && e.At != tc.wantReset.Add(50*time.Millisecond) {
				t.Fatal("explicit zero lost retained absolute reset floor", e)
			}
		})
	}
	shared := &RequestPacing{burst: true}
	shared.observe(initial, true, true, true, "SearchTimeline")
	local := &RequestPacing{}
	(&Client{pacing: local}).recordRateLimit(2 * time.Minute)
	shared.merge(local)
	if e := shared.Eligibility(time.Millisecond, now, "SearchTimeline"); e.Complete || e.Quota.Remaining != 0 || e.Quota.Reset.Before(now.Add(2*time.Minute)) || e.Authoritative {
		t.Fatal("synthetic denial merge lost unknown floor", e)
	}
}
