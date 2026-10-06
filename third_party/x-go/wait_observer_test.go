package x

import (
	"context"
	"testing"
	"time"
)

func TestWaitObserverMeasuresOnlyActualSleep(t *testing.T) {
	c := &Client{pacing: &RequestPacing{}, minGap: 25 * time.Millisecond}
	var calls int
	var duration time.Duration
	ctx := WithWaitObserver(context.Background(), func(reason string) func(bool) {
		calls++
		if reason != "gap" {
			t.Fatalf("gap reason = %q", reason)
		}
		started := time.Now()
		return func(cancelled bool) {
			duration = time.Since(started)
			if cancelled {
				t.Fatal("completed sleep claimed cancellation")
			}
		}
	})
	c.waitForGap(ctx)
	if calls != 0 {
		t.Fatal("immediate reservation fabricated a wait")
	}
	c.waitForGap(ctx)
	if calls != 1 || duration < 15*time.Millisecond {
		t.Fatal("observer did not measure the real wait", calls, duration)
	}
}

func TestWaitObserverCancellationPreservesQuotaAndReservation(t *testing.T) {
	now := time.Now()
	quota := RateLimitState{Remaining: 0, Reset: now.Add(time.Second), RetryAfter: time.Second}
	pacing := &RequestPacing{lastReqAt: now, rlState: quota}
	c := &Client{pacing: pacing, minGap: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var calls int
	var cancelled bool
	ctx = WithWaitObserver(ctx, func(reason string) func(bool) {
		calls++
		if reason != "quota" {
			t.Fatalf("quota reason = %q", reason)
		}
		return func(value bool) { cancelled = value }
	})
	c.waitForGap(ctx)
	if calls != 1 || !cancelled || pacing.RateLimit() != quota || !pacing.LastRequestAt().After(now) {
		t.Fatal("observed cancellation changed cooldown or reservation", calls, cancelled, pacing.RateLimit(), pacing.LastRequestAt())
	}
}

func TestWaitObserverPanicsCannotChangeProviderWait(t *testing.T) {
	for _, atStart := range []bool{true, false} {
		c := &Client{pacing: &RequestPacing{lastReqAt: time.Now()}, minGap: 10 * time.Millisecond}
		ctx := WithWaitObserver(context.Background(), func(string) func(bool) {
			if atStart {
				panic("synthetic observational failure")
			}
			return func(bool) { panic("synthetic observational failure") }
		})
		started := time.Now()
		c.waitForGap(ctx)
		if time.Since(started) < 5*time.Millisecond || ctx.Err() != nil {
			t.Fatal("observer changed the wait")
		}
	}
}
