package x

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestSharedPacingPreservesCooldownAgainstLaterHeaders(t *testing.T) {
	domain := &RequestPacing{}
	first, second := &Client{pacing: domain}, &Client{pacing: domain}
	first.recordRateLimit(time.Minute)
	prior := domain.RateLimit()
	response := &http.Response{Header: http.Header{}}
	response.Header.Set("X-Rate-Limit-Limit", "100")
	response.Header.Set("X-Rate-Limit-Remaining", "99")
	response.Header.Set("X-Rate-Limit-Reset", strconv.FormatInt(prior.Reset.Add(time.Second).Unix(), 10))
	second.updateRateLimit(response)
	got := domain.RateLimit()
	if got.Remaining != 0 || got.Reset.Before(prior.Reset) || got.RetryAfter != prior.RetryAfter {
		t.Fatal("later session headers relaxed the active cooldown", got)
	}
	// An older response cannot shorten the shared reset either.
	response.Header.Set("X-Rate-Limit-Reset", strconv.FormatInt(prior.Reset.Add(-10*time.Second).Unix(), 10))
	second.updateRateLimit(response)
	if domain.RateLimit() != got {
		t.Fatal("stale headers replaced the shared quota state")
	}
}

func TestSharedPacingAcceptsNewWindowOnlyAfterExpiry(t *testing.T) {
	domain := &RequestPacing{rlState: RateLimitState{Remaining: 0, Reset: time.Now().Add(-time.Second), RetryAfter: time.Minute}}
	client := &Client{pacing: domain}
	response := &http.Response{Header: http.Header{}}
	response.Header.Set("X-Rate-Limit-Limit", "100")
	response.Header.Set("X-Rate-Limit-Remaining", "99")
	response.Header.Set("X-Rate-Limit-Reset", "120")
	client.updateRateLimit(response)
	got := domain.RateLimit()
	if got.Remaining != 99 || got.ResetIn() < 119*time.Second || got.RetryAfter != 0 {
		t.Fatal("expired quota did not advance to a fresh window", got)
	}
}

func TestIdentityPacingMergeKeepsEarlierReservationsAndQuota(t *testing.T) {
	now := time.Now()
	shared := &RequestPacing{lastReqAt: now.Add(30 * time.Second), rlState: RateLimitState{Remaining: 0, Reset: now.Add(time.Minute), RetryAfter: time.Minute}}
	local := &RequestPacing{lastReqAt: now}
	local.observe(RateLimitState{Limit: 100, Remaining: 99, Reset: now.Add(2 * time.Minute)}, true, true, true)
	shared.merge(local)
	if got := shared.RateLimit(); got.Remaining != 0 || got.Reset.Before(local.RateLimit().Reset) || got.RetryAfter != time.Minute {
		t.Fatal("validation merge discarded existing quota", got)
	}
	if shared.LastRequestAt() != now.Add(30*time.Second) {
		t.Fatal("validation merge reset an already reserved slot")
	}
}
