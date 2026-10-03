//go:build xperf

package worker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	x "github.com/teslashibe/x-go"
)

// Reuse only HTTP client metadata and endpoint quota state. Every request uses
// its own context-owned bound transport and starts a fresh TLSNotary proof.
type xPerfClientRouter struct{}

func (xPerfClientRouter) RoundTrip(r *http.Request) (*http.Response, error) {
	t, ok := r.Context().Value(xAttemptTransportKey{}).(*xBoundTransport)
	if !ok || t == nil {
		return nil, errUnprovenXCall
	}
	return t.RoundTrip(r)
}

type xPerfClientEntry struct {
	ready   chan struct{}
	client  *x.Client
	err     error
	expires time.Time
}

type xPerfClientPool struct {
	mu      sync.Mutex
	entries map[[32]byte]*xPerfClientEntry
	ttl     time.Duration
	now     func() time.Time
	builds  int
}

func newXPerfClientPool(ttl time.Duration) *xPerfClientPool {
	return &xPerfClientPool{entries: make(map[[32]byte]*xPerfClientEntry), ttl: ttl, now: time.Now}
}

func (p *xPerfClientPool) factory(profile string) xClientFactory {
	return func(ctx context.Context, session x.Session, _ *xBoundTransport, ids map[string]string, timeout time.Duration) (*x.Client, error) {
		// Canonical JSON makes credential rotation, profile ownership, operation
		// metadata and timeout changes select a new entry. The digest stays in
		// private memory and is never reported or persisted.
		raw, err := json.Marshal([]any{profile, session, ids, int64(timeout)})
		if err != nil {
			return nil, errors.New("client cache key unavailable")
		}
		key := sha256.Sum256(raw)
		clear(raw)
		return p.get(ctx, key, func() (*x.Client, error) {
			client, err := newXClient(ctx, session, xPerfClientRouter{}, ids, timeout)
			if err == nil && (!client.TransactionReady() || client.TransactionInitErr() != nil) {
				err = errors.New("reusable client requires successful transaction initialization")
			}
			return client, err
		})
	}
}

func (p *xPerfClientPool) get(ctx context.Context, key [32]byte, build func() (*x.Client, error)) (*x.Client, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	now := p.now()
	if entry := p.entries[key]; entry != nil && (entry.expires.IsZero() || now.Before(entry.expires)) {
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-entry.ready:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return entry.client, entry.err
		}
	}
	for k, e := range p.entries {
		if !e.expires.IsZero() && !now.Before(e.expires) {
			delete(p.entries, k)
		}
	}
	if len(p.entries) >= 2 && p.entries[key] == nil {
		p.mu.Unlock()
		return nil, errors.New("experimental client cache capacity exhausted")
	}
	entry := &xPerfClientEntry{ready: make(chan struct{})}
	p.entries[key] = entry
	p.builds++
	p.mu.Unlock()
	client, err := build()
	p.mu.Lock()
	entry.client, entry.err, entry.expires = client, err, p.now().Add(p.ttl)
	if err != nil && p.entries[key] == entry {
		delete(p.entries, key)
	}
	close(entry.ready)
	p.mu.Unlock()
	return client, err
}

func TestXPerfClientPoolCoalescingRotationAndExpiry(t *testing.T) {
	p := newXPerfClientPool(time.Minute)
	clock := time.Now()
	p.now = func() time.Time { return clock }
	started, release := make(chan struct{}), make(chan struct{})
	client := &x.Client{}
	key := sha256.Sum256([]byte("synthetic-account-one"))
	done := make(chan *x.Client, 1)
	go func() {
		got, _ := p.get(context.Background(), key, func() (*x.Client, error) { close(started); <-release; return client, nil })
		done <- got
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.get(ctx, key, func() (*x.Client, error) { t.Error("cancelled waiter rebuilt a client"); return nil, nil }); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled cache waiter ignored its deadline")
	}
	close(release)
	if <-done != client {
		t.Fatal("client build lost")
	}
	got, err := p.get(context.Background(), key, func() (*x.Client, error) { t.Error("ready client rebuilt"); return nil, nil })
	if err != nil || got != client || p.builds != 1 {
		t.Fatal("client was not reused")
	}
	for range 20 {
		if _, err := p.get(ctx, key, func() (*x.Client, error) { t.Fatal("cancelled ready hit rebuilt"); return nil, nil }); !errors.Is(err, context.Canceled) {
			t.Fatal("ready cache hit ignored cancellation")
		}
	}
	rotated := sha256.Sum256([]byte("synthetic-account-rotated"))
	other := &x.Client{}
	got, err = p.get(context.Background(), rotated, func() (*x.Client, error) { return other, nil })
	if err != nil || got != other {
		t.Fatal("rotated account reused another client")
	}
	if _, err := p.get(context.Background(), sha256.Sum256([]byte("third")), func() (*x.Client, error) { t.Error("capacity rejection ran provider setup"); return nil, nil }); err == nil {
		t.Fatal("unbounded client cache")
	}
	clock = clock.Add(2 * time.Minute)
	got, err = p.get(context.Background(), key, func() (*x.Client, error) { return other, nil })
	if err != nil || got != other || p.builds != 3 {
		t.Fatal("expired client was reused")
	}
}

func TestXPerfClientRouterKeepsEachAttemptBound(t *testing.T) {
	router := xPerfClientRouter{}
	var calls [2]int
	for i := range 2 {
		index := i
		spec := xSpec{Operation: "SearchTimeline", QueryID: "q", Variables: map[string]any{"count": json.Number("20")}, Features: map[string]any{}}
		bound := &xBoundTransport{specs: []xSpec{spec}, proof: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls[index]++
			return &http.Response{StatusCode: 200}, nil
		})}
		r := mustRequest(t, http.MethodGet, "https://x.com/i/api/graphql/q/SearchTimeline?variables=%7B%22count%22%3A20%7D&features=%7B%7D")
		r = r.WithContext(context.WithValue(context.Background(), xAttemptTransportKey{}, bound))
		if _, err := router.RoundTrip(r); err != nil || bound.next != 1 {
			t.Fatal("cached client lost current attempt binding")
		}
		if _, err := router.RoundTrip(r); !errors.Is(err, errUnprovenXCall) {
			t.Fatal("completed attempt accepted another provider request")
		}
	}
	if calls != [2]int{1, 1} {
		t.Fatal("cached client mixed attempt transports")
	}
	if _, err := router.RoundTrip(mustRequest(t, http.MethodGet, "https://x.com/")); !errors.Is(err, errUnprovenXCall) {
		t.Fatal("cached client made an unbound provider call")
	}
}
