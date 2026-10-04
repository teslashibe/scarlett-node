package worker

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

// xCounter is a Base transport that counts what a job sends unproven: x-go's
// construction-time GraphQL reads and its transaction-ID bootstrap fetches.
type xCounter struct {
	graphql, bootstrap atomic.Int32
}

func (c *xCounter) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.Contains(r.URL.Path, "/i/api/graphql/") {
		c.graphql.Add(1)
	} else {
		c.bootstrap.Add(1)
	}
	return xBootstrap(r)
}

// TestXWarmAccountMeasurement runs the same profile read three times on one
// account and reports, per job, the unproven requests that went through Base
// and the wall time. Fixture latencies are synthetic, so the counts are the
// metric; the times show the 1 s request gap. A warm account must do nothing
// but its proven read: the second and third jobs send zero unproven requests.
func TestXWarmAccountMeasurement(t *testing.T) {
	c, l, _ := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "fixture"})
	var proofs atomic.Int32
	proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		proofs.Add(1)
		return xBootstrap(r)
	})
	type run struct {
		graphql, bootstrap, proofs int32
		took                       time.Duration
	}
	var runs []run
	for i := 0; i < 3; i++ {
		if i == 2 {
			// An account idle for longer than the request gap pays no gap at all.
			time.Sleep(1100 * time.Millisecond)
		}
		base := &xCounter{}
		proofs.Store(0)
		start := time.Now()
		if code := (X{Config: c, Base: base, Proof: proof}).Run(context.Background(), l); code != "" {
			t.Fatal("job failed", code)
		}
		runs = append(runs, run{base.graphql.Load(), base.bootstrap.Load(), proofs.Load(), time.Since(start)})
	}
	for i, r := range runs {
		t.Logf("job %d: %d unproven GraphQL reads, %d bootstrap fetches, %d proven reads, %s", i+1, r.graphql, r.bootstrap, r.proofs, r.took.Round(time.Millisecond))
	}
	if runs[0].proofs != 1 || runs[1].proofs != 1 || runs[2].proofs != 1 {
		t.Fatal("each job must prove exactly one read")
	}
	if runs[1].graphql != 0 || runs[1].bootstrap != 0 || runs[2].graphql != 0 || runs[2].bootstrap != 0 {
		t.Fatalf("warm account sent unproven requests: %+v", runs[1:])
	}
}
