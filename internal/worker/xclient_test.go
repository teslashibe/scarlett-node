package worker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	x "github.com/teslashibe/x-go"
)

// xOK is a proof transport that answers the profile read the fixture pins.
func xOK(r *http.Request) (*http.Response, error) { return xBootstrap(r) }

// A session X refuses on a proven read is dropped: the next job on the
// account builds a client again instead of reusing the dead one.
func TestXAuthFailureDropsTheWarmClient(t *testing.T) {
	c, l, _ := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "fixture"})
	base := &xCounter{}
	if code := (X{Config: c, Base: base, Proof: roundTripFunc(xOK)}).Run(context.Background(), l); code != "" || base.graphql.Load() != 2 {
		t.Fatal("cold job", code, base.graphql.Load())
	}
	if !XClientStatus(c.XSession, time.Now()).Warm {
		t.Fatal("client not cached after a successful job")
	}
	unauthorized := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return xResponse(r, 401, `{"errors":[{"code":32,"message":"Could not authenticate you"}]}`), nil
	})
	if code := (X{Config: c, Base: base, Proof: unauthorized}).Run(context.Background(), l); code != "auth_required" {
		t.Fatal("401 classified as", code)
	}
	if XClientStatus(c.XSession, time.Now()).Warm {
		t.Fatal("refused session kept its client")
	}
	base = &xCounter{}
	if code := (X{Config: c, Base: base, Proof: roundTripFunc(xOK)}).Run(context.Background(), l); code != "" || base.graphql.Load() != 2 {
		t.Fatal("next job did not rebuild", code, base.graphql.Load())
	}
}

// A rewritten session file replaces the client, and the new client carries
// the new credentials; an unchanged file does not.
func TestXChangedSessionFileRebuildsTheClient(t *testing.T) {
	c, l, _ := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "fixture"})
	var cookie atomic.Value
	proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		cookie.Store(r.Header.Get("Cookie"))
		return xOK(r)
	})
	base := &xCounter{}
	if code := (X{Config: c, Base: base, Proof: proof}).Run(context.Background(), l); code != "" {
		t.Fatal(code)
	}
	// Same credentials, different bytes and timestamps.
	raw := []byte(`{"auth_token": "synthetic-auth", "ct0": "synthetic-csrf"}`)
	if e := localfs.WriteAtomic(c.XSession, raw, true); e != nil {
		t.Fatal(e)
	}
	base = &xCounter{}
	if code := (X{Config: c, Base: base, Proof: proof}).Run(context.Background(), l); code != "" || base.graphql.Load() != 0 {
		t.Fatal("identical credentials rebuilt the client", code, base.graphql.Load())
	}
	raw, _ = json.Marshal(x.Session{AuthToken: "synthetic-auth", CT0: "rotated-csrf"})
	if e := localfs.WriteAtomic(c.XSession, raw, true); e != nil {
		t.Fatal(e)
	}
	base = &xCounter{}
	if code := (X{Config: c, Base: base, Proof: proof}).Run(context.Background(), l); code != "" || base.graphql.Load() != 2 {
		t.Fatal("changed credentials reused the old client", code, base.graphql.Load())
	}
	if got, _ := cookie.Load().(string); !strings.Contains(got, "rotated-csrf") || strings.Contains(got, "synthetic-csrf") {
		t.Fatal("proven read carried the old credentials")
	}
	// A file that is no longer usable drops the client; the account is back
	// to needing a sign-in, not serving from memory.
	if e := makeSessionPublic(c.XSession); e != nil {
		t.Fatal(e)
	}
	if code := (X{Config: c, Base: base, Proof: proof}).Run(context.Background(), l); code != "auth_required" || XClientStatus(c.XSession, time.Now()).Warm {
		t.Fatal("unusable session file left a client serving", code)
	}
}

// Two jobs on one account run at once on the shared client. Each proves only
// its own exchanges through its own transport, so neither can spend the
// other's verifier token or match the other's pinned read.
func TestXConcurrentJobsOnOneAccountKeepTheirOwnBinding(t *testing.T) {
	ca, la, _ := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "fixture"})
	cb, lb, _ := xFixture(t, coordinator.XRequest{Operation: "post", PostID: "20"})
	cb.XSession = ca.XSession
	lb.VerifierToken = strings.Repeat("cd", 32)
	var seenA, seenB []string
	var mu sync.Mutex
	record := func(seen *[]string, body string) roundTripFunc {
		return func(r *http.Request) (*http.Response, error) {
			mu.Lock()
			*seen = append(*seen, r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:])
			mu.Unlock()
			return xResponse(r, 200, body), nil
		}
	}
	proofA := record(&seenA, `{"data":{"user":{"result":{"__typename":"User","rest_id":"12","legacy":{"screen_name":"fixture"}}}}}`)
	proofB := record(&seenB, `{"data":{"tweetResult":{"result":{"__typename":"Tweet","rest_id":"20","legacy":{"id_str":"20","full_text":"synthetic post","user_id_str":"12"}}}}}`)
	base := &xCounter{}
	var codes [2]string
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		codes[0] = X{Config: ca, Base: base, Proof: proofA}.Run(context.Background(), la)
	}()
	go func() {
		defer wg.Done()
		codes[1] = X{Config: cb, Base: base, Proof: proofB}.Run(context.Background(), lb)
	}()
	wg.Wait()
	if codes != [2]string{"", ""} {
		t.Fatal("concurrent jobs failed", codes)
	}
	if strings.Join(seenA, ",") != "UserByScreenName" || strings.Join(seenB, ",") != "TweetResultByRestId" {
		t.Fatal("a job's read reached the other job's proof transport", seenA, seenB)
	}
	if base.graphql.Load() != 2 {
		t.Fatal("two jobs arriving together built two clients", base.graphql.Load())
	}
}

// A lease may pin a query ID x-go does not know for the operation. The read
// x-go builds with its own ID is stopped in the node, the client is rebuilt
// with the lease's IDs, and the proven read carries the pinned ID. Later
// leases with that ID find the client warm.
func TestXLeasePinnedQueryIDRebuildsOnceAndIsHonoured(t *testing.T) {
	c, l, plan := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "fixture"})
	base := &xCounter{}
	if code := (X{Config: c, Base: base, Proof: roundTripFunc(xOK)}).Run(context.Background(), l); code != "" {
		t.Fatal(code)
	}
	plan.Exchanges[0].QueryID = "pinnedByTheLease_1"
	l.XPayload, _ = json.Marshal(plan)
	var paths []string
	proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Path)
		return xOK(r)
	})
	base = &xCounter{}
	if code := (X{Config: c, Base: base, Proof: proof}).Run(context.Background(), l); code != "" {
		t.Fatal("pinned query ID job failed", code)
	}
	if len(paths) != 1 || paths[0] != "/i/api/graphql/pinnedByTheLease_1/UserByScreenName" {
		t.Fatal("proven read did not carry the lease's query ID", paths)
	}
	if base.graphql.Load() != 2 {
		t.Fatalf("rebuild sent %d unproven reads, want one construction", base.graphql.Load())
	}
	base = &xCounter{}
	if code := (X{Config: c, Base: base, Proof: proof}).Run(context.Background(), l); code != "" || base.graphql.Load() != 0 || len(paths) != 2 {
		t.Fatal("second pinned job was not warm", code, base.graphql.Load())
	}
}

// X's rate-limit headers on a 200 never reach x-go. Otherwise one response
// saying "49 left in this window" would pace every later read on the account
// to the window length divided by 49, far beyond the one-second gap.
func TestXRateLimitHeadersDoNotPaceTheSharedClient(t *testing.T) {
	c, l, _ := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "fixture"})
	limit := func(resp *http.Response) *http.Response {
		resp.Header.Set("X-Rate-Limit-Limit", "50")
		resp.Header.Set("X-Rate-Limit-Remaining", "1")
		resp.Header.Set("X-Rate-Limit-Reset", "4102444800")
		return resp
	}
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, e := xBootstrap(r)
		return limit(resp), e
	})
	proof := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, e := xOK(r)
		return limit(resp), e
	})
	start := time.Now()
	for i := 0; i < 2; i++ {
		if code := (X{Config: c, Base: base, Proof: proof}).Run(context.Background(), l); code != "" {
			t.Fatal("job", i, code)
		}
	}
	if took := time.Since(start); took > 6*time.Second {
		t.Fatal("rate-limit headers paced the shared client:", took)
	}
	// A 429 keeps its headers: the typed cooldown still reaches the scheduler.
	observed := time.Duration(0)
	c.AccountCooldown = func(wait time.Duration) { observed = wait }
	limited := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp := xResponse(r, 429, "")
		resp.Header.Set("Retry-After", "120")
		return resp, nil
	})
	if code := (X{Config: c, Base: base, Proof: limited}).Run(context.Background(), l); code != "x_rate_limited" || observed != 2*time.Minute {
		t.Fatal("429 lost its cooldown", code, observed)
	}
}

// xGate is a Base that can hold x-go's Viewer read until released, and can
// answer it with a chosen status.
type xGate struct {
	xCounter
	hold   chan struct{}
	viewer int
}

func (g *xGate) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/Viewer") {
		if g.hold != nil {
			<-g.hold
		}
		if g.viewer != 0 && g.viewer != 200 {
			g.graphql.Add(1)
			body := ""
			if g.viewer == 401 {
				body = `{"errors":[{"code":32,"message":"Could not authenticate you"}]}`
			}
			return xResponse(r, g.viewer, body), nil
		}
	}
	return g.xCounter.RoundTrip(r)
}

func warm(t *testing.T, path string, base http.RoundTripper) string {
	t.Helper()
	code := make(chan string, 1)
	WarmXClient(context.Background(), path, base, 10*time.Second, func(c string) { code <- c })
	select {
	case c := <-code:
		return c
	case <-time.After(15 * time.Second):
		t.Fatal("warm-up reported nothing")
		return ""
	}
}

// The background refresh. An account idle past the interval is rebuilt, and
// the rebuild's first request, Viewer, is the session check: a session that
// died while idle is found before a buyer's job is. An account that proved a
// read within the interval is left alone. A refresh never takes the old
// client away while it runs or when it fails for reasons other than auth.
func TestXBackgroundRefreshChecksIdleSessionsAndKeepsBusyOnes(t *testing.T) {
	c, l, _ := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "fixture"})
	path := c.XSession
	now := time.Now()
	if code := warm(t, path, &xGate{}); code != "" || !XClientStatus(path, now).Warm {
		t.Fatal("warm-up", code)
	}
	if st := XClientStatus(path, now); st.Stale || st.Building {
		t.Fatal("fresh client reported stale")
	}
	// Recently active: nothing is sent.
	if !AgeXClientForTests(path, now.Add(-xRefreshInterval-time.Minute), now.Add(-time.Minute)) {
		t.Fatal("no client to age")
	}
	if XClientStatus(path, now).Stale {
		t.Fatal("recently proven account due a refresh")
	}
	base := &xGate{}
	if code := warm(t, path, base); code != "" || base.graphql.Load() != 0 || base.bootstrap.Load() != 0 {
		t.Fatal("active account was re-validated", code, base.graphql.Load())
	}
	// Idle: a refresh is due. While it runs the old client serves and stays
	// reported warm; a job on it proves without any unproven request.
	AgeXClientForTests(path, now.Add(-xRefreshInterval-time.Minute), time.Time{})
	if !XClientStatus(path, now).Stale {
		t.Fatal("idle account not due a refresh")
	}
	gate := &xGate{hold: make(chan struct{})}
	done := make(chan string, 1)
	go WarmXClient(context.Background(), path, gate, 10*time.Second, func(code string) { done <- code })
	deadline := time.Now().Add(5 * time.Second)
	for !XClientStatus(path, time.Now()).Building {
		if time.Now().After(deadline) {
			t.Fatal("refresh did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st := XClientStatus(path, time.Now()); !st.Warm || st.Stale {
		t.Fatalf("refresh in progress took the client away: %+v", st)
	}
	jobBase := &xCounter{}
	if code := (X{Config: c, Base: jobBase, Proof: roundTripFunc(xOK)}).Run(context.Background(), l); code != "" || jobBase.graphql.Load() != 0 {
		t.Fatal("job during refresh", code, jobBase.graphql.Load())
	}
	close(gate.hold)
	if code := <-done; code != "" || !XClientStatus(path, time.Now()).Warm || XClientStatus(path, time.Now()).Stale {
		t.Fatal("refresh outcome", code)
	}
	// Idle again, and a transient failure: the old client keeps serving and
	// the next attempt waits.
	AgeXClientForTests(path, now.Add(-xRefreshInterval-time.Minute), time.Time{})
	if code := warm(t, path, &xGate{viewer: 503}); code != "x_request_failed" {
		t.Fatal("transient refresh failure classified as", code)
	}
	if st := XClientStatus(path, time.Now()); !st.Warm || st.Stale {
		t.Fatalf("transient refresh failure dropped the client or retries at once: %+v", st)
	}
	// Idle, and the session has died: exactly one unproven read goes out, the
	// client is dropped and the account needs a sign-in.
	AgeXClientForTests(path, now.Add(-xRefreshInterval-time.Minute), time.Time{})
	dead := &xGate{viewer: 401}
	if code := warm(t, path, dead); code != "auth_required" || dead.graphql.Load() != 1 || dead.bootstrap.Load() != 0 {
		t.Fatal("dead session on refresh", code, dead.graphql.Load(), dead.bootstrap.Load())
	}
	if st := XClientStatus(path, time.Now()); st.Warm || st.Building {
		t.Fatalf("dead session kept a client: %+v", st)
	}
	// A busy account is still rebuilt once its material is older than the cap.
	if code := warm(t, path, &xGate{}); code != "" {
		t.Fatal(code)
	}
	AgeXClientForTests(path, now.Add(-xClientMaxAge-time.Minute), now)
	if !XClientStatus(path, now).Stale {
		t.Fatal("client past the age cap not due a refresh")
	}
}

// Warm-ups run one account at a time, a failed one does not stop the next,
// and a session file that cannot be used reports auth_required.
func TestXWarmUpsRunOneAtATimeAndFailIndependently(t *testing.T) {
	c1, _, _ := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "fixture"})
	c2, _, _ := xFixture(t, coordinator.XRequest{Operation: "profile", Username: "fixture"})
	raw, _ := json.Marshal(x.Session{AuthToken: "second-auth", CT0: "second-csrf"})
	if e := localfs.WriteAtomic(c2.XSession, raw, true); e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var order []string
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		account := "first"
		if strings.Contains(r.Header.Get("Cookie"), "second-auth") {
			account = "second"
		}
		order = append(order, account)
		mu.Unlock()
		return xBootstrap(r)
	})
	codes := make(chan string, 3)
	report := func(code string) { codes <- code }
	missing := filepath.Join(t.TempDir(), "missing.json")
	go WarmXClient(context.Background(), c1.XSession, base, 10*time.Second, report)
	go WarmXClient(context.Background(), missing, base, 10*time.Second, report)
	go WarmXClient(context.Background(), c2.XSession, base, 10*time.Second, report)
	got := map[string]int{}
	for i := 0; i < 3; i++ {
		select {
		case code := <-codes:
			got[code]++
		case <-time.After(20 * time.Second):
			t.Fatal("warm-ups did not finish")
		}
	}
	if got[""] != 2 || got["auth_required"] != 1 {
		t.Fatal("warm-up outcomes", got)
	}
	if !XClientStatus(c1.XSession, time.Now()).Warm || !XClientStatus(c2.XSession, time.Now()).Warm || XClientStatus(missing, time.Now()).Warm {
		t.Fatal("warm state after warm-ups")
	}
	// Each account's three construction requests are contiguous.
	mu.Lock()
	defer mu.Unlock()
	switches := 0
	for i := 1; i < len(order); i++ {
		if order[i] != order[i-1] {
			switches++
		}
	}
	if len(order) != 6 || switches != 1 {
		t.Fatal("warm-ups interleaved", order)
	}
}

// Construction failures are classified by cause: x-go wraps every failed
// validation as unauthorized, but only X refusing the session is one.
func TestXBuildFailureClassification(t *testing.T) {
	network := errors.Join(x.ErrUnauthorized, errors.New("session validation failed: "+x.ErrRequestFailed.Error()))
	for _, tc := range []struct {
		err  error
		code string
	}{
		{x.ErrUnauthorized, "auth_required"},
		{&x.OperationError{Operation: "Viewer", Status: 401, Err: x.ErrUnauthorized}, "auth_required"},
		{errors.Join(x.ErrUnauthorized, x.ErrRequestFailed), "x_request_failed"},
		{errors.Join(x.ErrUnauthorized, &x.RateLimitError{Wait: time.Minute}), "x_rate_limited"},
		{context.DeadlineExceeded, "x_request_failed"},
		{x.ErrForbidden, "x_request_failed"},
	} {
		if got := xBuildFailure(tc.err); got != tc.code {
			t.Fatalf("%v classified as %q, want %q", tc.err, got, tc.code)
		}
	}
	if xBuildFailure(network) != "auth_required" {
		// A joined message without the wrapped sentinel is still auth: only
		// the sentinel chain, never the text, decides.
		t.Fatal("text decided classification")
	}
}

// A proven read X answers with 404 is how a gated read with stale transaction
// material fails, so the client is dropped and the next job bootstraps fresh
// material. Other failures keep the client: a 5xx says nothing about it.
func TestXNotFoundDropsTheClientOtherFailuresKeepIt(t *testing.T) {
	c, l, _ := xFixture(t, coordinator.XRequest{Operation: "search", Query: "bitcoin", Count: 20, Pages: 1})
	status := func(code int) roundTripFunc {
		return func(r *http.Request) (*http.Response, error) { return xResponse(r, code, ""), nil }
	}
	base := &xCounter{}
	if code := (X{Config: c, Base: base, Proof: status(500)}).Run(context.Background(), l); code != "x_request_failed" || !XClientStatus(c.XSession, time.Now()).Warm {
		t.Fatal("5xx", code, XClientStatus(c.XSession, time.Now()))
	}
	if code := (X{Config: c, Base: base, Proof: status(404)}).Run(context.Background(), l); code != "x_request_failed" || XClientStatus(c.XSession, time.Now()).Warm {
		t.Fatal("404", code, XClientStatus(c.XSession, time.Now()))
	}
	if base.graphql.Load() != 2 {
		t.Fatal("constructions so far", base.graphql.Load())
	}
	base = &xCounter{}
	if code := (X{Config: c, Base: base, Proof: status(500)}).Run(context.Background(), l); code != "x_request_failed" || base.graphql.Load() != 2 {
		t.Fatal("next job did not rebuild after a 404", code, base.graphql.Load())
	}
}
