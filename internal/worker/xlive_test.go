//go:build xlive

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	x "github.com/teslashibe/x-go"
)

// readOperations is every GraphQL operation x-go's read methods use; the
// verifier's x.read allowlist must match it.
var readOperations = []string{
	"Viewer", "UserByRestId", "UserByScreenName", "UserTweets", "TweetResultByRestId", "TweetDetail", "SearchTimeline",
	"Followers", "Following", "ListBySlug", "ListLatestTweetsTimeline", "ListMembers", "HomeTimeline", "HomeLatestTimeline",
}

// TestXLive pins an x.read job to the exact requests x-go builds for every read
// method, then runs them through XTransport against a running verifier with a
// real X session. Paginated methods follow the cursor to page 2, and search to
// page 3, with each later page pinned to the cursor in the verifier's own copy
// of the page before. Every pinned exchange must be fulfilled with a response
// identical to what x-go parsed. A second job checks that live cheats are
// rejected. It spends the session's X quota and never calls a write method.
// SCARLETT_X_LIST_ID picks the public list to read.
//
//	SCARLETT_VERIFIER_KEY=... scarlett-prover verifier
//	SCARLETT_X_SESSION=path/to/session.json SCARLETT_PROVER=path/to/scarlett-prover \
//	SCARLETT_VERIFIER=127.0.0.1:7047 SCARLETT_VERIFIER_API=http://127.0.0.1:7070 SCARLETT_VERIFIER_KEY=... \
//	go test -tags xlive -run TestXLive -v ./internal/worker
func TestXLive(t *testing.T) {
	env := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			t.Skipf("%s is not set", k)
		}
		return v
	}
	sessionPath, prover, verifierAddr, api, key := env("SCARLETT_X_SESSION"), env("SCARLETT_PROVER"), env("SCARLETT_VERIFIER"), env("SCARLETT_VERIFIER_API"), env("SCARLETT_VERIFIER_KEY")
	listID := os.Getenv("SCARLETT_X_LIST_ID")
	if listID == "" {
		listID = "1477950212878618625"
	}
	var session x.Session
	data, err := os.ReadFile(sessionPath)
	if err != nil || json.Unmarshal(data, &session) != nil {
		t.Fatal("X session file is unreadable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()

	// @jack is 12; @jack follows only a handful of accounts, @elonmusk (44196397) over a thousand.
	latest := x.WithSearchType(x.SearchLatest)
	advanced := &x.AdvancedSearch{AllWords: "ethereum", Language: "en", ResultType: x.SearchLatest}
	searchBitcoin := tweetRead(func(c *x.Client, cur string) (x.TweetPage, error) {
		return c.SearchTweetsPage(ctx, "bitcoin", 20, cur, latest)
	})
	reads := []liveRead{
		{"GetTweet", 1, false, func(c *x.Client, _ string) ([]string, string, error) {
			tw, err := c.GetTweet(ctx, "20")
			if err == nil && tw.Text != "just setting up my twttr" {
				err = fmt.Errorf("unexpected text %q", tw.Text)
			}
			return nil, "", err
		}},
		{"GetTweetDetail", 1, false, func(c *x.Client, _ string) ([]string, string, error) {
			d, err := c.GetTweetDetail(ctx, "20")
			if err == nil && d.Tweet.ID != "20" {
				err = fmt.Errorf("detail is for tweet %q", d.Tweet.ID)
			}
			return nil, "", err
		}},
		{"GetProfile", 1, false, func(c *x.Client, _ string) ([]string, string, error) {
			u, err := c.GetProfile(ctx, "jack")
			if err == nil && u.ID != "12" {
				err = fmt.Errorf("@jack has id %q", u.ID)
			}
			return nil, "", err
		}},
		{"GetProfileByID", 1, false, func(c *x.Client, _ string) ([]string, string, error) {
			u, err := c.GetProfileByID(ctx, "12")
			if err == nil && !strings.EqualFold(u.ScreenName, "jack") {
				err = fmt.Errorf("user 12 is %q", u.ScreenName)
			}
			return nil, "", err
		}},
		// x-go v1.13.0 sends listId to ListBySlug, which X rejects with HTTP 422;
		// the rejection is still a proven exchange, but it never fulfils one.
		{"GetList", 1, true, func(c *x.Client, _ string) ([]string, string, error) {
			_, err := c.GetList(ctx, listID)
			return nil, "", err
		}},
		{"UserTweets", 2, false, tweetRead(func(c *x.Client, cur string) (x.TweetPage, error) { return c.UserTweetsPage(ctx, "12", 20, cur) })},
		{"HomeTimeline", 2, false, tweetRead(func(c *x.Client, cur string) (x.TweetPage, error) { return c.HomeTimelinePage(ctx, 20, cur) })},
		{"HomeLatestTimeline", 2, false, tweetRead(func(c *x.Client, cur string) (x.TweetPage, error) { return c.HomeLatestTimelinePage(ctx, 20, cur) })},
		{"SearchTweets", 3, false, searchBitcoin},
		{"AdvancedSearchTweets", 2, false, tweetRead(func(c *x.Client, cur string) (x.TweetPage, error) {
			return c.AdvancedSearchTweetsPage(ctx, advanced, 20, cur)
		})},
		{"GetListTimeline", 2, false, tweetRead(func(c *x.Client, cur string) (x.TweetPage, error) { return c.GetListTimelinePage(ctx, listID, 20, cur) })},
		{"GetFollowers", 2, false, userRead(func(c *x.Client, cur string) (x.UserPage, error) { return c.GetFollowersPage(ctx, "12", 20, cur) })},
		{"GetFollowing", 2, false, userRead(func(c *x.Client, cur string) (x.UserPage, error) { return c.GetFollowingPage(ctx, "44196397", 20, cur) })},
		{"SearchUsers", 2, false, userRead(func(c *x.Client, cur string) (x.UserPage, error) { return c.SearchUsersPage(ctx, "bitcoin", 20, cur) })},
		{"GetListMembers", 2, false, userRead(func(c *x.Client, cur string) (x.UserPage, error) { return c.GetListMembersPage(ctx, listID, 20, cur) })},
	}

	// Plan: record the requests x-go builds without sending them, the way a
	// coordinator would pin a job. Client construction validates the session
	// with Viewer and UserByRestId for the account, sent unproven here and
	// pinned as the first two exchanges.
	capt := &capture{forward: true}
	planner, err := session.NewClient(ctx, x.WithHTTPClient(&http.Client{Timeout: time.Minute, Transport: capt}), x.WithRetry(1, time.Millisecond), x.WithMinRequestGap(0))
	if err != nil {
		t.Fatalf("x-go planning client: %v", err)
	}
	if len(capt.got) != 2 || capt.got[0].Operation != "Viewer" || capt.got[1].Operation != "UserByRestId" {
		t.Fatalf("session validation sent %d reads, want Viewer and UserByRestId", len(capt.got))
	}
	p := &plan{t: t, capture: capt, specs: capt.got}
	capt.forward = false
	firstPage := map[string]int{}
	for _, r := range reads {
		prev := -1
		for page := 1; page <= r.pages; page++ {
			prev = p.add(fmt.Sprintf("%s page %d", r.name, page), func(cursor string) { r.fetch(planner, cursor) }, prev)
			if page == 1 {
				firstPage[r.name] = prev
			}
		}
	}

	jobID := fmt.Sprintf("xlive-%d", time.Now().UnixNano())
	var created struct{ Token string }
	verifierAPI(t, ctx, http.MethodPost, api+"/v1/sessions", key, map[string]any{
		"job_id": jobID, "attempt": "1", "ttl_seconds": 600,
		"payload": map[string]any{"type": "x.read", "exchanges": p.specs, "max_attempts": len(p.specs) + 10},
	}, &created)

	rec := &recorder{t: t, next: XTransport{Prover: prover, Verifier: verifierAddr, Token: created.Token}}
	c, err := session.NewClient(ctx, x.WithHTTPClient(&http.Client{Timeout: 5 * time.Minute, Transport: rec}))
	if err != nil {
		t.Fatalf("x-go client: %v", err)
	}
	for _, r := range reads {
		var pages [][]string
		var cursors []string
		cursor := ""
		for page := 1; page <= r.pages; page++ {
			ids, next, err := r.fetch(c, cursor)
			if err != nil {
				if !r.mayFail {
					t.Errorf("%s page %d: %v", r.name, page, err)
				}
				break
			}
			pages, cursors = append(pages, ids), append(cursors, next)
			if page < r.pages && next == "" {
				t.Errorf("%s page %d has no next cursor", r.name, page)
				break
			}
			cursor = next
		}
		for i := 1; i < len(pages); i++ {
			checkPages(t, fmt.Sprintf("%s page %d", r.name, i+1), pages[i-1], pages[i], cursors[i-1], cursors[i])
		}
	}

	status := waitForVerifier(t, ctx, api, jobID, key, rec.attempts)
	if len(status.Rejections) > 0 {
		t.Errorf("verifier rejected exchanges: %v", status.Rejections)
	}
	if len(status.Exchanges) != len(rec.bodies) {
		t.Fatalf("verifier recorded %d exchanges, x-go received %d", len(status.Exchanges), len(rec.bodies))
	}
	seen := map[string]int{}
	for i, e := range status.Exchanges {
		if e.Operation != rec.ops[i] || e.Body != rec.bodies[i] {
			t.Errorf("exchange %d: verifier has %s (%d bytes), x-go parsed %s (%d bytes)", i, e.Operation, len(e.Body), rec.ops[i], len(rec.bodies[i]))
		}
		seen[e.Operation]++
		t.Logf("#%-3d %-25s HTTP %d  sent %5d B  received %6d B  body %7d B  verifier %5d ms  node %6d ms", e.Index, e.Operation, e.HTTPStatus, e.SentBytes, e.ReceivedBytes, len(e.Body), e.DurationMS, rec.took[i].Milliseconds())
	}
	for _, op := range readOperations {
		if seen[op] == 0 {
			t.Errorf("no proven %s exchange", op)
		}
	}
	// Only GetList's ListBySlug may stay pending, and only after a proven non-200.
	listBySlug := firstPage["GetList"]
	if status.Complete || len(status.Pending) != 1 || status.Pending[0] != listBySlug {
		t.Errorf("pending exchanges %v (complete %v), want only %d (ListBySlug)", status.Pending, status.Complete, listBySlug)
	}
	fulfilled := 0
	for _, e := range status.Exchanges {
		if e.Fulfilled {
			fulfilled++
		}
		if e.Index == listBySlug && e.HTTPStatus == 200 {
			t.Errorf("ListBySlug returned HTTP 200; drop the GetList exception")
		}
	}
	summary := make([]string, 0, len(seen))
	for op, n := range seen {
		summary = append(summary, fmt.Sprintf("%s=%d", op, n))
	}
	sort.Strings(summary)
	t.Logf("%d pinned exchanges, %d fulfilled, %d proven: %s", len(p.specs), fulfilled, len(status.Exchanges), strings.Join(summary, " "))

	t.Run("cheats", func(t *testing.T) {
		// A two-page bitcoin search. The node tries a swapped search term, page 2
		// before page 1, and page 2 with a cursor from another query, all of
		// which X answers and the verifier must refuse to count.
		cp := &plan{t: t, capture: capt}
		cp.add("bitcoin page 1", func(cursor string) { searchBitcoin(planner, cursor) }, -1)
		cp.add("bitcoin page 2", func(cursor string) { searchBitcoin(planner, cursor) }, 0)
		cheatJob := jobID + "-cheats"
		verifierAPI(t, ctx, http.MethodPost, api+"/v1/sessions", key, map[string]any{
			"job_id": cheatJob, "attempt": "1", "ttl_seconds": 600,
			"payload": map[string]any{"type": "x.read", "exchanges": cp.specs, "max_attempts": 8},
		}, &created)
		// The same client now proves its reads under the cheat job's token.
		base, before := len(rec.bodies), rec.attempts
		rec.t, rec.next = t, XTransport{Prover: prover, Verifier: verifierAddr, Token: created.Token}

		eth, err := c.SearchTweets(ctx, "ethereum", 20, latest)
		if err != nil || eth.NextCursor == "" {
			t.Fatalf("ethereum search: %v", err)
		}
		if _, err := c.SearchTweetsPage(ctx, "bitcoin", 20, eth.NextCursor, latest); err != nil {
			t.Fatalf("bitcoin page 2 before page 1: %v", err)
		}
		btc, err := c.SearchTweets(ctx, "bitcoin", 20, latest)
		if err != nil || btc.NextCursor == "" {
			t.Fatalf("bitcoin page 1: %v", err)
		}
		if _, err := c.SearchTweetsPage(ctx, "bitcoin", 20, eth.NextCursor, latest); err != nil {
			t.Fatalf("bitcoin page 2 with the ethereum cursor: %v", err)
		}
		if _, err := c.SearchTweetsPage(ctx, "bitcoin", 20, btc.NextCursor, latest); err != nil {
			t.Fatalf("bitcoin page 2: %v", err)
		}
		st := waitForVerifier(t, ctx, api, cheatJob, key, rec.attempts-before)
		if _, err := c.SearchTweets(ctx, "bitcoin", 20, latest); err == nil {
			t.Errorf("a completed job's token still proves reads")
		}
		if !st.Complete || len(st.Pending) != 0 || len(st.Exchanges) != 2 || len(st.Rejections) != 3 {
			t.Fatalf("cheat job: complete %v, pending %v, %d exchanges, rejections %v", st.Complete, st.Pending, len(st.Exchanges), st.Rejections)
		}
		for i, e := range st.Exchanges {
			if e.Index != i || !e.Fulfilled || e.Body != rec.bodies[base+2+2*i] {
				t.Errorf("cheat job exchange %d: index %d, fulfilled %v", i, e.Index, e.Fulfilled)
			}
		}
		for _, r := range st.Rejections {
			if !strings.Contains(r, "matches no pending exchange") {
				t.Errorf("unexpected rejection: %s", r)
			}
			t.Logf("rejected: %.160s", r)
		}
		t.Logf("cheat job remaining attempts %d", st.RemainingAttempts)
	})
}

// liveRead is one x-go read method. fetch gets page 1 for an empty cursor and
// returns the item IDs and next cursor of paginated reads.
type liveRead struct {
	name    string
	pages   int
	mayFail bool
	fetch   func(c *x.Client, cursor string) ([]string, string, error)
}

func tweetRead(page func(c *x.Client, cursor string) (x.TweetPage, error)) func(*x.Client, string) ([]string, string, error) {
	return func(c *x.Client, cursor string) ([]string, string, error) {
		p, err := page(c, cursor)
		return tweetIDs(p.Tweets), p.NextCursor, err
	}
}

func userRead(page func(c *x.Client, cursor string) (x.UserPage, error)) func(*x.Client, string) ([]string, string, error) {
	return func(c *x.Client, cursor string) ([]string, string, error) {
		p, err := page(c, cursor)
		return userIDs(p.Users), p.NextCursor, err
	}
}

// spec is one pinned exchange of an x.read job.
type spec struct {
	Operation    string          `json:"operation"`
	QueryID      string          `json:"query_id"`
	Variables    map[string]any  `json:"variables"`
	Features     json.RawMessage `json:"features,omitempty"`
	FieldToggles json.RawMessage `json:"field_toggles,omitempty"`
	CursorFrom   *int            `json:"cursor_from,omitempty"`
}

var errCaptured = errors.New("captured, not sent")

// capture records the X GraphQL reads x-go makes. It forwards them unproven
// while forward is set and otherwise fails them without sending anything.
// Other requests, such as x-go's page and script fetches, go out unchanged.
type capture struct {
	forward bool
	got     []spec
}

func (c *capture) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "x.com" || !strings.HasPrefix(req.URL.Path, "/i/api/graphql/") {
		return http.DefaultTransport.RoundTrip(req)
	}
	qid, op, _ := strings.Cut(strings.TrimPrefix(req.URL.Path, "/i/api/graphql/"), "/")
	q := req.URL.Query()
	s := spec{Operation: op, QueryID: qid}
	dec := json.NewDecoder(strings.NewReader(q.Get("variables")))
	dec.UseNumber()
	if err := dec.Decode(&s.Variables); err != nil {
		return nil, fmt.Errorf("capture: %s variables: %v", op, err)
	}
	if f := q.Get("features"); f != "" {
		s.Features = json.RawMessage(f)
	}
	if f := q.Get("fieldToggles"); f != "" {
		s.FieldToggles = json.RawMessage(f)
	}
	c.got = append(c.got, s)
	if c.forward {
		return http.DefaultTransport.RoundTrip(req)
	}
	return nil, errCaptured
}

// plan builds a job's exchanges from captured x-go requests.
type plan struct {
	t       *testing.T
	capture *capture
	specs   []spec
}

const cursorPlaceholder = "SCARLETT_CURSOR"

// add pins the one X read call makes as the next exchange and returns its
// index. With cursorFrom >= 0 the read is the page after that exchange: call
// gets a placeholder cursor, which the exchange replaces with cursor_from.
func (p *plan) add(name string, call func(cursor string), cursorFrom int) int {
	p.t.Helper()
	p.capture.got = nil
	cursor := ""
	if cursorFrom >= 0 {
		cursor = cursorPlaceholder
	}
	call(cursor)
	if len(p.capture.got) != 1 {
		p.t.Fatalf("%s sent %d X reads, want 1", name, len(p.capture.got))
	}
	s := p.capture.got[0]
	if cursorFrom >= 0 {
		if s.Variables["cursor"] != cursorPlaceholder {
			p.t.Fatalf("%s did not send the cursor as variables.cursor", name)
		}
		delete(s.Variables, "cursor")
		s.CursorFrom = &cursorFrom
	}
	p.specs = append(p.specs, s)
	return len(p.specs) - 1
}

type xReadStatus struct {
	RemainingAttempts int   `json:"remaining_attempts"`
	Complete          bool  `json:"complete"`
	Pending           []int `json:"pending"`
	Exchanges         []struct {
		Index         int    `json:"index"`
		Fulfilled     bool   `json:"fulfilled"`
		Operation     string `json:"operation"`
		HTTPStatus    int    `json:"http_status"`
		Body          string `json:"body"`
		SentBytes     int    `json:"sent_bytes"`
		ReceivedBytes int    `json:"received_bytes"`
		DurationMS    int    `json:"duration_ms"`
	} `json:"exchanges"`
	Rejections []string `json:"rejections"`
}

// waitForVerifier returns the session status once the verifier has recorded
// every attempt; the prover reports success before the verifier records it.
func waitForVerifier(t *testing.T, ctx context.Context, api, jobID, key string, attempts int) xReadStatus {
	t.Helper()
	var status xReadStatus
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		status = xReadStatus{}
		verifierAPI(t, ctx, http.MethodGet, api+"/v1/sessions/"+jobID+"/1", key, nil, &status)
		if len(status.Exchanges)+len(status.Rejections) >= attempts || time.Now().After(deadline) {
			return status
		}
	}
}

// checkPages requires two non-empty pages, a moved cursor and new items on the second page.
func checkPages(t *testing.T, name string, first, second []string, cursor1, cursor2 string) {
	t.Helper()
	fresh := 0
	have := map[string]bool{}
	for _, id := range first {
		have[id] = true
	}
	for _, id := range second {
		if !have[id] {
			fresh++
		}
	}
	if len(first) == 0 || fresh == 0 || cursor2 == cursor1 {
		t.Errorf("%s: previous page has %d items, this page %d new of %d, cursor moved %v", name, len(first), fresh, len(second), cursor2 != cursor1)
		return
	}
	t.Logf("%s: previous page %d items, this page %d new of %d", name, len(first), fresh, len(second))
}

func tweetIDs(tweets []x.Tweet) []string {
	ids := make([]string, len(tweets))
	for i, tw := range tweets {
		ids[i] = tw.ID
	}
	return ids
}

func userIDs(users []x.User) []string {
	ids := make([]string, len(users))
	for i, u := range users {
		ids[i] = u.ID
	}
	return ids
}

// recorder keeps the proven response bodies x-go receives, in order.
type recorder struct {
	t           *testing.T
	next        http.RoundTripper
	attempts    int
	ops, bodies []string
	took        []time.Duration
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	proven := req.URL.Host == "x.com" && strings.HasPrefix(req.URL.Path, "/i/api/graphql/")
	if proven {
		r.attempts++
	}
	resp, err := r.next.RoundTrip(req)
	if err != nil {
		r.t.Logf("%s failed after %s: %v", req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:], time.Since(start).Round(time.Millisecond), err)
	}
	if err != nil || !proven {
		return resp, err
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	r.ops = append(r.ops, req.URL.Path[strings.LastIndex(req.URL.Path, "/")+1:])
	r.bodies = append(r.bodies, string(body))
	r.took = append(r.took, time.Since(start))
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

func verifierAPI(t *testing.T, ctx context.Context, method, url, key string, in, out any) {
	t.Helper()
	var body io.Reader
	if in != nil {
		data, _ := json.Marshal(in)
		body = bytes.NewReader(data)
	}
	req, _ := http.NewRequestWithContext(ctx, method, url, body)
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("verifier API: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 || json.Unmarshal(data, out) != nil {
		t.Fatalf("verifier API %s %s: %d %s", method, url, resp.StatusCode, data)
	}
}
