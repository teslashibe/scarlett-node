//go:build xlive

package worker

import (
	"bytes"
	"context"
	"encoding/json"
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

// TestXLive runs every x-go read method through XTransport against a running
// verifier with a real X session, following cursors to a second page for each
// paginated method, and checks that the verifier's copy of every response is
// exactly what x-go parsed. It spends the session's X quota and never calls a
// write method. SCARLETT_X_LIST_ID picks the public list to read.
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	jobID := fmt.Sprintf("xlive-%d", time.Now().UnixNano())
	var created struct{ Token string }
	verifierAPI(t, ctx, http.MethodPost, api+"/v1/sessions", key, map[string]any{
		"job_id": jobID, "attempt": "1", "ttl_seconds": 600,
		"payload": map[string]any{"type": "x.read", "max_exchanges": 100, "operations": readOperations},
	}, &created)

	rec := &recorder{t: t, next: XTransport{Prover: prover, Verifier: verifierAddr, Token: created.Token}}
	c, err := session.NewClient(ctx, x.WithHTTPClient(&http.Client{Timeout: 5 * time.Minute, Transport: rec}))
	if err != nil {
		t.Fatalf("x-go client: %v", err)
	}
	me, err := c.Me(ctx)
	if err != nil || me.ID == "" {
		t.Fatalf("Me: %v", err)
	}
	tweet, err := c.GetTweet(ctx, "20")
	if err != nil || tweet.Text != "just setting up my twttr" {
		t.Fatalf("GetTweet: %v %+v", err, tweet)
	}
	if detail, err := c.GetTweetDetail(ctx, "20"); err != nil || detail.Tweet.ID != "20" {
		t.Errorf("GetTweetDetail: %v", err)
	}
	jack, err := c.GetProfile(ctx, "jack")
	if err != nil || jack.ID == "" {
		t.Fatalf("GetProfile: %v", err)
	}
	if byID, err := c.GetProfileByID(ctx, jack.ID); err != nil || byID.ScreenName != jack.ScreenName {
		t.Errorf("GetProfileByID: %v", err)
	}
	// x-go v1.13.0 sends listId to ListBySlug, which X rejects with HTTP 422;
	// the rejection is still a proven exchange.
	if _, err := c.GetList(ctx, listID); err != nil {
		t.Logf("GetList: %v", err)
	}

	tweetPages := []struct {
		name  string
		first func() (x.TweetPage, error)
		next  func(cursor string) (x.TweetPage, error)
	}{
		{"UserTweets", func() (x.TweetPage, error) { return c.UserTweets(ctx, jack.ID, 20) },
			func(cur string) (x.TweetPage, error) { return c.UserTweetsPage(ctx, jack.ID, 20, cur) }},
		{"HomeTimeline", func() (x.TweetPage, error) { return c.HomeTimeline(ctx, 20) },
			func(cur string) (x.TweetPage, error) { return c.HomeTimelinePage(ctx, 20, cur) }},
		{"HomeLatestTimeline", func() (x.TweetPage, error) { return c.HomeLatestTimeline(ctx, 20) },
			func(cur string) (x.TweetPage, error) { return c.HomeLatestTimelinePage(ctx, 20, cur) }},
		{"SearchTweets", func() (x.TweetPage, error) {
			return c.SearchTweets(ctx, "bitcoin", 20, x.WithSearchType(x.SearchLatest))
		},
			func(cur string) (x.TweetPage, error) {
				return c.SearchTweetsPage(ctx, "bitcoin", 20, cur, x.WithSearchType(x.SearchLatest))
			}},
		{"AdvancedSearchTweets", func() (x.TweetPage, error) {
			return c.AdvancedSearchTweets(ctx, &x.AdvancedSearch{AllWords: "ethereum", Language: "en", ResultType: x.SearchLatest}, 20)
		}, func(cur string) (x.TweetPage, error) {
			return c.AdvancedSearchTweetsPage(ctx, &x.AdvancedSearch{AllWords: "ethereum", Language: "en", ResultType: x.SearchLatest}, 20, cur)
		}},
		{"GetListTimeline", func() (x.TweetPage, error) { return c.GetListTimeline(ctx, listID, 20) },
			func(cur string) (x.TweetPage, error) { return c.GetListTimelinePage(ctx, listID, 20, cur) }},
	}
	for _, p := range tweetPages {
		first, err := p.first()
		if err != nil {
			t.Errorf("%s page 1: %v", p.name, err)
			continue
		}
		second, err := pageAfter(first.HasNext, first.NextCursor, p.next)
		if err != nil {
			t.Errorf("%s page 2: %v", p.name, err)
			continue
		}
		checkPages(t, p.name, tweetIDs(first.Tweets), tweetIDs(second.Tweets), first.NextCursor, second.NextCursor)
	}

	userPages := []struct {
		name  string
		first func() (x.UserPage, error)
		next  func(cursor string) (x.UserPage, error)
	}{
		{"GetFollowers", func() (x.UserPage, error) { return c.GetFollowers(ctx, jack.ID, 20) },
			func(cur string) (x.UserPage, error) { return c.GetFollowersPage(ctx, jack.ID, 20, cur) }},
		// @jack follows only a handful of accounts; @elonmusk follows over a thousand.
		{"GetFollowing", func() (x.UserPage, error) { return c.GetFollowing(ctx, "44196397", 20) },
			func(cur string) (x.UserPage, error) { return c.GetFollowingPage(ctx, "44196397", 20, cur) }},
		{"SearchUsers", func() (x.UserPage, error) { return c.SearchUsers(ctx, "bitcoin", 20) },
			func(cur string) (x.UserPage, error) { return c.SearchUsersPage(ctx, "bitcoin", 20, cur) }},
		{"GetListMembers", func() (x.UserPage, error) { return c.GetListMembers(ctx, listID, 20) },
			func(cur string) (x.UserPage, error) { return c.GetListMembersPage(ctx, listID, 20, cur) }},
	}
	for _, p := range userPages {
		first, err := p.first()
		if err != nil {
			t.Errorf("%s page 1: %v", p.name, err)
			continue
		}
		second, err := pageAfter(first.HasNext, first.NextCursor, p.next)
		if err != nil {
			t.Errorf("%s page 2: %v", p.name, err)
			continue
		}
		checkPages(t, p.name, userIDs(first.Users), userIDs(second.Users), first.NextCursor, second.NextCursor)
	}

	it := x.NewSearchIterator(c, "solana", 20, x.WithMaxTweets(45))
	pages := 0
	for it.Next(ctx) {
		pages++
	}
	if it.Err() != nil || pages < 3 || it.Seen() != 45 || it.Checkpoint().Cursor == "" {
		t.Errorf("NewSearchIterator: %d pages, %d tweets, cursor %q, err %v", pages, it.Seen(), it.Checkpoint().Cursor, it.Err())
	}
	if report, err := c.ScrapeTimelineTrends(ctx, jack.ID, x.WithTrendMaxTweets(30)); err != nil || report.TweetsAnalyzed == 0 {
		t.Errorf("ScrapeTimelineTrends: %v", err)
	}
	if ev := c.DiagnoseSearchCapability(ctx); !ev.Ready {
		t.Errorf("DiagnoseSearchCapability: %+v", ev)
	}

	var status struct {
		Exchanges []struct {
			Operation     string `json:"operation"`
			HTTPStatus    int    `json:"http_status"`
			Body          string `json:"body"`
			SentBytes     int    `json:"sent_bytes"`
			ReceivedBytes int    `json:"received_bytes"`
			DurationMS    int    `json:"duration_ms"`
		}
		Rejections []string
	}
	// The prover reports success before the verifier has recorded the exchange.
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		verifierAPI(t, ctx, http.MethodGet, api+"/v1/sessions/"+jobID+"/1", key, nil, &status)
		if len(status.Exchanges)+len(status.Rejections) >= rec.attempts || time.Now().After(deadline) {
			break
		}
	}
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
		t.Logf("%-25s HTTP %d  sent %5d B  received %6d B  body %7d B  verifier %5d ms  node %6d ms", e.Operation, e.HTTPStatus, e.SentBytes, e.ReceivedBytes, len(e.Body), e.DurationMS, rec.took[i].Milliseconds())
	}
	for _, op := range readOperations {
		if seen[op] == 0 {
			t.Errorf("no proven %s exchange", op)
		}
	}
	summary := make([]string, 0, len(seen))
	for op, n := range seen {
		summary = append(summary, fmt.Sprintf("%s=%d", op, n))
	}
	sort.Strings(summary)
	t.Logf("%d proven exchanges: %s", len(status.Exchanges), strings.Join(summary, " "))
}

// pageAfter fetches the page after cursor, failing if the first page did not offer one.
func pageAfter[P any](hasNext bool, cursor string, next func(string) (P, error)) (P, error) {
	if !hasNext || cursor == "" {
		var zero P
		return zero, fmt.Errorf("first page has no next cursor")
	}
	return next(cursor)
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
		t.Errorf("%s: page 1 has %d items, page 2 has %d new of %d, cursor moved %v", name, len(first), fresh, len(second), cursor2 != cursor1)
		return
	}
	t.Logf("%s: page 1 %d items, page 2 %d new of %d", name, len(first), fresh, len(second))
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
