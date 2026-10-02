# x-go

Go client for [X (formerly Twitter)](https://x.com) internal APIs. Zero dependencies, cookie-based auth.

```bash
go get github.com/teslashibe/x-go
```

## Quick start

```go
import x "github.com/teslashibe/x-go"

c, _ := x.New(x.Cookies{
    AuthToken: os.Getenv("X_AUTH_TOKEN"),
    CT0:       os.Getenv("X_CT0"),
    Twid:      os.Getenv("X_TWID"),
})
ctx := context.Background()

profile, _ := c.GetProfile(ctx, "elonmusk")
timeline, _ := c.HomeTimeline(ctx, 20)
results, _ := c.SearchTweets(ctx, "golang", 20)
tweet, _ := c.CreateTweet(ctx, "Hello from x-go!")
_ = c.Like(ctx, tweet.ID)
_ = c.Follow(ctx, profile.ID)
_ = c.SendDM(ctx, conversationID, "Hey!")
```

## Authentication

Export session cookies from a logged-in browser session. No API keys or developer app registration required.

```bash
export X_AUTH_TOKEN="9220b5d6a5926..."
export X_CT0="a1e823788453..."
export X_TWID="u%3D123456789"
```

| Cookie | Header | Required | Purpose |
|---|---|---|---|
| `auth_token` | `X_AUTH_TOKEN` | Yes | Primary session credential |
| `ct0` | `X_CT0` | Yes | CSRF token |
| `twid` | `X_TWID` | No | User ID (`u=<restId>`); used to derive authenticated user |

## Features

### Profiles

```go
user, _ := c.GetProfile(ctx, "elonmusk")      // by handle
user, _ = c.GetProfileByID(ctx, "44196397")    // by numeric ID
me, _ := c.Me(ctx)                             // authenticated user
```

### Timelines

```go
page, _ := c.HomeTimeline(ctx, 20)              // algorithmic (For You)
page, _ = c.HomeLatestTimeline(ctx, 20)          // reverse-chronological (Following)

// Cursor pagination
page, _ = c.HomeTimelinePage(ctx, 20, page.NextCursor)
page, _ = c.HomeLatestTimelinePage(ctx, 20, page.NextCursor)
```

### Search

```go
tweets, _ := c.SearchTweets(ctx, "golang", 20,
    x.WithSearchType(x.SearchLatest),
    x.WithSearchSince("2025-01-01"),
    x.WithSearchUntil("2025-06-01"),
)

users, _ := c.SearchUsers(ctx, "golang", 20)

// Cursor pagination
tweets, _ = c.SearchTweetsPage(ctx, "golang", 20, tweets.NextCursor)
```

Search types: `SearchTop`, `SearchLatest`, `SearchPeople`, `SearchMedia`, `SearchLists`

### Tweets

```go
tweet, _ := c.GetTweet(ctx, tweetID)             // single tweet
detail, _ := c.GetTweetDetail(ctx, tweetID)       // tweet + reply thread
page, _ := c.UserTweets(ctx, userID, 20)          // user's tweets
page, _ = c.UserTweetsPage(ctx, userID, 20, cursor)
```

### Social graph

```go
followers, _ := c.GetFollowers(ctx, userID, 20)
following, _ := c.GetFollowing(ctx, userID, 20)

// Cursor pagination
followers, _ = c.GetFollowersPage(ctx, userID, 20, followers.NextCursor)
following, _ = c.GetFollowingPage(ctx, userID, 20, following.NextCursor)
```

### Lists

```go
list, _ := c.GetList(ctx, listID)
tweets, _ := c.GetListTimeline(ctx, listID, 20)
members, _ := c.GetListMembers(ctx, listID, 20)

// Cursor pagination
tweets, _ = c.GetListTimelinePage(ctx, listID, 20, tweets.NextCursor)
```

### Trend analysis

```go
report, _ := c.ScrapeTimelineTrends(ctx, userID,
    x.WithTrendMaxTweets(500),
    x.WithTrendTopN(30),
    x.WithTrendStopWords([]string{"promo", "giveaway"}),
)

fmt.Println(report.TweetsAnalyzed)  // tweets scanned
fmt.Println(report.TopKeywords)     // keyword frequency
fmt.Println(report.TopHashtags)     // hashtag frequency
fmt.Println(report.TopMentions)     // mention frequency
fmt.Println(report.AvgEngagement)   // mean likes+RT+replies+quotes
fmt.Println(report.PeakHours)       // UTC hours ranked by activity
fmt.Println(report.ActiveAuthors)   // most active authors
```

### Tweet composition

```go
tweet, _ := c.CreateTweet(ctx, "Hello world!")                         // 280-char validated
tweet, _ = c.Reply(ctx, tweetID, "Great thread!")
tweet, _ = c.QuoteTweet(ctx, "https://x.com/user/status/123", "This")
_ = c.DeleteTweet(ctx, tweet.ID)

// With media or sensitivity flag
tweet, _ = c.CreateTweet(ctx, "Check this out",
    x.WithMediaIDs("media_id_1", "media_id_2"),
    x.WithPossiblySensitive(),
)
```

### Engagement

```go
_ = c.Like(ctx, tweetID)
_ = c.Unlike(ctx, tweetID)
_ = c.Retweet(ctx, tweetID)
_ = c.Unretweet(ctx, tweetID)
_ = c.Bookmark(ctx, tweetID)
_ = c.Unbookmark(ctx, tweetID)
```

### Social actions

```go
_ = c.Follow(ctx, userID)
_ = c.Unfollow(ctx, userID)
_ = c.Mute(ctx, userID)
_ = c.Unmute(ctx, userID)
_ = c.Block(ctx, userID)
_ = c.Unblock(ctx, userID)
```

### Direct messages

```go
// DM a new person by user ID (cold outreach)
msg, _ := c.SendNewDM(ctx, userID, "Hey, saw your post about AI agents!")

// Reply in an existing conversation
msg, _ = c.SendDM(ctx, conversationID, "Following up on our chat")

// List conversations and read messages
convos, _ := c.GetConversations(ctx)
msgs, _ := c.GetConversation(ctx, conversationID)
```

### Advanced search

Full parity with X's Advanced Search UI:

```go
search := x.NewAdvancedSearch()
search.AllWords = "AI agents"
search.ExactPhrase = "go-to-market"
search.AnyWords = []string{"startup", "SaaS", "B2B"}
search.NoneWords = []string{"spam"}
search.Hashtags = []string{"buildinpublic"}
search.Language = "en"
search.From = []string{"elonmusk"}
search.To = []string{"OpenAI"}
search.Mentioning = []string{"ycombinator"}
search.Replies = x.ReplyFilterExclude
search.Links = x.LinkFilterOnly
search.MinReplies = 10
search.MinLikes = 100
search.MinReposts = 50
search.Since = "2026-01-01"
search.Until = "2026-04-20"
search.ResultType = x.SearchLatest

page, _ := c.AdvancedSearchTweets(ctx, search, 20)
page, _ = c.AdvancedSearchTweetsPage(ctx, search, 20, page.NextCursor)
```

### Iterators (paginated scraping with checkpoint/resume)

Walk through results page by page with serialisable checkpoints:

```go
it := x.NewSearchIterator(c, "golang", 20,
    x.WithMaxTweets(500),
    x.WithSearchResultType(x.SearchLatest),
)
for it.Next(ctx) {
    for _, tweet := range it.Page() {
        process(tweet)
    }
}
if err := it.Err(); err != nil { handle(err) }

// Save position for next run
cp := it.Checkpoint()
data, _ := cp.Marshal()
os.WriteFile("checkpoint.json", data, 0644)

// Resume later
data, _ = os.ReadFile("checkpoint.json")
cp, _ = x.UnmarshalCheckpoint(data)
it = x.NewSearchIterator(c, "golang", 20, x.WithCheckpoint(cp))
```

Iterator types:

| Factory | Source |
|---------|--------|
| `NewSearchIterator` | Simple search |
| `NewAdvancedSearchIterator` | Advanced search |
| `NewUserTweetsIterator` | User's tweet history |
| `NewTimelineIterator` | Home timeline (For You or Following) |

Options: `WithMaxTweets(n)`, `WithStopAtID(id)`, `WithCheckpoint(cp)`, `WithSearchResultType(t)`

### Rate limit management

Adaptive throttling using X's response headers:

```go
rl := c.RateLimit()
fmt.Printf("remaining=%d/%d reset=%s\n", rl.Remaining, rl.Limit, rl.Reset)
```

- Tracks `x-rate-limit-limit`, `x-rate-limit-remaining`, `x-rate-limit-reset` from every response
- Automatically widens request gap when remaining is low
- On 429, sleeps the exact retry-after duration before retrying

## Configuration

```go
c, _ := x.New(cookies,
    x.WithMinRequestGap(2*time.Second),   // leaky-bucket gap (default 1s)
    x.WithRetry(5, 1*time.Second),        // max attempts + backoff base (default 3, 500ms)
    x.WithProxy("http://127.0.0.1:8080"), // route through proxy
    x.WithUserAgent("my-bot/1.0"),        // custom User-Agent
    x.WithQueryIDs(map[string]string{     // override stale queryIds
        "HomeTimeline": "newQueryId123",
    }),
)
```

## QueryID rotation

X rotates GraphQL queryIds with each deploy (roughly every 2–4 weeks). The client ships with baked-in defaults, but they go stale. Two options:

```go
// Option 1: auto-refresh from X's main.js bundle
err := c.RefreshQueryIDs(ctx)

// Option 2: pass known-good IDs at construction
c, _ := x.New(cookies, x.WithQueryIDs(map[string]string{
    "HomeTimeline":   "abc123",
    "SearchTimeline": "def456",
}))
```

## Transport

- **stdlib only** — zero `require` entries in `go.mod`
- **Adaptive rate limiting** — tracks `x-rate-limit-remaining` headers and widens request gap as budget depletes; on 429 sleeps the exact retry-after duration
- **Exponential backoff** — retries with `500ms × 2^n` on transient failures; rate-limit retries use server-specified wait
- **`X-Client-Transaction-Id` header** — generated via X's animation-key algorithm to bypass CDN bot detection
- **10 MB body cap** — all response bodies are limited to prevent memory exhaustion
- **Thread-safe** — `Client` is safe for concurrent use from multiple goroutines
- **`X-Rate-Limit-Reset` parsing** — respects Unix-timestamp, seconds, and HTTP-date formats

## Error handling

All errors are sentinel-wrapped for programmatic handling:

```go
if errors.Is(err, x.ErrUnauthorized)      { /* session expired */ }
if errors.Is(err, x.ErrForbidden)         { /* protected account */ }
if errors.Is(err, x.ErrNotFound)          { /* user/tweet doesn't exist */ }
if errors.Is(err, x.ErrRateLimited)       { /* slow down */ }
if errors.Is(err, x.ErrSuspended)         { /* account suspended */ }
if errors.Is(err, x.ErrQueryIDStale)      { /* call RefreshQueryIDs */ }
if errors.Is(err, x.ErrTweetTooLong)      { /* >280 characters */ }
if errors.Is(err, x.ErrAlreadyRetweeted)  { /* duplicate retweet */ }
if errors.Is(err, x.ErrDMClosed)          { /* recipient has DMs closed */ }
if errors.Is(err, x.ErrPartialResult)     { /* context cancelled mid-scrape */ }
```

## MCP support

This package ships an [MCP](https://modelcontextprotocol.io/) tool surface in `./mcp` for use with [`teslashibe/mcptool`](https://github.com/teslashibe/mcptool)-compatible hosts (e.g. [`teslashibe/agent-setup`](https://github.com/teslashibe/agent-setup)). 37 tools cover the full client API: profile fetch (handle/ID/me), follower/following graph, home + latest timelines, tweet fetch + thread, user-tweet feed, simple/user/advanced search, tweet compose (create/reply/quote/delete), engagement (like/unlike/retweet/unretweet/bookmark/unbookmark), social graph writes (follow/unfollow/mute/unmute/block/unblock), DMs (list/read/send/cold-send), lists (metadata/timeline/members), and timeline trend analysis.

```go
import (
    "github.com/teslashibe/mcptool"
    x "github.com/teslashibe/x-go"
    xmcp "github.com/teslashibe/x-go/mcp"
)

client, _ := x.New(x.Cookies{...})
provider := xmcp.Provider{}
for _, tool := range provider.Tools() {
    // register tool with your MCP server, passing client as the
    // opaque client argument when invoking
}
```

A coverage test in `mcp/mcp_test.go` fails if a new exported method is added to `*Client` without either being wrapped by an MCP tool or being added to `mcp.Excluded` with a reason — keeping the MCP surface in lockstep with the package API is enforced by CI rather than convention.

## Testing

```bash
export X_AUTH_TOKEN="..."
export X_CT0="..."
export X_TWID="..."

go test -tags integration -v -count=1 ./...
```
