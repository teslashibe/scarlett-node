package x

import (
	"context"
	"encoding/json"
	"time"
)

// Checkpoint is a serialisable position in a paginated result set.
// Save it to disk/DB between runs; pass it back to resume where you left off.
type Checkpoint struct {
	Cursor       string    `json:"cursor,omitempty"`
	LastTweetID  string    `json:"lastTweetId,omitempty"`
	TweetsSeen   int       `json:"tweetsSeen"`
	CreatedAt    time.Time `json:"createdAt"`
	Query        string    `json:"query,omitempty"`
}

// Marshal serialises a Checkpoint to JSON bytes for storage.
func (cp Checkpoint) Marshal() ([]byte, error) {
	return json.Marshal(cp)
}

// UnmarshalCheckpoint deserialises a Checkpoint from JSON bytes.
func UnmarshalCheckpoint(data []byte) (Checkpoint, error) {
	var cp Checkpoint
	err := json.Unmarshal(data, &cp)
	return cp, err
}

// TweetIterator walks through paginated tweet results one page at a time.
// It works with any paginated tweet source (search, timeline, user tweets).
//
// Use the factory functions: NewSearchIterator, NewAdvancedSearchIterator,
// NewUserTweetsIterator, NewTimelineIterator.
type TweetIterator struct {
	client    *Client
	fetchFn   func(ctx context.Context, cursor string) (TweetPage, error)
	cursor    string
	lastID    string
	seen      int
	maxTweets int
	stopAtID  string // stop when we encounter this tweet ID (resume boundary)
	done       bool
	query      string // for checkpoint serialisation
	searchType SearchType
	page       []Tweet
	err        error
}

// IteratorOption configures a TweetIterator.
type IteratorOption func(*TweetIterator)

// WithMaxTweets caps the total tweets the iterator will return across all pages.
func WithMaxTweets(n int) IteratorOption {
	return func(it *TweetIterator) { it.maxTweets = n }
}

// WithStopAtID makes the iterator stop when it encounters a tweet with this ID.
// Use this to stop when you reach a previously-seen tweet (incremental scraping).
func WithStopAtID(tweetID string) IteratorOption {
	return func(it *TweetIterator) { it.stopAtID = tweetID }
}

// WithCheckpoint resumes iteration from a previously saved checkpoint.
func WithCheckpoint(cp Checkpoint) IteratorOption {
	return func(it *TweetIterator) {
		it.cursor = cp.Cursor
		it.lastID = cp.LastTweetID
		it.seen = cp.TweetsSeen
	}
}

// WithSearchResultType sets the search tab for NewSearchIterator (Top, Latest, Media).
// Has no effect on other iterator types.
func WithSearchResultType(t SearchType) IteratorOption {
	return func(it *TweetIterator) { it.searchType = t }
}

// Next fetches the next page of tweets. Returns false when there are no more
// results or the iterator has been exhausted (max tweets reached, stopAtID hit,
// or no more pages). Call Page() to get the current page's tweets.
//
// Typical usage:
//
//	it := x.NewSearchIterator(client, "golang", 20, x.WithMaxTweets(500))
//	for it.Next(ctx) {
//	    for _, tweet := range it.Page() {
//	        process(tweet)
//	    }
//	}
//	if err := it.Err(); err != nil { ... }
//	cp := it.Checkpoint() // save for next run
func (it *TweetIterator) Next(ctx context.Context) bool {
	if it.done {
		return false
	}
	if ctx.Err() != nil {
		it.err = ctx.Err()
		it.done = true
		return false
	}
	if it.maxTweets > 0 && it.seen >= it.maxTweets {
		it.done = true
		return false
	}

	page, err := it.fetchFn(ctx, it.cursor)
	if err != nil {
		it.err = err
		it.done = true
		return false
	}

	if len(page.Tweets) == 0 {
		it.done = true
		return false
	}

	// If stopAtID is set, trim tweets at the boundary
	if it.stopAtID != "" {
		trimmed := make([]Tweet, 0, len(page.Tweets))
		for _, tw := range page.Tweets {
			if tw.ID == it.stopAtID {
				it.done = true
				break
			}
			trimmed = append(trimmed, tw)
		}
		page.Tweets = trimmed
		if len(page.Tweets) == 0 {
			return false
		}
	}

	// Apply maxTweets cap
	if it.maxTweets > 0 {
		remaining := it.maxTweets - it.seen
		if remaining < len(page.Tweets) {
			page.Tweets = page.Tweets[:remaining]
			it.done = true
		}
	}

	it.page = page.Tweets
	it.seen += len(page.Tweets)
	if len(page.Tweets) > 0 {
		it.lastID = page.Tweets[len(page.Tweets)-1].ID
	}

	if page.HasNext && page.NextCursor != "" && !it.done {
		it.cursor = page.NextCursor
	} else {
		it.done = true
	}

	return len(it.page) > 0
}

// Page returns the tweets from the most recent Next() call.
func (it *TweetIterator) Page() []Tweet {
	return it.page
}

// Err returns the first error encountered during iteration, if any.
func (it *TweetIterator) Err() error {
	return it.err
}

// Seen returns the total number of tweets returned so far.
func (it *TweetIterator) Seen() int {
	return it.seen
}

// Checkpoint returns a serialisable position that can be used to resume
// iteration later via WithCheckpoint.
func (it *TweetIterator) Checkpoint() Checkpoint {
	return Checkpoint{
		Cursor:      it.cursor,
		LastTweetID: it.lastID,
		TweetsSeen:  it.seen,
		CreatedAt:   time.Now(),
		Query:       it.query,
	}
}

// NewSearchIterator creates a TweetIterator that paginates through search results.
// Use WithSearchResultType(SearchLatest) to iterate chronologically.
func NewSearchIterator(c *Client, query string, pageSize int, opts ...IteratorOption) *TweetIterator {
	it := &TweetIterator{
		client:     c,
		query:      query,
		searchType: SearchTop,
	}
	for _, o := range opts {
		o(it)
	}
	st := it.searchType
	it.fetchFn = func(ctx context.Context, cursor string) (TweetPage, error) {
		return c.SearchTweetsPage(ctx, query, pageSize, cursor, WithSearchType(st))
	}
	return it
}

// NewAdvancedSearchIterator creates a TweetIterator that paginates through
// advanced search results. The search query is snapshotted at construction time;
// subsequent mutations to the AdvancedSearch struct have no effect.
func NewAdvancedSearchIterator(c *Client, search *AdvancedSearch, pageSize int, opts ...IteratorOption) *TweetIterator {
	snapshot := *search
	it := &TweetIterator{
		client: c,
		query:  snapshot.Build(),
	}
	it.fetchFn = func(ctx context.Context, cursor string) (TweetPage, error) {
		return c.AdvancedSearchTweetsPage(ctx, &snapshot, pageSize, cursor)
	}
	for _, o := range opts {
		o(it)
	}
	return it
}

// NewUserTweetsIterator creates a TweetIterator that paginates through
// a user's tweet history.
func NewUserTweetsIterator(c *Client, userID string, pageSize int, opts ...IteratorOption) *TweetIterator {
	it := &TweetIterator{
		client: c,
		query:  "user:" + userID,
	}
	it.fetchFn = func(ctx context.Context, cursor string) (TweetPage, error) {
		return c.UserTweetsPage(ctx, userID, pageSize, cursor)
	}
	for _, o := range opts {
		o(it)
	}
	return it
}

// NewTimelineIterator creates a TweetIterator that paginates through
// the home timeline (For You or Following).
func NewTimelineIterator(c *Client, latest bool, pageSize int, opts ...IteratorOption) *TweetIterator {
	label := "timeline:foryou"
	if latest {
		label = "timeline:following"
	}
	it := &TweetIterator{
		client: c,
		query:  label,
	}
	it.fetchFn = func(ctx context.Context, cursor string) (TweetPage, error) {
		if latest {
			return c.HomeLatestTimelinePage(ctx, pageSize, cursor)
		}
		return c.HomeTimelinePage(ctx, pageSize, cursor)
	}
	for _, o := range opts {
		o(it)
	}
	return it
}
