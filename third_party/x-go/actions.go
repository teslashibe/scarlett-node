package x

import "context"

// Like adds a like to a tweet.
func (c *Client) Like(ctx context.Context, tweetID string) error {
	if tweetID == "" {
		return ErrInvalidParams
	}
	vars := map[string]interface{}{
		"tweet_id": tweetID,
	}
	_, err := c.graphqlPOST(ctx, "FavoriteTweet", vars)
	return err
}

// Unlike removes a like from a tweet.
func (c *Client) Unlike(ctx context.Context, tweetID string) error {
	if tweetID == "" {
		return ErrInvalidParams
	}
	vars := map[string]interface{}{
		"tweet_id": tweetID,
	}
	_, err := c.graphqlPOST(ctx, "UnfavoriteTweet", vars)
	return err
}

// Retweet retweets a tweet.
func (c *Client) Retweet(ctx context.Context, tweetID string) error {
	if tweetID == "" {
		return ErrInvalidParams
	}
	vars := map[string]interface{}{
		"tweet_id":     tweetID,
		"dark_request": false,
	}
	_, err := c.graphqlPOST(ctx, "CreateRetweet", vars)
	return err
}

// Unretweet undoes a retweet.
func (c *Client) Unretweet(ctx context.Context, tweetID string) error {
	if tweetID == "" {
		return ErrInvalidParams
	}
	vars := map[string]interface{}{
		"source_tweet_id": tweetID,
		"dark_request":    false,
	}
	_, err := c.graphqlPOST(ctx, "DeleteRetweet", vars)
	return err
}

// Bookmark bookmarks a tweet.
func (c *Client) Bookmark(ctx context.Context, tweetID string) error {
	if tweetID == "" {
		return ErrInvalidParams
	}
	vars := map[string]interface{}{
		"tweet_id": tweetID,
	}
	_, err := c.graphqlPOST(ctx, "CreateBookmark", vars)
	return err
}

// Unbookmark removes a tweet from bookmarks.
func (c *Client) Unbookmark(ctx context.Context, tweetID string) error {
	if tweetID == "" {
		return ErrInvalidParams
	}
	vars := map[string]interface{}{
		"tweet_id": tweetID,
	}
	_, err := c.graphqlPOST(ctx, "DeleteBookmark", vars)
	return err
}
