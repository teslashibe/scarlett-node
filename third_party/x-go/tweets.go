package x

import (
	"context"
	"encoding/json"
	"fmt"
)

// GetTweet retrieves a single tweet by its ID.
func (c *Client) GetTweet(ctx context.Context, tweetID string) (*Tweet, error) {
	if tweetID == "" {
		return nil, fmt.Errorf("%w: tweetID must not be empty", ErrInvalidParams)
	}

	vars := map[string]interface{}{
		"tweetId":                tweetID,
		"withCommunity":          true,
		"includePromotedContent": false,
		"withVoice":              false,
	}

	raw, err := c.graphqlGET(ctx, "TweetResultByRestId", vars)
	if err != nil {
		return nil, err
	}

	var data struct {
		TweetResult struct {
			Result json.RawMessage `json:"result"`
		} `json:"tweetResult"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("%w: decoding tweet: %v", ErrRequestFailed, err)
	}

	t, ok, err := (tweetResult{Result: data.TweetResult.Result}).tweet()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	return &t, nil
}

// GetTweetDetail retrieves a tweet and its conversation thread (replies).
func (c *Client) GetTweetDetail(ctx context.Context, tweetID string) (*TweetDetail, error) {
	if tweetID == "" {
		return nil, fmt.Errorf("%w: tweetID must not be empty", ErrInvalidParams)
	}

	vars := map[string]interface{}{
		"focalTweetId":                           tweetID,
		"with_rux_injections":                    false,
		"includePromotedContent":                 false,
		"withCommunity":                          true,
		"withQuickPromoteEligibilityTweetFields": true,
		"withBirdwatchNotes":                     true,
		"withVoice":                              true,
		"withV2Timeline":                         true,
	}

	raw, err := c.graphqlGET(ctx, "TweetDetail", vars)
	if err != nil {
		return nil, err
	}

	var data struct {
		ThreadedConversation json.RawMessage `json:"threaded_conversation_with_injections_v2"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("%w: decoding tweet detail: %v", ErrRequestFailed, err)
	}

	var tl struct {
		Instructions []timelineInstruction `json:"instructions"`
	}
	if err := json.Unmarshal(data.ThreadedConversation, &tl); err != nil {
		return nil, fmt.Errorf("%w: decoding conversation: %v", ErrRequestFailed, err)
	}

	detail := &TweetDetail{}
	for _, inst := range tl.Instructions {
		for _, entry := range inst.Entries {
			tweet, ok, err := extractTweetFromEntry(entry)
			if err != nil {
				return nil, err
			}
			if ok && tweet.ID != "" {
				if tweet.ID == tweetID {
					detail.Tweet = tweet
				} else {
					detail.Replies = append(detail.Replies, tweet)
				}
				continue
			}
			for _, item := range entry.Content.Items {
				if item.Item.ItemContent.TweetResults != nil {
					tw, ok, err := item.Item.ItemContent.TweetResults.tweet()
					if err != nil {
						return nil, err
					}
					if !ok {
						continue
					}
					if tw.ID == tweetID {
						detail.Tweet = tw
					} else if tw.ID != "" {
						detail.Replies = append(detail.Replies, tw)
					}
				}
			}
		}
	}

	if detail.Tweet.ID == "" {
		return nil, ErrNotFound
	}

	return detail, nil
}

// UserTweets returns the first page of tweets for a given user.
func (c *Client) UserTweets(ctx context.Context, userID string, count int) (TweetPage, error) {
	return c.UserTweetsPage(ctx, userID, count, "")
}

// UserTweetsPage returns a page of tweets for a given user, starting from cursor.
func (c *Client) UserTweetsPage(ctx context.Context, userID string, count int, cursor string) (TweetPage, error) {
	if userID == "" {
		return TweetPage{}, fmt.Errorf("%w: userID must not be empty", ErrInvalidParams)
	}
	if count <= 0 {
		count = 20
	}

	vars := map[string]interface{}{
		"userId":                                 userID,
		"count":                                  count,
		"includePromotedContent":                 false,
		"withQuickPromoteEligibilityTweetFields": true,
		"withVoice":                              true,
		"withV2Timeline":                         true,
	}
	if cursor != "" {
		vars["cursor"] = cursor
	}

	raw, err := c.graphqlGET(ctx, "UserTweets", vars)
	if err != nil {
		return TweetPage{}, err
	}

	return parseTweetPage(raw, "user.result.timeline")
}
