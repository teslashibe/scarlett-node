package x

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	// maxTweetLengthFree is X's default post length for non-Premium accounts.
	maxTweetLengthFree = 280
	// maxTweetLengthPremium is X Premium's long-post ceiling (posts, replies,
	// quotes). Detected via the authenticated viewer's IsBlueVerified flag.
	maxTweetLengthPremium = 25000
)

// MaxTweetLength returns the authenticated account's post character limit.
// Premium / Blue-verified accounts get the long-post ceiling; everyone else
// stays at the free-tier 280. When the viewer is unknown, defaults to free.
func (c *Client) MaxTweetLength() int {
	if c == nil {
		return maxTweetLengthFree
	}
	me, err := c.Me(context.Background())
	if err != nil || me == nil {
		return maxTweetLengthFree
	}
	if me.IsBlueVerified {
		return maxTweetLengthPremium
	}
	return maxTweetLengthFree
}

func (c *Client) assertTweetLength(text string) error {
	limit := c.MaxTweetLength()
	if len([]rune(text)) > limit {
		return fmt.Errorf("%w (limit %d)", ErrTweetTooLong, limit)
	}
	return nil
}

func applyTweetOpts(opts []TweetOption) *tweetOptions {
	o := &tweetOptions{}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

func buildMediaVars(o *tweetOptions) map[string]interface{} {
	entities := make([]map[string]interface{}, 0, len(o.mediaIDs))
	for _, id := range o.mediaIDs {
		entities = append(entities, map[string]interface{}{
			"media_id": id, "tagged_users": []string{},
		})
	}
	return map[string]interface{}{
		"media_entities":     entities,
		"possibly_sensitive": o.possiblySensitive,
	}
}

// composeOp picks CreateNoteTweet for Premium long posts (>280). Standard
// CreateTweet rejects those with error 186 even for Blue-verified accounts.
func composeOp(text string) string {
	if len([]rune(text)) > maxTweetLengthFree {
		return "CreateNoteTweet"
	}
	return "CreateTweet"
}

func baseComposeVars(text string, o *tweetOptions) map[string]interface{} {
	vars := map[string]interface{}{
		"tweet_text":              text,
		"dark_request":            false,
		"media":                   buildMediaVars(o),
		"semantic_annotation_ids": []interface{}{},
	}
	// Required for CreateNoteTweet; harmless on CreateTweet. Omitting it can
	// yield an empty tweet_results payload instead of a usable error.
	vars["disallowed_reply_options"] = nil
	return vars
}

// CreateTweet publishes a new tweet. Texts over 280 chars use CreateNoteTweet
// (X Premium long-form); shorter texts stay on CreateTweet.
func (c *Client) CreateTweet(ctx context.Context, text string, opts ...TweetOption) (*Tweet, error) {
	if text == "" {
		return nil, ErrInvalidParams
	}
	if err := c.assertTweetLength(text); err != nil {
		return nil, err
	}

	o := applyTweetOpts(opts)
	vars := baseComposeVars(text, o)
	data, err := c.graphqlPOST(ctx, composeOp(text), vars)
	if err != nil {
		return nil, err
	}

	return parseTweetFromCreateResponse(data)
}

// Reply publishes a reply to an existing tweet. Long replies use CreateNoteTweet.
func (c *Client) Reply(ctx context.Context, inReplyToID, text string, opts ...TweetOption) (*Tweet, error) {
	if inReplyToID == "" || text == "" {
		return nil, ErrInvalidParams
	}
	if err := c.assertTweetLength(text); err != nil {
		return nil, err
	}

	o := applyTweetOpts(opts)
	vars := baseComposeVars(text, o)
	vars["reply"] = map[string]interface{}{
		"in_reply_to_tweet_id":   inReplyToID,
		"exclude_reply_user_ids": []string{},
	}

	data, err := c.graphqlPOST(ctx, composeOp(text), vars)
	if err != nil {
		return nil, err
	}
	return parseTweetFromCreateResponse(data)
}

// QuoteTweet publishes a quote tweet. Long quotes use CreateNoteTweet.
func (c *Client) QuoteTweet(ctx context.Context, quotedTweetURL, text string, opts ...TweetOption) (*Tweet, error) {
	if quotedTweetURL == "" || text == "" {
		return nil, ErrInvalidParams
	}
	if err := c.assertTweetLength(text); err != nil {
		return nil, err
	}

	o := applyTweetOpts(opts)
	vars := baseComposeVars(text, o)
	vars["attachment_url"] = quotedTweetURL

	data, err := c.graphqlPOST(ctx, composeOp(text), vars)
	if err != nil {
		return nil, err
	}
	return parseTweetFromCreateResponse(data)
}

// DeleteTweet deletes a tweet owned by the authenticated user.
func (c *Client) DeleteTweet(ctx context.Context, tweetID string) error {
	if tweetID == "" {
		return ErrInvalidParams
	}
	vars := map[string]interface{}{
		"tweet_id":     tweetID,
		"dark_request": false,
	}
	_, err := c.graphqlPOST(ctx, "DeleteTweet", vars)
	return err
}

// parseTweetFromCreateResponse extracts a Tweet from CreateTweet /
// CreateNoteTweet mutation responses. X has used create_tweet,
// notetweet_create, and create_note_tweet envelopes.
func parseTweetFromCreateResponse(data json.RawMessage) (*Tweet, error) {
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("%w: parsing create tweet response: %v", ErrRequestFailed, err)
	}

	var resultRaw json.RawMessage
	for _, key := range []string{"create_tweet", "notetweet_create", "create_note_tweet"} {
		if raw, ok := wrapper[key]; ok && len(raw) > 0 && string(raw) != "null" {
			resultRaw = raw
			break
		}
	}
	if resultRaw == nil {
		return nil, fmt.Errorf("%w: tweet creation missing result (snippet: %s)", ErrRequestFailed, truncate(string(data), 300))
	}

	var envelope struct {
		TweetResults struct {
			Result json.RawMessage `json:"result"`
		} `json:"tweet_results"`
	}
	if err := json.Unmarshal(resultRaw, &envelope); err != nil {
		return nil, fmt.Errorf("%w: parsing create tweet result: %v", ErrRequestFailed, err)
	}
	tweet, ok, err := (tweetResult{Result: envelope.TweetResults.Result}).tweet()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: tweet creation returned empty ID", ErrRequestFailed)
	}
	return &tweet, nil
}
