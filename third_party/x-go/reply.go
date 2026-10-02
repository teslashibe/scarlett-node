package x

import "context"

// ReplyToPost publishes text as a reply to postID.
func (c *Client) ReplyToPost(ctx context.Context, postID, text string, opts ...TweetOption) (*Tweet, error) {
	tweet, err := c.Reply(ctx, postID, text, opts...)
	if err != nil {
		return nil, classifyWriteOutcome(err)
	}
	return tweet, nil
}
