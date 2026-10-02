package x

import (
	"context"
	"net/url"
)

// Follow follows a user.
func (c *Client) Follow(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrInvalidParams
	}
	form := url.Values{}
	form.Set("user_id", userID)
	_, err := c.restFormPOST(ctx, "/i/api/1.1/friendships/create.json", form)
	return err
}

// Unfollow unfollows a user.
func (c *Client) Unfollow(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrInvalidParams
	}
	form := url.Values{}
	form.Set("user_id", userID)
	_, err := c.restFormPOST(ctx, "/i/api/1.1/friendships/destroy.json", form)
	return err
}

// Mute mutes a user.
func (c *Client) Mute(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrInvalidParams
	}
	form := url.Values{}
	form.Set("user_id", userID)
	_, err := c.restFormPOST(ctx, "/i/api/1.1/mutes/users/create.json", form)
	return err
}

// Unmute unmutes a user.
func (c *Client) Unmute(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrInvalidParams
	}
	form := url.Values{}
	form.Set("user_id", userID)
	_, err := c.restFormPOST(ctx, "/i/api/1.1/mutes/users/destroy.json", form)
	return err
}

// Block blocks a user.
func (c *Client) Block(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrInvalidParams
	}
	form := url.Values{}
	form.Set("user_id", userID)
	_, err := c.restFormPOST(ctx, "/i/api/1.1/blocks/create.json", form)
	return err
}

// Unblock unblocks a user.
func (c *Client) Unblock(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrInvalidParams
	}
	form := url.Values{}
	form.Set("user_id", userID)
	_, err := c.restFormPOST(ctx, "/i/api/1.1/blocks/destroy.json", form)
	return err
}
