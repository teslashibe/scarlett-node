package x

import (
	"context"
	"fmt"
)

// GetFollowers returns the first page of followers for a user.
func (c *Client) GetFollowers(ctx context.Context, userID string, count int) (UserPage, error) {
	return c.GetFollowersPage(ctx, userID, count, "")
}

// GetFollowersPage returns a page of followers starting from cursor.
func (c *Client) GetFollowersPage(ctx context.Context, userID string, count int, cursor string) (UserPage, error) {
	if userID == "" {
		return UserPage{}, fmt.Errorf("%w: userID must not be empty", ErrInvalidParams)
	}
	if count <= 0 {
		count = 20
	}

	vars := map[string]interface{}{
		"userId":               userID,
		"count":                count,
		"includePromotedContent": false,
	}
	if cursor != "" {
		vars["cursor"] = cursor
	}

	raw, err := c.graphqlGET(ctx, "Followers", vars)
	if err != nil {
		return UserPage{}, err
	}

	return parseUserPage(raw, "user.result.timeline")
}

// GetFollowing returns the first page of users a given user is following.
func (c *Client) GetFollowing(ctx context.Context, userID string, count int) (UserPage, error) {
	return c.GetFollowingPage(ctx, userID, count, "")
}

// GetFollowingPage returns a page of following users starting from cursor.
func (c *Client) GetFollowingPage(ctx context.Context, userID string, count int, cursor string) (UserPage, error) {
	if userID == "" {
		return UserPage{}, fmt.Errorf("%w: userID must not be empty", ErrInvalidParams)
	}
	if count <= 0 {
		count = 20
	}

	vars := map[string]interface{}{
		"userId":               userID,
		"count":                count,
		"includePromotedContent": false,
	}
	if cursor != "" {
		vars["cursor"] = cursor
	}

	raw, err := c.graphqlGET(ctx, "Following", vars)
	if err != nil {
		return UserPage{}, err
	}

	return parseUserPage(raw, "user.result.timeline")
}
