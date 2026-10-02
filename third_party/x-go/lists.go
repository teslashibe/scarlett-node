package x

import (
	"context"
	"encoding/json"
	"fmt"
)

// GetList retrieves metadata for an X list by its ID.
func (c *Client) GetList(ctx context.Context, listID string) (*List, error) {
	if listID == "" {
		return nil, fmt.Errorf("%w: listID must not be empty", ErrInvalidParams)
	}

	vars := map[string]interface{}{
		"listId": listID,
	}

	raw, err := c.graphqlGET(ctx, "ListBySlug", vars)
	if err != nil {
		return nil, err
	}

	var data struct {
		List struct {
			ID          string `json:"id_str"`
			Name        string `json:"name"`
			Slug        string `json:"slug"`
			Description string `json:"description"`
			MemberCount int    `json:"member_count"`
			Mode        string `json:"mode"`
			User        struct {
				RestID string     `json:"rest_id"`
				Legacy userLegacy `json:"legacy"`
			} `json:"user"`
		} `json:"list"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("%w: decoding list: %v", ErrRequestFailed, err)
	}

	if data.List.Name == "" {
		return nil, ErrNotFound
	}

	l := &List{
		ID:          data.List.ID,
		Name:        data.List.Name,
		Slug:        data.List.Slug,
		Description: data.List.Description,
		MemberCount: data.List.MemberCount,
		OwnerID:     data.List.User.RestID,
		OwnerName:   data.List.User.Legacy.Name,
		IsPrivate:   data.List.Mode == "Private",
	}
	return l, nil
}

// GetListTimeline returns the first page of tweets from a list.
func (c *Client) GetListTimeline(ctx context.Context, listID string, count int) (TweetPage, error) {
	return c.GetListTimelinePage(ctx, listID, count, "")
}

// GetListTimelinePage returns a page of tweets from a list starting from cursor.
func (c *Client) GetListTimelinePage(ctx context.Context, listID string, count int, cursor string) (TweetPage, error) {
	if listID == "" {
		return TweetPage{}, fmt.Errorf("%w: listID must not be empty", ErrInvalidParams)
	}
	if count <= 0 {
		count = 20
	}

	vars := map[string]interface{}{
		"listId": listID,
		"count":  count,
	}
	if cursor != "" {
		vars["cursor"] = cursor
	}

	raw, err := c.graphqlGET(ctx, "ListLatestTweetsTimeline", vars)
	if err != nil {
		return TweetPage{}, err
	}

	return parseTweetPage(raw, "list.tweets_timeline")
}

// GetListMembers returns the first page of members of a list.
func (c *Client) GetListMembers(ctx context.Context, listID string, count int) (UserPage, error) {
	return c.GetListMembersPage(ctx, listID, count, "")
}

// GetListMembersPage returns a page of list members starting from cursor.
func (c *Client) GetListMembersPage(ctx context.Context, listID string, count int, cursor string) (UserPage, error) {
	if listID == "" {
		return UserPage{}, fmt.Errorf("%w: listID must not be empty", ErrInvalidParams)
	}
	if count <= 0 {
		count = 20
	}

	vars := map[string]interface{}{
		"listId": listID,
		"count":  count,
	}
	if cursor != "" {
		vars["cursor"] = cursor
	}

	raw, err := c.graphqlGET(ctx, "ListMembers", vars)
	if err != nil {
		return UserPage{}, err
	}

	return parseUserPage(raw, "list.members_timeline")
}
