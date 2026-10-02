package x

import (
	"context"
	"encoding/json"
	"fmt"
)

// GetProfile retrieves a user's profile by screen name (handle).
func (c *Client) GetProfile(ctx context.Context, screenName string) (*User, error) {
	if screenName == "" {
		return nil, fmt.Errorf("%w: screenName must not be empty", ErrInvalidParams)
	}

	vars := map[string]interface{}{
		"screen_name":                    screenName,
		"withSafetyModeUserFields":       true,
	}

	raw, err := c.graphqlGET(ctx, "UserByScreenName", vars)
	if err != nil {
		return nil, err
	}

	var data struct {
		User struct {
			Result userObj `json:"result"`
		} `json:"user"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("%w: decoding profile: %v", ErrRequestFailed, err)
	}

	if data.User.Result.Typename == "UserUnavailable" {
		return nil, ErrSuspended
	}
	if data.User.Result.RestID == "" {
		return nil, ErrNotFound
	}

	u := toUser(data.User.Result)
	return &u, nil
}

// GetProfileByID retrieves a user's profile by their numeric REST ID.
func (c *Client) GetProfileByID(ctx context.Context, userID string) (*User, error) {
	if userID == "" {
		return nil, fmt.Errorf("%w: userID must not be empty", ErrInvalidParams)
	}

	vars := map[string]interface{}{
		"userId":                         userID,
		"withSafetyModeUserFields":       true,
	}

	raw, err := c.graphqlGET(ctx, "UserByRestId", vars)
	if err != nil {
		return nil, err
	}

	var data struct {
		User struct {
			Result userObj `json:"result"`
		} `json:"user"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("%w: decoding profile: %v", ErrRequestFailed, err)
	}

	if data.User.Result.Typename == "UserUnavailable" {
		return nil, ErrSuspended
	}
	if data.User.Result.RestID == "" {
		return nil, ErrNotFound
	}

	u := toUser(data.User.Result)
	return &u, nil
}
