package x

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const xDateFormat = "Mon Jan 02 15:04:05 +0000 2006"

// ---------------------------------------------------------------------------
// GraphQL envelope
// ---------------------------------------------------------------------------

type gqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []gqlError      `json:"errors"`
}

type gqlError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// ---------------------------------------------------------------------------
// Timeline instruction shapes
// ---------------------------------------------------------------------------

type timelineData struct {
	Timeline struct {
		Instructions []timelineInstruction `json:"instructions"`
	} `json:"timeline"`
}

type timelineInstruction struct {
	Type    string          `json:"type"`
	Entries []timelineEntry `json:"entries"`
	Entry   *timelineEntry  `json:"entry"`
}

type timelineEntry struct {
	EntryID   string       `json:"entryId"`
	SortIndex string       `json:"sortIndex"`
	Content   entryContent `json:"content"`
}

type entryContent struct {
	EntryType   string       `json:"entryType"`
	Typename    string       `json:"__typename"`
	ItemContent *itemContent `json:"itemContent"`
	Items       []struct {
		Item struct {
			ItemContent itemContent `json:"itemContent"`
		} `json:"item"`
	} `json:"items"`
	CursorType string `json:"cursorType"`
	Value      string `json:"value"`
}

type itemContent struct {
	ItemType     string       `json:"itemType"`
	TweetResults *tweetResult `json:"tweet_results"`
	UserResults  *userResult  `json:"user_results"`
}

type tweetResult struct {
	Result json.RawMessage `json:"result"`
}

type userResult struct {
	Result userObj `json:"result"`
}

// ---------------------------------------------------------------------------
// Tweet object (from tweet_results.result)
// ---------------------------------------------------------------------------

type tweetObj struct {
	Typename string    `json:"__typename"`
	RestID   string    `json:"rest_id"`
	Tweet    *tweetObj `json:"tweet"`
	Core     struct {
		UserResults struct {
			Result userObj `json:"result"`
		} `json:"user_results"`
	} `json:"core"`
	Legacy             tweetLegacy  `json:"legacy"`
	Views              tweetViews   `json:"views"`
	QuotedStatusResult *tweetResult `json:"quoted_status_result"`
	NoteTweet          *noteTweet   `json:"note_tweet"`
}

func (r tweetResult) tweet() (Tweet, bool, error) {
	if len(r.Result) == 0 || string(r.Result) == "null" {
		return Tweet{}, false, nil
	}
	var o tweetObj
	if err := json.Unmarshal(r.Result, &o); err != nil {
		return Tweet{}, false, fmt.Errorf("%w: decoding tweet result: %v", ErrRequestFailed, err)
	}
	t := toTweet(o)
	if t.ID == "" {
		return Tweet{}, false, nil
	}
	t.Raw = &RawTweetEnvelope{
		SchemaVersion: 1,
		Provider:      "x_graphql",
		Result:        append(json.RawMessage(nil), r.Result...),
	}
	return t, true, nil
}

type tweetViews struct {
	Count string `json:"count"`
	State string `json:"state"`
}

type noteTweet struct {
	NoteTweetResults struct {
		Result struct {
			Text string `json:"text"`
		} `json:"result"`
	} `json:"note_tweet_results"`
}

type tweetLegacy struct {
	FullText              string            `json:"full_text"`
	FavoriteCount         int               `json:"favorite_count"`
	RetweetCount          int               `json:"retweet_count"`
	ReplyCount            int               `json:"reply_count"`
	QuoteCount            int               `json:"quote_count"`
	BookmarkCount         int               `json:"bookmark_count"`
	ConversationIDStr     string            `json:"conversation_id_str"`
	InReplyToStatusIDStr  string            `json:"in_reply_to_status_id_str"`
	Lang                  string            `json:"lang"`
	CreatedAt             string            `json:"created_at"`
	Entities              tweetEntities     `json:"entities"`
	ExtendedEntities      *extendedEntities `json:"extended_entities"`
	RetweetedStatusResult *tweetResult      `json:"retweeted_status_result"`
	IsQuoteStatus         bool              `json:"is_quote_status"`
	QuotedStatusIDStr     string            `json:"quoted_status_id_str"`
}

type tweetEntities struct {
	Hashtags     []hashtagEntity `json:"hashtags"`
	UserMentions []mentionEntity `json:"user_mentions"`
	URLs         []urlEntity     `json:"urls"`
	Media        []mediaEntity   `json:"media"`
}

type extendedEntities struct {
	Media []mediaEntity `json:"media"`
}

type hashtagEntity struct {
	Text string `json:"text"`
}

type mentionEntity struct {
	ScreenName string `json:"screen_name"`
}

type urlEntity struct {
	ExpandedURL string `json:"expanded_url"`
}

type mediaEntity struct {
	MediaURLHTTPS string `json:"media_url_https"`
}

// ---------------------------------------------------------------------------
// User object (from user_results.result)
// ---------------------------------------------------------------------------

type userObj struct {
	Typename       string     `json:"__typename"`
	RestID         string     `json:"rest_id"`
	Legacy         userLegacy `json:"legacy"`
	IsBlueVerified bool       `json:"is_blue_verified"`
	Core           *userCore  `json:"core"`
	Avatar         *struct {
		ImageURL string `json:"image_url"`
	} `json:"avatar"`
	Location *struct {
		Location string `json:"location"`
	} `json:"location"`
	ProfileBio *struct {
		Description string `json:"description"`
	} `json:"profile_bio"`
}

type userCore struct {
	ScreenName string `json:"screen_name"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
}

type userLegacy struct {
	ScreenName           string        `json:"screen_name"`
	Name                 string        `json:"name"`
	Description          string        `json:"description"`
	Location             string        `json:"location"`
	URL                  string        `json:"url"`
	FollowersCount       int           `json:"followers_count"`
	FriendsCount         int           `json:"friends_count"`
	StatusesCount        int           `json:"statuses_count"`
	ListedCount          int           `json:"listed_count"`
	Verified             bool          `json:"verified"`
	CreatedAt            string        `json:"created_at"`
	ProfileImageURLHTTPS string        `json:"profile_image_url_https"`
	ProfileBannerURL     string        `json:"profile_banner_url"`
	PinnedTweetIDsStr    []string      `json:"pinned_tweet_ids_str"`
	Entities             *userEntities `json:"entities"`
}

type userEntities struct {
	URL *struct {
		URLs []urlEntity `json:"urls"`
	} `json:"url"`
}

// ---------------------------------------------------------------------------
// Converters
// ---------------------------------------------------------------------------

func toUser(o userObj) User {
	u := User{
		ID:              o.RestID,
		ScreenName:      o.Legacy.ScreenName,
		Name:            o.Legacy.Name,
		Description:     o.Legacy.Description,
		Location:        o.Legacy.Location,
		ProfileImageURL: o.Legacy.ProfileImageURLHTTPS,
		BannerURL:       o.Legacy.ProfileBannerURL,
		FollowersCount:  o.Legacy.FollowersCount,
		FollowingCount:  o.Legacy.FriendsCount,
		TweetCount:      o.Legacy.StatusesCount,
		ListedCount:     o.Legacy.ListedCount,
		Verified:        o.Legacy.Verified,
		IsBlueVerified:  o.IsBlueVerified,
		PinnedTweetIDs:  o.Legacy.PinnedTweetIDsStr,
	}

	// X has moved core profile fields out of legacy into top-level objects.
	// Prefer the new locations, fall back to legacy for older responses.
	if o.Core != nil {
		if o.Core.ScreenName != "" {
			u.ScreenName = o.Core.ScreenName
		}
		if o.Core.Name != "" {
			u.Name = o.Core.Name
		}
		if o.Core.CreatedAt != "" {
			if t, err := time.Parse(xDateFormat, o.Core.CreatedAt); err == nil {
				u.CreatedAt = t
			}
		}
	}
	if u.CreatedAt.IsZero() && o.Legacy.CreatedAt != "" {
		if t, err := time.Parse(xDateFormat, o.Legacy.CreatedAt); err == nil {
			u.CreatedAt = t
		}
	}

	if o.Avatar != nil && o.Avatar.ImageURL != "" {
		u.ProfileImageURL = o.Avatar.ImageURL
	}
	if o.Location != nil && o.Location.Location != "" {
		u.Location = o.Location.Location
	}
	if o.ProfileBio != nil && o.ProfileBio.Description != "" {
		u.Description = o.ProfileBio.Description
	}

	if o.Legacy.Entities != nil && o.Legacy.Entities.URL != nil {
		for _, eu := range o.Legacy.Entities.URL.URLs {
			if eu.ExpandedURL != "" {
				u.URL = eu.ExpandedURL
				break
			}
		}
	}
	if u.URL == "" {
		u.URL = o.Legacy.URL
	}

	return u
}

func toTweet(o tweetObj) Tweet {
	// Handle TweetWithVisibilityResults wrapper
	if o.Typename == "TweetWithVisibilityResults" {
		if o.Tweet == nil {
			return Tweet{}
		}
		o = *o.Tweet
	}

	t := Tweet{
		ID:             o.RestID,
		ConversationID: o.Legacy.ConversationIDStr,
		Text:           o.Legacy.FullText,
		LikeCount:      o.Legacy.FavoriteCount,
		RetweetCount:   o.Legacy.RetweetCount,
		ReplyCount:     o.Legacy.ReplyCount,
		QuoteCount:     o.Legacy.QuoteCount,
		BookmarkCount:  o.Legacy.BookmarkCount,
		Language:       o.Legacy.Lang,
		InReplyToID:    o.Legacy.InReplyToStatusIDStr,
		IsQuote:        o.Legacy.IsQuoteStatus,
		QuotedTweetID:  o.Legacy.QuotedStatusIDStr,
	}

	if o.Legacy.InReplyToStatusIDStr != "" {
		t.IsReply = true
	}
	if o.Legacy.RetweetedStatusResult != nil {
		t.IsRetweet = true
	}

	// Use note tweet text if available (long tweets)
	if o.NoteTweet != nil && o.NoteTweet.NoteTweetResults.Result.Text != "" {
		t.Text = o.NoteTweet.NoteTweetResults.Result.Text
	}

	if o.Views.Count != "" {
		if v, err := strconv.Atoi(o.Views.Count); err == nil {
			t.ViewCount = v
		}
	}

	if o.Legacy.CreatedAt != "" {
		if parsed, err := time.Parse(xDateFormat, o.Legacy.CreatedAt); err == nil {
			t.CreatedAt = parsed
		}
	}

	// Author from core.user_results — use toUser to handle both legacy and new field locations
	author := toUser(o.Core.UserResults.Result)
	t.AuthorID = author.ID
	t.AuthorScreenName = author.ScreenName
	t.AuthorName = author.Name

	for _, h := range o.Legacy.Entities.Hashtags {
		t.Hashtags = append(t.Hashtags, h.Text)
	}
	for _, m := range o.Legacy.Entities.UserMentions {
		t.MentionedUsers = append(t.MentionedUsers, m.ScreenName)
	}
	for _, u := range o.Legacy.Entities.URLs {
		t.URLs = append(t.URLs, u.ExpandedURL)
	}

	// Prefer extended_entities for media (includes all media in multi-photo)
	if o.Legacy.ExtendedEntities != nil {
		for _, m := range o.Legacy.ExtendedEntities.Media {
			t.MediaURLs = append(t.MediaURLs, m.MediaURLHTTPS)
		}
	} else {
		for _, m := range o.Legacy.Entities.Media {
			t.MediaURLs = append(t.MediaURLs, m.MediaURLHTTPS)
		}
	}

	return t
}

// ---------------------------------------------------------------------------
// Timeline instruction parsers
// ---------------------------------------------------------------------------

// parseTweetPage extracts tweets and cursor from a timeline instruction response.
// timelineKey is the JSON path segment to reach the timeline object,
// e.g. "home.home_timeline_urt" or "user.result.timeline_v2".
func parseTweetPage(raw json.RawMessage, timelineKey string) (TweetPage, error) {
	instructions, err := extractInstructions(raw, timelineKey)
	if err != nil {
		return TweetPage{}, err
	}

	var page TweetPage
	for _, inst := range instructions {
		entries := inst.Entries
		if inst.Entry != nil {
			entries = append(entries, *inst.Entry)
		}
		for _, entry := range entries {
			tweet, ok, err := extractTweetFromEntry(entry)
			if err != nil {
				return TweetPage{}, err
			}
			if ok {
				if tweet.ID != "" {
					page.Tweets = append(page.Tweets, tweet)
				}
			}
			if entry.Content.CursorType == "Bottom" && entry.Content.Value != "" {
				page.NextCursor = entry.Content.Value
				page.HasNext = true
			}
			// Module entries (e.g. search results grouped in modules)
			for _, item := range entry.Content.Items {
				if item.Item.ItemContent.TweetResults != nil {
					tw, ok, err := item.Item.ItemContent.TweetResults.tweet()
					if err != nil {
						return TweetPage{}, err
					}
					if ok {
						page.Tweets = append(page.Tweets, tw)
					}
				}
			}
		}
	}

	return page, nil
}

// parseUserPage extracts users and cursor from a timeline instruction response.
func parseUserPage(raw json.RawMessage, timelineKey string) (UserPage, error) {
	instructions, err := extractInstructions(raw, timelineKey)
	if err != nil {
		return UserPage{}, err
	}

	var page UserPage
	for _, inst := range instructions {
		entries := inst.Entries
		if inst.Entry != nil {
			entries = append(entries, *inst.Entry)
		}
		for _, entry := range entries {
			if user, ok := extractUserFromEntry(entry); ok {
				if user.ID != "" {
					page.Users = append(page.Users, user)
				}
			}
			if entry.Content.CursorType == "Bottom" && entry.Content.Value != "" {
				page.NextCursor = entry.Content.Value
				page.HasNext = true
			}
		}
	}

	return page, nil
}

func extractTweetFromEntry(entry timelineEntry) (Tweet, bool, error) {
	ic := entry.Content.ItemContent
	if ic == nil || ic.TweetResults == nil {
		return Tweet{}, false, nil
	}
	return ic.TweetResults.tweet()
}

func extractUserFromEntry(entry timelineEntry) (User, bool) {
	ic := entry.Content.ItemContent
	if ic == nil || ic.UserResults == nil {
		return User{}, false
	}
	return toUser(ic.UserResults.Result), true
}

// extractInstructions navigates the nested JSON to reach the timeline
// instructions array. The timelineKey uses dot-separated path segments.
func extractInstructions(raw json.RawMessage, timelineKey string) ([]timelineInstruction, error) {
	current := raw
	parts := strings.Split(timelineKey, ".")

	for _, part := range parts {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(current, &m); err != nil {
			return nil, fmt.Errorf("%w: navigating to %q: %v", ErrRequestFailed, part, err)
		}
		next, ok := m[part]
		if !ok {
			return nil, fmt.Errorf("%w: key %q not found in response", ErrRequestFailed, part)
		}
		current = next
	}

	// Try nested timeline.instructions first, then direct instructions.
	// JSON unmarshal silently succeeds with zero values for missing keys,
	// so we must check if the result is non-empty before returning.
	var td timelineData
	if err := json.Unmarshal(current, &td); err == nil && len(td.Timeline.Instructions) > 0 {
		return td.Timeline.Instructions, nil
	}

	var direct struct {
		Instructions []timelineInstruction `json:"instructions"`
	}
	if err := json.Unmarshal(current, &direct); err != nil {
		return nil, fmt.Errorf("%w: decoding timeline instructions: %v", ErrRequestFailed, err)
	}
	return direct.Instructions, nil
}
