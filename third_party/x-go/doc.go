// Package x provides a Go client for X (formerly Twitter) internal APIs.
//
// It covers reads (timelines, search, trends, profiles, followers, lists,
// bookmarks) and writes (tweets, replies, retweets, likes, follows, DMs).
//
// No API keys, no developer-app registration, zero dependencies.
// Authenticate with session cookies from a logged-in browser session.
//
// Quick start (reads):
//
//	c, err := x.New(x.Cookies{
//		AuthToken: "9220b5d6a5926...",
//		CT0:       "a1e823788453...",
//	})
//
//	timeline, err := c.HomeTimeline(ctx, 20)
//	results, err := c.SearchTweets(ctx, "golang", 20)
//	profile, err := c.GetProfile(ctx, "elonmusk")
//	followers, err := c.GetFollowers(ctx, userID, 20)
//
// Quick start (writes):
//
//	tweet, err := c.CreateTweet(ctx, "Hello from x-go!")
//	err = c.Reply(ctx, tweetID, "Great thread!")
//	err = c.Like(ctx, tweetID)
//	err = c.Retweet(ctx, tweetID)
//	err = c.Follow(ctx, userID)
//	err = c.SendDM(ctx, conversationID, "Hey!")
package x
