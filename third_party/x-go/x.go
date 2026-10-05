package x

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	baseURL           = "https://x.com"
	graphqlBase       = "https://x.com/i/api/graphql"
	bearerToken       = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA"
	defaultUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
	defaultMinGap     = 1 * time.Second
	defaultMaxRetries = 3
	defaultRetryBase  = 500 * time.Millisecond
)

// Default queryIDs harvested from X's main.js bundle.
// These rotate with each deploy; override via WithQueryIDs.
var defaultQueryIDs = map[string]string{
	"HomeTimeline":             "Yf4WJo0fW46TnqrHUw_1Ow",
	"HomeLatestTimeline":       "hlno2aLQsxiQlOrK-a2V-w",
	"SearchTimeline":           "R0u1RWRf748KzyGBXvOYRA",
	"UserByScreenName":         "IGgvgiOx4QZndDHuD3x9TQ",
	"UserByRestId":             "VQfQ9wwYdk6j_u2O4vt64Q",
	"UserTweets":               "6fWQaBPK51aGyC_VC7t9GQ",
	"TweetDetail":              "tCivIG3o9ls-9cLxTsdxZQ",
	"TweetResultByRestId":      "fHLDP3qFEjnTqhWBVvsREg",
	"Followers":                "_wt2xR9Ozi8ZI7agzWf_bw",
	"Following":                "j4s0ZOO_DvhECpS-2U-SUA",
	"FollowersYouKnow":         "Iq5xmBUZ059hvTDUMkv1xA",
	"ListBySlug":               "LDQpQ89B5ipR8izCKrWU0g",
	"ListLatestTweetsTimeline": "EX6I_XpJSz1eZ2H9WsR4tA",
	"ListMembers":              "_7ye8v2J1nJQ6gX-Q4Fjng",
	"ListMemberships":          "asjMuAwNVSnmASqz-bJb8Q",
	"Viewer":                   "_8ClT24oZ8tpylf_OSuNdg",
	"CreateTweet":              "c50A_puUoQGK_4SXseYz3A",
	"CreateNoteTweet":          "iCUB42lIfXf9qPKctjE5rQ",
	"DeleteTweet":              "nxpZCY2K-I6QoFHAHeojFQ",
	"FavoriteTweet":            "lI07N6Otwv1PhnEgXILM7A",
	"UnfavoriteTweet":          "ZYKSe-w7KEslx3JhSIk5LA",
	"CreateRetweet":            "mbRO74GrOvSfRcJnlMapnQ",
	"DeleteRetweet":            "ZyZigVsNiFO6v1dEks1eWg",
	"CreateBookmark":           "aoDbu3RHznuiSkQ9aNM67Q",
	"DeleteBookmark":           "Wlmlj2-xzyS1GN3a6cj-mQ",
}

// defaultFeatures is the standard features map sent with every GraphQL request.
var defaultFeatures = map[string]bool{
	"rweb_tipjar_consumption_enabled":                                         true,
	"responsive_web_graphql_exclude_directive_enabled":                        true,
	"verified_phone_label_enabled":                                            false,
	"creator_subscriptions_tweet_preview_api_enabled":                         true,
	"responsive_web_graphql_timeline_navigation_enabled":                      true,
	"responsive_web_graphql_skip_user_profile_image_extensions_enabled":       false,
	"communities_web_enable_tweet_community_results_fetch":                    true,
	"c9s_tweet_anatomy_moderator_badge_enabled":                               true,
	"articles_preview_enabled":                                                true,
	"responsive_web_edit_tweet_api_enabled":                                   true,
	"graphql_is_translatable_rweb_tweet_is_translatable_enabled":              true,
	"view_counts_everywhere_api_enabled":                                      true,
	"longform_notetweets_consumption_enabled":                                 true,
	"responsive_web_twitter_article_tweet_consumption_enabled":                true,
	"tweet_awards_web_tipping_enabled":                                        false,
	"creator_subscriptions_quote_tweet_preview_enabled":                       false,
	"freedom_of_speech_not_reach_fetch_enabled":                               true,
	"standardized_nudges_misinfo":                                             true,
	"tweet_with_visibility_results_prefer_gql_limited_actions_policy_enabled": true,
	"tweet_with_visibility_results_prefer_gql_media_interstitial_enabled":     true,
	"rweb_video_timestamps_enabled":                                           true,
	"longform_notetweets_rich_text_read_enabled":                              true,
	"longform_notetweets_inline_media_enabled":                                true,
	"responsive_web_enhance_cards_enabled":                                    false,
	"hidden_profile_subscriptions_enabled":                                    true,
	"subscriptions_verification_info_is_identity_verified_enabled":            true,
	"subscriptions_verification_info_verified_since_enabled":                  true,
	"highlights_tweets_tab_ui_enabled":                                        true,
	"responsive_web_twitter_article_notes_tab_enabled":                        true,
	"subscriptions_feature_can_gift_premium":                                  true,
	"profile_label_improvements_pcf_label_in_post_enabled":                    true,
	"rweb_video_screen_enabled":                                               false,
	"responsive_web_profile_redirect_enabled":                                 false,
	"premium_content_api_read_enabled":                                        false,
	"responsive_web_grok_analyze_button_fetch_trends_enabled":                 false,
	"responsive_web_grok_analyze_post_followups_enabled":                      false,
	"responsive_web_grok_share_attachment_enabled":                            true,
	"responsive_web_grok_annotations_enabled":                                 true,
	"responsive_web_jetfuel_frame":                                            true,
	"content_disclosure_indicator_enabled":                                    true,
	"content_disclosure_ai_generated_indicator_enabled":                       true,
}

// Client is an X API client. It is safe for concurrent use.
type Client struct {
	cookies           Cookies
	restID            string
	httpClient        *http.Client
	userAgent         string
	queryIDs          map[string]string
	features          map[string]bool
	maxRetries        int
	retryBase         time.Duration
	minGap            time.Duration
	gapMu             sync.Mutex
	lastReqAt         time.Time
	reqMu             sync.RWMutex // protects queryIDs
	queryIDsRefreshed bool
	rlMu              sync.Mutex
	rlState           RateLimitState
	viewer            *User
	txState           transactionState
	txInitErr         error // non-nil if initTransaction failed; Followers/Search may 404
}

// Option configures a Client.
type Option func(*Client)

// WithUserAgent overrides the default Chrome User-Agent string.
func WithUserAgent(ua string) Option {
	return func(c *Client) { c.userAgent = ua }
}

// WithQueryIDs overrides one or more GraphQL queryIds.
func WithQueryIDs(overrides map[string]string) Option {
	return func(c *Client) {
		for k, v := range overrides {
			c.queryIDs[k] = v
		}
	}
}

// WithFeatures overrides one or more GraphQL feature flags.
func WithFeatures(overrides map[string]bool) Option {
	return func(c *Client) {
		for k, v := range overrides {
			c.features[k] = v
		}
	}
}

// WithRetry configures retry behaviour.
// Default: 3 attempts, 500ms exponential base.
func WithRetry(maxAttempts int, base time.Duration) Option {
	return func(c *Client) {
		c.maxRetries = maxAttempts
		c.retryBase = base
	}
}

// WithHTTPClient replaces the default http.Client. Nil is ignored.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// WithProxy routes all HTTP traffic through the given proxy URL.
func WithProxy(proxyURL string) Option {
	return func(c *Client) {
		parsed, err := url.Parse(proxyURL)
		if err != nil {
			return
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = http.ProxyURL(parsed)
		c.httpClient = &http.Client{
			Timeout:   c.httpClient.Timeout,
			Transport: transport,
		}
	}
}

// WithMinRequestGap sets the minimum time between consecutive requests.
// Default: 1s. Lower values risk triggering X's rate limiter.
func WithMinRequestGap(d time.Duration) Option {
	return func(c *Client) { c.minGap = d }
}

// New creates a Client and validates the session via the Viewer query.
// Returns ErrInvalidAuth if AuthToken or CT0 is empty.
func New(cookies Cookies, opts ...Option) (*Client, error) {
	return NewWithContext(context.Background(), cookies, opts...)
}

// NewWithContext creates a Client and bounds session validation and
// transaction bootstrap with ctx.
func NewWithContext(ctx context.Context, cookies Cookies, opts ...Option) (*Client, error) {
	if cookies.AuthToken == "" || cookies.CT0 == "" {
		return nil, fmt.Errorf("%w: AuthToken and CT0 must both be non-empty", ErrInvalidAuth)
	}

	restID := parseRestID(cookies.Twid)

	qids := make(map[string]string, len(defaultQueryIDs))
	for k, v := range defaultQueryIDs {
		qids[k] = v
	}

	feats := make(map[string]bool, len(defaultFeatures))
	for k, v := range defaultFeatures {
		feats[k] = v
	}

	c := &Client{
		cookies:    cookies,
		restID:     restID,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		userAgent:  defaultUserAgent,
		queryIDs:   qids,
		features:   feats,
		maxRetries: defaultMaxRetries,
		retryBase:  defaultRetryBase,
		minGap:     defaultMinGap,
	}

	for _, o := range opts {
		o(c)
	}

	if err := c.validateSession(ctx); err != nil {
		return nil, err
	}

	c.txInitErr = c.initTransaction(ctx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	return c, nil
}

// RateLimit returns a snapshot of the most recently observed rate-limit state.
// Use RateLimitState.IsLimited() to check if the client is currently throttled.
func (c *Client) RateLimit() RateLimitState {
	c.rlMu.Lock()
	defer c.rlMu.Unlock()
	return c.rlState
}

// TransactionInitErr returns the error from X-Client-Transaction-Id bootstrap,
// if any. A non-nil value means transaction headers are unavailable; provider
// endpoints may reject requests. Session validation does not prove readiness.
func (c *Client) TransactionInitErr() error {
	return c.txInitErr
}

// TransactionReady reports whether requests can carry X's transaction header.
func (c *Client) TransactionReady() bool { return c.txState.initialized }

// QueryMetadataRefreshed reports whether this client successfully refreshed
// GraphQL operation metadata after construction.
func (c *Client) QueryMetadataRefreshed() bool {
	c.reqMu.RLock()
	defer c.reqMu.RUnlock()
	return c.queryIDsRefreshed
}

// Me returns the authenticated user's profile.
func (c *Client) Me(ctx context.Context) (*User, error) {
	if c.viewer != nil {
		return c.viewer, nil
	}
	return nil, ErrUnauthorized
}

// parseRestID extracts the numeric user ID from the twid cookie value.
// The twid cookie is URL-encoded and has the format "u=<restId>".
func parseRestID(twid string) string {
	if twid == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(twid)
	if err != nil {
		decoded = twid
	}
	if strings.HasPrefix(decoded, "u=") {
		return decoded[2:]
	}
	return decoded
}
