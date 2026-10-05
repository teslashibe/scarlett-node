package x

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Session is the canonical cookie-authenticated X connection. AuthToken and
// CT0 are required; the remaining fields preserve browser and proxy affinity.
type Session struct {
	AuthToken string `json:"auth_token"`
	CT0       string `json:"ct0"`
	Twid      string `json:"twid,omitempty"`
	KDT       string `json:"kdt,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Proxy     string `json:"proxy,omitempty"`
}

// String prevents credentials and authenticated proxy URLs from leaking
// through logs that format a Session value.
func (Session) String() string { return "x.Session{credentials:redacted}" }

// GoString prevents credentials from leaking through %#v formatting.
func (Session) GoString() string { return "x.Session{credentials:redacted}" }

// LogValue prevents structured slog records from reflecting exported secrets.
func (Session) LogValue() slog.Value {
	return slog.StringValue("x.Session{credentials:redacted}")
}

// Validate checks the session without exposing credential values.
func (s Session) Validate() error {
	if strings.TrimSpace(s.AuthToken) == "" || strings.TrimSpace(s.CT0) == "" {
		return ErrInvalidAuth
	}
	if s.Proxy != "" {
		u, err := url.Parse(s.Proxy)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("%w: invalid proxy URL", ErrInvalidParams)
		}
	}
	return nil
}

// NewClient constructs and validates a client using this session.
func (s Session) NewClient(ctx context.Context, opts ...Option) (*Client, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if s.UserAgent != "" {
		opts = append(opts, WithUserAgent(s.UserAgent))
	}
	if s.Proxy != "" {
		opts = append(opts, WithProxy(s.Proxy))
	}
	return NewWithContext(ctx, Cookies{
		AuthToken: s.AuthToken,
		CT0:       s.CT0,
		Twid:      s.Twid,
		KDT:       s.KDT,
	}, opts...)
}

// validateSession calls the Viewer query to verify auth, then fetches the
// full profile via UserByRestId to populate all fields.
func (c *Client) validateSession(ctx context.Context) error {
	vars := map[string]interface{}{
		"withCommunitiesMemberships": true,
		"withSubscribedTab":          true,
		"withCommunitiesCreation":    true,
	}

	raw, err := c.graphqlGET(ctx, "Viewer", vars)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("x: session validation failed: %w", err)
	}

	var data struct {
		Viewer struct {
			UserResults struct {
				Result struct {
					RestID string `json:"rest_id"`
				} `json:"result"`
			} `json:"user_results"`
		} `json:"viewer"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("%w: invalid viewer response", ErrRequestFailed)
	}

	viewerID := data.Viewer.UserResults.Result.RestID
	if viewerID == "" {
		return fmt.Errorf("%w: viewer identity missing", ErrRequestFailed)
	}

	if c.restID != "" && c.restID != viewerID {
		return fmt.Errorf("%w: viewer identity does not match session", ErrRequestFailed)
	}
	c.restID = viewerID

	// Fetch full profile — the Viewer query only returns partial fields.
	profileVars := map[string]interface{}{
		"userId":                   viewerID,
		"withSafetyModeUserFields": true,
	}
	profileRaw, err := c.graphqlGET(ctx, "UserByRestId", profileVars)
	if err != nil {
		// Auth is valid (Viewer succeeded); cache a minimal User.
		c.viewer = &User{ID: viewerID}
		return nil
	}

	var profileData struct {
		User struct {
			Result userObj `json:"result"`
		} `json:"user"`
	}
	if err := json.Unmarshal(profileRaw, &profileData); err != nil {
		c.viewer = &User{ID: viewerID}
		return nil
	}

	u := toUser(profileData.User.Result)
	c.viewer = &u
	return nil
}

// Regex patterns for extracting queryIDs from X's main.js bundle.
var (
	reMainJS  = regexp.MustCompile(`"([^"]*main\.[a-f0-9]+[a-z]\.js)"`)
	reQueryID = regexp.MustCompile(`\{queryId:"([^"]+)",operationName:"([^"]+)",operationType:"([^"]+)"`)
)

// RefreshQueryIDs fetches the current main.js bundle from x.com and extracts
// all queryId/operationName pairs, updating the client's queryIDs map under
// a write lock.
func (c *Client) RefreshQueryIDs(ctx context.Context) error {
	htmlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return fmt.Errorf("%w: building HTML request: %v", ErrRequestFailed, err)
	}
	htmlReq.Header.Set("User-Agent", c.userAgent)
	htmlReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	htmlResp, err := c.httpClient.Do(htmlReq)
	if err != nil {
		return fmt.Errorf("%w: fetching x.com: %v", ErrRequestFailed, err)
	}
	defer htmlResp.Body.Close()

	htmlBody, err := io.ReadAll(io.LimitReader(htmlResp.Body, maxResponseBody))
	if err != nil {
		return fmt.Errorf("%w: reading HTML: %v", ErrRequestFailed, err)
	}

	matches := reMainJS.FindSubmatch(htmlBody)
	if matches == nil {
		return fmt.Errorf("%w: could not find main.js URL in page source", ErrRequestFailed)
	}

	jsURL := string(matches[1])
	if strings.HasPrefix(jsURL, "//") {
		jsURL = "https:" + jsURL
	} else if jsURL != "" && jsURL[0] == '/' {
		jsURL = baseURL + jsURL
	}

	jsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, jsURL, nil)
	if err != nil {
		return fmt.Errorf("%w: building JS request: %v", ErrRequestFailed, err)
	}
	jsReq.Header.Set("User-Agent", c.userAgent)

	jsResp, err := c.httpClient.Do(jsReq)
	if err != nil {
		return fmt.Errorf("%w: fetching main.js: %v", ErrRequestFailed, err)
	}
	defer jsResp.Body.Close()

	const maxJSBody = 5 << 20 // 5 MB — main.js is typically ~3 MB
	jsBody, err := io.ReadAll(io.LimitReader(jsResp.Body, maxJSBody))
	if err != nil {
		return fmt.Errorf("%w: reading main.js: %v", ErrRequestFailed, err)
	}

	found := reQueryID.FindAllSubmatch(jsBody, -1)
	if len(found) == 0 {
		return fmt.Errorf("%w: no queryIds found in main.js", ErrRequestFailed)
	}

	c.reqMu.Lock()
	for _, m := range found {
		opName := string(m[2])
		qid := string(m[1])
		c.queryIDs[opName] = qid
	}
	c.queryIDsRefreshed = true
	c.reqMu.Unlock()

	return nil
}
