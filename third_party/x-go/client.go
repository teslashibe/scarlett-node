package x

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResponseBody = 10 << 20 // 10 MB

// graphqlGET executes an authenticated GraphQL GET request with retries.
func (c *Client) graphqlGET(ctx context.Context, operationName string, variables map[string]interface{}) (json.RawMessage, error) {
	qid := c.queryID(operationName)
	if qid == "" {
		return nil, fmt.Errorf("%w: no queryId registered for %q", ErrInvalidParams, operationName)
	}

	varsJSON, err := json.Marshal(variables)
	if err != nil {
		return nil, fmt.Errorf("%w: marshalling variables: %v", ErrInvalidParams, err)
	}

	featsJSON, err := json.Marshal(c.features)
	if err != nil {
		return nil, fmt.Errorf("%w: marshalling features: %v", ErrInvalidParams, err)
	}

	attempts := c.maxRetries
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			wait := retryWait(lastErr, c.retryBase, i)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}

		data, err := c.doGraphQLGET(ctx, qid, operationName, varsJSON, featsJSON)
		if err == nil {
			return data, nil
		}

		if isNonRetriable(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// graphqlPOST executes an authenticated GraphQL POST request with retries.
func (c *Client) graphqlPOST(ctx context.Context, operationName string, variables map[string]interface{}) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(errWriteNotAttempted, err)
	}
	qid := c.queryID(operationName)
	if qid == "" {
		return nil, fmt.Errorf("%w: no queryId registered for %q", ErrInvalidParams, operationName)
	}

	// Writes are never retried: after a transport failure the server outcome is
	// unknown, and retrying could publish duplicate content.
	return c.doGraphQLPOST(ctx, qid, operationName, variables)
}

// retryWait returns the duration to sleep before the next retry. If the
// previous error was a 429 with a Wait duration, uses that; otherwise
// falls back to exponential backoff.
func retryWait(lastErr error, base time.Duration, attempt int) time.Duration {
	var rle *RateLimitError
	if errors.As(lastErr, &rle) && rle.Wait > 0 {
		return rle.Wait
	}
	return base * time.Duration(math.Pow(2, float64(attempt-1)))
}

// doGraphQLGET performs a single GraphQL GET request.
func (c *Client) doGraphQLGET(ctx context.Context, qid, operationName string, varsJSON, featsJSON []byte) (json.RawMessage, error) {
	c.waitForGap(ctx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	endpoint := fmt.Sprintf("%s/%s/%s", graphqlBase, qid, operationName)
	params := url.Values{}
	params.Set("variables", string(varsJSON))
	params.Set("features", string(featsJSON))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %v", ErrRequestFailed, err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequestFailed, err)
	}
	defer resp.Body.Close()

	if err := c.checkStatus(resp); err != nil {
		return nil, c.operationError(operationName, req, resp, err)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body: %v", ErrRequestFailed, err)
	}

	return c.parseGQLResponse(body)
}

func (c *Client) operationError(operation string, req *http.Request, resp *http.Response, err error) error {
	return &OperationError{
		Operation:              operation,
		Status:                 resp.StatusCode,
		ContentType:            strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]),
		TransactionIDAttached:  req.Header.Get("X-Client-Transaction-Id") != "",
		TransactionReady:       c.TransactionReady(),
		QueryMetadataRefreshed: c.QueryMetadataRefreshed(),
		Err:                    err,
	}
}

// doGraphQLPOST performs a single GraphQL POST request.
func (c *Client) doGraphQLPOST(ctx context.Context, qid, operationName string, variables map[string]interface{}) (json.RawMessage, error) {
	c.waitForGap(ctx)
	if ctx.Err() != nil {
		return nil, errors.Join(errWriteNotAttempted, ctx.Err())
	}

	endpoint := fmt.Sprintf("%s/%s/%s", graphqlBase, qid, operationName)

	payload := map[string]interface{}{
		"variables": variables,
		"features":  c.features,
		"queryId":   qid,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: marshalling body: %v", ErrRequestFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %v", ErrRequestFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequestFailed, err)
	}
	defer resp.Body.Close()

	if err := c.checkStatus(resp); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body: %v", ErrRequestFailed, err)
	}

	return c.parseGQLResponse(body)
}

// restGET performs an authenticated REST API GET request.
func (c *Client) restGET(ctx context.Context, path string, params url.Values) (json.RawMessage, error) {
	c.waitForGap(ctx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	endpoint := baseURL + path
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %v", ErrRequestFailed, err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequestFailed, err)
	}
	defer resp.Body.Close()

	if err := c.checkStatus(resp); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body: %v", ErrRequestFailed, err)
	}

	return body, nil
}

// restPOST performs an authenticated REST API POST request.
func (c *Client) restPOST(ctx context.Context, path string, payload interface{}) (json.RawMessage, error) {
	c.waitForGap(ctx)
	if ctx.Err() != nil {
		return nil, errors.Join(errWriteNotAttempted, ctx.Err())
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: marshalling body: %v", ErrRequestFailed, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %v", ErrRequestFailed, err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequestFailed, err)
	}
	defer resp.Body.Close()

	if err := c.checkStatus(resp); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body: %v", ErrRequestFailed, err)
	}

	return body, nil
}

// restFormPOST performs an authenticated form-encoded POST to a REST endpoint.
func (c *Client) restFormPOST(ctx context.Context, path string, form url.Values) (json.RawMessage, error) {
	c.waitForGap(ctx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %v", ErrRequestFailed, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequestFailed, err)
	}
	defer resp.Body.Close()

	if err := c.checkStatus(resp); err != nil {
		return nil, err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("%w: reading body: %v", ErrRequestFailed, err)
	}

	return body, nil
}

// setHeaders sets all required auth and fingerprint headers on the request.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-Csrf-Token", c.cookies.CT0)
	req.Header.Set("X-Twitter-Active-User", "yes")
	req.Header.Set("X-Twitter-Auth-Type", "OAuth2Session")
	req.Header.Set("X-Twitter-Client-Language", "en")
	req.Header.Set("Referer", baseURL+"/")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Cookie", c.cookieHeader())
	if txID := c.generateTransactionID(req.Method, req.URL.Path); txID != "" {
		req.Header.Set("X-Client-Transaction-Id", txID)
	}
}

// cookieHeader builds the Cookie header value.
func (c *Client) cookieHeader() string {
	var b strings.Builder
	add := func(name, val string) {
		if val == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(val)
	}
	add("auth_token", c.cookies.AuthToken)
	add("ct0", c.cookies.CT0)
	add("twid", c.cookies.Twid)
	add("kdt", c.cookies.KDT)
	return b.String()
}

// queryID performs a thread-safe lookup of the queryId for a given operation.
func (c *Client) queryID(name string) string {
	c.reqMu.RLock()
	defer c.reqMu.RUnlock()
	return c.queryIDs[name]
}

// waitForGap enforces the leaky-bucket minimum request gap, adapting based
// on X's rate limit headers. When remaining requests are low, the gap widens
// automatically to spread requests across the remaining window.
func (c *Client) waitForGap(ctx context.Context) {
	gap := c.adaptiveGap()

	c.gapMu.Lock()
	now := time.Now()
	nextSlot := c.lastReqAt.Add(gap)
	if now.After(nextSlot) {
		nextSlot = now
	}
	c.lastReqAt = nextSlot
	c.gapMu.Unlock()

	if wait := time.Until(nextSlot); wait > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
	// Clear RetryAfter once we've waited past it.
	c.rlMu.Lock()
	c.rlState.RetryAfter = 0
	c.rlMu.Unlock()
}

// adaptiveGap returns the delay before the next request based on observed
// rate-limit state. Spreads requests across the window when quota is low;
// waits for reset when quota is exhausted.
func (c *Client) adaptiveGap() time.Duration {
	c.rlMu.Lock()
	rs := c.rlState
	c.rlMu.Unlock()

	// Quota exhausted — wait for the window to reset.
	if rs.Remaining == 0 && !rs.Reset.IsZero() {
		if d := time.Until(rs.Reset); d > 0 {
			return d + 50*time.Millisecond
		}
	}
	// Spread remaining quota evenly across the reset window (90% safety margin).
	if rs.Remaining > 0 && !rs.Reset.IsZero() {
		if d := time.Until(rs.Reset); d > 0 {
			slots := max(int64(float64(rs.Remaining)*0.9), 1)
			spread := d / time.Duration(slots)
			if spread > c.minGap {
				return spread
			}
		}
	}
	return c.minGap
}

// updateRateLimit reads rate-limit headers from a response and updates
// the client's tracked state. Call on every HTTP response.
func (c *Client) updateRateLimit(resp *http.Response) {
	h := resp.Header
	c.rlMu.Lock()
	defer c.rlMu.Unlock()
	if v := rlHeader(h, "Limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.rlState.Limit = n
		}
	}
	if v := rlHeader(h, "Remaining"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.rlState.Remaining = n
		}
	}
	if v := rlHeader(h, "Reset"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			if ts > 1_000_000_000 {
				c.rlState.Reset = time.Unix(ts, 0) // Unix epoch (Twitter/X style)
			} else {
				c.rlState.Reset = time.Now().Add(time.Duration(ts) * time.Second) // relative (Reddit style)
			}
		}
	}
}

// rlHeader returns the trimmed value of a rate-limit header, checking the four
// most common prefix variants.
func rlHeader(h http.Header, suffix string) string {
	for _, p := range []string{"X-RateLimit-", "X-Rate-Limit-", "X-Ratelimit-", "RateLimit-"} {
		if v := strings.TrimSpace(h.Get(p + suffix)); v != "" {
			return v
		}
	}
	return ""
}

// checkStatus maps HTTP status codes to sentinel errors.
// On non-OK responses, it drains the body so the TCP connection can be reused.
func (c *Client) checkStatus(resp *http.Response) error {
	c.updateRateLimit(resp)

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	// Read a bounded body snippet so 4xx/5xx surfaces X's reason instead of
	// a bare status code (DM new2 often returns useful JSON on 400).
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	snippet := truncate(strings.TrimSpace(string(body)), 400)
	if err := classifyRESTErrorBody(body); err != nil {
		return err
	}

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return ErrUnauthorized
	case resp.StatusCode == http.StatusForbidden:
		return ErrForbidden
	case resp.StatusCode == http.StatusNotFound:
		return ErrNotFound
	case resp.StatusCode == http.StatusTooManyRequests:
		wait := parseRetryAfter(resp.Header.Get("X-Rate-Limit-Reset"), 0)
		if wait == 0 {
			wait = parseRetryAfter(resp.Header.Get("Retry-After"), 60*time.Second)
		}
		c.rlMu.Lock()
		c.rlState.Remaining = 0
		c.rlState.RetryAfter = wait
		if c.rlState.Reset.IsZero() || time.Until(c.rlState.Reset) < wait {
			c.rlState.Reset = time.Now().Add(wait)
		}
		c.rlMu.Unlock()
		c.gapMu.Lock()
		if earliest := time.Now().Add(wait); c.lastReqAt.Before(earliest) {
			c.lastReqAt = earliest
		}
		c.gapMu.Unlock()
		return &RateLimitError{Wait: wait}
	case resp.StatusCode >= 500:
		if snippet != "" {
			return fmt.Errorf("%w: HTTP %d: %s", ErrRequestFailed, resp.StatusCode, snippet)
		}
		return fmt.Errorf("%w: HTTP %d", ErrRequestFailed, resp.StatusCode)
	default:
		if snippet != "" {
			return fmt.Errorf("%w: unexpected HTTP %d: %s", ErrRequestFailed, resp.StatusCode, snippet)
		}
		return fmt.Errorf("%w: unexpected HTTP %d", ErrRequestFailed, resp.StatusCode)
	}
}

// classifyRESTErrorBody maps known X REST error payloads to sentinels so
// callers (outbox, MCP) can show actionable failures instead of bare HTTP 400.
func classifyRESTErrorBody(body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var envelope struct {
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &envelope) != nil || len(envelope.Errors) == 0 {
		lower := strings.ToLower(string(body))
		switch {
		case strings.Contains(lower, "send a direct message"),
			strings.Contains(lower, "cannot send"), strings.Contains(lower, "not allowed to send"):
			return ErrDMClosed
		default:
			return nil
		}
	}
	first := envelope.Errors[0]
	msg := strings.ToLower(first.Message)
	switch {
	case first.Code == 32 || strings.Contains(msg, "not authenticated"):
		return ErrUnauthorized
	case first.Code == 88 || strings.Contains(msg, "rate limit"):
		return ErrRateLimited
	case first.Code == 349 || strings.Contains(msg, "send a direct message"),
		strings.Contains(msg, "cannot send"), strings.Contains(msg, "not allowed to send"):
		return ErrDMClosed
	case first.Code == 34 || strings.Contains(msg, "not found"):
		return ErrNotFound
	default:
		return nil
	}
}

// RateLimitError carries the retry-after duration from a 429 response.
// It wraps ErrRateLimited for errors.Is compatibility.
type RateLimitError struct {
	Wait time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("%s (retry after %s)", ErrRateLimited.Error(), e.Wait)
}

func (e *RateLimitError) Unwrap() error {
	return ErrRateLimited
}

// parseGQLResponse extracts the data field from a GraphQL response.
func (c *Client) parseGQLResponse(body []byte) (json.RawMessage, error) {
	var envelope gqlResponse
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("%w: decoding response: %v (snippet: %s)", ErrRequestFailed, err, truncate(string(body), 300))
	}

	if len(envelope.Errors) > 0 {
		first := envelope.Errors[0]
		msg := strings.ToLower(first.Message)
		switch {
		case strings.Contains(msg, "challenge") ||
			strings.Contains(msg, "verification required") ||
			strings.Contains(msg, "verify your identity"):
			return nil, ErrChallenge
		case first.Code == 32 || strings.Contains(msg, "not authenticated"):
			return nil, ErrUnauthorized
		case first.Code == 63 || strings.Contains(msg, "suspended"):
			return nil, ErrSuspended
		case first.Code == 34 || strings.Contains(msg, "not found"):
			return nil, ErrNotFound
		case first.Code == 88 || strings.Contains(msg, "rate limit"):
			return nil, ErrRateLimited
		case first.Code == 327 || strings.Contains(msg, "already retweeted"):
			return nil, ErrAlreadyRetweeted
		case first.Code == 349 || strings.Contains(msg, "send a direct message"):
			return nil, ErrDMClosed
		case strings.Contains(msg, "forbidden") || strings.Contains(msg, "not allowed"):
			return nil, ErrForbidden
		default:
			return nil, fmt.Errorf("%w: %s (code %d)", ErrRequestFailed, first.Message, first.Code)
		}
	}

	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, fmt.Errorf("%w: no data in response (snippet: %s)", ErrRequestFailed, truncate(string(body), 300))
	}

	return envelope.Data, nil
}

// parseRetryAfter parses rate-limit headers. Handles three formats:
// - Seconds integer (Retry-After: 60)
// - Unix epoch timestamp (X-Rate-Limit-Reset: 1716000000)
// - HTTP-date (Retry-After: Mon, 01 Jan 2024 00:00:00 GMT)
func parseRetryAfter(val string, fallback time.Duration) time.Duration {
	if val == "" {
		return fallback
	}
	trimmed := strings.TrimSpace(val)
	if n, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		if n > 1_000_000_000 {
			// Unix timestamp — compute duration until that time.
			if d := time.Until(time.Unix(n, 0)); d > 0 {
				return d
			}
			return fallback
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(trimmed); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return fallback
}

// isNonRetriable reports whether err should not be retried.
func isNonRetriable(err error) bool {
	return errors.Is(err, ErrInvalidAuth) ||
		errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrForbidden) ||
		errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrSuspended) ||
		errors.Is(err, ErrInvalidParams) ||
		errors.Is(err, ErrQueryIDStale)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
