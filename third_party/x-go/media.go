package x

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// uploadBase is the browser/web upload host used with cookie sessions.
	// The official api.x.com/2/media/upload path requires OAuth bearer
	// tokens, which this cookie-based client does not have.
	uploadBase = "https://upload.twitter.com"

	// maxImageUploadBytes bounds static image uploads (X's image limit is 5 MiB).
	maxImageUploadBytes = 5 << 20

	// maxGifUploadBytes bounds animated GIF uploads (X allows up to 15 MiB).
	maxGifUploadBytes = 15 << 20

	// maxMediaFetchBytes is the ceiling for a UploadMediaFromURL source fetch;
	// per-type limits are enforced after the type is known.
	maxMediaFetchBytes = maxGifUploadBytes

	// mediaFetchTimeout bounds a UploadMediaFromURL source fetch.
	mediaFetchTimeout = 30 * time.Second
)

// supportedImageTypes maps accepted image MIME types to X media categories.
var supportedImageTypes = map[string]string{
	"image/png":  "tweet_image",
	"image/jpeg": "tweet_image",
	"image/webp": "tweet_image",
	"image/gif":  "tweet_gif",
}

// maxUploadBytesForType returns the X size limit for a supported media type.
func maxUploadBytesForType(mimeType string) int {
	if mimeType == "image/gif" {
		return maxGifUploadBytes
	}
	return maxImageUploadBytes
}

// mediaOptions configures a media upload.
type mediaOptions struct {
	altText string
	// maxVideoBytes optionally lowers the video size ceiling (see WithMaxVideoBytes).
	maxVideoBytes int64
}

// MediaOption configures UploadMedia / UploadMediaFromURL.
type MediaOption func(*mediaOptions)

// WithAltText attaches accessibility alt text to the uploaded media via
// media/metadata/create after the upload completes.
func WithAltText(text string) MediaOption {
	return func(o *mediaOptions) { o.altText = text }
}

func applyMediaOpts(opts []MediaOption) *mediaOptions {
	o := &mediaOptions{}
	for _, opt := range opts {
		opt(o)
	}
	return o
}

// normalizeMediaType lowercases and strips any parameters (e.g. charset)
// from a MIME type string.
func normalizeMediaType(mime string) string {
	mime = strings.ToLower(strings.TrimSpace(mime))
	if i := strings.IndexByte(mime, ';'); i >= 0 {
		mime = strings.TrimSpace(mime[:i])
	}
	return mime
}

// UploadMedia uploads image bytes to X and returns the media_id_string,
// using the client's cookie auth. Supported types: PNG, JPEG, WebP, GIF.
// Optional alt text is applied via WithAltText.
func (c *Client) UploadMedia(ctx context.Context, data []byte, mimeType string, opts ...MediaOption) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("%w: empty media payload", ErrInvalidParams)
	}
	mimeType = normalizeMediaType(mimeType)
	// Sniff the type when the caller omits it (e.g. base64 without mime_type).
	if _, ok := supportedImageTypes[mimeType]; !ok {
		mimeType = normalizeMediaType(http.DetectContentType(data))
	}
	category, ok := supportedImageTypes[mimeType]
	if !ok {
		return "", fmt.Errorf("%w: %q (supported: png, jpeg, webp, gif)", ErrUnsupportedMediaType, mimeType)
	}
	if limit := maxUploadBytesForType(mimeType); len(data) > limit {
		return "", fmt.Errorf("%w: %d bytes (max %d)", ErrMediaTooLarge, len(data), limit)
	}

	o := applyMediaOpts(opts)

	mediaID, err := c.uploadSimple(ctx, data, mimeType, category)
	if err != nil {
		return "", err
	}

	if o.altText != "" {
		// Alt text is best-effort: the media is already uploaded, so a
		// metadata failure must not discard a usable media_id (which would
		// force a duplicate re-upload). Report it via the returned error
		// while still surfacing the id.
		if err := c.createMediaMetadata(ctx, mediaID, o.altText); err != nil {
			return mediaID, fmt.Errorf("media uploaded (id %s) but alt text failed: %w", mediaID, err)
		}
	}
	return mediaID, nil
}

// UploadMediaFromURL fetches an image from url (bounded size + timeout) and
// delegates to UploadMedia. The MIME type is taken from the response
// Content-Type, falling back to content sniffing.
func (c *Client) UploadMediaFromURL(ctx context.Context, mediaURL string, opts ...MediaOption) (string, error) {
	if strings.TrimSpace(mediaURL) == "" {
		return "", fmt.Errorf("%w: empty media URL", ErrInvalidParams)
	}

	fetchCtx, cancel := context.WithTimeout(ctx, mediaFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, mediaURL, nil)
	if err != nil {
		return "", fmt.Errorf("%w: building media fetch request: %v", ErrInvalidParams, err)
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: fetching media URL: %v", ErrRequestFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: fetching media URL: HTTP %d", ErrRequestFailed, resp.StatusCode)
	}

	// Read one extra byte so we can detect an over-limit body. The per-type
	// cap (image vs GIF) is enforced by UploadMedia once the type is known.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMediaFetchBytes+1))
	if err != nil {
		return "", fmt.Errorf("%w: reading media body: %v", ErrRequestFailed, err)
	}
	if len(data) > maxMediaFetchBytes {
		return "", fmt.Errorf("%w: source exceeds max %d bytes", ErrMediaTooLarge, maxMediaFetchBytes)
	}

	mimeType := normalizeMediaType(resp.Header.Get("Content-Type"))
	if _, ok := supportedImageTypes[mimeType]; !ok {
		mimeType = normalizeMediaType(http.DetectContentType(data))
	}

	return c.UploadMedia(ctx, data, mimeType, opts...)
}

// uploadSimple performs the single-request image upload and returns the
// media_id_string from the response.
func (c *Client) uploadSimple(ctx context.Context, data []byte, mimeType, category string) (string, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("media_category", category); err != nil {
		return "", fmt.Errorf("%w: writing multipart field: %v", ErrRequestFailed, err)
	}
	if err := w.WriteField("media_type", mimeType); err != nil {
		return "", fmt.Errorf("%w: writing multipart field: %v", ErrRequestFailed, err)
	}
	part, err := w.CreateFormField("media")
	if err != nil {
		return "", fmt.Errorf("%w: creating multipart part: %v", ErrRequestFailed, err)
	}
	if _, err := part.Write(data); err != nil {
		return "", fmt.Errorf("%w: writing media bytes: %v", ErrRequestFailed, err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("%w: closing multipart writer: %v", ErrRequestFailed, err)
	}

	respBody, err := c.uploadPOST(ctx, "/i/media/upload.json", w.FormDataContentType(), body.Bytes())
	if err != nil {
		return "", err
	}

	var out struct {
		MediaIDString string `json:"media_id_string"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("%w: decoding upload response: %v", ErrRequestFailed, err)
	}
	if out.MediaIDString == "" {
		return "", fmt.Errorf("%w: upload returned empty media_id", ErrRequestFailed)
	}
	return out.MediaIDString, nil
}

// createMediaMetadata attaches alt text to an uploaded media_id.
func (c *Client) createMediaMetadata(ctx context.Context, mediaID, altText string) error {
	payload := map[string]any{
		"media_id": mediaID,
		"alt_text": map[string]string{"text": altText},
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%w: marshalling metadata: %v", ErrRequestFailed, err)
	}
	_, err = c.uploadPOST(ctx, "/1.1/media/metadata/create.json", "application/json", bodyBytes)
	return err
}

// uploadPOST performs an authenticated POST to the media upload host and
// returns the raw response body. It applies cookie/CSRF auth headers and
// maps non-2xx statuses to typed errors without leaking credentials.
func (c *Client) uploadPOST(ctx context.Context, path, contentType string, body []byte) (json.RawMessage, error) {
	c.waitForGap(ctx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadBase+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: building upload request: %v", ErrRequestFailed, err)
	}
	req.Header.Set("Content-Type", contentType)
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRequestFailed, err)
	}
	defer resp.Body.Close()

	// Chunked APPEND replies with 204 No Content on success; accept it
	// without routing an empty body through checkStatus (which treats
	// non-200 as an error).
	if resp.StatusCode == http.StatusNoContent {
		c.updateRateLimit(resp)
		return nil, nil
	}

	if err := c.checkStatus(resp); err != nil {
		return nil, err
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("%w: reading upload body: %v", ErrRequestFailed, err)
	}
	return respBody, nil
}

// uploadGET performs an authenticated GET to the media upload host (used for
// the chunked-upload STATUS command) and returns the raw response body.
func (c *Client) uploadGET(ctx context.Context, path string, query url.Values) (json.RawMessage, error) {
	c.waitForGap(ctx)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	u := uploadBase + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building upload request: %v", ErrRequestFailed, err)
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

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("%w: reading upload body: %v", ErrRequestFailed, err)
	}
	return respBody, nil
}
