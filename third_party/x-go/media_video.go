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
	"strconv"
	"strings"
	"time"
)

const (
	// maxVideoUploadBytes bounds video uploads. X's async video limit is
	// 512 MiB; callers can lower it with WithMaxVideoBytes.
	maxVideoUploadBytes = 512 << 20

	// uploadChunkBytes is the APPEND segment size. X caps a single APPEND
	// media chunk at 5 MiB; 4 MiB keeps a margin for multipart overhead.
	uploadChunkBytes = 4 << 20

	// videoProcessMaxWait bounds the total STATUS poll window after FINALIZE.
	videoProcessMaxWait = 5 * time.Minute

	// videoProcessPollDefault is used when X omits check_after_secs.
	videoProcessPollDefault = 2 * time.Second

	// videoProcessPollMax caps a single backoff interval between polls.
	videoProcessPollMax = 15 * time.Second
)

// supportedVideoTypes maps accepted video MIME types to X media categories.
var supportedVideoTypes = map[string]string{
	"video/mp4":       "tweet_video",
	"video/quicktime": "tweet_video",
}

// WithMaxVideoBytes lowers the accepted video size ceiling (default 512 MiB).
// Values <= 0 or above the default are clamped to the default.
func WithMaxVideoBytes(n int64) MediaOption {
	return func(o *mediaOptions) { o.maxVideoBytes = n }
}

// processingInfo mirrors X's async media processing_info payload.
type processingInfo struct {
	State           string `json:"state"`
	CheckAfterSecs  int    `json:"check_after_secs"`
	ProgressPercent int    `json:"progress_percent"`
	Error           *struct {
		Code    int    `json:"code"`
		Name    string `json:"name"`
		Message string `json:"message"`
	} `json:"error"`
}

// UploadVideo uploads a video via X's chunked media upload (INIT -> APPEND ->
// FINALIZE) and polls processing_info until the media is usable, returning the
// media_id_string. The reader is streamed in bounded chunks so the whole file
// is never buffered in memory. totalBytes must be the exact source length.
// Supported types: video/mp4, video/quicktime. Optional alt text via WithAltText.
func (c *Client) UploadVideo(ctx context.Context, r io.Reader, mimeType string, totalBytes int64, opts ...MediaOption) (string, error) {
	if r == nil {
		return "", fmt.Errorf("%w: nil video reader", ErrInvalidParams)
	}
	mimeType = normalizeMediaType(mimeType)
	category, ok := supportedVideoTypes[mimeType]
	if !ok {
		return "", fmt.Errorf("%w: %q (supported: mp4, quicktime)", ErrUnsupportedMediaType, mimeType)
	}
	if totalBytes <= 0 {
		return "", fmt.Errorf("%w: video size must be > 0", ErrInvalidParams)
	}

	o := applyMediaOpts(opts)
	limit := int64(maxVideoUploadBytes)
	if o.maxVideoBytes > 0 && o.maxVideoBytes < limit {
		limit = o.maxVideoBytes
	}
	if totalBytes > limit {
		return "", fmt.Errorf("%w: %d bytes (max %d)", ErrMediaTooLarge, totalBytes, limit)
	}

	mediaID, err := c.videoInit(ctx, totalBytes, mimeType, category)
	if err != nil {
		return "", err
	}

	if err := c.videoAppend(ctx, mediaID, r, totalBytes); err != nil {
		return "", err
	}

	info, err := c.videoFinalize(ctx, mediaID)
	if err != nil {
		return "", err
	}

	if err := c.pollVideoProcessing(ctx, mediaID, info); err != nil {
		return "", err
	}

	if o.altText != "" {
		if err := c.createMediaMetadata(ctx, mediaID, o.altText); err != nil {
			return mediaID, fmt.Errorf("video uploaded (id %s) but alt text failed: %w", mediaID, err)
		}
	}
	return mediaID, nil
}

// UploadVideoFromURL fetches a video from url and streams it into the chunked
// upload without buffering the whole file. The source must advertise a
// Content-Length and a supported video Content-Type (mp4/quicktime); an
// explicit mimeType overrides the response header when non-empty.
func (c *Client) UploadVideoFromURL(ctx context.Context, mediaURL, mimeType string, opts ...MediaOption) (string, error) {
	if strings.TrimSpace(mediaURL) == "" {
		return "", fmt.Errorf("%w: empty media URL", ErrInvalidParams)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mediaURL, nil)
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
	if resp.ContentLength <= 0 {
		return "", fmt.Errorf("%w: source did not report a Content-Length for the video", ErrInvalidParams)
	}

	if strings.TrimSpace(mimeType) == "" {
		mimeType = resp.Header.Get("Content-Type")
	}
	return c.UploadVideo(ctx, resp.Body, mimeType, resp.ContentLength, opts...)
}

// videoInit performs the INIT command and returns the allocated media_id.
func (c *Client) videoInit(ctx context.Context, totalBytes int64, mimeType, category string) (string, error) {
	form := url.Values{
		"command":        {"INIT"},
		"total_bytes":    {strconv.FormatInt(totalBytes, 10)},
		"media_type":     {mimeType},
		"media_category": {category},
	}
	respBody, err := c.uploadPOST(ctx, "/i/media/upload.json", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		return "", err
	}
	var out struct {
		MediaIDString string `json:"media_id_string"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("%w: decoding INIT response: %v", ErrRequestFailed, err)
	}
	if out.MediaIDString == "" {
		return "", fmt.Errorf("%w: INIT returned empty media_id", ErrRequestFailed)
	}
	return out.MediaIDString, nil
}

// videoAppend streams the reader to X in ordered APPEND segments.
func (c *Client) videoAppend(ctx context.Context, mediaID string, r io.Reader, totalBytes int64) error {
	buf := make([]byte, uploadChunkBytes)
	var (
		segment int
		read    int64
	)
	for {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			read += int64(n)
			if read > totalBytes {
				return fmt.Errorf("%w: source larger than declared %d bytes", ErrInvalidParams, totalBytes)
			}
			if aerr := c.videoAppendChunk(ctx, mediaID, segment, buf[:n]); aerr != nil {
				return aerr
			}
			segment++
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: reading video chunk: %v", ErrRequestFailed, err)
		}
	}
	if read != totalBytes {
		return fmt.Errorf("%w: read %d bytes, declared %d", ErrInvalidParams, read, totalBytes)
	}
	if segment == 0 {
		return fmt.Errorf("%w: empty video payload", ErrInvalidParams)
	}
	return nil
}

// videoAppendChunk uploads a single APPEND segment.
func (c *Client) videoAppendChunk(ctx context.Context, mediaID string, segment int, chunk []byte) error {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("command", "APPEND"); err != nil {
		return fmt.Errorf("%w: writing APPEND field: %v", ErrRequestFailed, err)
	}
	if err := w.WriteField("media_id", mediaID); err != nil {
		return fmt.Errorf("%w: writing APPEND field: %v", ErrRequestFailed, err)
	}
	if err := w.WriteField("segment_index", strconv.Itoa(segment)); err != nil {
		return fmt.Errorf("%w: writing APPEND field: %v", ErrRequestFailed, err)
	}
	part, err := w.CreateFormField("media")
	if err != nil {
		return fmt.Errorf("%w: creating APPEND part: %v", ErrRequestFailed, err)
	}
	if _, err := part.Write(chunk); err != nil {
		return fmt.Errorf("%w: writing APPEND bytes: %v", ErrRequestFailed, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("%w: closing APPEND writer: %v", ErrRequestFailed, err)
	}
	_, err = c.uploadPOST(ctx, "/i/media/upload.json", w.FormDataContentType(), body.Bytes())
	return err
}

// videoFinalize performs FINALIZE and returns any processing_info X reports.
func (c *Client) videoFinalize(ctx context.Context, mediaID string) (*processingInfo, error) {
	form := url.Values{
		"command":  {"FINALIZE"},
		"media_id": {mediaID},
	}
	respBody, err := c.uploadPOST(ctx, "/i/media/upload.json", "application/x-www-form-urlencoded", []byte(form.Encode()))
	if err != nil {
		return nil, err
	}
	var out struct {
		ProcessingInfo *processingInfo `json:"processing_info"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("%w: decoding FINALIZE response: %v", ErrRequestFailed, err)
	}
	return out.ProcessingInfo, nil
}

// pollVideoProcessing blocks until processing succeeds, fails, times out, or
// ctx is cancelled. A nil/empty/succeeded state returns immediately.
func (c *Client) pollVideoProcessing(ctx context.Context, mediaID string, info *processingInfo) error {
	deadline := time.Now().Add(videoProcessMaxWait)
	for {
		// A nil processing_info (FINALIZE returned none) or a succeeded/empty
		// state means the media is usable without further polling.
		if info == nil {
			return nil
		}
		switch info.State {
		case "", "succeeded":
			return nil
		case "failed":
			return videoProcessingError(info)
		}
		wait := videoProcessPollDefault
		if info != nil && info.CheckAfterSecs > 0 {
			wait = time.Duration(info.CheckAfterSecs) * time.Second
		}
		if wait > videoProcessPollMax {
			wait = videoProcessPollMax
		}
		if time.Now().Add(wait).After(deadline) {
			return fmt.Errorf("%w: media %s still processing after %s", ErrMediaProcessingTimeout, mediaID, videoProcessMaxWait)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}

		next, err := c.videoStatus(ctx, mediaID)
		if err != nil {
			return err
		}
		info = next
	}
}

// videoStatus performs the STATUS command GET and returns processing_info.
func (c *Client) videoStatus(ctx context.Context, mediaID string) (*processingInfo, error) {
	q := url.Values{
		"command":  {"STATUS"},
		"media_id": {mediaID},
	}
	respBody, err := c.uploadGET(ctx, "/i/media/upload.json", q)
	if err != nil {
		return nil, err
	}
	var out struct {
		ProcessingInfo *processingInfo `json:"processing_info"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("%w: decoding STATUS response: %v", ErrRequestFailed, err)
	}
	// A missing processing_info at STATUS time means processing is complete.
	if out.ProcessingInfo == nil {
		return &processingInfo{State: "succeeded"}, nil
	}
	return out.ProcessingInfo, nil
}

// videoProcessingError builds a typed error from a failed processing_info.
func videoProcessingError(info *processingInfo) error {
	if info != nil && info.Error != nil {
		reason := strings.TrimSpace(info.Error.Message)
		if reason == "" {
			reason = info.Error.Name
		}
		return fmt.Errorf("%w: %s (code %d)", ErrMediaProcessingFailed, reason, info.Error.Code)
	}
	return ErrMediaProcessingFailed
}
