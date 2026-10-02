package x

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	txEpochOffsetSec = 1682924400
	txTotalTime      = 4096
	txKeyword        = "obfiowerehiring"
	txTrailingByte   = 3
	onDemandURLFmt   = "https://abs.twimg.com/responsive-web/client-web/ondemand.s.%sa.js"
)

var (
	reMetaTag       = regexp.MustCompile(`<meta\s[^>]*twitter-site-verification[^>]*>`)
	reContentAttr   = regexp.MustCompile(`content=["']([^"']+)["']`)
	reOnDemandChunk = regexp.MustCompile(`,(\d+):["']ondemand\.s["']`)
	reKeyIndices    = regexp.MustCompile(`\(\w\[(\d{1,2})\],\s*16\)`)
	rePathD         = regexp.MustCompile(`<path[^>]+d=["']([^"']+)["']`)
	reNonDigit      = regexp.MustCompile(`[^\d]+`)
)

// transactionState holds precomputed values for X-Client-Transaction-Id
// generation. Computed once during client init, then read-only.
type transactionState struct {
	keyBytes     []byte
	animationKey string
	initialized  bool
}

// initTransaction fetches the x.com home page and ondemand.s JS bundle,
// extracts the verification key and animation parameters, and precomputes
// the animation key used for per-request transaction ID generation.
func (c *Client) initTransaction(ctx context.Context) error {
	html, err := c.fetchRaw(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("fetching home page: %w", err)
	}

	keyStr, err := extractVerificationKey(html)
	if err != nil {
		return err
	}
	keyBytes, err := b64Decode(keyStr)
	if err != nil {
		return fmt.Errorf("decoding verification key: %w", err)
	}

	ondemandURL, err := buildOnDemandURL(html)
	if err != nil {
		return err
	}
	jsBody, err := c.fetchRaw(ctx, ondemandURL)
	if err != nil {
		return fmt.Errorf("fetching ondemand.s: %w", err)
	}

	rowIndex, keyByteIndices, err := extractKeyIndices(jsBody)
	if err != nil {
		return err
	}

	animKey, err := computeAnimationKey(keyBytes, html, rowIndex, keyByteIndices)
	if err != nil {
		return fmt.Errorf("computing animation key: %w", err)
	}

	c.txState.keyBytes = keyBytes
	c.txState.animationKey = animKey
	c.txState.initialized = true
	return nil
}

// generateTransactionID produces the X-Client-Transaction-Id header value.
func (c *Client) generateTransactionID(method, path string) string {
	if !c.txState.initialized {
		return ""
	}

	timeNow := int((time.Now().UnixMilli() - int64(txEpochOffsetSec)*1000) / 1000)
	timeNowBytes := []byte{
		byte(timeNow & 0xFF),
		byte((timeNow >> 8) & 0xFF),
		byte((timeNow >> 16) & 0xFF),
		byte((timeNow >> 24) & 0xFF),
	}

	hashInput := fmt.Sprintf("%s!%s!%d%s%s", method, path, timeNow, txKeyword, c.txState.animationKey)
	hashVal := sha256.Sum256([]byte(hashInput))

	randomByte := byte(rand.Intn(256))

	var buf []byte
	buf = append(buf, c.txState.keyBytes...)
	buf = append(buf, timeNowBytes...)
	buf = append(buf, hashVal[:16]...)
	buf = append(buf, txTrailingByte)

	out := make([]byte, 1+len(buf))
	out[0] = randomByte
	for i, b := range buf {
		out[i+1] = b ^ randomByte
	}

	return strings.TrimRight(base64.StdEncoding.EncodeToString(out), "=")
}

// fetchRaw performs a simple GET and returns the response body as a string.
func (c *Client) fetchRaw(ctx context.Context, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cookie", c.cookieHeader())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ---------------------------------------------------------------------------
// HTML / JS parsing (regex-only, no external deps)
// ---------------------------------------------------------------------------

func extractVerificationKey(html string) (string, error) {
	tagMatch := reMetaTag.FindString(html)
	if tagMatch == "" {
		return "", fmt.Errorf("twitter-site-verification meta tag not found")
	}
	contentMatch := reContentAttr.FindStringSubmatch(tagMatch)
	if contentMatch == nil {
		return "", fmt.Errorf("content attribute not found in verification meta tag")
	}
	return contentMatch[1], nil
}

func buildOnDemandURL(html string) (string, error) {
	chunkMatch := reOnDemandChunk.FindStringSubmatch(html)
	if chunkMatch == nil {
		return "", fmt.Errorf("ondemand.s chunk ID not found in page source")
	}
	chunkID := chunkMatch[1]
	hashRe := regexp.MustCompile(`,` + regexp.QuoteMeta(chunkID) + `:"([0-9a-f]+)"`)
	hashMatch := hashRe.FindStringSubmatch(html)
	if hashMatch == nil {
		return "", fmt.Errorf("ondemand.s hash not found for chunk %s", chunkID)
	}
	return fmt.Sprintf(onDemandURLFmt, hashMatch[1]), nil
}

func extractKeyIndices(js string) (int, []int, error) {
	matches := reKeyIndices.FindAllStringSubmatch(js, -1)
	if len(matches) < 2 {
		return 0, nil, fmt.Errorf("could not extract key byte indices (found %d)", len(matches))
	}
	indices := make([]int, len(matches))
	for i, m := range matches {
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, nil, fmt.Errorf("parsing index %q: %w", m[1], err)
		}
		indices[i] = n
	}
	return indices[0], indices[1:], nil
}

func extractAnimPath(html string, frameIndex int) string {
	marker := fmt.Sprintf("loading-x-anim-%d", frameIndex)
	pos := strings.Index(html, marker)
	if pos < 0 {
		return ""
	}
	end := pos + 10000
	if end > len(html) {
		end = len(html)
	}
	// The SVG structure is: <g><path (logo)/><path (animation data)/></g>
	// We need the second <path> element's d attribute.
	matches := rePathD.FindAllStringSubmatch(html[pos:end], -1)
	if len(matches) < 2 {
		return ""
	}
	return matches[1][1]
}

func parseSVGPath(pathD string) ([][]int, error) {
	if len(pathD) < 10 {
		return nil, fmt.Errorf("path d attribute too short")
	}
	segments := strings.Split(pathD[9:], "C")
	var result [][]int
	for _, seg := range segments {
		cleaned := strings.TrimSpace(reNonDigit.ReplaceAllString(seg, " "))
		if cleaned == "" {
			continue
		}
		fields := strings.Fields(cleaned)
		nums := make([]int, 0, len(fields))
		for _, f := range fields {
			n, err := strconv.Atoi(f)
			if err != nil {
				continue
			}
			nums = append(nums, n)
		}
		if len(nums) > 0 {
			result = append(result, nums)
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------
// Animation key computation
// ---------------------------------------------------------------------------

func computeAnimationKey(keyBytes []byte, html string, rowIdx int, keyByteIndices []int) (string, error) {
	if len(keyBytes) < 6 {
		return "", fmt.Errorf("key bytes too short (%d)", len(keyBytes))
	}

	frameIdx := int(keyBytes[5]) % 4
	pathD := extractAnimPath(html, frameIdx)
	if pathD == "" {
		return "", fmt.Errorf("animation frame %d path not found", frameIdx)
	}

	arr, err := parseSVGPath(pathD)
	if err != nil {
		return "", err
	}

	row := int(keyBytes[rowIdx]) % 16
	if row >= len(arr) {
		return "", fmt.Errorf("row %d out of range (%d rows)", row, len(arr))
	}

	frameTime := 1
	for _, idx := range keyByteIndices {
		if idx < len(keyBytes) {
			frameTime *= int(keyBytes[idx]) % 16
		}
	}
	frameTime = jsRound(float64(frameTime)/10) * 10

	targetTime := float64(frameTime) / float64(txTotalTime)
	return txAnimate(arr[row], targetTime), nil
}

func txAnimate(frames []int, targetTime float64) string {
	if len(frames) < 11 {
		return ""
	}

	fromColor := []float64{float64(frames[0]), float64(frames[1]), float64(frames[2]), 1.0}
	toColor := []float64{float64(frames[3]), float64(frames[4]), float64(frames[5]), 1.0}
	fromRotation := []float64{0.0}
	toRotation := []float64{txSolve(float64(frames[6]), 60.0, 360.0, true)}

	remaining := frames[7:]
	curves := make([]float64, len(remaining))
	for i, v := range remaining {
		curves[i] = txSolve(float64(v), isOddVal(i), 1.0, false)
	}

	val := cubicGetValue(curves, targetTime)

	color := txInterpolate(fromColor, toColor, val)
	for i := range color {
		color[i] = math.Max(0, math.Min(255, color[i]))
	}
	rotation := txInterpolate(fromRotation, toRotation, val)
	matrix := rotationToMatrix(rotation[0])

	var parts []string
	for i := 0; i < 3 && i < len(color); i++ {
		parts = append(parts, fmt.Sprintf("%x", int(math.Round(color[i]))))
	}
	for _, v := range matrix {
		rounded := math.Round(v*100) / 100
		if rounded < 0 {
			rounded = -rounded
		}
		hex := floatToHex(rounded)
		switch {
		case strings.HasPrefix(hex, "."):
			hex = strings.ToLower("0" + hex)
		case hex == "":
			hex = "0"
		}
		parts = append(parts, hex)
	}
	parts = append(parts, "0", "0")

	joined := strings.Join(parts, "")
	return strings.NewReplacer(".", "", "-", "").Replace(joined)
}

func txSolve(value, minVal, maxVal float64, rounding bool) float64 {
	result := value*(maxVal-minVal)/255.0 + minVal
	if rounding {
		return math.Floor(result)
	}
	return math.Round(result*100) / 100
}

func isOddVal(n int) float64 {
	if n%2 != 0 {
		return -1.0
	}
	return 0.0
}

func txInterpolate(from, to []float64, f float64) []float64 {
	out := make([]float64, len(from))
	for i := range from {
		out[i] = from[i]*(1-f) + to[i]*f
	}
	return out
}

func rotationToMatrix(deg float64) []float64 {
	rad := deg * math.Pi / 180.0
	c, s := math.Cos(rad), math.Sin(rad)
	return []float64{c, -s, s, c}
}

// ---------------------------------------------------------------------------
// Cubic bezier
// ---------------------------------------------------------------------------

func cubicGetValue(curves []float64, t float64) float64 {
	if len(curves) < 4 {
		return 0
	}

	if t <= 0 {
		var g float64
		if curves[0] > 0 {
			g = curves[1] / curves[0]
		} else if curves[1] == 0 && curves[2] > 0 {
			g = curves[3] / curves[2]
		}
		return g * t
	}

	if t >= 1 {
		var g float64
		if curves[2] < 1 {
			g = (curves[3] - 1) / (curves[2] - 1)
		} else if curves[2] == 1 && curves[0] < 1 {
			g = (curves[1] - 1) / (curves[0] - 1)
		}
		return 1 + g*(t-1)
	}

	start, end := 0.0, 1.0
	var mid float64
	for i := 0; i < 100 && start < end; i++ {
		mid = (start + end) / 2
		xEst := cubicCalc(curves[0], curves[2], mid)
		if math.Abs(t-xEst) < 0.00001 {
			return cubicCalc(curves[1], curves[3], mid)
		}
		if xEst < t {
			start = mid
		} else {
			end = mid
		}
	}
	return cubicCalc(curves[1], curves[3], mid)
}

func cubicCalc(a, b, m float64) float64 {
	return 3*a*(1-m)*(1-m)*m + 3*b*(1-m)*m*m + m*m*m
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

func floatToHex(x float64) string {
	var result []byte

	quotient := int(x)
	fraction := x - float64(quotient)

	xv := x
	for quotient > 0 {
		quotient = int(xv / 16)
		remainder := int(xv - float64(quotient)*16)
		if remainder > 9 {
			result = append([]byte{byte(remainder + 55)}, result...)
		} else {
			result = append([]byte{byte('0' + remainder)}, result...)
		}
		xv = float64(quotient)
	}

	if fraction == 0 {
		return string(result)
	}

	result = append(result, '.')
	for i := 0; fraction > 0 && i < 20; i++ {
		fraction *= 16
		digit := int(fraction)
		fraction -= float64(digit)
		if digit > 9 {
			result = append(result, byte(digit+55))
		} else {
			result = append(result, byte('0'+digit))
		}
	}
	return string(result)
}

// jsRound implements JavaScript-style Math.round (0.5 rounds up).
func jsRound(num float64) int {
	x := math.Floor(num)
	if (num - x) >= 0.5 {
		x = math.Ceil(num)
	}
	return int(math.Copysign(x, num))
}

func b64Decode(s string) ([]byte, error) {
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}
