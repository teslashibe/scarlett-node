package webruntime

import "strconv"

// The pinned Chrome for Testing build. A pin bump changes PinnedVersion and
// PinnedMajor here, MaxBrowserMajor in the app and MAX_BROWSER_MAJOR in the
// verifier in the same release.
const (
	PinnedVersion = "155.0.8059.39"
	PinnedMajor   = 155
	// Engine is what the helper reports and the upload names.
	Engine = "scrapling/0.4.15+scarlett.2"
)

// UserAgent is the only User-Agent the browser and the proven re-fetch send,
// and the only family the verifier accepts. It is empty for any other OS.
func UserAgent(goos string, major int) string {
	platform := map[string]string{
		"darwin":  "Macintosh; Intel Mac OS X 10_15_7",
		"windows": "Windows NT 10.0; Win64; x64",
		"linux":   "X11; Linux x86_64",
	}[goos]
	if platform == "" || major < 1 {
		return ""
	}
	return "Mozilla/5.0 (" + platform + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + strconv.Itoa(major) + ".0.0.0 Safari/537.36"
}
