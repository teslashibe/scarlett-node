package coordinator

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// NodeRelease is this build's release version. It must equal the desktop
// version in desktop/src-tauri/tauri.conf.json; release-manifest.py
// check-version refuses a release where they differ.
const NodeRelease = "0.1.10"

// Release version headers, copied from api/fixtures/version-headers.json. The
// node sends NodeVersionHeader on every request. While the coordinator
// enforces a release policy, it answers with the latest published release and
// the minimum release still offered new jobs, and tells a node older than the
// minimum that it must update. Such a node keeps heartbeating and finishing
// work it holds but is offered no new jobs.
const (
	NodeVersionHeader        = "Scarlett-Node-Version"
	NodeLatestVersionHeader  = "Scarlett-Node-Latest-Version"
	NodeMinimumVersionHeader = "Scarlett-Node-Minimum-Version"
	NodeUpdateRequiredHeader = "Scarlett-Node-Update-Required"
)

// ReleaseNotice is the coordinator's latest view of this node's release.
type ReleaseNotice struct {
	Latest   string
	Minimum  string
	Required bool
}

// UpdateAvailable reports whether the coordinator publishes a release newer
// than this build.
func (n ReleaseNotice) UpdateAvailable() bool {
	return n.Latest != "" && CompareVersions(n.Latest, NodeRelease) > 0
}

// releaseState is shared by a client's requests; the zero value has seen no
// notice.
type releaseState struct {
	mu     sync.Mutex
	notice ReleaseNotice
}

// Release returns the most recent release notice the coordinator sent, and
// false before any response carried one.
func (c *Client) Release() (ReleaseNotice, bool) {
	if c == nil || c.release == nil {
		return ReleaseNotice{}, false
	}
	c.release.mu.Lock()
	defer c.release.mu.Unlock()
	return c.release.notice, c.release.notice.Latest != ""
}

// observeRelease records the release headers of one coordinator response. A
// response without a valid latest version leaves the last notice in place:
// a proxy error page carries no policy.
func (c *Client) observeRelease(h http.Header) {
	if c.release == nil || h == nil {
		return
	}
	latest := h.Get(NodeLatestVersionHeader)
	if !ValidVersion(latest) {
		return
	}
	notice := ReleaseNotice{Latest: latest}
	if minimum := h.Get(NodeMinimumVersionHeader); ValidVersion(minimum) {
		notice.Minimum = minimum
	}
	notice.Required = strings.EqualFold(h.Get(NodeUpdateRequiredHeader), "true")
	c.release.mu.Lock()
	c.release.notice = notice
	c.release.mu.Unlock()
}

// ValidVersion accepts MAJOR.MINOR.PATCH with an optional prerelease, at most
// 64 bytes, without leading zeros or build metadata.
func ValidVersion(s string) bool {
	_, _, ok := parseVersion(s)
	return ok
}

func parseVersion(s string) ([3]int, []string, bool) {
	var core [3]int
	if s == "" || len(s) > 64 {
		return core, nil, false
	}
	main, pre, hasPre := strings.Cut(s, "-")
	parts := strings.Split(main, ".")
	if len(parts) != 3 {
		return core, nil, false
	}
	for i, p := range parts {
		if !numericIdentifier(p) || len(p) > 9 {
			return core, nil, false
		}
		core[i], _ = strconv.Atoi(p)
	}
	if !hasPre {
		return core, nil, true
	}
	ids := strings.Split(pre, ".")
	for _, id := range ids {
		if id == "" || strings.Trim(id, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-") != "" || allDigits(id) && !numericIdentifier(id) {
			return core, nil, false
		}
	}
	return core, ids, true
}

func allDigits(s string) bool { return s != "" && strings.Trim(s, "0123456789") == "" }

func numericIdentifier(s string) bool { return allDigits(s) && (s == "0" || s[0] != '0') }

// CompareVersions orders two valid versions by semantic version precedence
// (0.1.10 is after 0.1.9; a prerelease comes before its release). An invalid
// version sorts before every valid one.
func CompareVersions(a, b string) int {
	ac, ap, aok := parseVersion(a)
	bc, bp, bok := parseVersion(b)
	switch {
	case !aok && !bok:
		return 0
	case !aok:
		return -1
	case !bok:
		return 1
	}
	for i := range ac {
		if ac[i] != bc[i] {
			if ac[i] < bc[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ap) == 0 && len(bp) == 0:
		return 0
	case len(ap) == 0:
		return 1
	case len(bp) == 0:
		return -1
	}
	for i := 0; i < len(ap) && i < len(bp); i++ {
		x, y := ap[i], bp[i]
		xn, yn := allDigits(x), allDigits(y)
		var c int
		switch {
		case xn && yn && len(x) != len(y):
			c = len(x) - len(y)
		case xn && !yn:
			c = -1
		case !xn && yn:
			c = 1
		default:
			c = strings.Compare(x, y)
		}
		if c < 0 {
			return -1
		}
		if c > 0 {
			return 1
		}
	}
	switch {
	case len(ap) < len(bp):
		return -1
	case len(ap) > len(bp):
		return 1
	}
	return 0
}
