package webruntime

import (
	"errors"
)

// Reason is one closed browser-health reason (contract C.8). It is safe to
// log and report: it never carries a path, URL or host.
type Reason string

const (
	ReasonDisabled              Reason = "disabled"
	ReasonWebUnavailable        Reason = "web_unavailable"
	ReasonMemoryLow             Reason = "memory_low"
	ReasonDiskLow               Reason = "disk_low"
	ReasonRuntimeMissing        Reason = "runtime_missing"
	ReasonRuntimeInvalid        Reason = "runtime_invalid"
	ReasonBrowserDownloading    Reason = "browser_downloading"
	ReasonBrowserDownloadFailed Reason = "browser_download_failed"
	ReasonBrowserInvalid        Reason = "browser_invalid"
	ReasonDepsMissing           Reason = "deps_missing"
	ReasonSandboxUnavailable    Reason = "sandbox_unavailable"
	ReasonHelperFailed          Reason = "helper_failed"
)

// ErrUnavailable is wrapped by every error that means the browser tier
// cannot take this fetch now (worker code web_browser_unavailable).
var ErrUnavailable = errors.New("web browser unavailable")

// Error is a failure with its closed reason and a fixed description.
type Error struct {
	Reason Reason
	what   string
}

func (e *Error) Error() string {
	if e.what == "" {
		return "web browser unavailable: " + string(e.Reason)
	}
	return "web browser unavailable: " + string(e.Reason) + ": " + e.what
}
func (e *Error) Unwrap() error { return ErrUnavailable }

func fail(reason Reason, what string) error { return &Error{Reason: reason, what: what} }

// ReasonOf is the closed reason inside err, or "" when it has none.
func ReasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}
