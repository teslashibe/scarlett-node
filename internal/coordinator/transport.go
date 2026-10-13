package coordinator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// HTTP/2 health checks on the coordinator connection. Heartbeats,
// acceptances, reports and uploads share one HTTP/2 connection, which a
// laptop's sleep, a network change or a NAT timeout can leave dead without the
// node knowing. After HTTP2PingAfter with no frame read the transport sends a
// ping, and it closes the connection when no answer comes within
// HTTP2PingTimeout, so the requests on a dead connection fail after about 15
// seconds instead of at their own deadlines.
const (
	HTTP2PingAfter   = 10 * time.Second
	HTTP2PingTimeout = 5 * time.Second
)

// coordinatorTransport is the coordinator client's round tripper: the default
// transport's settings with the HTTP/2 health checks. ResetConnections swaps
// it for a fresh copy, so new requests dial afresh while requests already in
// flight finish on the connection they have.
type coordinatorTransport struct {
	mu      sync.Mutex // serializes resets
	current atomic.Pointer[http.Transport]
}

func newCoordinatorTransport(tlsConfig *tls.Config) *coordinatorTransport {
	base := http.DefaultTransport.(*http.Transport).Clone()
	if tlsConfig != nil {
		base.TLSClientConfig = tlsConfig
	}
	base.HTTP2 = &http.HTTP2Config{SendPingTimeout: HTTP2PingAfter, PingTimeout: HTTP2PingTimeout}
	t := &coordinatorTransport{}
	t.current.Store(base)
	return t
}

func (t *coordinatorTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.current.Load().RoundTrip(r)
}

func (t *coordinatorTransport) CloseIdleConnections() { t.current.Load().CloseIdleConnections() }

func (t *coordinatorTransport) reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.current.Load()
	t.current.Store(old.Clone())
	old.CloseIdleConnections()
}

// ResetConnections makes the next coordinator request open a new connection.
// The node calls it on wake, when a pooled connection may be dead without the
// transport knowing yet; requests in flight are left to finish or fail on
// their own. A client whose HTTP was replaced only closes its idle
// connections.
func (c *Client) ResetConnections() {
	if c == nil || c.HTTP == nil {
		return
	}
	if t, ok := c.HTTP.Transport.(*coordinatorTransport); ok {
		t.reset()
		return
	}
	c.HTTP.CloseIdleConnections()
}

// ErrUnavailable is a coordinator request that got no HTTP answer at all.
// Every such failure is a *TransportError, which matches it with errors.Is.
var ErrUnavailable = errors.New("coordinator unavailable")

// TransportError is a coordinator request that failed before any HTTP answer.
// Class names the failure without addresses or other detail, so it is safe
// in logs and status.json: cancelled, timeout, dns, tls, connection_lost (an
// HTTP/2 health check found the connection dead), refused, reset,
// unreachable, eof, http2 or network.
type TransportError struct {
	Class string
	err   error
}

func (e *TransportError) Error() string        { return "coordinator unavailable (" + e.Class + ")" }
func (e *TransportError) Is(target error) bool { return target == ErrUnavailable }
func (e *TransportError) Unwrap() error        { return e.err }

func transportError(err error) error {
	return &TransportError{Class: transportClass(err), err: err}
}

func transportClass(err error) string {
	var dns *net.DNSError
	var verification *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var timeout net.Error
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &verification), errors.As(err, &record), errors.As(err, &alert), errors.As(err, &authority), errors.As(err, &hostname), errors.As(err, &invalid), strings.Contains(text, "tls:"):
		return "tls"
	case strings.Contains(text, "client connection lost"):
		return "connection_lost"
	case errors.Is(err, syscall.ECONNREFUSED), strings.Contains(text, "refused"):
		return "refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE), strings.Contains(text, "reset by peer"), strings.Contains(text, "forcibly closed"):
		return "reset"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH), strings.Contains(text, "unreachable"):
		return "unreachable"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	case strings.Contains(text, "http2:"):
		return "http2"
	}
	return "network"
}

// ErrorClass is a short machine word for a failed coordinator call, for logs
// and status.json: a TransportError's class, a StatusError's code (or
// http_<status> without one), invalid_response for an answer the node could
// not read, and error for anything else.
func ErrorClass(err error) string {
	var transport *TransportError
	var status *StatusError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &transport):
		return transport.Class
	case errors.As(err, &status) && status.Code != "":
		return status.Code
	case errors.As(err, &status):
		return "http_" + strconv.Itoa(status.Status)
	case errors.Is(err, ErrInvalidResponse):
		return "invalid_response"
	}
	return "error"
}

// Stats are local counters of one client's coordinator traffic. They are
// never sent anywhere.
type Stats struct {
	// Connections is how many connections the client has opened, the first
	// included; more than one means it reconnected.
	Connections int64
	// RTT is the last round trip of a request the coordinator answers at once
	// (every call but the held heartbeat), from the request written to the
	// first response byte. Zero before the first.
	RTT time.Duration
	// AvailabilityPosts, Goodbyes and Rejections count the calls the client
	// made, answered or not.
	AvailabilityPosts, Goodbyes, Rejections int64
}

type clientStats struct {
	connections, rtt                        atomic.Int64
	availabilityPosts, goodbyes, rejections atomic.Int64
}

// Stats returns the client's counters.
func (c *Client) Stats() Stats {
	if c == nil || c.stats == nil {
		return Stats{}
	}
	return Stats{Connections: c.stats.connections.Load(), RTT: time.Duration(c.stats.rtt.Load()),
		AvailabilityPosts: c.stats.availabilityPosts.Load(), Goodbyes: c.stats.goodbyes.Load(), Rejections: c.stats.rejections.Load()}
}

// monotonic is a fixed point that durations are taken from, so round trips
// use the monotonic clock even when they are measured across callbacks.
var monotonic = time.Now()

// traced counts the connections a request opens and, unless it is a held
// heartbeat, records its round trip. The trace callbacks run on transport
// goroutines.
func (c *Client) traced(ctx context.Context, held bool) context.Context {
	if c.stats == nil {
		return ctx
	}
	stats := c.stats
	var wrote atomic.Int64
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if !info.Reused {
			stats.connections.Add(1)
		}
	}}
	if !held {
		trace.WroteRequest = func(httptrace.WroteRequestInfo) { wrote.Store(int64(time.Since(monotonic))) }
		trace.GotFirstResponseByte = func() {
			if at := wrote.Load(); at != 0 {
				stats.rtt.Store(int64(time.Since(monotonic)) - at)
			}
		}
	}
	return httptrace.WithClientTrace(ctx, trace)
}
