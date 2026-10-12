package coordinator

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func coordinatorBase(t *testing.T, c *Client) *http.Transport {
	t.Helper()
	ct, ok := c.HTTP.Transport.(*coordinatorTransport)
	if !ok {
		t.Fatalf("coordinator transport is %T", c.HTTP.Transport)
	}
	base := ct.current.Load()
	if base == http.DefaultTransport || base.HTTP2 == nil || base.HTTP2.SendPingTimeout != 10*time.Second || base.HTTP2.PingTimeout != 5*time.Second || !base.ForceAttemptHTTP2 {
		t.Fatalf("coordinator transport without its own HTTP/2 health checks: %+v", base.HTTP2)
	}
	return base
}

func caFile(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "coordinator-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Every coordinator client has its own transport with HTTP/2 pings after 10
// seconds without a frame and a 5-second ping timeout, with or without an
// operator CA, and a reset keeps them on the fresh copy.
func TestCoordinatorTransportChecksHTTP2Health(t *testing.T) {
	c := New("https://coordinator.example", "cred")
	first := coordinatorBase(t, c)
	c.ResetConnections()
	if coordinatorBase(t, c) == first {
		t.Fatal("reset kept the old transport")
	}
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	withCA, err := NewWithCA(server.URL, "cred", caFile(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if base := coordinatorBase(t, withCA); base.TLSClientConfig == nil || base.TLSClientConfig.RootCAs == nil {
		t.Fatal("operator CA lost")
	}
	if New("https://a.example", "x").HTTP.Transport == New("https://b.example", "y").HTTP.Transport {
		t.Fatal("clients share a transport")
	}
}

// Against an HTTP/2 coordinator the client multiplexes on one connection
// until a reset, after which it dials a new one; the counters see both and
// the round trip of an immediate answer.
func TestCoordinatorClientSpeaksHTTP2AndReconnectsAfterReset(t *testing.T) {
	var mu sync.Mutex
	protos := map[int]bool{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protos[r.ProtoMajor] = true
		mu.Unlock()
		if r.URL.Path == "/api/node/v1/heartbeat" {
			io.WriteString(w, `{"leases":[]}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	var conns int
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			conns++
			mu.Unlock()
		}
	}
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	c, err := NewWithCA(server.URL, "cred", caFile(t, server))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := c.Availability(context.Background(), Availability{Version: Version}); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	h2, opened := protos[2] && len(protos) == 1, conns
	mu.Unlock()
	if !h2 || opened != 1 {
		t.Fatalf("protocols %v over %d connections, want HTTP/2 over one", protos, opened)
	}
	c.ResetConnections()
	if err := c.Goodbye(context.Background(), "node", GoodbyeStop); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	opened = conns
	mu.Unlock()
	stats := c.Stats()
	// A loopback answer can take less than one tick of Windows' clock, so
	// its measured round trip may be exactly zero.
	if opened != 2 || stats.Connections != 2 || stats.RTT < 0 || stats.RTT > 5*time.Second || stats.AvailabilityPosts != 3 || stats.Goodbyes != 1 || stats.Rejections != 0 {
		t.Fatalf("after a reset: %d server connections, stats %+v", opened, stats)
	}
}

// A request that gets no HTTP answer keeps its failure class, and only the
// class: the error names no address.
func TestTransportFailuresKeepTheirClass(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusedURL := "http://" + closed.Addr().String()
	closed.Close()
	hang := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read the body to its end, so that the server sees the node hang up.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	defer close(hang)
	hangup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer hangup.Close()
	untrusted := httptest.NewTLSServer(http.NotFoundHandler())
	defer untrusted.Close()
	untrusted.Config.ErrorLog = nil
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shortCancel()
	for _, tc := range []struct {
		origin string
		ctx    context.Context
		class  string
	}{
		{refusedURL, context.Background(), "refused"},
		{slow.URL, shortCtx, "timeout"},
		{slow.URL, cancelled, "cancelled"},
		{hangup.URL, context.Background(), "eof"},
		{untrusted.URL, context.Background(), "tls"},
	} {
		_, err := New(tc.origin, "cred").Post(tc.ctx, "/api/node/v1/availability", Availability{Version: Version}, nil)
		var transport *TransportError
		if !errors.As(err, &transport) || transport.Class != tc.class || !errors.Is(err, ErrUnavailable) || ErrorClass(err) != tc.class {
			t.Fatalf("%s: %v, want class %s", tc.origin, err, tc.class)
		}
		if strings.Contains(err.Error(), "127.0.0.1") || err.Error() != "coordinator unavailable ("+tc.class+")" {
			t.Fatalf("error text %q", err)
		}
	}
	for err, class := range map[error]string{
		&net.DNSError{Err: "no such host", Name: "coordinator.invalid", IsNotFound: true}: "dns",
		errors.New("http2: client connection lost"):                                       "connection_lost",
		fmt.Errorf("read: %w", syscall.ECONNRESET):                                        "reset",
		fmt.Errorf("dial: %w", syscall.ENETUNREACH):                                       "unreachable",
		fmt.Errorf("dial: %w", syscall.EHOSTUNREACH):                                      "unreachable",
		fmt.Errorf("read: %w", io.ErrUnexpectedEOF):                                       "eof",
		errors.New("http2: server sent GOAWAY and closed the connection"):                 "http2",
		errors.New("something else"):                                                      "network",
	} {
		if got := transportClass(err); got != class {
			t.Errorf("%v classified %s, want %s", err, got, class)
		}
	}
	for err, class := range map[error]string{
		nil: "",
		&StatusError{Status: 503, Code: "network_unavailable"}: "network_unavailable",
		&StatusError{Status: 502}:                              "http_502",
		fmt.Errorf("%w: %w", ErrHeartbeatRejected, &StatusError{Status: 413, Code: "heartbeat_too_large"}): "heartbeat_too_large",
		fmt.Errorf("%w: too large", ErrInvalidResponse):                                                    "invalid_response",
		errors.New("challenge echo is not allowed for this coordinator"):                                   "error",
	} {
		if got := ErrorClass(err); got != class {
			t.Errorf("ErrorClass(%v) = %q, want %q", err, got, class)
		}
	}
}

// A coordinator that no longer serves this protocol holds the heartbeat and
// answers 426 update_required with Scarlett-Node-Update-Required. Poll
// reports the status and code, which is no rejected heartbeat, records the
// release notice, and keeps the acknowledgements for the next heartbeat.
func TestPollReportsUpdateRequired(t *testing.T) {
	body, err := os.ReadFile("../../api/fixtures/error-update-required.json")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(NodeLatestVersionHeader, "0.1.18")
		w.Header().Set(NodeMinimumVersionHeader, "0.1.18")
		w.Header().Set(NodeUpdateRequiredHeader, "true")
		w.WriteHeader(http.StatusUpgradeRequired)
		w.Write(body)
	}))
	defer ts.Close()
	c := New(ts.URL, "cred")
	c.seen.record(ref(1))
	_, err = c.Poll(context.Background(), Heartbeat{Version: Version, NodeID: "node"})
	var status *StatusError
	if !errors.As(err, &status) || status.Status != http.StatusUpgradeRequired || status.Code != "update_required" || errors.Is(err, ErrHeartbeatRejected) || ErrorClass(err) != "update_required" {
		t.Fatalf("426 reported as %v", err)
	}
	if notice, ok := c.Release(); !ok || !notice.Required || notice.Minimum != "0.1.18" {
		t.Fatalf("release notice %+v", notice)
	}
	if got := c.seen.take(); len(got) != 1 || got[0] != ref(1) {
		t.Fatalf("acknowledgements after 426: %v", got)
	}
}
