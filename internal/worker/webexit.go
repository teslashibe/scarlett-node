package worker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
)

// A proxied Webshare job learns its exit address with one small request
// through its own session to Webshare's echo of the address a request comes
// from. The probe runs beside hop 0 or the browser page, never in front of
// them, and passes the same egress guard as any target: its host is resolved
// here and checked (IPv4 only, as proxy exits are), the tunnel goes to the
// checked address, TLS is verified against the system roots, and the body
// must be one public IPv4 address. The exit is the node's word, like egress
// itself; the report leaves it out when the probe has not answered in time.

const (
	// webExitHost answers GET / with the address the request arrived from.
	webExitHost = "ipv4.webshare.io"
	// webExitLimit bounds one probe, from its start beside the job.
	webExitLimit = 5 * time.Second
	// webExitWait is how much longer than the job the report waits for it.
	webExitWait = 2 * time.Second
	// maxWebExitBody is the most body read: an address and a newline.
	maxWebExitBody = 64
	// maxConnectReply bounds a proxy's CONNECT reply head, as the prover does.
	maxConnectReply = 8 << 10
	// maxWebExitHead bounds the probe response's status line and headers.
	maxWebExitHead = 16 << 10
)

// exitProbe is one running probe. Every method is nil-safe.
type exitProbe struct {
	done   chan struct{}
	cancel context.CancelFunc
	exit   netip.Addr
	class  string
}

// startExitProbe starts a probe through upstream, bounded by webExitLimit.
func (w Web) startExitProbe(ctx context.Context, upstream ProxyUpstream) *exitProbe {
	ctx, cancel := context.WithTimeout(ctx, webExitLimit)
	p := &exitProbe{done: make(chan struct{}), cancel: cancel}
	go func() {
		defer close(p.done)
		defer cancel()
		p.exit, p.class = w.probeExit(ctx, upstream)
	}()
	return p
}

// wait returns the probe's exit once it has one, waiting at most limit.
func (p *exitProbe) wait(limit time.Duration) (netip.Addr, bool) {
	if p == nil {
		return netip.Addr{}, false
	}
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-p.done:
		return p.exit, p.exit.IsValid()
	case <-timer.C:
		return netip.Addr{}, false
	}
}

// stop ends a probe still running; its result is then never read.
func (p *exitProbe) stop() {
	if p != nil {
		p.cancel()
	}
}

func (w Web) exitHost() string {
	if w.exitTarget != "" {
		return w.exitTarget
	}
	return webExitHost
}

// probeExit asks the exit host, through upstream, which address the request
// came from. It returns that public IPv4 address, or the proxy class of what
// failed: the proxy's own classes for a tunnel it would not open, and
// proxy_exit for anything after the tunnel opened (the exit could not reach
// the host, TLS failed, or the answer was not a public IPv4 address).
func (w Web) probeExit(ctx context.Context, upstream ProxyUpstream) (netip.Addr, string) {
	host := w.exitHost()
	lookupCtx, cancel := context.WithTimeout(ctx, webLookupLimit)
	addrs, err := w.resolver()(lookupCtx, host)
	cancel()
	if err != nil {
		return netip.Addr{}, proxyUnreachable
	}
	target, allowed := w.egress().pickWebAddr4(ctx, addrs)
	if !allowed || !target.IsValid() {
		return netip.Addr{}, proxyUnreachable
	}
	conn, class := w.connectTunnel(ctx, upstream, netip.AddrPortFrom(target, 443))
	if class != "" {
		return netip.Addr{}, class
	}
	defer conn.Close()
	// A stopped probe ends at once; the context's deadline already bounds
	// every read and write.
	defer context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: w.exitRoots, MinVersion: tls.VersionTLS12})
	if tlsConn.HandshakeContext(ctx) != nil {
		return netip.Addr{}, proxyExit
	}
	req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	req.Header.Set("Accept", "text/plain")
	req.Close = true
	if req.Write(tlsConn) != nil {
		return netip.Addr{}, proxyExit
	}
	res, err := http.ReadResponse(bufio.NewReader(io.LimitReader(tlsConn, maxWebExitHead+maxWebExitBody)), req)
	if err != nil {
		return netip.Addr{}, proxyExit
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxWebExitBody+1))
	if err != nil || res.StatusCode != http.StatusOK || len(body) > maxWebExitBody {
		return netip.Addr{}, proxyExit
	}
	exit, err := netip.ParseAddr(string(bytes.TrimSpace(body)))
	if err != nil || !publicIPv4(exit) {
		return netip.Addr{}, proxyExit
	}
	return exit, ""
}

// connectTunnel opens a CONNECT tunnel to target through upstream, as the
// prover's dial does, and classifies a failure the same way: the proxy
// unreachable or not answering as HTTP, its refusals by status, and an exit
// that never answered in time.
func (w Web) connectTunnel(ctx context.Context, upstream ProxyUpstream, target netip.AddrPort) (net.Conn, string) {
	dial := w.proxyDial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", upstream.Addr.String())
	if err != nil {
		return nil, proxyUnreachable
	}
	// The context's deadline bounds the tunnel and everything through it.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	defer context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })()
	request := "CONNECT " + target.String() + " HTTP/1.1\r\nHost: " + target.String() + "\r\n"
	if upstream.Authorization != "" {
		request += "Proxy-Authorization: " + upstream.Authorization + "\r\n"
	}
	if _, err := io.WriteString(conn, request+"\r\n"); err != nil {
		conn.Close()
		return nil, proxyUnreachable
	}
	status, err := connectStatus(conn)
	if err != nil {
		conn.Close()
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() || ctx.Err() != nil {
			// The proxy took the connection and the exit never answered.
			return nil, proxyExit
		}
		return nil, proxyUnreachable
	}
	if status != http.StatusOK {
		conn.Close()
		return nil, connectClass(status)
	}
	return conn, ""
}

// connectClass is the proxy class of a CONNECT reply status other than 200,
// as prover/src/relay/node.rs proxy_class.
func connectClass(status int) string {
	switch status {
	case http.StatusProxyAuthRequired:
		return proxyAuth
	case http.StatusPaymentRequired:
		return proxyQuota
	case http.StatusTooManyRequests:
		return proxyBusy
	case http.StatusForbidden:
		return proxyRefused
	}
	return proxyExit
}

var errConnectReply = errors.New("unexpected CONNECT reply")

// connectStatus reads a CONNECT reply head a byte at a time, so nothing past
// it is consumed: the target speaks only after the client's TLS hello, so
// any byte after the head came from the proxy and refuses the tunnel.
func connectStatus(conn net.Conn) (int, error) {
	head := make([]byte, 0, 256)
	one := make([]byte, 1)
	for !bytes.HasSuffix(head, []byte("\r\n\r\n")) {
		if len(head) >= maxConnectReply {
			return 0, errConnectReply
		}
		if _, err := io.ReadFull(conn, one); err != nil {
			return 0, err
		}
		head = append(head, one[0])
	}
	rest, ok := bytes.CutPrefix(head, []byte("HTTP/1.1 "))
	if !ok {
		rest, ok = bytes.CutPrefix(head, []byte("HTTP/1.0 "))
	}
	if !ok || len(rest) < 4 || rest[3] != ' ' && rest[3] != '\r' {
		return 0, errConnectReply
	}
	status, err := strconv.Atoi(string(rest[:3]))
	if err != nil || rest[0] < '0' || rest[0] > '9' {
		return 0, errConnectReply
	}
	return status, nil
}

// ProbeWebProxy runs one exit probe through a fresh session of p, as
// `scarlett-node desktop proxy-test` does: the proxy's host is resolved and
// checked as for a job, and the probe passes the node-wide egress guard. It
// returns the exit, or the proxy class of the failure.
func ProbeWebProxy(ctx context.Context, p *config.WebProxy) (netip.Addr, string) {
	return Web{}.probeWebProxy(ctx, p)
}

func (w Web) probeWebProxy(ctx context.Context, p *config.WebProxy) (netip.Addr, string) {
	addr, ok := w.proxyAddress(ctx, p)
	if !ok {
		return netip.Addr{}, proxyUnreachable
	}
	session := p.Session(proxyTestJob(), "test", 0)
	ctx, cancel := context.WithTimeout(ctx, webExitLimit)
	defer cancel()
	return w.probeExit(ctx, ProxyUpstream{Addr: addr, Authorization: session.Authorization})
}
