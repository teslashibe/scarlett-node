package worker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/process"
)

// The node runs its web hops through one long-lived `scarlett-prover serve`
// per process and verifier (design C1): it keeps a few verifier connections
// warm, reuses the one a verifier keeps after a redirect hop, and takes a
// hop's token after the hop has started (E1). Messages both ways are a
// big-endian uint32 length and that much JSON (api/verifier-v1.md 14).
//
// A daemon that cannot start, or keeps dying, is left alone for a while and
// hops run as one-shot `relay-web` helpers instead. A daemon that dies under
// a hop whose token it had not yet announced ("presenting") never sent that
// token, so the hop runs again one-shot; once it was announced, the hop's
// session may have been spent and the hop fails as any helper failure.

const (
	daemonMaxMessage = 1 << 20
	daemonReadyWait  = 5 * time.Second
	// More than daemonCrashLimit starts or deaths within daemonCrashWindow
	// leave web on one-shot helpers until the oldest falls out of it.
	daemonCrashLimit  = 3
	daemonCrashWindow = 5 * time.Minute
	// daemonQueue bounds requests waiting for the daemon's stdin; a daemon
	// that falls this far behind is treated as dead.
	daemonQueue = 256
	// webWarmConnections is the most warm verifier connections a node keeps.
	webWarmConnections = 2
)

// webDaemonEnabled lets tests run web hops one-shot only.
var webDaemonEnabled atomic.Bool

func init() { webDaemonEnabled.Store(true) }

// The daemon's stderr is part of the node's log, each line prefixed "web
// daemon:": it writes a few lines always, and with SCARLETT_WEB_DAEMON_LOG=1
// (which the node passes on as SCARLETT_SERVE_LOG=1) every hop's steps,
// which the node's side of each hop joins. No line carries a token, a job's
// URL or a target address.
var webDaemonVerbose = os.Getenv("SCARLETT_WEB_DAEMON_LOG") == "1"

// daemonLogLines bounds the daemon's lines waiting for the node's stderr;
// beyond it lines are dropped (and counted) rather than slowing the daemon.
const daemonLogLines = 256

// daemonDetail writes one verbose line about the daemon's hops.
func daemonDetail(format string, args ...any) {
	if webDaemonVerbose {
		fmt.Fprintf(os.Stderr, "web daemon: node: "+format+"\n", args...)
	}
}

// daemonLog passes the daemon's stderr to the node's, one line at a time,
// without ever blocking the daemon, and keeps its last line.
type daemonLog struct {
	mu      sync.Mutex
	partial []byte
	last    string
	lines   chan string
	dropped int
	closed  bool
}

func newDaemonLog() *daemonLog {
	l := &daemonLog{lines: make(chan string, daemonLogLines)}
	go func() {
		for line := range l.lines {
			fmt.Fprintln(os.Stderr, "web daemon:", line)
		}
	}()
	return l
}

func (l *daemonLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return len(p), nil
	}
	l.partial = append(l.partial, p...)
	for {
		at := bytes.IndexByte(l.partial, '\n')
		if at < 0 {
			break
		}
		l.line(string(l.partial[:at]))
		l.partial = l.partial[at+1:]
	}
	if len(l.partial) > 4<<10 {
		l.line(string(l.partial))
		l.partial = nil
	}
	return len(p), nil
}

// line queues one line, cleaned and bounded.
func (l *daemonLog) line(raw string) {
	line := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(raw))
	if line == "" {
		return
	}
	line = line[:min(len(line), 240)]
	l.last = line
	if l.dropped > 0 {
		select {
		case l.lines <- fmt.Sprintf("(%d lines dropped)", l.dropped):
			l.dropped = 0
		default:
		}
	}
	select {
	case l.lines <- line:
	default:
		l.dropped++
	}
}

// close ends the forwarding once the daemon has exited and returns its last line.
func (l *daemonLog) close() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return l.last
	}
	if len(l.partial) > 0 {
		l.line(string(l.partial))
		l.partial = nil
	}
	l.closed = true
	close(l.lines)
	return l.last
}

type daemonKey struct {
	prover, verifier, verifierCA string
	plaintextFixture             bool
}

func daemonKeyOf(c config.Config) daemonKey {
	return daemonKey{c.Prover, c.Verifier, c.VerifierCA, c.VerifierPlaintextFixture}
}

// daemonReply is any reply; Type says which fields are set. "crashed" is
// made up here for the hops a dying daemon leaves behind.
type daemonReply struct {
	Type        string          `json:"type"`
	ID          string          `json:"id"`
	Version     int             `json:"version"`
	Summary     json.RawMessage `json:"summary"`
	Class       string          `json:"class"`
	Error       string          `json:"error"`
	Presented   bool            `json:"presented"`
	Diagnostics json.RawMessage `json:"diagnostics"`
}

type daemonHop struct {
	id        string
	final     chan daemonReply
	presented atomic.Bool
}

type webDaemon struct {
	key   daemonKey
	queue chan []byte
	stop  context.CancelFunc
	ready chan struct{}
	gone  chan struct{}
	once  sync.Once
	// log carries what the daemon says to the node's log: never a secret.
	log *daemonLog

	mu   sync.Mutex
	hops map[string]*daemonHop
	dead bool
	// stopped: the node ended it, rather than it dying on its own.
	stopped bool
	next    uint64
	pool    int
}

var webDaemons = struct {
	sync.Mutex
	running  map[daemonKey]*webDaemon
	starting map[daemonKey]bool
	crashes  map[daemonKey][]time.Time
}{running: map[daemonKey]*webDaemon{}, starting: map[daemonKey]bool{}, crashes: map[daemonKey][]time.Time{}}

// webBusy counts this process's web hops in flight, for the warm pool size.
var webBusy atomic.Int64

// webHopBusy marks one web hop (or a hop started before its accept) busy
// until the returned func runs, and keeps the daemon's warm pool at
// min(2, free web slots).
func webHopBusy(c config.Config) func() {
	webBusy.Add(1)
	updateWebPool(c)
	var once sync.Once
	return func() {
		once.Do(func() {
			webBusy.Add(-1)
			updateWebPool(c)
		})
	}
}

func webPoolSize(c config.Config) int {
	if RelayHalted() {
		return 0
	}
	return max(0, min(webWarmConnections, c.WebConcurrency-int(webBusy.Load())))
}

func updateWebPool(c config.Config) {
	webDaemons.Lock()
	d := webDaemons.running[daemonKeyOf(c)]
	webDaemons.Unlock()
	if d != nil {
		d.setPool(webPoolSize(c))
	}
}

// daemonFor returns the running daemon for c's prover and verifier,
// starting it if need be, or nil when hops should run one-shot.
func daemonFor(c config.Config) *webDaemon {
	if !webDaemonEnabled.Load() || c.Prover == "" || c.Verifier == "" || RelayHalted() {
		return nil
	}
	key := daemonKeyOf(c)
	webDaemons.Lock()
	if d := webDaemons.running[key]; d != nil {
		webDaemons.Unlock()
		return d
	}
	recent := webDaemons.crashes[key][:0]
	for _, at := range webDaemons.crashes[key] {
		if time.Since(at) < daemonCrashWindow {
			recent = append(recent, at)
		}
	}
	webDaemons.crashes[key] = recent
	// One start at a time; hops meanwhile run one-shot.
	if len(recent) >= daemonCrashLimit || webDaemons.starting[key] {
		webDaemons.Unlock()
		return nil
	}
	webDaemons.starting[key] = true
	webDaemons.Unlock()
	d := startDaemon(key)
	webDaemons.Lock()
	delete(webDaemons.starting, key)
	if d != nil {
		webDaemons.running[key] = d
	}
	webDaemons.Unlock()
	if d == nil {
		return nil
	}
	d.setPool(webPoolSize(c))
	return d
}

// StopWebDaemons ends every daemon: its stdin closes and it exits.
func StopWebDaemons() {
	webDaemons.Lock()
	running := webDaemons.running
	webDaemons.running = map[daemonKey]*webDaemon{}
	webDaemons.Unlock()
	for _, d := range running {
		d.fail(false)
	}
}

// startDaemon starts one and waits for its ready reply; nil if it does not
// come, which counts toward the crash limit.
func startDaemon(key daemonKey) *webDaemon {
	ctx, stop := context.WithCancel(context.Background())
	d := &webDaemon{key: key, queue: make(chan []byte, daemonQueue), stop: stop, ready: make(chan struct{}), gone: make(chan struct{}), hops: map[string]*daemonHop{}, pool: -1}
	cmd := exec.CommandContext(ctx, key.prover, "serve")
	if webDaemonVerbose {
		cmd.Env = append(os.Environ(), "SCARLETT_SERVE_LOG=1")
	}
	stdin, err := cmd.StdinPipe()
	// Stdout is a pipe of our own, closed only once the daemon has exited, so
	// its last replies (a presenting among them) are always read.
	stdoutR, stdoutW, pipeErr := os.Pipe()
	if err != nil || pipeErr != nil {
		stop()
		webDaemons.Lock()
		webDaemons.crashes[key] = append(webDaemons.crashes[key], time.Now())
		webDaemons.Unlock()
		return nil
	}
	d.log = newDaemonLog()
	cmd.Stdout, cmd.Stderr = stdoutW, d.log
	exited := make(chan struct{})
	go func() {
		process.Run(cmd)
		stdoutW.Close()
		close(exited)
	}()
	go func() {
		// A daemon that dies on its own says so, with its last line.
		<-exited
		last := d.log.close()
		d.mu.Lock()
		stopped := d.stopped
		d.mu.Unlock()
		if !stopped {
			fmt.Fprintln(os.Stderr, "web helper daemon ended:", last)
		}
	}()
	go d.write(stdin)
	go d.read(stdoutR)
	select {
	case <-d.ready:
		return d
	case <-d.gone:
		return nil
	case <-time.After(daemonReadyWait):
		d.fail(true)
		return nil
	}
}

// write sends queued requests in order; a write error ends the daemon.
func (d *webDaemon) write(stdin io.WriteCloser) {
	defer stdin.Close()
	for message := range d.queue {
		frame := binary.BigEndian.AppendUint32(nil, uint32(len(message)))
		if _, err := stdin.Write(append(frame, message...)); err != nil {
			d.fail(true)
			return
		}
	}
}

// read dispatches replies until the daemon's stdout ends.
func (d *webDaemon) read(stdout *os.File) {
	defer stdout.Close()
	var head [4]byte
	for {
		if _, err := io.ReadFull(stdout, head[:]); err != nil {
			break
		}
		size := binary.BigEndian.Uint32(head[:])
		if size > daemonMaxMessage {
			break
		}
		message := make([]byte, size)
		if _, err := io.ReadFull(stdout, message); err != nil {
			break
		}
		var reply daemonReply
		if json.Unmarshal(message, &reply) != nil {
			break
		}
		switch reply.Type {
		case "ready":
			if reply.Version != 1 {
				d.fail(true)
				return
			}
			d.once.Do(func() { close(d.ready) })
		case "presenting":
			d.mu.Lock()
			h := d.hops[reply.ID]
			if h != nil {
				h.presented.Store(true)
			}
			d.mu.Unlock()
			daemonDetail("hop %s: presenting (waited for: %v)", reply.ID, h != nil)
		case "summary", "error", "cancelled":
			d.mu.Lock()
			h := d.hops[reply.ID]
			delete(d.hops, reply.ID)
			d.mu.Unlock()
			daemonDetail("hop %s: %s %s (waited for: %v)", reply.ID, reply.Type, reply.Class, h != nil)
			if h != nil {
				h.final <- reply
			}
		}
	}
	d.fail(true)
}

// fail ends the daemon. Hops still waiting get a "crashed" reply saying
// whether their token was announced. An unexpected end counts toward the
// crash limit.
func (d *webDaemon) fail(crashed bool) {
	d.mu.Lock()
	if d.dead {
		d.mu.Unlock()
		return
	}
	d.dead = true
	d.stopped = !crashed
	hops := d.hops
	d.hops = map[string]*daemonHop{}
	close(d.queue)
	close(d.gone)
	d.mu.Unlock()
	for _, h := range hops {
		h.final <- daemonReply{Type: "crashed", ID: h.id, Presented: h.presented.Load()}
	}
	webDaemons.Lock()
	if webDaemons.running[d.key] == d {
		delete(webDaemons.running, d.key)
	}
	if crashed {
		webDaemons.crashes[d.key] = append(webDaemons.crashes[d.key], time.Now())
	}
	webDaemons.Unlock()
	// stdin closing ends it; the context makes sure.
	time.AfterFunc(2*time.Second, d.stop)
}

func (d *webDaemon) send(request any) error {
	message, err := json.Marshal(request)
	if err != nil || len(message) > daemonMaxMessage {
		return errors.New("web daemon request is invalid")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dead {
		return errors.New("web daemon is gone")
	}
	select {
	case d.queue <- message:
		return nil
	default:
		// Not reading its input: treat it as dead.
		go d.fail(true)
		return errors.New("web daemon is not keeping up")
	}
}

func (d *webDaemon) setPool(size int) {
	d.mu.Lock()
	changed := d.pool != size
	d.pool = size
	d.mu.Unlock()
	if changed {
		d.send(map[string]any{"type": "pool", "size": size, "verifier": d.key.verifier, "verifier_ca_file": nilIfEmpty(d.key.verifierCA), "plaintext_fixture": d.key.plaintextFixture})
	}
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// startHop sends a hop: with its token it runs at once, without one it
// waits for token or cancel. The daemon groups a job's hops by their token,
// so a redirect hop takes the connection its previous hop left.
func (d *webDaemon) startHop(in webHopInput) (*daemonHop, error) {
	d.mu.Lock()
	if d.dead {
		d.mu.Unlock()
		return nil, errors.New("web daemon is gone")
	}
	d.next++
	h := &daemonHop{id: "h" + strconv.FormatUint(d.next, 36), final: make(chan daemonReply, 1)}
	d.hops[h.id] = h
	d.mu.Unlock()
	if err := d.send(map[string]any{"type": "hop", "id": h.id, "input": in}); err != nil {
		d.forget(h.id)
		daemonDetail("hop %s: not sent: %v", h.id, err)
		return nil, err
	}
	daemonDetail("hop %s: sent (hop %d, token given: %v)", h.id, in.Hop, in.Token != "")
	return h, nil
}

func (d *webDaemon) token(h *daemonHop, token string) error {
	err := d.send(map[string]any{"type": "token", "id": h.id, "token": token})
	daemonDetail("hop %s: token sent (error: %v)", h.id, err)
	return err
}

// cancel ends a hop that has no token: it sends nothing and reaches no
// target. The daemon's answer is not waited for.
func (d *webDaemon) cancel(h *daemonHop) {
	err := d.send(map[string]any{"type": "cancel", "id": h.id})
	daemonDetail("hop %s: cancel sent (error: %v)", h.id, err)
}

func (d *webDaemon) forget(id string) {
	d.mu.Lock()
	delete(d.hops, id)
	d.mu.Unlock()
}

// wait returns the hop's final reply, or, when ctx ends first, a "timeout"
// that says whether its token was announced.
func (d *webDaemon) wait(ctx context.Context, h *daemonHop) daemonReply {
	select {
	case reply := <-h.final:
		return reply
	case <-ctx.Done():
		d.forget(h.id)
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			fmt.Fprintf(os.Stderr, "web daemon: hop %s gave no answer in its time (token presented: %v)\n", h.id, h.presented.Load())
		}
		return daemonReply{Type: "timeout", ID: h.id, Presented: h.presented.Load()}
	}
}

// run runs one hop with its token on the daemon. ok is false when the
// daemon died before announcing the token: nothing was sent, and the hop
// should run one-shot.
func (d *webDaemon) run(ctx context.Context, in webHopInput) (webHelperResult, bool) {
	h, err := d.startHop(in)
	if err != nil {
		return webHelperResult{}, false
	}
	return daemonResult(d.wait(ctx, h))
}

// daemonResult reads a final reply as a helper result; ok is false for a
// daemon that died before the token was announced.
func daemonResult(reply daemonReply) (webHelperResult, bool) {
	switch reply.Type {
	case "summary":
		return webHelperResult{fromDaemon: true, stdout: reply.Summary, dropped: len(reply.Summary) > maxWebStdout}, true
	case "error":
		return webHelperResult{fromDaemon: true, class: reply.Class, cause: reply.Error, diagnostics: reply.Diagnostics, err: errors.New("web hop failed")}, true
	case "crashed":
		if !reply.Presented {
			return webHelperResult{}, false
		}
		return webHelperResult{fromDaemon: true, class: "fetch_failed", cause: "web daemon ended during the session", err: errors.New("web daemon ended")}, true
	case "timeout":
		return webHelperResult{fromDaemon: true, class: "fetch_failed", cause: "web hop timed out", err: context.DeadlineExceeded}, true
	}
	return webHelperResult{fromDaemon: true, class: "fetch_failed", cause: "unexpected web daemon reply", err: errors.New("unexpected web daemon reply")}, true
}
