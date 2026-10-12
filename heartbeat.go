package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/update"
)

// heartbeatWatchInterval is how often the node rechecks, while the coordinator
// holds a heartbeat, whether what that heartbeat advertised still holds, and
// whether the wall clock jumped.
const heartbeatWatchInterval = time.Second

// heartbeatStatusRefresh is how often a pause between heartbeats rewrites
// status.json, well inside statusFresh.
const heartbeatStatusRefresh = 10 * time.Second

// availabilityTimeout bounds one availability post. One that fails ends the
// hold instead, so the next heartbeat carries the change.
const availabilityTimeout = 5 * time.Second

// goodbyePostWait is how long a goodbye waits for an availability post
// already on the wire, so that the coordinator sees the two in order. It is
// part of coordinator.GoodbyeTimeout.
const goodbyePostWait = 200 * time.Millisecond

// rejectTimeout bounds one offer rejection. A lost one costs the coordinator
// only the wait for its own timer.
const rejectTimeout = 5 * time.Second

// sleepPauseLimit is the longest the node holds its heartbeats after a sleep
// command when neither a wake command nor a wall-clock jump ends the pause
// first, such as when the machine never went to sleep.
var sleepPauseLimit = 60 * time.Second

// Causes a watch gives the held heartbeat it ends. None is a coordinator
// failure, so none earns a backoff.
var (
	// errHeartbeatStale: what the heartbeat advertised changed and could not
	// be posted as availability, so the next heartbeat carries it.
	errHeartbeatStale = errors.New("heartbeat availability changed and could not be posted")
	// errPollDrained: a drain began, or the drain marker became unreadable.
	errPollDrained = errors.New("heartbeat ended by a drain")
	// errPollStopping: the node is stopping.
	errPollStopping = errors.New("heartbeat ended by a stop")
	// errPollSleep: the owner said the machine is about to sleep.
	errPollSleep = errors.New("heartbeat ended for sleep")
	// errPollWake: the owner said the machine woke, or the wall clock jumped.
	errPollWake = errors.New("heartbeat ended on wake")
)

// errOwnerClosed is the stop cause when the desktop app closes the owner pipe.
var errOwnerClosed = errors.New("owner pipe closed")

// notifyStop is the context a run stops with on SIGTERM or Ctrl-C; tests
// replace it to stand in for a signal.
var notifyStop = func(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, syscall.SIGTERM, os.Interrupt)
}

// availability is every local input to a heartbeat's advertised state that can
// change while the coordinator holds it: an operator drain, a rest after the
// gateway ran out of capacity, the local Codex admission guard, a full
// attempt journal, and each service's health, including occupancy and active
// coordinator lease references.
type availability struct {
	drained, drainUnreadable, resting, codexBlocked, journalFull bool
	services                                                     string
}

// serviceStates snapshots service admission and occupancy. health returns
// services and active lease references in a stable order. The exact in-flight
// count and references matter even while a service remains offerable or blocked:
// the coordinator uses both to account for occupied capacity conservatively.
func serviceStates(health []coordinator.ServiceHealth) string {
	// ServiceHealth contains only JSON-safe scalar values and slices.
	snapshot, _ := json.Marshal(health)
	return string(snapshot)
}

// ownerCommand is one line the desktop app writes to the owner pipe of
// `desktop run`.
type ownerCommand int

const (
	ownerSleep ownerCommand = iota + 1 // the machine is about to sleep
	ownerWake                          // the machine woke up
)

// maxOwnerLine bounds one owner pipe line; a longer one is ignored.
const maxOwnerLine = 64

// readOwner reads the owner pipe: newline-delimited commands, of which sleep
// and wake go to commands and any other line is ignored. EOF or a read error
// is the app's Stop or Quit, which close the pipe; closed reports it. It
// gives up sending when done closes.
func readOwner(owner io.Reader, commands chan<- ownerCommand, done <-chan struct{}, closed func()) {
	defer closed()
	reader := bufio.NewReaderSize(owner, 256)
	for {
		line, err := readOwnerLine(reader)
		if err != nil {
			return
		}
		var command ownerCommand
		switch line {
		case "sleep":
			command = ownerSleep
		case "wake":
			command = ownerWake
		default:
			continue
		}
		select {
		case commands <- command:
		case <-done:
			return
		}
	}
}

// readOwnerLine returns the next line without its line ending or surrounding
// spaces. A line longer than maxOwnerLine comes back empty, so it is ignored;
// a last line without a newline is dropped with the EOF that ends it.
func readOwnerLine(r *bufio.Reader) (string, error) {
	var line []byte
	long := false
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > maxOwnerLine+2 {
			long = true
		} else {
			line = append(line, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return "", err
		}
		break
	}
	if long {
		return "", nil
	}
	return strings.TrimSpace(string(line)), nil
}

// clockReading is one look at both clocks.
type clockReading struct {
	wall time.Time     // the wall clock, without a monotonic reading
	mono time.Duration // the monotonic clock, since the process started
}

var processStart = time.Now()

// readClock looks at both clocks; tests replace it.
var readClock = func() clockReading {
	now := time.Now()
	return clockReading{wall: now.Round(0), mono: now.Sub(processStart)}
}

// wallClockJump is how much further than the monotonic clock the wall clock
// may move between two looks before the node takes it for a sleep. Monotonic
// clocks stop while macOS and Linux sleep; the wall clock does not.
const wallClockJump = 5 * time.Second

// clockWatch spots a sleep the owner pipe did not announce, such as on a
// headless Linux node: between two looks the wall clock moved more than
// wallClockJump further than the monotonic clock. A wall clock set back, or
// a process stopped while the machine ran, is no jump.
type clockWatch struct {
	mu   sync.Mutex
	last clockReading
	ok   bool
}

// jumped takes a look and reports whether the wall clock jumped ahead since
// the previous one.
func (w *clockWatch) jumped() bool {
	now := readClock()
	w.mu.Lock()
	defer w.mu.Unlock()
	jumped := w.ok && now.wall.Sub(w.last.wall)-(now.mono-w.last.mono) > wallClockJump
	w.last, w.ok = now, true
	return jumped
}

// pollWatch is what watchHeartbeat needs while one heartbeat is held.
type pollWatch struct {
	stop    context.Context // ends when the node is stopping
	sent    availability    // what the held heartbeat advertised
	current func() availability
	// changes wakes the check at once: worker completions and account
	// readiness. A web capacity change is one too.
	changes <-chan struct{}
	owner   <-chan ownerCommand
	clock   *clockWatch
	// post sends the node's availability now and returns what it advertised.
	post func(context.Context) (availability, error)
	// goodbye tells the coordinator the node is leaving, by the deadline.
	goodbye     func(reason string, deadline time.Time)
	stopReason  func() string
	drainReason func() string
}

// watchResult is how a watch ended its heartbeat.
type watchResult struct {
	cause      error  // nil when the heartbeat ended on its own
	goodbye    bool   // a goodbye was sent
	wakeReason string // owner or clock_jump, with errPollWake
}

type postResult struct {
	sent availability
	err  error
}

// watchHeartbeat runs while the coordinator holds a heartbeat. It never cuts
// the hold short because what the node advertises changed: it posts the new
// availability instead, at most every coordinator.AvailabilityInterval, and
// the coordinator looks for offers for the held heartbeat again. A worker
// completion or a readiness deadline wakes the check at once; an already
// reflected change posts nothing. It ends the hold itself only to leave:
// for a stop, a drain or a sleep it first says goodbye, within
// coordinator.GoodbyeTimeout, and then cancels; on a wake or a wall-clock jump
// it cancels so the node can heartbeat again on a fresh connection; and when a
// post fails it cancels so the next heartbeat carries the change.
func watchHeartbeat(ctx context.Context, cancel context.CancelCauseFunc, w pollWatch) watchResult {
	tick := time.NewTicker(heartbeatWatchInterval)
	defer tick.Stop()
	var ready <-chan time.Time
	if deadline := nextReady(w.sent); !deadline.IsZero() {
		timer := time.NewTimer(max(0, time.Until(deadline)))
		defer timer.Stop()
		ready = timer.C
	}
	due := time.NewTimer(time.Hour)
	due.Stop()
	defer due.Stop()
	advertised := w.sent
	var posting chan postResult
	var lastPost time.Time
	waiting := false
	end := func(cause error, reason string) watchResult {
		result := watchResult{cause: cause}
		if reason != "" {
			deadline := time.Now().Add(coordinator.GoodbyeTimeout)
			if posting != nil {
				// Let an availability post already on the wire land first.
				select {
				case <-posting:
				case <-time.After(goodbyePostWait):
				}
			}
			w.goodbye(reason, deadline)
			result.goodbye = true
		}
		cancel(cause)
		return result
	}
	for {
		select {
		case <-ctx.Done():
			return watchResult{}
		case <-w.stop.Done():
			return end(errPollStopping, w.stopReason())
		case command := <-w.owner:
			if command == ownerSleep {
				return end(errPollSleep, coordinator.GoodbyeSleep)
			}
			result := end(errPollWake, "")
			result.wakeReason = "owner"
			return result
		case <-tick.C:
			if w.clock.jumped() {
				result := end(errPollWake, "")
				result.wakeReason = "clock_jump"
				return result
			}
		case <-w.changes:
		case <-ready:
			ready = nil
		case <-due.C:
			waiting = false
		case result := <-posting:
			posting = nil
			if result.err != nil {
				return end(errHeartbeatStale, "")
			}
			advertised = result.sent
		}
		if ctx.Err() != nil {
			return watchResult{}
		}
		a := w.current()
		if a.drainUnreadable || a.drained && !advertised.drained {
			return end(errPollDrained, w.drainReason())
		}
		if a == advertised || posting != nil || waiting {
			continue
		}
		if wait := coordinator.AvailabilityInterval - time.Since(lastPost); !lastPost.IsZero() && wait > 0 {
			due.Reset(wait)
			waiting = true
			continue
		}
		lastPost = time.Now()
		posting = make(chan postResult, 1)
		go func(out chan<- postResult) {
			postCtx, cancelPost := context.WithTimeout(context.Background(), availabilityTimeout)
			defer cancelPost()
			sent, err := w.post(postCtx)
			out <- postResult{sent, err}
		}(posting)
	}
}

// nextReady is the earliest future readiness deadline an advertisement names.
func nextReady(sent availability) time.Time {
	var health []coordinator.ServiceHealth
	_ = json.Unmarshal([]byte(sent.services), &health)
	var deadline time.Time
	for _, service := range health {
		candidates := []*time.Time{service.NextReadyAt}
		for _, operation := range service.OperationAvailability {
			candidates = append(candidates, operation.NextReadyAt)
		}
		for _, at := range candidates {
			if at != nil && at.After(time.Now()) && (deadline.IsZero() || at.Before(deadline)) {
				deadline = *at
			}
		}
	}
	return deadline
}

// waitOutcome is how a pause between heartbeats ended.
type waitOutcome int

const (
	waitElapsed waitOutcome = iota // it ran its length
	waitStopped                    // the node is stopping
	waitWake                       // a wake command or a wall-clock jump
	waitSleep                      // a sleep command
)

// waitFor pauses d before the next heartbeat. The loop saves status.json once
// per heartbeat, but a pause can outlast statusFresh, so refresh runs when it
// starts and every heartbeatStatusRefresh while it lasts: a node that is only
// waiting never reads as offline. A stop, an owner command or a wall-clock
// jump ends it early; with waitWake it also says what woke the node.
func waitFor(ctx context.Context, d time.Duration, commands <-chan ownerCommand, clock *clockWatch, refresh func()) (waitOutcome, string) {
	if ctx.Err() != nil {
		return waitStopped, ""
	}
	refresh()
	timer := time.NewTimer(d)
	defer timer.Stop()
	save := time.NewTicker(heartbeatStatusRefresh)
	defer save.Stop()
	tick := time.NewTicker(heartbeatWatchInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return waitStopped, ""
		case <-timer.C:
			return waitElapsed, ""
		case <-save.C:
			refresh()
		case <-tick.C:
			if clock.jumped() {
				return waitWake, "clock_jump"
			}
		case command := <-commands:
			if command == ownerWake {
				return waitWake, "owner"
			}
			return waitSleep, ""
		}
	}
}

// drainGoodbyeReason is the goodbye reason for a drain that began: update
// while the desktop updater's install is draining the node (its
// update-state.json lives in the node's state directory), stop otherwise. A
// headless update keeps its state elsewhere, so its drain says stop and its
// service restart says signal.
func drainGoodbyeReason(stateDir string) string {
	s, err := update.StateFile{Path: filepath.Join(stateDir, "update-state.json")}.Read()
	if err == nil && s.Pending != nil && (s.Pending.Phase == update.PhaseDraining || s.Pending.Phase == update.PhaseHandoff) {
		return coordinator.GoodbyeUpdate
	}
	return coordinator.GoodbyeStop
}

// heartbeatCounters are this run's local heartbeat diagnostics. They are
// copied into status.json and never sent to the coordinator.
type heartbeatCounters struct {
	polls, failures, sleeps, wakes atomic.Int64
	lastPoll                       atomic.Int64
	mu                             sync.Mutex
	lastWakeAt                     time.Time
	lastWake                       string
}

func (h *heartbeatCounters) wake(reason string) {
	h.wakes.Add(1)
	h.mu.Lock()
	h.lastWakeAt, h.lastWake = time.Now().UTC(), reason
	h.mu.Unlock()
}

func (h *heartbeatCounters) snapshot(stats coordinator.Stats) *heartbeatDiagnostics {
	d := &heartbeatDiagnostics{Polls: h.polls.Load(), Failures: h.failures.Load(), LastPollMS: time.Duration(h.lastPoll.Load()).Milliseconds(),
		RTTMS: stats.RTT.Milliseconds(), Reconnects: max(0, stats.Connections-1), AvailabilityPosts: stats.AvailabilityPosts,
		Goodbyes: stats.Goodbyes, RejectedOffers: stats.Rejections, Sleeps: h.sleeps.Load(), Wakes: h.wakes.Load()}
	h.mu.Lock()
	if !h.lastWakeAt.IsZero() {
		at := h.lastWakeAt
		d.LastWakeAt, d.LastWake = &at, h.lastWake
	}
	h.mu.Unlock()
	return d
}
