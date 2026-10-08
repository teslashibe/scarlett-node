package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"github.com/teslashibe/scarlett-node/internal/diagnostics"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/worker"
)

type identity struct {
	NodeID         string `json:"node_id"`
	SupplierPubkey string `json:"supplier_pubkey"`
	Credential     string `json:"credential"`
}

func main() {
	if err := start(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func start(args []string) error {
	if len(args) > 0 && args[0] == "desktop" {
		return desktopCommand(args[1:], os.Stdin, os.Stdout)
	}
	if len(args) > 0 && args[0] == "accounts" {
		return accountsCommand(args[1:], os.Stdin, os.Stdout)
	}
	if len(args) > 0 && args[0] == "web-runtime" {
		return webRuntimeCommand(args[1:], os.Stdout)
	}
	if len(args) != 1 {
		return errors.New("usage: scarlett-node pair|run|status|diagnostics|drain|resume|relay-resume|accounts|web-runtime")
	}
	if args[0] == "status" || args[0] == "diagnostics" || args[0] == "drain" || args[0] == "resume" || args[0] == "relay-resume" {
		return localCommand(args[0], os.Stdout)
	}
	if args[0] != "pair" && args[0] != "run" {
		return errors.New("usage: scarlett-node pair|run|status|diagnostics|drain|resume|relay-resume|accounts|web-runtime")
	}
	c, err := config.Load()
	if err != nil {
		return err
	}
	if args[0] == "pair" {
		return pair(c)
	}
	return run(c)
}
func identityPath(c config.Config) string { return filepath.Join(c.StateDir, "identity.json") }
func pair(c config.Config) error {
	if err := prepareStateDir(c.StateDir); err != nil {
		return err
	}
	if _, err := os.Lstat(identityPath(c)); err == nil {
		return errors.New("already paired; refusing to overwrite credentials")
	} else if !os.IsNotExist(err) {
		return err
	}
	fmt.Fprintln(os.Stderr, "Enter one-time pairing code:")
	code, err := readProtectedPairCode(os.Stdin)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	client, err := coordinator.NewWithCA(c.Coordinator, "", c.CoordinatorCA)
	if err != nil {
		return err
	}
	var reply coordinator.PairReply
	_, err = client.Post(context.Background(), "/api/node/v1/pair", map[string]string{"version": coordinator.Version, "code": code, "profile": c.Profile}, &reply)
	if err != nil {
		return err
	}
	if reply.Version != coordinator.Version || !validIdentityField(reply.NodeID, 128) || !validIdentityField(reply.SupplierPubkey, 128) || !validIdentityField(reply.Credential, 4096) {
		return errors.New("invalid pairing response")
	}
	if err = saveIdentity(c, identity{reply.NodeID, reply.SupplierPubkey, reply.Credential}); err != nil {
		return err
	}
	fmt.Printf("Paired node %s (supplier %s)\n", reply.NodeID, reply.SupplierPubkey)
	return nil
}
func loadIdentity(c config.Config) (identity, error) {
	var id identity
	if err := localfs.CheckDir(c.StateDir); err != nil {
		return id, err
	}
	f, err := localfs.OpenPrivate(identityPath(c))
	if err != nil {
		return id, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return id, err
	}
	if len(data) > 8192 {
		return id, errors.New("identity too large")
	}
	if err = json.Unmarshal(data, &id); err != nil {
		return id, err
	}
	if id.Credential == "" || id.NodeID == "" {
		return id, errors.New("incomplete identity")
	}
	return id, nil
}

// capacityRest is how long a node without an account pool reports "exhausted"
// after its gateway or prover had no capacity. An account pool rests only the
// account that ran out (settle), and reuses this as the unreachable retry delay.
const capacityRest = 30 * time.Second

// restsNode reports whether a job outcome rests the whole node. Without an
// account pool the node is the only unit that can rest. With one, settle has
// already exhausted just the account that ran out, for its known reset or 15
// minutes; a node-wide rest would also stop the node's other services and
// accounts, which have their own quota.
func restsNode(pooled bool, code string) bool {
	return code == "capacity_unavailable" && !pooled
}

// webWorker builds the web worker for one lease; tests replace it to inject a
// resolver, egress guard, browser tier or upload.
var webWorker = func(c config.Config) worker.Web { return worker.Web{Config: c} }

// nodeBrowser holds this process's browser tier while run serves web with the
// browser on; it is empty otherwise.
var nodeBrowser atomic.Value

type browserHolder struct{ tier worker.BrowserTier }

func setNodeBrowser(tier worker.BrowserTier) { nodeBrowser.Store(browserHolder{tier}) }

// currentBrowser is the running browser tier, or nil.
func currentBrowser() worker.BrowserTier {
	held, _ := nodeBrowser.Load().(browserHolder)
	return held.tier
}

// heartbeatWatchInterval is how often the node rechecks, while the coordinator
// holds a heartbeat, whether what that heartbeat advertised still holds.
const heartbeatWatchInterval = time.Second

// errHeartbeatStale ends a held heartbeat whose advertised availability the
// node has since changed. It is not a coordinator failure and earns no backoff.
var errHeartbeatStale = errors.New("heartbeat availability changed while held")

// Failed heartbeats back off from heartbeatBackoffBase, doubling to
// heartbeatBackoffCap: well inside the coordinator's 30-second staleness rule,
// so no single pause outlasts a node's freshness at the coordinator.
const (
	heartbeatBackoffBase = time.Second
	heartbeatBackoffCap  = 15 * time.Second
)

// heartbeatBackoff paces heartbeats after consecutive failures. Each pause has
// equal jitter: half the current step, never under heartbeatBackoffBase, plus
// a random share of the other half, so even the first pause is spread over
// one to one and a half seconds. Nodes that failed together, as when a
// coordinator crashes or a proxy drops every held heartbeat at once, come back
// spread out instead of in one wave. An answered heartbeat resets it.
type heartbeatBackoff struct {
	step time.Duration
	// fixed replaces the schedule with one constant pause (the local fixture).
	fixed time.Duration
	// jitter returns a duration in [0, n]; nil draws it uniformly. Tests pin it.
	jitter func(n time.Duration) time.Duration
}

// next is the pause after a failed heartbeat. A 429 or 503 that carries
// Retry-After waits at least that long, clamped, plus jitter.
func (b *heartbeatBackoff) next(err error) time.Duration {
	wait := b.fixed
	if wait == 0 {
		b.step = min(max(2*b.step, heartbeatBackoffBase), heartbeatBackoffCap)
		half := max(b.step/2, heartbeatBackoffBase)
		spread := b.step - b.step/2
		if b.jitter != nil {
			wait = half + min(max(b.jitter(spread), 0), spread)
		} else {
			wait = half + rand.N(spread+1)
		}
	}
	var status *coordinator.StatusError
	if errors.As(err, &status) && (status.Status == http.StatusTooManyRequests || status.Status == http.StatusServiceUnavailable) && status.RetryAfter > 0 {
		wait = max(wait, coordinator.RetryAfterWait(status.RetryAfter))
	}
	return wait
}

func (b *heartbeatBackoff) reset() { b.step = 0 }

// newHeartbeatBackoff is the run loop's failure pacing: the full schedule, or
// one fixed second for the local fixture. Tests replace it to observe the
// schedule the loop drives.
var newHeartbeatBackoff = func(localFixture bool) heartbeatBackoff {
	if localFixture {
		return heartbeatBackoff{fixed: time.Second}
	}
	return heartbeatBackoff{}
}

// heartbeatStatusRefresh is how often a pause between heartbeats rewrites
// status.json, well inside statusFresh.
const heartbeatStatusRefresh = 10 * time.Second

// waitRefreshing waits d, calling refresh when it starts and every interval
// meanwhile. It reports false if ctx ended first.
func waitRefreshing(ctx context.Context, d, every time.Duration, refresh func()) bool {
	if ctx.Err() != nil {
		return false
	}
	refresh()
	timer := time.NewTimer(d)
	defer timer.Stop()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		case <-ticker.C:
			refresh()
		}
	}
}

// availability is every local input to a heartbeat's advertised state that can
// change while the coordinator holds it: an operator drain, a rest after the
// gateway ran out of capacity, the local Codex admission guard, and each
// service's health, including occupancy and active coordinator lease references.
type availability struct {
	drained, drainUnreadable, resting, codexBlocked bool
	services                                        string
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

// watchHeartbeat cancels a held heartbeat with errHeartbeatStale as soon as
// current() no longer matches what it advertised. A worker completion wakes the
// check immediately; an already reflected completion leaves the heartbeat held.
// Otherwise the coordinator could see the old state for HeartbeatWaitSeconds
// or return a lease after admission stopped.
func watchHeartbeat(ctx context.Context, cancel context.CancelCauseFunc, sent availability, current func() availability, changes <-chan struct{}) {
	tick := time.NewTicker(heartbeatWatchInterval)
	defer tick.Stop()
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
	var ready <-chan time.Time
	if !deadline.IsZero() {
		timer := time.NewTimer(max(0, time.Until(deadline)))
		defer timer.Stop()
		ready = timer.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-changes:
		case <-ready:
			ready = nil
		}
		if current() != sent {
			cancel(errHeartbeatStale)
			return
		}
	}
}

// xKeepInterval is how often the node checks that every X account still has a
// warm client. A check reads session files only, unless a build is due.
const xKeepInterval = 15 * time.Second

// keepXClientsWarm builds each usable X account's client once, one at a time,
// then on every tick evicts the clients of accounts the pool no longer holds,
// starts a background build for an account that has none and confirms the
// accounts that have one. The pool calls
// return before the cache is called, so no build ever runs under the pool lock.
func keepXClientsWarm(ctx context.Context, c config.Config, clients *worker.XClients, pool *servicePool, every time.Duration) {
	clients.Warm(ctx, c, pool.xAccounts())
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			clients.Retain(pool.xSessionPaths())
			clients.Ensure(c, pool.xAccounts())
		}
	}
}

// startXKeeper runs keepXClientsWarm and returns the function that ends it.
// That function returns only once the keeper has, so a check already under way
// cannot create a client after the cache is stopped.
func startXKeeper(ctx context.Context, c config.Config, clients *worker.XClients, pool *servicePool, every time.Duration) (stop func()) {
	clients.RefreshAdmission(pool.xRefreshAllowed)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		keepXClientsWarm(ctx, c, clients, pool, every)
	}()
	return func() { cancel(); <-done }
}

func run(c config.Config) error {
	return runWithOwner(c, nil)
}
func runWithOwner(c config.Config, owner io.Reader) error {
	if err := prepareStateDir(c.StateDir); err != nil {
		return err
	}
	// A relay halt from an earlier run stays in force until the operator
	// clears it; a restart alone must not re-arm relay.
	if err := worker.LoadRelayHalt(c.StateDir); err != nil {
		return err
	}
	journal, err := attempts.OpenWithLimits(filepath.Join(c.StateDir, "attempts"), c.JournalLimits)
	if err != nil {
		return err
	}
	defer journal.Close()
	cred, nodeID := c.Credential, c.NodeID
	if cred == "" {
		id, err := loadIdentity(c)
		if err != nil {
			return err
		}
		cred, nodeID = id.Credential, id.NodeID
	} else if nodeID == "" {
		return errors.New("SCARLETT_NODE_ID required with SCARLETT_CREDENTIAL")
	}
	client, err := coordinator.NewWithCA(c.Coordinator, cred, c.CoordinatorCA)
	if err != nil {
		return err
	}
	if c.LocalFixture {
		client.EchoUnqualifiedHTTP = true
	}
	// The heartbeat is a long poll: while idle the coordinator holds it for
	// HeartbeatWaitSeconds and answers the moment a job is funded, so the loop
	// adds no delay of its own. failures paces heartbeats after a failure, and
	// drainRejectDelay is the pause after rejecting a lease during a drain.
	failures := newHeartbeatBackoff(c.LocalFixture)
	drainRejectDelay := 5 * time.Second
	if c.LocalFixture {
		drainRejectDelay = time.Second
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	if owner != nil {
		go func() { _, _ = io.Copy(io.Discard, owner); stop() }()
	}
	defer stop()
	workCtx, cancelWork := context.WithCancel(context.Background())
	defer cancelWork()
	var diagnosticStore *diagnostics.Store
	if !c.DiagnosticsDisabled {
		diagnosticStore = diagnostics.New(c.StateDir)
		diagnosticCtx, cancelDiagnostics := context.WithCancel(context.Background())
		go diagnosticStore.Run(diagnosticCtx)
		defer func() { cancelDiagnostics(); diagnosticStore.Close() }()
	}
	if err := journal.Purge(time.Now()); err != nil {
		return err
	}
	pending, err := journal.Pending()
	if err != nil {
		return err
	}
	for _, record := range pending {
		if err := recoverAttempt(ctx, client, journal, record); err != nil {
			fmt.Fprintln(os.Stderr, "reconcile:", err)
		}
	}
	// Whatever is still pending was left by an earlier process, whose helper
	// may outlive it. This process's own attempts are tracked as active work.
	inherited, err := journal.Pending()
	if err != nil {
		return err
	}
	inheritedKeys := map[string]bool{}
	for _, record := range inherited {
		inheritedKeys[record.Key()] = true
	}
	active := &activeAttempts{}
	var local worker.Completer
	if c.Executor == config.ExecutorCodex {
		cx, err := worker.NewCodex(c)
		if err != nil {
			return err
		}
		local = cx
	}
	capacity := max(c.Concurrency, 1)
	availabilityChanges := make(chan struct{}, 1)
	var services *servicePool
	if c.Executor == config.ExecutorServices {
		services = newServicePool(c)
		services.availabilityChanges = availabilityChanges
		services.xRecovery = inheritedPending(journal.Pending, inheritedKeys)
		services.xEligibility = worker.DefaultXClients().NextEligibility
		// The static slot ceiling is read before renewal can adjust health.
		capacity = services.capacity()
		stopRenewal := services.startCodexRenewal(ctx, managedAuthenticationFactory, inheritedPending(journal.Pending, inheritedKeys))
		defer stopRenewal()
		// Build each X account's client now and keep it warm from then on, so a
		// job does only its proven read; each validated build's outcome becomes
		// the account's advertised state.
		stopKeeping := func() {}
		if c.Enabled("x_read") {
			worker.DefaultXClients().ObserveIdentity(services.xIdentityValidated)
			worker.DefaultXClients().Observe(services.xValidated)
			stopKeeping = startXKeeper(workCtx, c, worker.DefaultXClients(), services, xKeepInterval)
		}
		defer func() {
			stopKeeping()
			worker.DefaultXClients().Stop()
		}()
		if c.Enabled("web") {
			// NAT64 prefixes and local addresses are kept fresh off the job path.
			go worker.KeepWebEgressFresh(workCtx)
		}
		if c.Enabled("web") && c.WebBrowser {
			// The tier prepares its runtime and browser in the background and
			// reports browser_downloading and the like until it is ready. It
			// stops after the workers, whose deferred wait runs first.
			tier, stopBrowser := startBrowserTier(workCtx, c)
			defer stopBrowser()
			services.browser = tier
			setNodeBrowser(tier)
			defer setNodeBrowser(nil)
		}
	}
	slots := make(chan struct{}, capacity)
	var running sync.WaitGroup
	status := runtimeStatus{Version: coordinator.Version, State: "running", NodeID: nodeID, Release: coordinator.NodeRelease, Services: []coordinator.ServiceHealth{}}
	defer func() {
		status.State = "draining"
		status.InFlight = len(slots)
		if services != nil {
			status.Services = services.health()
			status.Accounts = services.accountStatus()
		}
		_ = saveRuntimeStatus(c.StateDir, status)
		waitForWorkers(&running, cancelWork, 2*time.Minute)
		status.State = "stopped"
		status.InFlight = 0
		if records, err := journal.Pending(); err == nil {
			status.UnresolvedAttempts = len(records)
		}
		if services != nil {
			status.Services = services.health()
			status.Accounts = services.accountStatus()
		}
		_ = saveRuntimeStatus(c.StateDir, status)
	}()
	var mu sync.Mutex
	var restUntil time.Time
	inFlight := map[string]struct{}{}
	legacyCodexBlocked := false
	// currentAvailability rereads, without the loop's side effects, what a
	// heartbeat's advertised state is built from.
	currentAvailability := func() availability {
		drained, err := drainRequested(c.StateDir)
		if err != nil {
			// Never equal to what a heartbeat advertised: the hold ends and
			// the loop reports the unreadable marker.
			return availability{drainUnreadable: true}
		}
		mu.Lock()
		resting := time.Now().Before(restUntil)
		mu.Unlock()
		a := availability{drained: drained, resting: resting, codexBlocked: legacyCodexAdmissionBlocked(c, time.Now())}
		if services != nil {
			a.services = serviceStates(services.health())
		}
		return a
	}
	// pause waits d before the next heartbeat and reports false if the node is
	// stopping. The loop saves status.json once per heartbeat, but a pause can
	// outlast statusFresh (a Retry-After asks for up to 90 seconds with
	// jitter), so the snapshot is saved again when a pause starts and every
	// heartbeatStatusRefresh while it lasts: a node that is only waiting never
	// reads as offline.
	pause := func(d time.Duration) bool {
		return waitRefreshing(ctx, d, heartbeatStatusRefresh, func() { _ = saveRuntimeStatus(c.StateDir, status) })
	}
	lastRecovery := time.Now()
	for ctx.Err() == nil {
		drained, err := drainRequested(c.StateDir)
		if err != nil {
			return err
		}
		if time.Since(lastRecovery) >= 30*time.Second {
			if err := journal.Purge(time.Now()); err != nil {
				return err
			}
			if err := reconcileIdle(ctx, client, journal, active.snapshot()); err != nil {
				return err
			}
			lastRecovery = time.Now()
		}
		mu.Lock()
		state := "available"
		resting := time.Now().Before(restUntil)
		if resting {
			state = "exhausted"
		}
		mu.Unlock()
		// Legacy reports have no typed service health and node-v1 requires
		// their capacity to stay positive; exhausted alone stops dispatch.
		if blocked := legacyCodexAdmissionBlocked(c, time.Now()); blocked != legacyCodexBlocked {
			legacyCodexBlocked = blocked
			if blocked {
				fmt.Fprintln(os.Stderr, "codex: local credential cannot cover a funded offer; advertising exhausted until it is renewed")
			}
		}
		if legacyCodexBlocked {
			state = "exhausted"
		}
		h := coordinator.Heartbeat{Version: coordinator.Version, NodeID: nodeID, Profile: c.Profile, State: state, Bid: c.Bid, Capacity: capacity, WaitSeconds: coordinator.HeartbeatWaitSeconds}
		sent := availability{drained: drained, resting: resting, codexBlocked: legacyCodexBlocked}
		if services != nil {
			h.Services = services.health()
			sent.services = serviceStates(h.Services)
			h.Capacity = 0
			for _, service := range h.Services {
				h.Capacity += service.Capacity
				if service.ConfiguredCapacity != nil {
					h.Capacity += *service.ConfiguredCapacity - service.Capacity
				}
			}
			h.State = "exhausted"
			for _, s := range h.Services {
				if (s.State == "configured" || s.State == "ready") && s.InFlight < s.Capacity {
					h.State = "available"
				}
				for _, operation := range s.OperationAvailability {
					if (s.State == "configured" || s.State == "ready") && operation.RunnableCapacity > 0 {
						h.State = "available"
					}
				}
			}
		}
		status.State = "running"
		if drained {
			h.State = "exhausted"
			status.State = "draining"
		}
		if drained || resting {
			blockOperationAvailability(h.Services)
		}
		journalCapacity, err := journal.Capacity()
		if err != nil {
			return err
		}
		status.JournalCapacity = &journalCapacity
		// In-flight goroutines may not have called Begin yet. Reserve one
		// additional slot for each before advertising new admission capacity.
		// Finished receipts count only if recent ones fill terminal storage.
		journalFull := journalCapacity.AvailableRecords <= len(slots)
		if journalFull != status.JournalFull {
			if journalFull {
				fmt.Fprintln(os.Stderr, "journal: receipt journal full; advertising exhausted until receipts clear")
			} else {
				fmt.Fprintln(os.Stderr, "journal: receipt journal has room again")
			}
		}
		status.JournalFull = journalFull
		if journalFull {
			h.State = "exhausted"
			for i := range h.Services {
				h.Services[i].State = "exhausted"
			}
			blockOperationAvailability(h.Services)
		}
		status.Services = h.Services
		if services != nil {
			status.Accounts = services.accountStatus()
		}
		status.InFlight = len(slots)
		if records, err := journal.Pending(); err != nil {
			return err
		} else {
			status.UnresolvedAttempts = len(records)
		}
		status.RelayHalted = worker.RelayHalted()
		status.observeRelease(client.Release())
		if err := saveRuntimeStatus(c.StateDir, status); err != nil {
			return err
		}
		// The coordinator may hold this heartbeat for HeartbeatWaitSeconds. If
		// the node changes what it advertised meanwhile, end the hold so the
		// next heartbeat carries the change at once. A lease answered in that
		// same instant is lost as on a dropped connection, and its offer
		// expires at the coordinator.
		pollCtx, cancelPoll := context.WithCancelCause(ctx)
		watched := make(chan struct{})
		go func() {
			defer close(watched)
			watchHeartbeat(pollCtx, cancelPoll, sent, currentAvailability, availabilityChanges)
		}()
		reply, err := client.Poll(pollCtx, h)
		stale := err != nil && errors.Is(context.Cause(pollCtx), errHeartbeatStale)
		cancelPoll(nil)
		<-watched
		if stale {
			// The node cut the hold short itself: heartbeat again now, with
			// the new state, rather than backing off as after a failure.
			continue
		}
		if err != nil {
			// A rejected heartbeat (400 or 413) is logged and backed off like
			// any other failure; the node never resends it in a reduced shape.
			fmt.Fprintln(os.Stderr, "heartbeat:", err)
		} else if reply.Lease != nil {
			failures.reset()
			status.LastHeartbeatAt = time.Now().UTC()
			// Read again after polling: drain may have arrived while the request
			// was in flight. Never start newly delivered work while draining.
			drained, err = drainRequested(c.StateDir)
			if err != nil {
				return err
			}
			if drained || ctx.Err() != nil {
				// The acceptance is sent once, never retried: it only precedes
				// an immediate service_unavailable report, and a busy
				// coordinator must not hold up the next heartbeat or a stop.
				if err := rejectLease(coordinator.WithoutAcceptRetry(workCtx), client, journal, *reply.Lease, "service_unavailable"); err != nil {
					fmt.Fprintln(os.Stderr, "drain rejection:", err)
				}
				if !pause(drainRejectDelay) {
					return nil
				}
				continue
			}
			l := *reply.Lease
			// The node heartbeats again the instant it holds an offer, while the
			// attempt is still being accepted. The coordinator leaves a
			// just-delivered offer out of that heartbeat, but another API process
			// may hand it over once more; an attempt already running here is
			// never started twice.
			mu.Lock()
			_, duplicate := inFlight[l.JobID]
			if !duplicate {
				inFlight[l.JobID] = struct{}{}
			}
			mu.Unlock()
			if duplicate {
				continue
			}
			observation := beginLeaseDiagnostics(diagnosticStore, l)
			attemptCtx := observation.Context(workCtx)
			endWorkerAcquire := diagnostics.Start(attemptCtx, "worker_acquire", 0)
			// The coordinator counts this node's open leases against its capacity,
			// so a slot frees up as soon as an earlier result is recorded.
			select {
			case slots <- struct{}{}:
				endWorkerAcquire("success")
			case <-ctx.Done():
				endWorkerAcquire("cancelled")
				observation.Finish("cancelled")
				mu.Lock()
				delete(inFlight, l.JobID)
				mu.Unlock()
				return nil
			}
			selected := c
			var account *accountLease
			serviceAvailable := true
			if services != nil {
				endAccountAcquire := diagnostics.Start(attemptCtx, "account_acquire", 0)
				if l.ServiceType == "x_read" && l.XRequest != nil {
					account, serviceAvailable = services.acquireAccount(l.ServiceType, l.XRequest.Operation)
				} else if l.ServiceType == "web" && l.WebRequest != nil && l.WebRequest.Mode == "browser" {
					// A browser job holds a browser slot inside its web slot.
					account, serviceAvailable = services.acquireAccount(l.ServiceType, "browser")
				} else {
					account, serviceAvailable = services.acquireAccount(l.ServiceType)
				}
				if serviceAvailable {
					endAccountAcquire("success")
				} else {
					endAccountAcquire("service_unavailable")
				}
				if serviceAvailable {
					services.bindCoordinatorLease(account, l)
					selected = account.config
				}
			}
			// Only this loop adds keys, so its reconciliation snapshot covers
			// every attempt a worker may still be executing.
			key := attempts.Record{JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence}.Key()
			active.add(key)
			running.Add(1)
			go func() {
				defer running.Done()
				defer active.done(key)
				defer func() {
					<-slots
					// Account release and any node-wide rest are already final. Refresh
					// the held heartbeat's capacity and active lease references now
					// that the worker slot is free. Completions coalesce while the
					// loop prepares its next heartbeat.
					select {
					case availabilityChanges <- struct{}{}:
					default:
					}
				}()
				defer func() {
					mu.Lock()
					delete(inFlight, l.JobID)
					mu.Unlock()
				}()
				var code string
				var err error
				if !serviceAvailable {
					code = "service_unavailable"
					if l.AcceptanceRequired && (l.ServiceType == "codex" || l.ServiceType == "x_read" || l.ServiceType == "web") {
						// No selected valid profile: leave the unaccepted offer to
						// expire rather than funding it through rejectLease.
						err = errors.New("provider offer has no locally eligible account")
					} else {
						err = rejectLease(attemptCtx, client, journal, l, code)
					}
				} else {
					code, err = submitLease(attemptCtx, client, selected, l, local, journal)
					if services != nil {
						if err != nil && code == "" {
							services.finishAccount(account, "report_pending")
						} else {
							services.finishAccount(account, code)
						}
					}
				}
				observation.Finish(diagnosticOutcome(attemptCtx, code, err))
				if restsNode(services != nil, code) {
					mu.Lock()
					restUntil = time.Now().Add(capacityRest)
					mu.Unlock()
				}
				if err != nil {
					fmt.Fprintln(os.Stderr, "submit:", err)
				} else if c.LocalFixture {
					fmt.Printf("fixture job %s: %s\n", l.JobID, map[bool]string{true: "failed (" + code + ")", false: "submitted"}[code != ""])
				}
			}()
			// Heartbeat again at once: the coordinator may hold more work.
			continue
		} else {
			// An idle hold ended with nothing to do; the next long poll is the
			// wait, so loop straight into it. A coordinator that is shutting
			// down answers at once and asks, with Retry-After, for a pause.
			failures.reset()
			status.LastHeartbeatAt = time.Now().UTC()
			if reply.RetryAfter > 0 && !pause(coordinator.RetryAfterWait(reply.RetryAfter)) {
				return nil
			}
			continue
		}
		if !pause(failures.next(err)) {
			return nil
		}
	}
	return nil
}

func submitLease(ctx context.Context, client *coordinator.Client, c config.Config, l coordinator.Lease, local worker.Completer, journal *attempts.Journal) (string, error) {
	if !c.LocalFixture && (c.Executor == config.ExecutorServices || c.Executor == config.ExecutorCodexTLSN) && !l.AcceptanceRequired {
		return "invalid_lease", errors.New("community provider work requires funded acceptance")
	}
	if _, err := coordinator.JobPath(l.JobID, "result"); err != nil {
		return "invalid_lease", err
	}
	// Decline a proof mode this node does not serve before accepting funds for it.
	if l.ServiceType == "x_read" && !worker.XOfferServable(c, l.XPayload) {
		return "invalid_lease", errors.New("x_read offer asks for a proof mode this node does not serve")
	}
	// For a browser offer, or a relay offer with the pre-warm hint, this also
	// starts the browser while the node accepts.
	if l.ServiceType == "web" && !worker.WebOfferServable(c, l, currentBrowser()) {
		return "invalid_lease", errors.New("web offer asks for a proof mode this node does not serve")
	}
	record, err := attemptRecord(l)
	if err != nil {
		return "invalid_lease", err
	}
	if c.LocalAccountID != "" {
		record.ProviderAccountID, record.ProviderService = c.LocalAccountID, l.ServiceType
	}
	// Offer terms are checked before the journal: nothing is bound to an
	// account or sent yet, so a refused offer leaves no record and a
	// redelivery is judged afresh. rejectLease would fund acceptance.
	if l.AcceptanceRequired {
		if err := coordinator.ValidOffer(l, time.Now()); err != nil {
			return "invalid_lease", err
		}
	}
	if err := journal.BeginContext(ctx, record); err != nil {
		return "", err
	}
	if l.AcceptanceRequired {
		// No acceptance HTTP or provider execution happens on either local
		// refusal below. Keep terminal replay metadata for this pinned attempt;
		// let its offer expire remotely.
		if l.ServiceType == "codex" && !codexAdmissionValid(c.CodexHome, l.LeaseDeadline) {
			// The offer itself is valid, so the selected local credential is what
			// fell short. This is local expiry evidence, never a provider denial.
			if err := journal.TerminalContext(ctx, record); err != nil {
				return codexLocalAuthExpired, err
			}
			return codexLocalAuthExpired, errors.New("Codex credential validity is insufficient for the offered deadline")
		}
		if l.ServiceType == "x_read" && (l.XRequest == nil || c.AccountReady != nil && !c.AccountReady(l.XRequest.Operation)) {
			if err := journal.TerminalContext(ctx, record); err != nil {
				return "service_unavailable", err
			}
			return "service_unavailable", errors.New("X account eligibility changed before acceptance")
		}
		// Persist uncertainty before acceptance HTTP. A lost acknowledgement
		// keeps this journal pending; recovery never re-executes the provider.
		endAccept := diagnostics.Start(ctx, "accept_http", 0)
		l, err = client.Accept(ctx, l)
		endAccept(diagnosticOutcome(ctx, "", err))
		if err != nil {
			return "", err
		}
	}
	provenExecutor := c.Executor == config.ExecutorCodexTLSN || c.Executor == config.ExecutorServices
	if l.AcceptanceRequired && provenExecutor {
		if limit := worker.ProofSampleLimit(c, l); limit > 0 {
			ctx = worker.WithProofObserver(ctx, func() (func(attempts.ProofSample) error, error) {
				ordinal, err := journal.BeginProofContext(ctx, record, limit)
				if err != nil {
					return nil, err
				}
				return func(sample attempts.ProofSample) error {
					sample.Ordinal = ordinal
					return journal.CompleteProofContext(ctx, record, sample)
				}, nil
			})
		}
	}
	var body any
	code := ""
	endWorker := diagnostics.Start(ctx, "worker", 0)
	if c.Executor == config.ExecutorCodexTLSN || c.Executor == config.ExecutorServices {
		var detail string
		if c.Executor == config.ExecutorServices && !c.Enabled(l.ServiceType) {
			code = "service_unavailable"
		} else if c.Executor == config.ExecutorServices && l.ServiceType == "x_read" {
			code = worker.X{Config: c}.Run(ctx, l)
		} else if c.Executor == config.ExecutorServices && l.ServiceType == "web" {
			w := webWorker(c)
			if w.Browser == nil {
				w.Browser = currentBrowser()
			}
			if w.Upload == nil && client != nil {
				w.Upload = logBrowserUpload(client.UploadBrowserResult, os.Stderr)
			}
			code = w.Run(ctx, l)
		} else {
			code, detail = worker.Prover{Config: c}.Run(ctx, l)
		}
		if detail != "" && c.Executor != config.ExecutorServices {
			fmt.Fprintln(os.Stderr, detail)
		}
		if code != "" {
			body = coordinator.Failure{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence, Code: code}
		} else {
			body = coordinator.Proven{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence}
		}
	} else {
		var result coordinator.Result
		if c.Executor == config.ExecutorCodex {
			result, code = worker.Codex{Config: c, Client: local}.Run(ctx, l)
		} else {
			result, code = worker.New(c).Run(ctx, l)
		}
		body = result
		if code != "" {
			body = coordinator.Failure{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence, Code: code}
		}
	}
	endWorker(diagnosticOutcome(ctx, code, nil))
	// Persist the exact report before touching the coordinator. Recovery may
	// retry only after the authenticated replay-safe contract is confirmed.
	if l.AcceptanceRequired && provenExecutor {
		if err := journal.FinishProofTrafficContext(ctx, record); err != nil {
			return code, err
		}
	}
	endPrepare := diagnostics.Start(ctx, "report_prepare", 0)
	raw, err := json.Marshal(body)
	endPrepare(diagnosticOutcome(ctx, "", err))
	if err != nil {
		return code, err
	}
	kind := "result"
	if code != "" {
		kind = "fail"
	} else if c.Executor == config.ExecutorCodexTLSN || c.Executor == config.ExecutorServices {
		kind = "proven"
	}
	record, err = journal.ReadyContext(ctx, record, kind, raw)
	if err != nil {
		return code, err
	}
	return code, submitRecord(ctx, client, journal, record)
}
