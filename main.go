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
	"path/filepath"
	"sync"
	"sync/atomic"
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
	if len(args) > 0 && args[0] == "update" {
		return updateCommand(args[1:], os.Stdin, os.Stdout)
	}
	if len(args) != 1 {
		return errors.New("usage: scarlett-node pair|run|status|diagnostics|drain|resume|relay-resume|accounts|web-runtime|update")
	}
	if args[0] == "status" || args[0] == "diagnostics" || args[0] == "drain" || args[0] == "resume" || args[0] == "relay-resume" {
		return localCommand(args[0], os.Stdout)
	}
	if args[0] != "pair" && args[0] != "run" {
		return errors.New("usage: scarlett-node pair|run|status|diagnostics|drain|resume|relay-resume|accounts|web-runtime|update")
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
	// A stop is SIGTERM or Ctrl-C, or the desktop app closing the owner pipe
	// (its Stop or Quit). The held heartbeat does not hang off ctx: the node
	// says goodbye first and only then ends the hold itself.
	signals, stopSignals := notifyStop(context.Background())
	defer stopSignals()
	ctx, stopRun := context.WithCancelCause(signals)
	defer stopRun(nil)
	ownerDone := make(chan struct{})
	defer close(ownerDone)
	var commands chan ownerCommand
	if owner != nil {
		commands = make(chan ownerCommand, 4)
		go readOwner(owner, commands, ownerDone, func() { stopRun(errOwnerClosed) })
	}
	stopReason := func() string {
		if errors.Is(context.Cause(ctx), errOwnerClosed) {
			return coordinator.GoodbyeStop
		}
		return coordinator.GoodbyeSignal
	}
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
	counters := &heartbeatCounters{}
	defer func() {
		status.State = "draining"
		status.InFlight = len(slots)
		if services != nil {
			status.Services = services.health()
			status.Accounts = services.accountStatus()
		}
		status.HeartbeatDiagnostics = counters.snapshot(client.Stats())
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
	// inFlight maps each job a worker holds to its attempt.
	inFlight := map[string]string{}
	legacyCodexBlocked := false
	// advertise builds what a heartbeat or an availability post reports from
	// every local input, without the loop's side effects. It is safe to call
	// from the watch while the loop is polling.
	advertise := func() (advertisement, error) {
		drained, err := drainRequested(c.StateDir)
		if err != nil {
			return advertisement{}, err
		}
		now := time.Now()
		mu.Lock()
		resting := now.Before(restUntil)
		mu.Unlock()
		codexBlocked := legacyCodexAdmissionBlocked(c, now)
		h := coordinator.Heartbeat{Version: coordinator.Version, NodeID: nodeID, Profile: c.Profile, State: "available", Bid: c.Bid, Capacity: capacity}
		// Legacy reports have no typed service health and their capacity must
		// stay positive; exhausted alone stops dispatch.
		if resting || codexBlocked {
			h.State = "exhausted"
		}
		ad := advertisement{drained: drained, codexBlocked: codexBlocked, availability: availability{drained: drained, resting: resting, codexBlocked: codexBlocked}}
		if services != nil {
			h.Services = services.health()
			ad.availability.services = serviceStates(h.Services)
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
		if drained {
			h.State = "exhausted"
		}
		if drained || resting {
			blockOperationAvailability(h.Services)
		}
		if ad.journal, err = journal.Capacity(); err != nil {
			return advertisement{}, err
		}
		// In-flight goroutines may not have called Begin yet. Reserve one
		// additional slot for each before advertising new admission capacity.
		// Finished receipts count only if recent ones fill terminal storage.
		ad.journalFull = ad.journal.AvailableRecords <= len(slots)
		ad.availability.journalFull = ad.journalFull
		if ad.journalFull {
			h.State = "exhausted"
			for i := range h.Services {
				h.Services[i].State = "exhausted"
			}
			blockOperationAvailability(h.Services)
		}
		ad.heartbeat = h
		return ad, nil
	}
	// current is what the watch compares with what the coordinator was told.
	// An unreadable drain marker or journal never equals an advertisement: the
	// hold ends and the loop reports the error.
	current := func() availability {
		ad, err := advertise()
		if err != nil {
			return availability{drainUnreadable: true}
		}
		return ad.availability
	}
	postAvailability := func(ctx context.Context) (availability, error) {
		ad, err := advertise()
		if err == nil {
			err = client.Availability(ctx, coordinator.AvailabilityOf(ad.heartbeat))
		}
		if err != nil {
			// The watch ends the hold instead, so the next heartbeat carries
			// what could not be posted.
			fmt.Fprintln(os.Stderr, "availability:", err)
		}
		return ad.availability, err
	}
	goodbye := func(reason string, deadline time.Time) {
		goodbyeCtx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		if err := client.Goodbye(goodbyeCtx, nodeID, reason); err != nil {
			fmt.Fprintln(os.Stderr, "goodbye:", err)
		}
	}
	// saidGoodbye is set from a goodbye until the next heartbeat brings the
	// node back, so a stop right after a sleep or a drain says it once.
	saidGoodbye := false
	sayGoodbye := func(reason string) {
		if !saidGoodbye {
			goodbye(reason, time.Now().Add(coordinator.GoodbyeTimeout))
			saidGoodbye = true
		}
	}
	// Whatever ends the run says goodbye first, before the accepted work's
	// drain: the coordinator moves this node's unaccepted offers elsewhere.
	defer func() {
		reason := coordinator.GoodbyeStop
		if ctx.Err() != nil {
			reason = stopReason()
		}
		sayGoodbye(reason)
	}()
	// reject declines an offer the node never accepted, in the background so
	// that neither a slot nor the coordinator holds up the loop.
	reject := func(offer coordinator.OfferAttempt, reason string) {
		fmt.Fprintln(os.Stderr, "offer: rejected ("+reason+")")
		running.Add(1)
		go func() {
			defer running.Done()
			rejectCtx, cancel := context.WithTimeout(workCtx, rejectTimeout)
			defer cancel()
			if err := client.Reject(rejectCtx, offer, reason); err != nil {
				fmt.Fprintln(os.Stderr, "offer: rejection not delivered:", err)
			}
		}()
	}
	// start runs one offer that passed the loop's checks: it takes a slot and,
	// with services, an account, or rejects the offer when either is taken.
	start := func(l coordinator.Lease) {
		observation := beginLeaseDiagnostics(diagnosticStore, l)
		attemptCtx := observation.Context(workCtx)
		endWorkerAcquire := diagnostics.Start(attemptCtx, "worker_acquire", 0)
		select {
		case slots <- struct{}{}:
			endWorkerAcquire("success")
		default:
			// The coordinator counts this node's open leases against its
			// capacity and sends no more offers than free slots, so a full node
			// means its view was stale. Rejecting moves the job at once.
			endWorkerAcquire("rejected")
			observation.Finish("rejected")
			if l.AcceptanceRequired {
				reject(l.OfferAttempt(), coordinator.RejectNoSlot)
			} else if err := rejectLease(coordinator.WithoutAcceptRetry(workCtx), client, journal, l, "service_unavailable"); err != nil {
				fmt.Fprintln(os.Stderr, "rejection:", err)
			}
			return
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
				services.bindCoordinatorLease(account, l)
				selected = account.config
			} else {
				endAccountAcquire("service_unavailable")
			}
		}
		if !serviceAvailable && l.AcceptanceRequired {
			// No local account (for web, no web or browser slot) can take it:
			// the coordinator moves it now rather than at its deadline.
			<-slots
			observation.Finish("rejected")
			reason := coordinator.RejectNoAccount
			if l.ServiceType == "web" {
				reason = coordinator.RejectNoSlot
			}
			reject(l.OfferAttempt(), reason)
			return
		}
		mu.Lock()
		inFlight[l.JobID] = l.Attempt
		mu.Unlock()
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
				// Account release and any node-wide rest are already final.
				// Post the freed slot and active lease references while the
				// heartbeat stays held. Completions coalesce.
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
				// A legacy lease without funded acceptance is failed at once.
				code = "service_unavailable"
				err = rejectLease(attemptCtx, client, journal, l, code)
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
				fmt.Fprintln(os.Stderr, submitStage(err)+":", err)
			} else if c.LocalFixture {
				fmt.Printf("fixture job %s: %s\n", l.JobID, map[bool]string{true: "failed (" + code + ")", false: "submitted"}[code != ""])
			}
		}()
	}
	// takeOffers starts or rejects every offer in a heartbeat answer, never
	// waiting for a slot or the coordinator. It reports whether it rejected an
	// offer because the node is draining or stopping.
	takeOffers := func(reply coordinator.HeartbeatReply) (bool, error) {
		for _, offer := range reply.Unreadable {
			reject(offer, coordinator.RejectInvalidOffer)
		}
		if len(reply.Leases) == 0 {
			return false, nil
		}
		// Read again after polling: drain may have arrived while the request
		// was in flight. Never start newly delivered work while draining.
		drained, err := drainRequested(c.StateDir)
		if err != nil {
			return false, err
		}
		draining := drained || ctx.Err() != nil
		rejectedForDrain := false
		for _, l := range reply.Leases {
			// The coordinator sends an offer again until a heartbeat
			// acknowledges it, and another API process may hand it over once
			// more; an attempt already running here is never started twice.
			mu.Lock()
			attempt, held := inFlight[l.JobID]
			mu.Unlock()
			if held {
				if attempt != l.Attempt {
					reject(l.OfferAttempt(), coordinator.RejectBusy)
				}
				continue
			}
			if draining {
				rejectedForDrain = true
				if l.AcceptanceRequired {
					reject(l.OfferAttempt(), coordinator.RejectDraining)
				} else if err := rejectLease(coordinator.WithoutAcceptRetry(workCtx), client, journal, l, "service_unavailable"); err != nil {
					fmt.Fprintln(os.Stderr, "drain rejection:", err)
				}
				continue
			}
			if l.AcceptanceRequired {
				if err := coordinator.ValidOffer(l, time.Now()); err != nil {
					// Never left to expire in silence: the coordinator moves
					// the job at once and counts the rejection.
					reject(l.OfferAttempt(), coordinator.RejectInvalidOffer)
					continue
				}
			}
			start(l)
		}
		return rejectedForDrain, nil
	}
	clock := &clockWatch{}
	clock.jumped()
	refresh := func() {
		status.HeartbeatDiagnostics = counters.snapshot(client.Stats())
		_ = saveRuntimeStatus(c.StateDir, status)
	}
	// wake runs after a wake command, a wall-clock jump or a sleep pause that
	// ran out: the pooled connection may be dead, so the next heartbeat goes
	// out at once on a new one and without the failure backoff.
	wake := func(reason string) {
		client.ResetConnections()
		failures.reset()
		counters.wake(reason)
		fmt.Fprintln(os.Stderr, "heartbeat: awake ("+reason+"); reconnecting")
	}
	// sleep holds heartbeats after a goodbye for sleep until a wake command,
	// a wall-clock jump, sleepPauseLimit or a stop. It reports false on a stop.
	sleep := func() bool {
		counters.sleeps.Add(1)
		for {
			outcome, reason := waitFor(ctx, sleepPauseLimit, commands, clock, refresh)
			switch outcome {
			case waitStopped:
				return false
			case waitWake:
				wake(reason)
				return true
			case waitElapsed:
				wake("timeout")
				return true
			}
		}
	}
	// pause waits d before the next heartbeat and reports false if the node is
	// stopping. A sleep command, a wake command or a wall-clock jump ends it
	// early, as during a held heartbeat.
	pause := func(d time.Duration) bool {
		outcome, reason := waitFor(ctx, d, commands, clock, refresh)
		switch outcome {
		case waitStopped:
			return false
		case waitWake:
			wake(reason)
		case waitSleep:
			sayGoodbye(coordinator.GoodbyeSleep)
			return sleep()
		}
		return true
	}
	lastPurge := time.Now()
	// The first idle pass follows startup recovery by the usual interval.
	reconcile := &idleReconciler{next: time.Now().Add(reconcileInterval)}
	advertisedDrained, firstHeartbeat := false, true
	for ctx.Err() == nil {
		// The purge waits for a running idle pass, which may hold a record it
		// would change.
		if time.Since(lastPurge) >= reconcileInterval && !reconcile.busy() {
			if err := journal.Purge(time.Now()); err != nil {
				return err
			}
			lastPurge = time.Now()
		}
		// The records are chosen here, after the active snapshot; the pass
		// asks the coordinator on its own goroutine, so this poll is never
		// held off by it.
		if reconcile.due(time.Now()) {
			if err := reconcile.start(ctx, client, journal, active.snapshot(), &running); err != nil {
				return err
			}
		}
		ad, err := advertise()
		if err != nil {
			return err
		}
		if ad.codexBlocked != legacyCodexBlocked {
			legacyCodexBlocked = ad.codexBlocked
			if ad.codexBlocked {
				fmt.Fprintln(os.Stderr, "codex: local credential cannot cover a funded offer; advertising exhausted until it is renewed")
			}
		}
		if ad.journalFull != status.JournalFull {
			if ad.journalFull {
				fmt.Fprintln(os.Stderr, "journal: receipt journal full; advertising exhausted until receipts clear")
			} else {
				fmt.Fprintln(os.Stderr, "journal: receipt journal has room again")
			}
		}
		status.State = "running"
		if ad.drained {
			status.State = "draining"
		}
		status.JournalCapacity = &ad.journal
		status.JournalFull = ad.journalFull
		status.Services = ad.heartbeat.Services
		if services != nil {
			status.Accounts = services.accountStatus()
			status.WebLimit = services.webLimitStatus() // S4b: adaptive web limit, local status only
		}
		status.InFlight = len(slots)
		if records, err := journal.Pending(); err != nil {
			return err
		} else {
			status.UnresolvedAttempts = len(records)
		}
		status.RelayHalted = worker.RelayHalted()
		status.observeRelease(client.Release())
		status.HeartbeatDiagnostics = counters.snapshot(client.Stats())
		if err := saveRuntimeStatus(c.StateDir, status); err != nil {
			return err
		}
		// A drain that began between holds says goodbye before the heartbeat
		// that reports it; the watch covers one during a hold.
		if ad.drained && !advertisedDrained && !firstHeartbeat {
			sayGoodbye(drainGoodbyeReason(c.StateDir))
		}
		advertisedDrained, firstHeartbeat = ad.drained, false
		// The coordinator may hold this heartbeat for HeartbeatWaitSeconds. A
		// change to what it advertised is posted as availability while the
		// hold goes on; only a stop, a drain, a sleep or a wake ends it early.
		h := ad.heartbeat
		h.WaitSeconds = coordinator.HeartbeatWaitSeconds
		saidGoodbye = false
		pollCtx, cancelPoll := context.WithCancelCause(context.Background())
		watched := make(chan watchResult, 1)
		go func() {
			watched <- watchHeartbeat(pollCtx, cancelPoll, pollWatch{stop: ctx, sent: ad.availability, current: current, changes: availabilityChanges, owner: commands, clock: clock,
				post: postAvailability, goodbye: goodbye, stopReason: stopReason, drainReason: func() string { return drainGoodbyeReason(c.StateDir) }})
		}()
		counters.polls.Add(1)
		polled := time.Now()
		reply, err := client.Poll(pollCtx, h)
		cancelPoll(nil)
		watch := <-watched
		saidGoodbye = saidGoodbye || watch.goodbye
		status.observeRelease(client.Release())
		if err == nil {
			failures.reset()
			at := time.Now().UTC()
			status.LastHeartbeatAt, status.LastHeartbeatOKAt, status.HeartbeatErrorClass = at, &at, ""
			counters.lastPoll.Store(int64(time.Since(polled)))
			if reply.Node != nil {
				status.observeDispatch(*reply.Node, time.Now())
			}
		}
		// Offers first, whatever ended the hold: none is left to expire
		// unanswered, and none starts while the node drains or stops.
		drainRejected, offerErr := takeOffers(reply)
		if offerErr != nil {
			return offerErr
		}
		switch watch.cause {
		case errPollStopping:
			continue
		case errPollSleep:
			sleep()
			continue
		case errPollWake:
			wake(watch.wakeReason)
			continue
		case errPollDrained, errHeartbeatStale:
			// The node cut the hold short itself: heartbeat again now, with
			// the new state, rather than backing off as after a failure.
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				continue
			}
			// A rejected heartbeat (400 or 413) is logged and backed off like
			// any other failure; the node never resends it in a reduced shape.
			fmt.Fprintln(os.Stderr, "heartbeat:", err)
			status.HeartbeatErrorClass = coordinator.ErrorClass(err)
			counters.failures.Add(1)
			pause(failures.next(err))
			continue
		}
		switch {
		case drainRejected:
			// A drained node is offered nothing; pace a coordinator that
			// sends offers anyway.
			pause(drainRejectDelay)
		case len(reply.Leases) == 0 && reply.RetryAfter > 0:
			// An idle hold ended with nothing to do; the next long poll is the
			// wait, so loop straight into it. A coordinator that is shutting
			// down answers at once and asks, with Retry-After, for a pause.
			pause(coordinator.RetryAfterWait(reply.RetryAfter))
		}
		// Otherwise heartbeat again at once: the coordinator may hold more work.
	}
	return nil
}

// advertisement is what a heartbeat or an availability post reports, with the
// local inputs it was built from.
type advertisement struct {
	heartbeat    coordinator.Heartbeat // without the hold or acknowledgements
	availability availability
	drained      bool
	codexBlocked bool
	journal      attempts.Capacity
	journalFull  bool
}

// servableDeclineReason is the rejection reason for an offer whose proof
// mode the node will not serve. A keyed-relay halt or a browser tier that is
// not ready is the node's own state, which changed after it advertised; only
// an offer for a mode the node never advertised is invalid.
func servableDeclineReason(c config.Config, l coordinator.Lease) string {
	browser := currentBrowser()
	switch {
	case worker.RelayHalted():
		return coordinator.RejectOther
	case l.ServiceType == "web" && l.WebRequest != nil && l.WebRequest.Mode == "browser" && !(c.WebBrowser && browser != nil && browser.Status().Ready):
		return coordinator.RejectNoSlot
	}
	return coordinator.RejectInvalidOffer
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
		declineOffer(ctx, client, l, servableDeclineReason(c, l))
		return "invalid_lease", errors.New("x_read offer asks for a proof mode this node does not serve")
	}
	// For a browser offer, or a relay offer with the pre-warm hint, this also
	// starts the browser while the node accepts.
	if l.ServiceType == "web" && !worker.WebOfferServable(c, l, currentBrowser()) {
		declineOffer(ctx, client, l, servableDeclineReason(c, l))
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
			declineOffer(ctx, client, l, coordinator.RejectInvalidOffer)
			return "invalid_lease", err
		}
	}
	if err := journal.BeginContext(ctx, record); err != nil {
		// No rejection: the attempt may already be recorded here, accepted
		// or with its acceptance in doubt.
		return "", err
	}
	if l.AcceptanceRequired {
		// No acceptance HTTP or provider execution happens on either local
		// refusal below. Keep terminal replay metadata for this pinned attempt
		// and reject the offer, so the coordinator moves it at once.
		if l.ServiceType == "codex" && !codexAdmissionValid(c.CodexHome, l.LeaseDeadline) {
			// The offer itself is valid, so the selected local credential is what
			// fell short. This is local expiry evidence, never a provider denial.
			if err := journal.TerminalContext(ctx, record); err != nil {
				return codexLocalAuthExpired, err
			}
			declineOffer(ctx, client, l, coordinator.RejectNoAccount)
			return codexLocalAuthExpired, errors.New("Codex credential validity is insufficient for the offered deadline")
		}
		if l.ServiceType == "x_read" && (l.XRequest == nil || c.AccountReady != nil && !c.AccountReady(l.XRequest.Operation)) {
			if err := journal.TerminalContext(ctx, record); err != nil {
				return "service_unavailable", err
			}
			declineOffer(ctx, client, l, coordinator.RejectNoAccount)
			return "service_unavailable", errors.New("X account eligibility changed before acceptance")
		}
		// E1: a relay web offer's hop 0 dials the verifier while the accept is
		// in flight; it gets the token only at hop 0 (worker.Web.StartPredial).
		predial := webWorker(c).StartPredial(ctx, l)
		defer predial.Cancel()
		// Persist uncertainty before acceptance HTTP. A lost acknowledgement
		// keeps this journal pending; recovery never re-executes the provider.
		endAccept := diagnostics.Start(ctx, "accept_http", 0)
		l, err = client.Accept(ctx, l)
		endAccept(diagnosticOutcome(ctx, "", err))
		if err != nil {
			// A refusal that proves the coordinator holds no lease for this
			// node ends the record now, as a local refusal does, so it is
			// never reconciled. No rejection follows: one would draw on the
			// same per-node budget a 429 says is spent, and the coordinator
			// already knows the attempt was not accepted.
			if coordinator.AcceptRefused(err) {
				if terminalErr := journal.TerminalContext(ctx, record); terminalErr != nil {
					return "", &stageError{"accept", terminalErr}
				}
			}
			return "", &stageError{"accept", err}
		}
		ctx = predial.Accepted(ctx, l)
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
	var webReport worker.WebReport
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
			webReport = w.Report(ctx, l)
			code = webReport.Code
		} else {
			code, detail = worker.Prover{Config: c}.Run(ctx, l)
		}
		if detail != "" && c.Executor != config.ExecutorServices {
			fmt.Fprintln(os.Stderr, detail)
		}
		if code != "" {
			failure := coordinator.Failure{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence, Code: code}
			if code == "page_too_large" {
				failure.Stage, failure.ObservedBytes = webReport.Stage, webReport.ObservedBytes
			}
			body = failure
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
	// Persist the exact report before touching the coordinator. Recovery may
	// retry only after the authenticated replay-safe contract is confirmed.
	// After a proven run the same write marks the proof traffic finished: one
	// journal write fewer between acceptance and the report, and the samples
	// were already final (proof_journal_complete ran inside the worker).
	ready := journal.ReadyContext
	if l.AcceptanceRequired && provenExecutor {
		ready = journal.ReadyAfterProofContext
	}
	record, err = ready(ctx, record, kind, raw)
	if err != nil {
		return code, err
	}
	deadline := l.LeaseDeadline
	if l.SettlementDeadline.Before(deadline) {
		deadline = l.SettlementDeadline
	}
	if err = submitReport(ctx, client, journal, record, deadline.Add(-worker.ReportMargin(l.ServiceType))); err != nil {
		return code, &stageError{"report", err}
	}
	return code, nil
}

// stageError names the coordinator call a submitLease error came from, so
// that the worker's log line says which one failed.
type stageError struct {
	stage string
	err   error
}

func (e *stageError) Error() string { return e.err.Error() }
func (e *stageError) Unwrap() error { return e.err }

// submitStage is the log prefix for a submitLease error: "accept" or "report"
// for a failed coordinator call, "submit" for anything else.
func submitStage(err error) string {
	var stage *stageError
	if errors.As(err, &stage) {
		return stage.stage
	}
	return "submit"
}
