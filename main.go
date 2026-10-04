package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/teslashibe/scarlett-node/internal/attempts"
	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
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
	if len(args) != 1 {
		return errors.New("usage: scarlett-node pair|run|status|drain|resume|relay-resume|accounts")
	}
	if args[0] == "status" || args[0] == "drain" || args[0] == "resume" || args[0] == "relay-resume" {
		return localCommand(args[0], os.Stdout)
	}
	if args[0] != "pair" && args[0] != "run" {
		return errors.New("usage: scarlett-node pair|run|status|drain|resume|relay-resume|accounts")
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

// capacityRest is how long a node reports "exhausted" after its gateway had no capacity.
const capacityRest = 30 * time.Second

// heartbeatWatchInterval is how often the node rechecks, while the coordinator
// holds a heartbeat, whether what that heartbeat advertised still holds.
const heartbeatWatchInterval = time.Second

// errHeartbeatStale ends a held heartbeat whose advertised availability the
// node has since changed. It is not a coordinator failure and earns no backoff.
var errHeartbeatStale = errors.New("heartbeat availability changed while held")

// availability is every local input to a heartbeat's advertised state that can
// change while the coordinator holds it: an operator drain, a rest after the
// gateway ran out of capacity, the local Codex admission guard, and each
// service's state and proof modes. In-flight counts are left out: work that
// finishes during a hold only frees capacity.
type availability struct {
	drained, drainUnreadable, resting, codexBlocked bool
	services                                        string
}

// serviceStates is the part of service health that decides whether a service
// takes work: its state and the proof modes it offers.
func serviceStates(health []coordinator.ServiceHealth) string {
	out := ""
	for _, s := range health {
		out += fmt.Sprintf("%s=%s%q;", s.Kind, s.State, s.ProofModes)
	}
	return out
}

// watchHeartbeat cancels a held heartbeat with errHeartbeatStale as soon as
// current() no longer matches what it advertised. Otherwise the hold could
// still return a lease up to HeartbeatWaitSeconds after the node stopped taking
// work, and the coordinator would go on seeing the old state for as long.
func watchHeartbeat(ctx context.Context, cancel context.CancelCauseFunc, sent availability, current func() availability) {
	tick := time.NewTicker(heartbeatWatchInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if current() != sent {
				cancel(errHeartbeatStale)
				return
			}
		}
	}
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
	// adds no delay of its own. backoff is the pause after a failed heartbeat.
	backoff := 5 * time.Second
	if c.LocalFixture {
		backoff = time.Second
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	if owner != nil {
		go func() { _, _ = io.Copy(io.Discard, owner); stop() }()
	}
	defer stop()
	workCtx, cancelWork := context.WithCancel(context.Background())
	defer cancelWork()
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
	var local worker.Completer
	if c.Executor == config.ExecutorCodex {
		cx, err := worker.NewCodex(c)
		if err != nil {
			return err
		}
		local = cx
	}
	capacity := max(c.Concurrency, 1)
	var services *servicePool
	if c.Executor == config.ExecutorServices {
		services = newServicePool(c)
		capacity = services.capacity()
	}
	slots := make(chan struct{}, capacity)
	var running sync.WaitGroup
	status := runtimeStatus{Version: coordinator.Version, State: "running", NodeID: nodeID, Services: []coordinator.ServiceHealth{}}
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
	// legacyHeartbeat is set once the coordinator has rejected a heartbeat that
	// carried proof_modes; from then on the node sends the older shape.
	legacyHeartbeat := false
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
			if records, err := journal.Pending(); err == nil {
				for _, record := range records {
					if record.State == "ready" {
						if err := recoverAttempt(ctx, client, journal, record); err != nil {
							fmt.Fprintln(os.Stderr, "reconcile:", err)
						}
					}
				}
			} else {
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
			if legacyHeartbeat {
				h.Services, _ = coordinator.WithoutProofModes(h.Services)
			}
			h.Capacity = 0
			for _, service := range h.Services {
				h.Capacity += service.Capacity
			}
			h.State = "exhausted"
			for _, s := range h.Services {
				if (s.State == "configured" || s.State == "ready") && s.InFlight < s.Capacity {
					h.State = "available"
				}
			}
		}
		status.State = "running"
		if drained {
			h.State = "exhausted"
			status.State = "draining"
		}
		journalCapacity, err := journal.Capacity()
		if err != nil {
			return err
		}
		status.JournalCapacity = &journalCapacity
		// In-flight goroutines may not have called Begin yet. Reserve one
		// additional slot for each before advertising new admission capacity.
		if journalCapacity.AvailableRecords <= len(slots) {
			h.State = "exhausted"
			for i := range h.Services {
				h.Services[i].State = "exhausted"
			}
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
			watchHeartbeat(pollCtx, cancelPoll, sent, currentAvailability)
		}()
		reply, err := client.Poll(pollCtx, h)
		if errors.Is(err, coordinator.ErrHeartbeatRejected) && !legacyHeartbeat {
			// A coordinator older than proof_modes rejects the whole heartbeat.
			// Send it the heartbeat it knows, and keep doing so: it cannot
			// offer relay work anyway. Without this a coordinator rollback
			// would take every node that advertises relay offline.
			if stripped, removed := coordinator.WithoutProofModes(h.Services); removed {
				h.Services = stripped
				if reply, err = client.Poll(pollCtx, h); err == nil {
					legacyHeartbeat = true
					fmt.Fprintln(os.Stderr, "heartbeat: coordinator rejected proof_modes; advertising MPC-TLS only until restart")
				}
			}
		}
		stale := err != nil && errors.Is(context.Cause(pollCtx), errHeartbeatStale)
		cancelPoll(nil)
		<-watched
		if stale {
			// The node cut the hold short itself: heartbeat again now, with
			// the new state, rather than backing off as after a failure.
			continue
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "heartbeat:", err)
		} else if reply.Lease != nil {
			status.LastHeartbeatAt = time.Now().UTC()
			// Read again after polling: drain may have arrived while the request
			// was in flight. Never start newly delivered work while draining.
			drained, err = drainRequested(c.StateDir)
			if err != nil {
				return err
			}
			if drained || ctx.Err() != nil {
				if err := rejectLease(workCtx, client, journal, *reply.Lease, "service_unavailable"); err != nil {
					fmt.Fprintln(os.Stderr, "drain rejection:", err)
				}
				select {
				case <-ctx.Done():
					return nil
				case <-time.After(backoff):
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
			// The coordinator counts this node's open leases against its capacity,
			// so a slot frees up as soon as an earlier result is recorded.
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				delete(inFlight, l.JobID)
				mu.Unlock()
				return nil
			}
			selected := c
			var account *accountLease
			serviceAvailable := true
			if services != nil {
				account, serviceAvailable = services.acquireAccount(l.ServiceType)
				if serviceAvailable {
					selected = account.config
				}
			}
			running.Add(1)
			go func() {
				defer running.Done()
				defer func() { <-slots }()
				defer func() {
					mu.Lock()
					delete(inFlight, l.JobID)
					mu.Unlock()
				}()
				var code string
				var err error
				if !serviceAvailable {
					code = "service_unavailable"
					if l.AcceptanceRequired && l.ServiceType == "codex" {
						// No selected valid profile: leave the unaccepted offer to
						// expire rather than funding it through rejectLease.
						err = errors.New("Codex offer has no locally valid account")
					} else {
						err = rejectLease(workCtx, client, journal, l, code)
					}
				} else {
					code, err = submitLease(workCtx, client, selected, l, local, journal)
					if services != nil {
						if err != nil && code == "" {
							services.finishAccount(account, "report_pending")
						} else {
							services.finishAccount(account, code)
						}
					}
				}
				if code == "capacity_unavailable" {
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
			// wait, so loop straight into it.
			status.LastHeartbeatAt = time.Now().UTC()
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
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
	record, err := attemptRecord(l)
	if err != nil {
		return "invalid_lease", err
	}
	if c.LocalAccountID != "" {
		record.ProviderAccountID, record.ProviderService = c.LocalAccountID, l.ServiceType
	}
	if err := journal.Begin(record); err != nil {
		return "", err
	}
	if l.AcceptanceRequired {
		if l.ServiceType == "codex" && !codexAdmissionValid(c.CodexHome, l.LeaseDeadline) {
			// No acceptance HTTP or provider execution has happened. Keep terminal
			// replay metadata for this pinned attempt; let its offer expire remotely.
			// rejectLease cannot be used here because it performs funded acceptance.
			if err := journal.Terminal(record); err != nil {
				return "auth_required", err
			}
			return "auth_required", errors.New("Codex credential validity is insufficient for the offered deadline")
		}
		// Persist uncertainty before acceptance HTTP. A lost acknowledgement
		// keeps this journal pending; recovery never re-executes the provider.
		l, err = client.Accept(ctx, l)
		if err != nil {
			return "", err
		}
	}
	provenExecutor := c.Executor == config.ExecutorCodexTLSN || c.Executor == config.ExecutorServices
	if l.AcceptanceRequired && provenExecutor {
		if limit := worker.ProofSampleLimit(c, l); limit > 0 {
			ctx = worker.WithProofObserver(ctx, func() (func(attempts.ProofSample) error, error) {
				ordinal, err := journal.BeginProof(record, limit)
				if err != nil {
					return nil, err
				}
				return func(sample attempts.ProofSample) error {
					sample.Ordinal = ordinal
					return journal.CompleteProof(record, sample)
				}, nil
			})
		}
	}
	var body any
	code := ""
	if c.Executor == config.ExecutorCodexTLSN || c.Executor == config.ExecutorServices {
		var detail string
		if c.Executor == config.ExecutorServices && !c.Enabled(l.ServiceType) {
			code = "service_unavailable"
		} else if c.Executor == config.ExecutorServices && l.ServiceType == "x_read" {
			code = worker.X{Config: c}.Run(ctx, l)
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
	// Persist the exact report before touching the coordinator. Recovery may
	// retry only after the authenticated replay-safe contract is confirmed.
	if l.AcceptanceRequired && provenExecutor {
		if err := journal.FinishProofTraffic(record); err != nil {
			return code, err
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return code, err
	}
	kind := "result"
	if code != "" {
		kind = "fail"
	} else if c.Executor == config.ExecutorCodexTLSN || c.Executor == config.ExecutorServices {
		kind = "proven"
	}
	record, err = journal.Ready(record, kind, raw)
	if err != nil {
		return code, err
	}
	return code, submitRecord(ctx, client, journal, record)
}
