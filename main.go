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
	if len(args) > 0 && args[0] == "accounts" {
		return accountsCommand(args[1:], os.Stdin, os.Stdout)
	}
	if len(args) != 1 {
		return errors.New("usage: scarlett-node pair|run|status|drain|resume|accounts")
	}
	if args[0] == "status" || args[0] == "drain" || args[0] == "resume" {
		return localCommand(args[0], os.Stdout)
	}
	if args[0] != "pair" && args[0] != "run" {
		return errors.New("usage: scarlett-node pair|run|status|drain|resume|accounts")
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
	info, err := os.Lstat(c.StateDir)
	if err != nil {
		return id, err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return id, errors.New("state directory permissions must be 0700")
	}
	info, err = os.Lstat(identityPath(c))
	if err != nil {
		return id, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return id, errors.New("identity file must be regular and private (0600)")
	}
	f, err := os.Open(identityPath(c))
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

func run(c config.Config) error {
	if err := prepareStateDir(c.StateDir); err != nil {
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
	wait := 5 * time.Second
	if c.LocalFixture {
		wait = time.Second
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
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
		if time.Now().Before(restUntil) {
			state = "exhausted"
		}
		mu.Unlock()
		h := coordinator.Heartbeat{Version: coordinator.Version, NodeID: nodeID, Profile: c.Profile, State: state, Bid: c.Bid, Capacity: capacity}
		if services != nil {
			h.Services = services.health()
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
		if err := saveRuntimeStatus(c.StateDir, status); err != nil {
			return err
		}
		reply, err := client.Poll(ctx, h)
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
				case <-time.After(wait):
				}
				continue
			}
			// The coordinator counts this node's open leases against its capacity,
			// so a slot frees up as soon as an earlier result is recorded.
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
			l := *reply.Lease
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
				var code string
				var err error
				if !serviceAvailable {
					code = "service_unavailable"
					err = rejectLease(workCtx, client, journal, l, code)
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
			continue
		} else {
			status.LastHeartbeatAt = time.Now().UTC()
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
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
		// Persist uncertainty before acceptance HTTP. A lost acknowledgement
		// keeps this journal pending; recovery never re-executes the provider.
		l, err = client.Accept(ctx, l)
		if err != nil {
			return "", err
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
