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
	if len(args) != 1 || (args[0] != "pair" && args[0] != "run") {
		return errors.New("usage: scarlett-node pair|run")
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
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(c.StateDir, 0700); err != nil {
		return err
	}
	if _, err := os.Lstat(identityPath(c)); err == nil {
		return errors.New("already paired; refusing to overwrite credentials")
	} else if !os.IsNotExist(err) {
		return err
	}
	fmt.Fprintln(os.Stderr, "Enter one-time pairing code:")
	// Read from stdin rather than flags/env so it does not appear in process arguments.
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 257))
	if err != nil {
		return err
	}
	code := string(b)
	for len(code) > 0 && (code[len(code)-1] == '\n' || code[len(code)-1] == '\r') {
		code = code[:len(code)-1]
	}
	if code == "" || len(code) > 256 {
		return errors.New("invalid pairing code")
	}
	client := coordinator.New(c.Coordinator, "")
	var reply coordinator.PairReply
	_, err = client.Post(context.Background(), "/api/node/v1/pair", map[string]string{"version": coordinator.Version, "code": code, "profile": c.Profile}, &reply)
	if err != nil {
		return err
	}
	if reply.Version != coordinator.Version || reply.NodeID == "" || reply.SupplierPubkey == "" || reply.Credential == "" {
		return errors.New("invalid pairing response")
	}
	f, err := os.OpenFile(identityPath(c), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	data, e := json.Marshal(identity{reply.NodeID, reply.SupplierPubkey, reply.Credential})
	if e == nil {
		_, e = f.Write(data)
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		os.Remove(identityPath(c))
		return e
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
	data, err := os.ReadFile(identityPath(c))
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
	client := coordinator.New(c.Coordinator, cred)
	if c.LocalFixture {
		client.EchoUnqualifiedHTTP = true
	}
	wait := 5 * time.Second
	if c.LocalFixture {
		wait = time.Second
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	capacity := max(c.Concurrency, 1)
	slots := make(chan struct{}, capacity)
	var running sync.WaitGroup
	defer running.Wait()
	var mu sync.Mutex
	var restUntil time.Time
	for ctx.Err() == nil {
		mu.Lock()
		state := "available"
		if time.Now().Before(restUntil) {
			state = "exhausted"
		}
		mu.Unlock()
		h := coordinator.Heartbeat{Version: coordinator.Version, NodeID: nodeID, Profile: c.Profile, State: state, Bid: c.Bid, Capacity: capacity}
		reply, err := client.Poll(ctx, h)
		if err != nil {
			fmt.Fprintln(os.Stderr, "heartbeat:", err)
		} else if reply.Lease != nil {
			// The coordinator counts this node's open leases against its capacity,
			// so a slot frees up as soon as an earlier result is recorded.
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return nil
			}
			l := *reply.Lease
			running.Add(1)
			go func() {
				defer running.Done()
				defer func() { <-slots }()
				code, err := submitLease(ctx, client, c, l)
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
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
	return nil
}

func submitLease(ctx context.Context, client *coordinator.Client, c config.Config, l coordinator.Lease) (string, error) {
	var body any
	path, err := coordinator.JobPath(l.JobID, "result")
	code := ""
	if c.Executor == config.ExecutorCodexTLSN {
		var detail string
		code, detail = worker.Prover{Config: c}.Run(ctx, l)
		if detail != "" {
			fmt.Fprintln(os.Stderr, detail)
		}
		if code != "" {
			path, err = coordinator.JobPath(l.JobID, "fail")
			body = coordinator.Failure{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence, Code: code}
		} else {
			path, err = coordinator.JobPath(l.JobID, "proven")
			body = coordinator.Proven{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence}
		}
	} else {
		var result coordinator.Result
		result, code = worker.New(c).Run(ctx, l)
		body = result
		if code != "" {
			path, err = coordinator.JobPath(l.JobID, "fail")
			body = coordinator.Failure{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence, Code: code}
		}
	}
	if err != nil {
		return code, err
	}
	// Never retry an ambiguous submit: only the coordinator can know whether it committed.
	status, err := client.Post(ctx, path, body, nil)
	if err != nil {
		return code, err
	}
	if status != 200 && status != 201 && status != 204 {
		return code, fmt.Errorf("unexpected submit status: %d", status)
	}
	return code, nil
}
