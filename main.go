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
	_, err = client.Post(context.Background(), "/api/node/v1/pair", map[string]string{"version": coordinator.Version, "code": code, "profile": c.Profile, "model_id": c.Model}, &reply)
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
func runFixture(c config.Config) error {
	client := coordinator.New(c.Coordinator, c.GatewayKey)
	client.EchoUnqualifiedHTTP = true
	gateway := worker.New(c)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	for ctx.Err() == nil {
		h := coordinator.Heartbeat{Version: coordinator.Version, NodeID: "local-fixture", Profile: c.Profile, ModelID: c.Model, State: "available"}
		reply, err := client.Poll(ctx, h)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fixture heartbeat:", err)
		} else if reply.Lease != nil {
			l := *reply.Lease
			result, code := gateway.Run(ctx, l)
			path, pathErr := coordinator.JobPath(l.JobID, "result")
			var body any = result
			if code != "" {
				path, pathErr = coordinator.JobPath(l.JobID, "fail")
				body = coordinator.Failure{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence, Code: code}
			}
			if pathErr != nil {
				fmt.Fprintln(os.Stderr, "fixture lease:", pathErr)
			} else {
				// The coordinator may have committed an ambiguous response; never retry.
				if _, err := client.Post(ctx, path, body, nil); err != nil {
					fmt.Fprintln(os.Stderr, "fixture submit:", err)
				} else {
					fmt.Printf("fixture job %s: %s\n", l.JobID, map[bool]string{true: "failed (" + code + ")", false: "result submitted"}[code != ""])
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
	return nil
}

func run(c config.Config) error {
	if c.LocalFixture {
		return runFixture(c)
	}
	id, err := loadIdentity(c)
	if err != nil {
		return err
	}
	client := coordinator.New(c.Coordinator, id.Credential)
	gateway := worker.New(c)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	for ctx.Err() == nil {
		h := coordinator.Heartbeat{Version: coordinator.Version, NodeID: id.NodeID, Profile: c.Profile, ModelID: c.Model, State: "available"}
		reply, err := client.Poll(ctx, h)
		if err != nil {
			fmt.Fprintln(os.Stderr, "heartbeat:", err)
		} else if reply.Lease != nil {
			l := *reply.Lease
			result, code := gateway.Run(ctx, l)
			path, pathErr := coordinator.JobPath(l.JobID, "result")
			if code != "" {
				path, pathErr = coordinator.JobPath(l.JobID, "fail")
			}
			if pathErr != nil {
				fmt.Fprintln(os.Stderr, "lease:", pathErr)
			} else {
				var body any = result
				if code != "" {
					body = coordinator.Failure{Version: coordinator.Version, Attempt: l.Attempt, Fence: l.Fence, Code: code}
				}
				// Never retry an ambiguous submit: only the coordinator can know whether it committed.
				status, e := client.Post(ctx, path, body, nil)
				if e != nil {
					fmt.Fprintln(os.Stderr, "submit:", e)
				} else if status != 200 && status != 201 && status != 204 {
					fmt.Fprintln(os.Stderr, "unexpected submit status:", status)
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}
