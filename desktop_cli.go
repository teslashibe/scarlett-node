package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/localfs"
	"github.com/teslashibe/scarlett-node/internal/process"
)

// Desktop helpers have no coordinator calls except explicit run. The renderer
// cannot supply their binary paths; its native bridge selects bundled sidecars.
func desktopCommand(args []string, owner io.Reader, out io.Writer) error {
	if len(args) == 2 && (args[0] == "preferences-get" || args[0] == "preferences-set") {
		return desktopPreferencesCommand(args[0], args[1], owner, out)
	}
	if len(args) == 2 && args[0] == "private-dir" {
		if !filepath.IsAbs(args[1]) || filepath.Clean(args[1]) != args[1] {
			return errors.New("invalid private directory")
		}
		var err error
		if _, statErr := os.Lstat(args[1]); statErr == nil {
			err = localfs.CheckDir(args[1])
		} else if os.IsNotExist(statErr) {
			err = localfs.EnsureDir(args[1])
		} else {
			err = statErr
		}
		if err != nil {
			return errors.New("desktop private storage unavailable")
		}
		return json.NewEncoder(out).Encode(map[string]bool{"ok": true})
	}
	// Exclusive reservation for a new app-owned profile. A Windows directory
	// created without a security descriptor only inherits ACEs and can never pass
	// CheckDir, so the protected ACL must be applied by the create itself. An
	// existing entry is a taken name for the caller to skip, never an error.
	if len(args) == 2 && args[0] == "private-dir-new" {
		if !filepath.IsAbs(args[1]) || filepath.Clean(args[1]) != args[1] {
			return errors.New("invalid private directory")
		}
		status := "created"
		if err := localfs.CreateDir(args[1]); errors.Is(err, fs.ErrExist) {
			status = "exists"
		} else if err != nil {
			return errors.New("desktop private storage unavailable")
		}
		return json.NewEncoder(out).Encode(map[string]string{"status": status})
	}
	if len(args) == 2 && args[0] == "bearer" {
		key, err := desktopBearer(args[1])
		if err != nil {
			return err
		}
		// This protected local stdout is consumed only by the native bridge.
		// Never print it in logs, telemetry, arguments or error messages.
		return json.NewEncoder(out).Encode(map[string]string{"key": key})
	}
	if len(args) == 1 && args[0] == "run" {
		if owner == nil {
			return errors.New("desktop owner pipe required")
		}
		c, err := config.Load()
		if err != nil {
			return err
		}
		return runWithOwner(c, owner)
	}
	if len(args) == 2 && args[0] == "api" {
		if owner == nil {
			return errors.New("desktop owner pipe required")
		}
		port, err := strconv.Atoi(args[1])
		if err != nil || port < 1024 || port > 65535 {
			return errors.New("invalid local API port")
		}
		exe, err := os.Executable()
		if err != nil {
			return errors.New("bundled API unavailable")
		}
		suffix := ""
		if runtime.GOOS == "windows" {
			suffix = ".exe"
		}
		binary := filepath.Join(filepath.Dir(exe), "open-agent-api"+suffix)
		info, err := os.Lstat(binary)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("bundled API unavailable")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		go func() { _, _ = io.Copy(io.Discard, owner); cancel() }()
		cmd := exec.CommandContext(ctx, binary, "--host", "127.0.0.1", "--port", strconv.Itoa(port))
		cmd.WaitDelay = 10 * time.Second
		configureDesktopAPI(cmd)
		err = process.Run(cmd)
		cleanupDesktopAPI(cmd)
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	return errors.New("usage: scarlett-node desktop private-dir PATH|private-dir-new PATH|bearer PATH|run|api PORT")
}

func desktopBearer(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "bearer" {
		return "", errors.New("invalid private key path")
	}
	if err := localfs.CheckDir(filepath.Dir(path)); err != nil {
		return "", errors.New("desktop private storage unavailable")
	}
	lock, err := localfs.LockPrivate(path + ".lock")
	if err != nil {
		return "", errors.New("private key busy or unavailable")
	}
	defer lock.Close()
	file, err := localfs.OpenPrivate(path)
	if os.IsNotExist(err) {
		var random [32]byte
		if _, err = rand.Read(random[:]); err != nil {
			return "", errors.New("private key unavailable")
		}
		key := hex.EncodeToString(random[:])
		if err = localfs.WriteAtomic(path, []byte(key), false); err != nil {
			return "", errors.New("private key unavailable")
		}
		return key, nil
	}
	if err != nil {
		return "", errors.New("private key unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil || len(raw) != 64 {
		return "", errors.New("private key unavailable")
	}
	for _, b := range raw {
		if b < '0' || b > '9' && b < 'a' || b > 'f' {
			return "", errors.New("private key unavailable")
		}
	}
	return string(raw), nil
}
