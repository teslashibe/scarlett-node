package update

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// Executables NSIS replaces; each must be unlocked before an installer runs,
// or NSIS stops on an abort/retry dialog.
var installedExecutables = []string{"scarlett-node-desktop.exe", "scarlett-node.exe", "scarlett-prover.exe", "open-agent-api.exe"}

func waitUnlocked(dir string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		locked := ""
		for _, name := range installedExecutables {
			path := filepath.Join(dir, name)
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err == nil {
				f.Close()
			} else if !os.IsNotExist(err) {
				locked = name
				break
			}
		}
		if locked == "" {
			return nil
		}
		if time.Now().After(deadline) {
			return fail(CodeBusy, fmt.Errorf("%s is still running", locked))
		}
		time.Sleep(time.Second)
	}
}

func runInstaller(ctx context.Context, installer string) error {
	if !strings.EqualFold(filepath.Ext(installer), ".exe") || !filepath.IsAbs(installer) {
		return fail(CodeInstallFailed, errors.New("invalid installer path"))
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	// Passive (/P) shows progress only; /UPDATE keeps shortcuts and settings.
	cmd := exec.CommandContext(ctx, installer, "/P", "/UPDATE")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: false}
	if err := cmd.Run(); err != nil {
		return fail(CodeInstallFailed, err)
	}
	return nil
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	if err = os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	tmp := to + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err == nil {
		err = out.Sync()
	}
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, to)
}

func (g *Guard) install(ctx context.Context, p *Pending) error {
	if p.Kind != "nsis" {
		return fail(CodeUnsupported, errors.New("not a Windows installer update"))
	}
	if err := waitUnlocked(filepath.Dir(p.App), 150*time.Second); err != nil {
		return err
	}
	if err := runInstaller(ctx, p.Staged); err != nil {
		return err
	}
	// The installer just used is the rollback source for the next update.
	return copyFile(p.Staged, filepath.Join(g.Updates, "installed", p.To+".exe"))
}

func (g *Guard) restore(ctx context.Context, p *Pending) error {
	if p.Previous == "" {
		return errors.New("no previous installer to restore")
	}
	if err := waitUnlocked(filepath.Dir(p.App), 150*time.Second); err != nil {
		return err
	}
	return runInstaller(ctx, p.Previous)
}

func launchApp(app string) error {
	cmd := exec.Command(app)
	cmd.Dir = filepath.Dir(app)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	event, _ := windows.WaitForSingleObject(h, 0)
	return event == uint32(windows.WAIT_TIMEOUT)
}

// terminateProcess asks the app to close, or ends it with force.
func terminateProcess(pid int, force bool) {
	args := []string{"/PID", fmt.Sprint(pid)}
	if force {
		args = append(args, "/F")
	}
	_ = exec.Command("taskkill", args...).Run()
}
