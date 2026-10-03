package browserx

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha1"
	"os/exec"
	"time"
)

func pathProtected(string) bool { return false }
func nativeChromeKey(ctx context.Context, _ string) ([]byte, error) {
	// The OS enforces Keychain approval. Never use fallback passwords, ask for
	// elevated access, or forward this command's output/errors to the UI.
	cmd := exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-s", "Chrome Safe Storage", "-a", "Chrome", "-w")
	cmd.WaitDelay = 2 * time.Second
	password, err := cmd.Output()
	defer clear(password)
	if err != nil || len(password) == 0 || len(password) > 4096 {
		return nil, Protected
	}
	password = bytes.TrimSuffix(password, []byte("\n"))
	key, err := pbkdf2.Key(sha1.New, string(password), []byte("saltysalt"), 1003, 16)
	if err != nil {
		return nil, Protected
	}
	return key, nil
}
