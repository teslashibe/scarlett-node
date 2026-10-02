package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/teslashibe/scarlett-node/internal/config"
	"golang.org/x/term"
)

func readPairCode(input io.Reader) (string, error) {
	// Read one bounded line, so Enter completes pairing without waiting for EOF.
	// Non-terminal input remains available for a protected pipe or secret file.
	line, err := bufio.NewReader(io.LimitReader(input, 258)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", errors.New("could not read pairing code")
	}
	return validatePairCode(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
}

func validatePairCode(code string) (string, error) {
	if len(code) == 0 || len(code) > 256 {
		return "", errors.New("invalid pairing code")
	}
	for _, c := range code {
		if c <= 32 || c >= 127 {
			return "", errors.New("invalid pairing code")
		}
	}
	return code, nil
}

func readProtectedPairCode(input *os.File) (string, error) {
	if !term.IsTerminal(int(input.Fd())) {
		return readPairCode(input)
	}
	b, err := term.ReadPassword(int(input.Fd()))
	if err != nil {
		return "", errors.New("could not read pairing code")
	}
	return validatePairCode(string(b))
}

func prepareStateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("state directory must be a directory, not a symlink")
	}
	return os.Chmod(path, 0700)
}

// A synced temporary inode becomes the identity using an exclusive hard link.
// Readers see the whole file or no file, and concurrent pairing cannot replace
// an existing identity. Credential bytes never appear in a temporary filename.
func saveIdentity(c config.Config, id identity) error {
	data, err := json.Marshal(id)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(c.StateDir, ".identity-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Link(f.Name(), identityPath(c)); err != nil {
		return err
	}
	dir, err := os.Open(c.StateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validIdentityField(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, c := range value {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}
