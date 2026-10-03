package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/teslashibe/scarlett-node/internal/config"
	"github.com/teslashibe/scarlett-node/internal/localfs"
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

func prepareStateDir(path string) error { return localfs.EnsureDir(path) }

// A complete synced private file claims the identity name exclusively. Pairing
// never overwrites an existing identity, including concurrent pairing calls.
func saveIdentity(c config.Config, id identity) error {
	data, err := json.Marshal(id)
	if err != nil {
		return err
	}
	return localfs.WriteAtomic(identityPath(c), data, false)
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
