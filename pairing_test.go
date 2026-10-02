package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/config"
	"golang.org/x/term"
)

func TestPairCodeCompletesOnEnterWithoutEOF(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	result := make(chan error, 1)
	go func() {
		code, err := readPairCode(r)
		if err == nil && code != "synthetic-code" {
			err = errors.New("wrong code")
		}
		result <- err
	}()
	if _, err := w.Write([]byte("synthetic-code\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("pairing still waited for EOF")
	}
}

func TestPairCodeInputBounds(t *testing.T) {
	for _, input := range []string{"", "\n", "a b\n", "a\tb\n", "a\x00b\n", strings.Repeat("a", 257) + "\n", strings.Repeat("a", 257), "\r\n"} {
		if _, err := readPairCode(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted invalid input length %d", len(input))
		}
	}
	for _, input := range []string{"synthetic-code", "synthetic-code\n", "synthetic-code\r\n", strings.Repeat("a", 256) + "\n"} {
		if _, err := readPairCode(strings.NewReader(input)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIdentityPersistenceExclusiveAndPrivate(t *testing.T) {
	c := config.Config{StateDir: filepath.Join(t.TempDir(), "node")}
	if err := prepareStateDir(c.StateDir); err != nil {
		t.Fatal(err)
	}
	ids := []identity{{"node-one", "synthetic-public-one", "synthetic-credential-one"}, {"node-two", "synthetic-public-two", "synthetic-credential-two"}}
	results := make([]error, 2)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i] = saveIdentity(c, ids[i]) }(i)
	}
	wg.Wait()
	winners := 0
	for _, err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("identity had %d writers", winners)
	}
	saved, err := loadIdentity(c)
	if err != nil || (saved != ids[0] && saved != ids[1]) {
		t.Fatal("identity was partial or mixed", err)
	}
	info, err := os.Stat(identityPath(c))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("identity not private")
	}
	files, err := os.ReadDir(c.StateDir)
	if err != nil || len(files) != 1 {
		t.Fatal("temporary credential files left behind")
	}
	if err := saveIdentity(c, ids[0]); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing identity replaced")
	}
}

func TestStateDirectoryAndIdentityRejectSymlinks(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	if err := prepareStateDir(link); err == nil {
		t.Fatal("symlink state directory accepted")
	}
	c := config.Config{StateDir: filepath.Join(t.TempDir(), "node")}
	if err := prepareStateDir(c.StateDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(target, "other-identity"), identityPath(c)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentity(c); err == nil {
		t.Fatal("symlink identity accepted")
	}
}

func TestProtectedPairCodeTerminal(t *testing.T) {
	// A local PTY check invokes this test with stdin attached to a terminal.
	// Ordinary CI has no terminal and still covers protected pipe input above.
	if os.Getenv("SCARLETT_TEST_PAIR_TTY") != "1" || !term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("no terminal attached")
	}
	code, err := readProtectedPairCode(os.Stdin)
	if err != nil || code != "synthetic-hidden-code" {
		t.Fatal("protected terminal input failed")
	}
}
