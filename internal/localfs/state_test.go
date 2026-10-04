package localfs

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPrivateAtomicPublicationNeverOverwritesIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private Unicode λ with spaces")
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "identity.json")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if WriteAtomic(path, []byte("synthetic complete identity"), false) == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("identity publication did not have one winner", wins.Load())
	}
	f, err := OpenPrivate(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(f)
	f.Close()
	if err != nil || !bytes.Equal(raw, []byte("synthetic complete identity")) {
		t.Fatal("identity partial or unreadable", err)
	}
	if err := WriteAtomic(path, []byte("replacement"), false); err == nil {
		t.Fatal("identity replaced")
	}
	if err := WriteAtomic(path, []byte("synthetic replacement"), true); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatal("private temporary files retained")
	}
}

func TestCreateDirClaimsOnlyNewPrivateDirectories(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private profiles λ")
	if err := EnsureDir(parent); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "codex-1")
	if err := CreateDir(path); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(path); err != nil {
		t.Fatal("new directory is not private", err)
	}
	if err := CreateDir(path); !errors.Is(err, fs.ErrExist) {
		t.Fatal("existing directory was claimed again", err)
	}
	file := filepath.Join(parent, "codex-2")
	if err := os.WriteFile(file, []byte("retained synthetic file"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CreateDir(file); !errors.Is(err, fs.ErrExist) {
		t.Fatal("existing file was not reported as taken", err)
	}
	if raw, err := os.ReadFile(file); err != nil || string(raw) != "retained synthetic file" {
		t.Fatal("existing file changed", err)
	}
	unclean := parent + string(filepath.Separator) + "x" + string(filepath.Separator) + ".." + string(filepath.Separator) + "codex-3"
	for _, invalid := range []string{"relative", unclean, filepath.Join(parent, "missing", "codex-4")} {
		if err := CreateDir(invalid); err == nil || errors.Is(err, fs.ErrExist) {
			t.Fatal("invalid or parentless directory was claimed or reported as taken", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(parent, "missing")); !os.IsNotExist(err) {
		t.Fatal("missing parent was created")
	}
}
