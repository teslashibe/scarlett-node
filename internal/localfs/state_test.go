package localfs

import (
	"bytes"
	"io"
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
