package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/teslashibe/scarlett-node/internal/update"
)

// The shell writes the update state through a separate helper process per
// read and write, so update-state-set is a compare-and-swap: a write based on
// a state another writer changed in between is refused, never applied over
// that change.
func TestDesktopUpdateStateSetRefusesAWriteBasedOnAChangedState(t *testing.T) {
	t.Setenv("SCARLETT_STATE_DIR", privateTestDir(t))
	get := func() update.Revisioned {
		t.Helper()
		var out bytes.Buffer
		if err := desktopUpdateCommand([]string{"update-state-get"}, strings.NewReader(""), &out); err != nil {
			t.Fatal(err)
		}
		r, err := update.DecodeRevisioned(bytes.TrimSpace(out.Bytes()))
		if err != nil {
			t.Fatalf("%v: %s", err, out.Bytes())
		}
		return r
	}
	set := func(r update.Revisioned) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(r)
		var out bytes.Buffer
		if err := desktopUpdateCommand([]string{"update-state-set"}, bytes.NewReader(raw), &out); err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.Unmarshal(out.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	// Two writers read the same state; the first one's change lands.
	first, second := get(), get()
	first.State.Announced = "0.1.14"
	if result := set(first); result["conflict"] != nil || result["revision"] != first.State.Revision() {
		t.Fatalf("first write: %v", result)
	}
	// The second is refused and changes nothing; read again, it applies.
	second.State.Postponed = 1
	if result := set(second); result["conflict"] != true {
		t.Fatalf("stale write accepted: %v", result)
	}
	again := get()
	if again.State.Announced != "0.1.14" || again.State.Postponed != 0 {
		t.Fatalf("stale write changed the state: %+v", again.State)
	}
	again.State.Postponed = 1
	if result := set(again); result["conflict"] != nil {
		t.Fatalf("fresh write refused: %v", result)
	}
	if s := get().State; s.Announced != "0.1.14" || s.Postponed != 1 {
		t.Fatalf("both changes not kept: %+v", s)
	}
	for _, bad := range []string{`{"schema":1}`, `{"revision":"x","state":{"schema":1}}`, `{"revision":"` + strings.Repeat("0", 64) + `","state":{"schema":2}}`} {
		if err := desktopUpdateCommand([]string{"update-state-set"}, strings.NewReader(bad), &bytes.Buffer{}); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
