package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/teslashibe/scarlett-node/internal/localfs"
)

func TestStateRoundTripsAndRefusesUnknownFields(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := localfs.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	f := StateFile{Path: filepath.Join(dir, "update-state.json")}
	s, err := f.Read()
	if err != nil || s.Schema != 1 || f.Exists() {
		t.Fatal("missing state is not a fresh one")
	}
	_, err = f.Update(func(s *State) error {
		s.Pending = &Pending{Phase: PhaseStaged, From: "0.1.13", To: "0.1.14", Kind: "mac-app", Staged: "/tmp/x/Scarlett Node.app", App: "/Applications/Scarlett Node.app", DrainOwner: "none", StartedAt: time.Now().Unix()}
		s.MarkFailed("0.1.12")
		s.MarkFailed("0.1.12")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err = f.Read()
	if err != nil || s.Pending.To != "0.1.14" || len(s.Failed) != 1 || !s.HasFailed("0.1.12") {
		t.Fatalf("state did not round trip: %+v %v", s, err)
	}
	for _, bad := range []string{
		`{"schema":2}`,
		`{"schema":1,"token":"x"}`,
		`{"schema":1,"installed":"latest"}`,
		`{"schema":1,"pending":{"phase":"exploded","from":"0.1.1","to":"0.1.2","kind":"mac-app","drain_owner":"none","started_at":1791480419}}`,
		`{"schema":1,"pending":{"phase":"staged","from":"0.1.1","to":"0.1.2","kind":"mac-app","staged":"relative/path","drain_owner":"none","started_at":1791480419}}`,
		`{"schema":1,"pending":{"phase":"staged","from":"0.1.1","to":"0.1.2","kind":"mac-app","drain_owner":"none","reason":"Bad Reason","started_at":1791480419}}`,
		`{"schema":1}{}`,
	} {
		if _, err := DecodeState([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := f.Write(State{Schema: 1, Installed: "../x"}); err == nil {
		t.Fatal("invalid state written")
	}
	raw, _ := os.ReadFile(f.Path)
	var check State
	if json.Unmarshal(raw, &check) != nil || check.Pending == nil {
		t.Fatal("invalid write replaced the saved state")
	}
}

func TestRolloutOffsetIsStableAndInsideTheWindow(t *testing.T) {
	a := RolloutOffset("node-a", "0.1.14")
	if a != RolloutOffset("node-a", "0.1.14") || a < 0 || a >= RolloutWindow {
		t.Fatal("offset not stable or out of window")
	}
	spread := map[time.Duration]bool{}
	for _, id := range []string{"node-a", "node-b", "node-c", "node-d", "node-e"} {
		spread[RolloutOffset(id, "0.1.14")/time.Minute] = true
	}
	if len(spread) < 4 {
		t.Fatal("nodes are not spread across the window")
	}
}

// The desktop shell (updater.rs) round-trips this exact document; both sides
// must accept it.
func TestStateMatchesTheDesktopShellSchema(t *testing.T) {
	raw := `{"schema":1,"installed":"0.1.13","high_water":"0.1.13","announced":"0.1.13","snooze":{"version":"0.1.14","until":1791480419},"first_seen":{"version":"0.1.14","at":1791480000},"postponed":2,"failed":["0.1.12"],"pending":{"phase":"staged","from":"0.1.13","to":"0.1.14","kind":"mac-app","staged":"/x/Scarlett Node.app","app":"/Applications/Scarlett Node.app","drain_owner":"none","resume_serving":true,"app_pid":42,"started_at":1791480419}}`
	s, err := DecodeState([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(s)
	if string(out) != raw {
		t.Fatalf("round trip changed the document:\n%s", out)
	}
}
