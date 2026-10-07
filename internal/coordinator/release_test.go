package coordinator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

type versionFixture struct {
	LegacyNodeVersion string            `json:"legacy_node_version"`
	Headers           map[string]string `json:"headers"`
	Exchanges         []struct {
		RequestHeaders  map[string]string `json:"request_headers"`
		ResponseHeaders map[string]string `json:"response_headers"`
	} `json:"exchanges"`
}

func readVersionFixture(t *testing.T) versionFixture {
	t.Helper()
	data, err := os.ReadFile("../../api/fixtures/version-headers.json")
	if err != nil {
		t.Fatal(err)
	}
	var f versionFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestVersionHeadersMatchTheContract(t *testing.T) {
	f := readVersionFixture(t)
	want := map[string]string{"node_version": NodeVersionHeader, "latest_version": NodeLatestVersionHeader, "minimum_version": NodeMinimumVersionHeader, "update_required": NodeUpdateRequiredHeader}
	for name, header := range want {
		if f.Headers[name] != header {
			t.Fatalf("%s header %q, contract %q", name, header, f.Headers[name])
		}
	}
	// A build older than the legacy release would be read as newer than it is.
	if !ValidVersion(NodeRelease) || CompareVersions(NodeRelease, f.LegacyNodeVersion) < 0 {
		t.Fatal("NodeRelease must be a version at or after the legacy release", NodeRelease)
	}
	if len(f.Exchanges) == 0 {
		t.Fatal("no exchanges")
	}
}

// Every exchange in the contract is replayed: the node reads the same notice
// from the coordinator's reply that the coordinator meant to send.
func TestReleaseNoticeFollowsContractExchanges(t *testing.T) {
	for _, exchange := range readVersionFixture(t).Exchanges {
		c := New("https://coordinator.invalid", "")
		h := http.Header{}
		for k, v := range exchange.ResponseHeaders {
			h.Set(k, v)
		}
		c.observeRelease(h)
		notice, ok := c.Release()
		if !ok || notice.Latest != exchange.ResponseHeaders[NodeLatestVersionHeader] || notice.Minimum != exchange.ResponseHeaders[NodeMinimumVersionHeader] || notice.Required != (exchange.ResponseHeaders[NodeUpdateRequiredHeader] == "true") {
			t.Fatalf("exchange %v read as %+v", exchange, notice)
		}
		// The coordinator requires an update exactly for a node below minimum.
		sent := exchange.RequestHeaders[NodeVersionHeader]
		if (CompareVersions(sent, notice.Minimum) < 0) != notice.Required {
			t.Fatalf("node %s, minimum %s, required %v", sent, notice.Minimum, notice.Required)
		}
	}
}

func TestEveryRequestSendsTheReleaseAndReadsTheNotice(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.Header.Get(NodeVersionHeader))
		w.Header().Set(NodeLatestVersionHeader, "99.0.0")
		w.Header().Set(NodeMinimumVersionHeader, "98.0.0")
		w.Header().Set(NodeUpdateRequiredHeader, "true")
		switch r.URL.Path {
		case "/api/node/v1/heartbeat":
			w.Write([]byte(`{"lease":null}`))
		case "/api/node/v1/jobs/job/attempt":
			// An unsupported reply still carries the policy.
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	c := New(server.URL, "test-credential")
	if _, ok := c.Release(); ok {
		t.Fatal("notice before any response")
	}
	if _, err := c.Poll(context.Background(), Heartbeat{Version: Version}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Post(context.Background(), "/api/node/v1/pair", map[string]string{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AttemptStatus(context.Background(), "job", "attempt", "fence"); err == nil {
		t.Fatal("unsupported attempt status accepted")
	}
	if len(seen) != 3 {
		t.Fatal(seen)
	}
	for _, line := range seen {
		if line[len(line)-len(NodeRelease)-1:] != " "+NodeRelease {
			t.Fatal("request without the release version:", line)
		}
	}
	notice, ok := c.Release()
	if !ok || notice != (ReleaseNotice{Latest: "99.0.0", Minimum: "98.0.0", Required: true}) || !notice.UpdateAvailable() {
		t.Fatalf("%+v %v", notice, ok)
	}
}

func TestReleaseNoticeIgnoresRepliesWithoutPolicy(t *testing.T) {
	c := New("https://coordinator.invalid", "")
	h := http.Header{}
	h.Set(NodeLatestVersionHeader, "0.1.10")
	h.Set(NodeUpdateRequiredHeader, "true")
	c.observeRelease(h)
	// A proxy page with no headers, or garbage, keeps the last notice.
	c.observeRelease(http.Header{})
	bad := http.Header{}
	bad.Set(NodeLatestVersionHeader, "v0.1.11")
	c.observeRelease(bad)
	if notice, _ := c.Release(); notice.Latest != "0.1.10" || !notice.Required {
		t.Fatalf("%+v", notice)
	}
	// The coordinator lifting the requirement clears it.
	ok := http.Header{}
	ok.Set(NodeLatestVersionHeader, "0.1.10")
	c.observeRelease(ok)
	if notice, _ := c.Release(); notice.Required {
		t.Fatalf("%+v", notice)
	}
}

func TestCompareVersions(t *testing.T) {
	ordered := []string{"0.1.8", "0.1.9", "0.1.10-alpha", "0.1.10-alpha.1", "0.1.10-alpha.beta", "0.1.10-beta.2", "0.1.10-beta.11", "0.1.10-rc.1", "0.1.10", "0.2.0", "1.0.0"}
	for i := range ordered {
		for k := range ordered {
			want := 0
			if i < k {
				want = -1
			} else if i > k {
				want = 1
			}
			if got := CompareVersions(ordered[i], ordered[k]); got != want {
				t.Fatalf("%s vs %s: %d, want %d", ordered[i], ordered[k], got, want)
			}
		}
	}
	for _, bad := range []string{"", "v0.1.10", "0.1", "0.01.1", "0.1.1+build", "0.1.1-", "0.1.1-01", "1.2.3.4", "0.1.1-a..b"} {
		if ValidVersion(bad) {
			t.Fatal("accepted", bad)
		}
		if CompareVersions(bad, "0.0.0") >= 0 {
			t.Fatal("invalid version sorted at or after a valid one", bad)
		}
	}
}
