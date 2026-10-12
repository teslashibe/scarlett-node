package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v2"
)

// Availability carries the heartbeat's report without the hold or the
// acknowledgements; a goodbye carries the node and its reason. Both are
// answered 204 on their own routes.
func TestAvailabilityAndGoodbyeBodies(t *testing.T) {
	type call struct {
		path string
		body map[string]any
	}
	calls := make(chan call, 4)
	status := http.StatusNoContent
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if r.Header.Get("Authorization") != "Bearer demo" || r.Header.Get(NodeVersionHeader) != NodeRelease || json.Unmarshal(raw, &body) != nil {
			t.Error("unauthenticated or malformed post")
		}
		calls <- call{r.URL.Path, body}
		w.WriteHeader(status)
	}))
	defer ts.Close()
	c := New(ts.URL, "demo")
	services := []ServiceHealth{{Kind: "x_read", State: "ready", Capacity: 2, ProofModes: []string{"mpc", "relay"}}}
	h := Heartbeat{Version: Version, NodeID: "synthetic-node", Profile: "standard", State: "available", Bid: 100, Capacity: 2, Services: services, WaitSeconds: 20, OffersSeen: []OfferRef{ref(1)}}
	if err := c.Availability(context.Background(), AvailabilityOf(h)); err != nil {
		t.Fatal(err)
	}
	got := <-calls
	var fixture map[string]any
	raw, _ := json.Marshal(AvailabilityOf(h))
	_ = json.Unmarshal(raw, &fixture)
	if got.path != "/api/node/v1/availability" || !reflect.DeepEqual(got.body, fixture) || got.body["wait_seconds"] != nil || got.body["offers_seen"] != nil || len(got.body) != 7 {
		t.Fatalf("availability %+v", got)
	}
	if err := c.Goodbye(context.Background(), "synthetic-node", GoodbyeSleep); err != nil {
		t.Fatal(err)
	}
	got = <-calls
	if got.path != "/api/node/v1/goodbye" || !reflect.DeepEqual(got.body, map[string]any{"version": Version, "node_id": "synthetic-node", "reason": "sleep"}) {
		t.Fatalf("goodbye %+v", got)
	}
	status = http.StatusBadRequest
	var refused *StatusError
	if err := c.Goodbye(context.Background(), "synthetic-node", GoodbyeStop); !errors.As(err, &refused) || refused.Status != http.StatusBadRequest {
		t.Fatalf("refused goodbye reported as %v", err)
	}
	<-calls
}

// The reasons the node sends are exactly the coordinator's enums.
func TestGoodbyeAndRejectReasonsMatchTheContract(t *testing.T) {
	if got := []string{GoodbyeStop, GoodbyeQuit, GoodbyeSignal, GoodbyeUpdate, GoodbyeSleep}; !reflect.DeepEqual(got, []string{"stop", "quit", "signal", "update", "sleep"}) {
		t.Fatal(got)
	}
	if got := []string{RejectInvalidOffer, RejectDraining, RejectNoSlot, RejectNoAccount, RejectBusy, RejectOther}; !reflect.DeepEqual(got, []string{"invalid_offer", "draining", "no_slot", "no_account", "busy", "other"}) {
		t.Fatal(got)
	}
}

// The spec's node-v2 pieces are the node's: every body names node-v2, the
// heartbeat requires offers_seen with the node's bound, an answer carries at
// most MaxLeasesPerReply leases, and the goodbye and rejection reasons are the
// node's constants.
func TestOpenAPIDescribesProtocolV2(t *testing.T) {
	raw, err := os.ReadFile("../../api/node-v1.openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "node-v1]") || !strings.Contains(string(raw), "version: node-v2") {
		t.Fatal("spec still names the old protocol")
	}
	type enumField struct {
		Enum []string `yaml:"enum"`
	}
	var spec struct {
		Paths      map[string]map[string]any `yaml:"paths"`
		Components struct {
			Schemas struct {
				Heartbeat struct {
					Required   []string `yaml:"required"`
					Properties struct {
						OffersSeen struct {
							MaxItems int `yaml:"maxItems"`
						} `yaml:"offers_seen"`
					} `yaml:"properties"`
				} `yaml:"Heartbeat"`
				HeartbeatReply struct {
					Required   []string `yaml:"required"`
					Properties struct {
						Leases struct {
							MaxItems int `yaml:"maxItems"`
						} `yaml:"leases"`
					} `yaml:"properties"`
				} `yaml:"HeartbeatReply"`
				Goodbye struct {
					Properties struct {
						Reason enumField `yaml:"reason"`
					} `yaml:"properties"`
				} `yaml:"Goodbye"`
				Rejection struct {
					Properties struct {
						Reason enumField `yaml:"reason"`
					} `yaml:"properties"`
				} `yaml:"Rejection"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	s := spec.Components.Schemas
	if !slices.Contains(s.Heartbeat.Required, "offers_seen") || s.Heartbeat.Properties.OffersSeen.MaxItems != MaxOffersSeen {
		t.Fatalf("heartbeat offers_seen %+v", s.Heartbeat)
	}
	if !reflect.DeepEqual(s.HeartbeatReply.Required, []string{"leases", "node"}) || s.HeartbeatReply.Properties.Leases.MaxItems != MaxLeasesPerReply {
		t.Fatalf("heartbeat reply %+v", s.HeartbeatReply)
	}
	if got := s.Goodbye.Properties.Reason.Enum; !reflect.DeepEqual(got, []string{GoodbyeStop, GoodbyeQuit, GoodbyeSignal, GoodbyeUpdate, GoodbyeSleep}) {
		t.Fatalf("goodbye reasons %v", got)
	}
	if got := s.Rejection.Properties.Reason.Enum; !reflect.DeepEqual(got, []string{RejectInvalidOffer, RejectDraining, RejectNoSlot, RejectNoAccount, RejectBusy, RejectOther}) {
		t.Fatalf("rejection reasons %v", got)
	}
	for _, path := range []string{"/api/node/v1/availability", "/api/node/v1/goodbye", "/api/node/v1/jobs/{job_id}/reject"} {
		if spec.Paths[path]["post"] == nil {
			t.Fatalf("spec lacks POST %s", path)
		}
	}
}
