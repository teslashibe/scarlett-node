package main

import (
	"context"
	"encoding/json"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOldCoordinatorFallbackRecomputesWholeHeartbeatAndStaysLegacy(t *testing.T) {
	for _, generic := range []int{0, 1} {
		for _, blocked := range []bool{false, true} {
			t.Run(string(rune('0'+generic))+map[bool]string{true: "blocked", false: "available"}[blocked], func(t *testing.T) {
				physical := 2
				calls, enhanced, accepted := 0, 0, 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					var h coordinator.Heartbeat
					if json.NewDecoder(r.Body).Decode(&h) != nil {
						t.Error("invalid test heartbeat")
						http.Error(w, "invalid", 400)
						return
					}
					s := h.Services[0]
					if s.ConfiguredCapacity != nil || s.OperationAvailability != nil || s.RunnableCapacity != nil {
						enhanced++
						http.Error(w, "old API rejects unknown extensions", 400)
						return
					}
					wantState := "exhausted"
					if generic > 0 && !blocked {
						wantState = "available"
					}
					if h.Capacity != generic || h.State != wantState || s.Capacity != generic || generic == 0 && s.State != "exhausted" {
						t.Errorf("physical hints leaked into old root contract: %+v", h)
						http.Error(w, "invalid", 400)
						return
					}
					accepted++
					json.NewEncoder(w).Encode(coordinator.HeartbeatReply{})
				}))
				defer server.Close()
				h := coordinator.Heartbeat{Version: coordinator.Version, NodeID: "synthetic-node", State: "available", Capacity: physical, Services: []coordinator.ServiceHealth{{Kind: "x_read", State: "configured", Capacity: generic, ConfiguredCapacity: &physical, RunnableCapacity: &generic, OperationAvailability: []coordinator.OperationAvailability{{Operation: "search", RunnableCapacity: 2}}}}}
				legacy := false
				client := coordinator.New(server.URL, "synthetic-credential")
				for range 3 {
					if _, err := pollHeartbeatWithFallback(context.Background(), client, h, &legacy, blocked); err != nil {
						t.Fatal("strict old API refused fallback", err)
					}
				}
				if !legacy || enhanced != 1 || calls != 4 || accepted != 3 {
					t.Fatal("fallback did not stick", legacy, enhanced, calls, accepted)
				}
			})
		}
	}
}
