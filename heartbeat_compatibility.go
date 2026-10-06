package main

import (
	"context"
	"errors"
	"github.com/teslashibe/scarlett-node/internal/coordinator"
)

func pollHeartbeatWithFallback(ctx context.Context, client *coordinator.Client, h coordinator.Heartbeat, legacy *bool, blocked bool) (coordinator.HeartbeatReply, error) {
	if *legacy && len(h.Services) > 0 {
		h.Services, _ = coordinator.WithoutExtensions(h.Services)
		h = legacyServiceHeartbeat(h, blocked)
	}
	reply, err := client.Poll(ctx, h)
	if errors.Is(err, coordinator.ErrHeartbeatRejected) && !*legacy {
		if stripped, removed := coordinator.WithoutExtensions(h.Services); removed {
			h.Services = stripped
			h = legacyServiceHeartbeat(h, blocked)
			reply, err = client.Poll(ctx, h)
			if err == nil {
				*legacy = true
			}
		}
	}
	return reply, err
}
