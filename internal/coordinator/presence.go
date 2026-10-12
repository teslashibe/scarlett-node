package coordinator

import (
	"context"
	"time"
)

// AvailabilityInterval is the least time between the starts of two
// availability posts; changes in between are sent together in the next one.
const AvailabilityInterval = 250 * time.Millisecond

// GoodbyeTimeout bounds a goodbye. It is best effort and must not hold up a
// stop or a sleep.
const GoodbyeTimeout = time.Second

// Availability is what a node reports while the coordinator holds its
// heartbeat: the heartbeat's report without the hold or the
// acknowledgements, under the same validation. The coordinator stores the
// state, capacity and services and has the held heartbeat look for offers
// again at once; it does not count as a heartbeat. The node sends one when
// what it advertised changes, at most every AvailabilityInterval, instead of
// cutting its held heartbeat short.
type Availability struct {
	Version  string          `json:"version"`
	NodeID   string          `json:"node_id"`
	Profile  string          `json:"profile"`
	State    string          `json:"state"`
	Bid      int64           `json:"bid"`
	Capacity int             `json:"capacity"`
	Services []ServiceHealth `json:"services,omitempty"`
}

// AvailabilityOf is the report of h as an availability post.
func AvailabilityOf(h Heartbeat) Availability {
	return Availability{Version: h.Version, NodeID: h.NodeID, Profile: h.Profile, State: h.State, Bid: h.Bid, Capacity: h.Capacity, Services: h.Services}
}

// Availability posts a. The coordinator answers 204.
func (c *Client) Availability(ctx context.Context, a Availability) error {
	if c.stats != nil {
		c.stats.availabilityPosts.Add(1)
	}
	_, err := c.Post(ctx, "/api/node/v1/availability", a, nil)
	return err
}

// Reasons a node gives for a goodbye.
const (
	// GoodbyeStop: the owner pipe closed (the desktop app's Stop or Quit),
	// or a drain began that is not an update's.
	GoodbyeStop = "stop"
	// GoodbyeQuit: the desktop app quit. The node cannot tell Quit from Stop
	// on its owner pipe, so the node itself never sends it.
	GoodbyeQuit = "quit"
	// GoodbyeSignal: SIGTERM or Ctrl-C.
	GoodbyeSignal = "signal"
	// GoodbyeUpdate: the updater paused new work to install a release.
	GoodbyeUpdate = "update"
	// GoodbyeSleep: the machine is about to sleep.
	GoodbyeSleep = "sleep"
)

// Goodbye is the body of a goodbye.
type Goodbye struct {
	Version string `json:"version"`
	NodeID  string `json:"node_id"`
	Reason  string `json:"reason"`
}

// Goodbye tells the coordinator the node is going away for now. The
// coordinator marks it offline, answers its held heartbeats at once with no
// leases and hands every offer this node has not accepted to another node;
// accepted work goes on, and the node's next heartbeat brings it back. It
// answers 204. Callers bound it to GoodbyeTimeout and treat it as best
// effort.
func (c *Client) Goodbye(ctx context.Context, nodeID, reason string) error {
	if c.stats != nil {
		c.stats.goodbyes.Add(1)
	}
	_, err := c.Post(ctx, "/api/node/v1/goodbye", Goodbye{Version: Version, NodeID: nodeID, Reason: reason}, nil)
	return err
}
