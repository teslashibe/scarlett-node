package coordinator

import (
	"context"
	"slices"
	"sync"

	"github.com/google/uuid"
)

// MaxLeasesPerReply is the most offers one heartbeat answer carries: the
// coordinator sends at most min(8, free slots).
const MaxLeasesPerReply = 8

// MaxOffersSeen is the most acknowledgements one heartbeat carries.
const MaxOffersSeen = 64

// OfferRef names one offer a node received: the job and the attempt of the
// assignment it was offered under.
type OfferRef struct {
	JobID   string `json:"job_id"`
	Attempt string `json:"attempt"`
}

// OfferAttempt identifies an offer well enough to reject it.
type OfferAttempt struct {
	JobID, Attempt, Fence string
}

// canonicalUUID reports whether value is a non-nil UUID in its canonical
// lowercase hyphenated form, the only form the coordinator issues.
func canonicalUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// offersSeen collects the offers the node received since its last heartbeat
// request started, for the next request's offers_seen. The coordinator
// redelivers an offer that a later heartbeat does not acknowledge, so an offer
// is recorded the moment its reply is decoded, before the node judges it.
type offersSeen struct {
	mu   sync.Mutex
	refs []OfferRef
}

// record adds refs in order, once each. An identifier the coordinator cannot
// have issued is left out: the coordinator would reject the whole heartbeat
// for it. Past MaxOffersSeen the oldest go first.
func (s *offersSeen) record(refs ...OfferRef) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ref := range refs {
		if !canonicalUUID(ref.JobID) || !canonicalUUID(ref.Attempt) || slices.Contains(s.refs, ref) {
			continue
		}
		s.refs = append(s.refs, ref)
	}
	if extra := len(s.refs) - MaxOffersSeen; extra > 0 {
		s.refs = slices.Clone(s.refs[extra:])
	}
}

// take returns the record and clears it. It is never nil, so a heartbeat
// carries offers_seen [] rather than null.
func (s *offersSeen) take() []OfferRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.refs
	s.refs = nil
	if out == nil {
		out = []OfferRef{}
	}
	return out
}

// restore puts back what a heartbeat that went unanswered carried, ahead of
// anything recorded since, so the next heartbeat acknowledges it instead.
// Acknowledging an offer twice is harmless.
func (s *offersSeen) restore(refs []OfferRef) {
	if len(refs) == 0 {
		return
	}
	s.mu.Lock()
	newer := s.refs
	s.refs = nil
	s.mu.Unlock()
	s.record(append(slices.Clone(refs), newer...)...)
}

// Reasons a node gives for rejecting an offer it has not accepted.
const (
	// RejectInvalidOffer: ValidOffer refused the offer, it did not decode, or
	// it asks for a proof mode this node does not serve.
	RejectInvalidOffer = "invalid_offer"
	// RejectDraining: the node is drained or stopping.
	RejectDraining = "draining"
	// RejectNoSlot: no worker slot (for web, no web slot) is free.
	RejectNoSlot = "no_slot"
	// RejectNoAccount: no local account can take the offer now.
	RejectNoAccount = "no_account"
	// RejectBusy: the node already runs this job under another attempt.
	RejectBusy = "busy"
	// RejectOther: anything else that stops the node before acceptance, such
	// as a journal that cannot record the attempt.
	RejectOther = "other"
)

// Rejection is the body of an offer rejection.
type Rejection struct {
	Version string `json:"version"`
	Attempt string `json:"attempt"`
	Fence   string `json:"fence"`
	Reason  string `json:"reason"`
}

// Reject tells the coordinator at once that this node will not accept an
// offer, so that the job goes to another node now instead of when a timer
// runs out. It is only for an offer the node never sent an acceptance for:
// the coordinator ends that assignment, and a reject is not a missed offer.
// A 409 attempt_conflict means the assignment is no longer this node's open
// one, which is final. The coordinator answers 204.
func (c *Client) Reject(ctx context.Context, offer OfferAttempt, reason string) error {
	path, err := JobPath(offer.JobID, "reject")
	if err != nil {
		return err
	}
	if c.stats != nil {
		c.stats.rejections.Add(1)
	}
	_, err = c.Post(ctx, path, Rejection{Version: Version, Attempt: offer.Attempt, Fence: offer.Fence, Reason: reason}, nil)
	return err
}

// OfferAttempt identifies l for Reject.
func (l Lease) OfferAttempt() OfferAttempt {
	return OfferAttempt{JobID: l.JobID, Attempt: l.Attempt, Fence: l.Fence}
}
