package worker

import "time"

// NextEligibility exposes only a scheduling deadline for one already verified
// local identity. Domain state survives removal while quota or jobs retain it.
// A missing domain has no observed quota floor; cold-client admission remains
// governed by the account pool's credential and identity checks.
func (c *XClients) NextEligibility(id, operation string, now time.Time) time.Time {
	c.mu.Lock()
	domain := c.identities[id]
	c.mu.Unlock()
	if domain == nil {
		return now
	}
	return domain.pacing.Eligibility(c.gap(), now, XGraphQLOperation(operation)).At
}

func XGraphQLOperation(operation string) string {
	switch operation {
	case "search":
		return "SearchTimeline"
	case "profile":
		return "UserByScreenName"
	case "post":
		return "TweetResultByRestId"
	case "thread":
		return "TweetDetail"
	}
	return ""
}
