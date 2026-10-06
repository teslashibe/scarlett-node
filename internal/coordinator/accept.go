package coordinator

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

type LeaseAcceptance struct {
	Version          string `json:"version"`
	State            string `json:"state"`
	FundingAuthority string `json:"funding_authority"`
	Lease            Lease  `json:"lease"`
}

// MaxOfferLifetime bounds the unchanged community offer accepted by a node.
const MaxOfferLifetime = 120 * time.Second

// acceptRetries is how many more times Accept sends the same acceptance after
// a 503 dispatch_busy or network_unavailable. Both are transient, acceptance
// of the exact attempt and fence is idempotent at the coordinator, and no
// provider work starts before an accepted reply.
const acceptRetries = 3

// acceptRetryMargin is how long before the lease deadline Accept stops
// retrying, leaving the rest of the lease to the provider work.
const acceptRetryMargin = 30 * time.Second

// acceptRetryAfter reports whether a failed acceptance may be repeated, and
// the Retry-After to honour first: one second when the coordinator sent none.
// A 401, 404, 409, 429, any other 503 and a transport failure are final.
func acceptRetryAfter(err error) (time.Duration, bool) {
	var status *StatusError
	if !errors.As(err, &status) || status.Status != http.StatusServiceUnavailable || status.Code != "dispatch_busy" && status.Code != "network_unavailable" {
		return 0, false
	}
	return max(status.RetryAfter, MinRetryAfter), true
}

func digest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

// ValidOffer applies Accept's local checks to the unchanged offered terms. A
// failure here means acceptance HTTP is never sent for the offer.
func ValidOffer(offer Lease, now time.Time) error {
	if !offer.AcceptanceRequired || offer.Version != Version || offer.VerifierToken != "" || !digest(offer.RequestSHA256) || !digest(offer.SignedJobID) || (offer.ServiceType != "codex" && offer.ServiceType != "x_read") || !offer.LeaseDeadline.After(now) || offer.LeaseDeadline.After(now.Add(MaxOfferLifetime)) || !offer.SettlementDeadline.Equal(offer.LeaseDeadline) {
		return errors.New("invalid community offer")
	}
	return nil
}

// Accept asks only the locally configured authenticated HTTPS coordinator to
// confirm production receipt authority for the exact immutable offered terms.
// It does not read a node-selected RPC or treat prototype funds as authority.
// A busy or temporarily unavailable coordinator is asked again within this
// call, at most acceptRetries times and never later than acceptRetryMargin
// before the lease deadline. No retry authorizes repeating provider work.
func (c *Client) Accept(ctx context.Context, offer Lease) (Lease, error) {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || c.Credential == "" {
		return Lease{}, errors.New("funded acceptance requires the configured HTTPS coordinator")
	}
	if err := ValidOffer(offer, time.Now()); err != nil {
		return Lease{}, err
	}
	path, err := JobPath(offer.JobID, "accept")
	if err != nil {
		return Lease{}, err
	}
	ctx, cancel := context.WithDeadline(ctx, offer.LeaseDeadline)
	defer cancel()
	body := struct {
		Version       string `json:"version"`
		Attempt       string `json:"attempt"`
		Fence         string `json:"fence"`
		RequestSHA256 string `json:"request_sha256"`
		TermsSHA256   string `json:"terms_sha256"`
	}{Version, offer.Attempt, offer.Fence, offer.RequestSHA256, offer.SignedJobID}
	var reply LeaseAcceptance
	var status int
	for retry := 0; ; retry++ {
		reply = LeaseAcceptance{}
		status, err = c.Post(ctx, path, body, &reply)
		after, retryable := acceptRetryAfter(err)
		if !retryable || retry == acceptRetries {
			break
		}
		wait := RetryAfterWait(after)
		if c.retryWait != nil {
			wait = c.retryWait(after)
		}
		if time.Now().Add(wait).After(offer.LeaseDeadline.Add(-acceptRetryMargin)) {
			break
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Lease{}, err
		case <-timer.C:
		}
	}
	if err != nil {
		return Lease{}, err
	}
	if status != http.StatusOK || reply.Version != Version || reply.State != "leased" || reply.FundingAuthority != "production_receipt" || !digest(reply.Lease.VerifierToken) || !reply.Lease.LeaseDeadline.After(time.Now()) {
		return Lease{}, errors.New("funded acceptance is unavailable or invalid")
	}
	token := reply.Lease.VerifierToken
	reply.Lease.VerifierToken = ""
	want, err := json.Marshal(offer)
	if err != nil {
		return Lease{}, err
	}
	got, err := json.Marshal(reply.Lease)
	if err != nil || string(want) != string(got) {
		return Lease{}, errors.New("accepted terms differ from offered work")
	}
	reply.Lease.VerifierToken = token
	return reply.Lease, nil
}
