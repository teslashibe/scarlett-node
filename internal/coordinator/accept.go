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

func digest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

// Accept asks only the locally configured authenticated HTTPS coordinator to
// confirm production receipt authority for the exact immutable offered terms.
// It does not read a node-selected RPC or treat prototype funds as authority.
// No transport retry authorizes repeating provider work.
func (c *Client) Accept(ctx context.Context, offer Lease) (Lease, error) {
	u, err := url.Parse(c.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || c.Credential == "" {
		return Lease{}, errors.New("funded acceptance requires the configured HTTPS coordinator")
	}
	now := time.Now()
	if !offer.AcceptanceRequired || offer.Version != Version || offer.VerifierToken != "" || !digest(offer.RequestSHA256) || !digest(offer.SignedJobID) || (offer.ServiceType != "codex" && offer.ServiceType != "x_read") || !offer.LeaseDeadline.After(now) || offer.LeaseDeadline.After(now.Add(MaxOfferLifetime)) || !offer.SettlementDeadline.Equal(offer.LeaseDeadline) {
		return Lease{}, errors.New("invalid community offer")
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
	status, err := c.Post(ctx, path, body, &reply)
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
