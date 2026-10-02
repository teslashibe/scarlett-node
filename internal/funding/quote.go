package funding

import (
	"crypto/ed25519"
	"encoding/binary"
	"time"
)

const QuoteSize = 273
const QuoteDomain = "scarlett/quote/v2"

// Trust comes only from reviewed local configuration, never a lease.
type Trust struct {
	Program, Config, Publisher, Genesis, USDCMint, Treasury Key
}
type Quote struct {
	Version                                          byte
	Program, Config, Genesis, JobID, Buyer, Supplier Key
	ServiceID                                        [16]byte
	InputCommitment                                  Key
	MaxWorkUnits, Price, QuoteExpiry, JobDeadline    uint64
}
type Expected struct {
	JobID, Buyer, Supplier, InputCommitment Key
	ServiceID                               [16]byte
	MaxWorkUnits                            uint64
	Deadline                                uint64
}

func DecodeQuote(raw []byte) (Quote, error) {
	var q Quote
	if len(raw) != QuoteSize {
		return q, ErrInvalid
	}
	q.Version = raw[0]
	at := 1
	for _, key := range []*Key{&q.Program, &q.Config, &q.Genesis, &q.JobID, &q.Buyer, &q.Supplier} {
		copy(key[:], raw[at:at+32])
		at += 32
	}
	copy(q.ServiceID[:], raw[at:at+16])
	at += 16
	copy(q.InputCommitment[:], raw[at:at+32])
	at += 32
	for _, n := range []*uint64{&q.MaxWorkUnits, &q.Price, &q.QuoteExpiry, &q.JobDeadline} {
		*n = binary.LittleEndian.Uint64(raw[at : at+8])
		at += 8
	}
	return q, nil
}

func (t Trust) Validate() error {
	for _, k := range []Key{t.Program, t.Config, t.Publisher, t.Genesis, t.USDCMint, t.Treasury} {
		if k == (Key{}) {
			return ErrInvalid
		}
	}
	config, _, e := PDA(t.Program, []byte("config"))
	if e != nil || config != t.Config {
		return ErrInvalid
	}
	return nil
}

// VerifyQuote binds the signature and quoted terms. Funding must still be
// independently read at finalized commitment; a signature is not a payment.
// QuoteExpiry can precede execution once the exact job was funded in time.
func VerifyQuote(t Trust, raw, signature []byte, expected Expected, now time.Time) (Quote, error) {
	if t.Validate() != nil || len(signature) != ed25519.SignatureSize {
		return Quote{}, ErrInvalid
	}
	q, e := DecodeQuote(raw)
	if e != nil {
		return Quote{}, e
	}
	if q.Version != 2 || q.Program != t.Program || q.Config != t.Config || q.Genesis != t.Genesis || q.JobID != expected.JobID || q.Buyer != expected.Buyer || q.Supplier != expected.Supplier || q.InputCommitment != expected.InputCommitment || q.ServiceID != expected.ServiceID || q.MaxWorkUnits != expected.MaxWorkUnits || q.JobDeadline != expected.Deadline || q.Buyer == q.Supplier || q.Buyer == (Key{}) || q.Supplier == (Key{}) || q.JobID == (Key{}) || q.InputCommitment == (Key{}) || q.ServiceID == ([16]byte{}) || q.Price == 0 || q.MaxWorkUnits == 0 || q.MaxWorkUnits > 1_000_000_000 || q.QuoteExpiry == 0 || q.QuoteExpiry > q.JobDeadline || now.Unix() < 0 || q.JobDeadline <= uint64(now.Unix()) || q.JobDeadline > uint64(now.Unix())+120 {
		return Quote{}, ErrInvalid
	}
	message := append([]byte(QuoteDomain), raw...)
	if !ed25519.Verify(ed25519.PublicKey(t.Publisher[:]), message, signature) {
		return Quote{}, ErrInvalid
	}
	return q, nil
}
