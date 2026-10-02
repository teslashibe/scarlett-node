package funding

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type anchorVector struct {
	ConfigBase64, JobBase64, EscrowBase64   string
	Now                                     int64 `json:"now"`
	Program, Publisher, Config, Job, Escrow string
	ConfigBump, JobBump, EscrowBump         byte
	QuoteBase64, SignatureBase64            string
}

func fixture(t *testing.T) (anchorVector, Trust, Expected, []byte, []byte) {
	t.Helper()
	raw, e := os.ReadFile("testdata/anchor-v2.json")
	if e != nil {
		t.Fatal(e)
	}
	var v anchorVector
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	quote, e := base64.StdEncoding.DecodeString(v.QuoteBase64)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := base64.StdEncoding.DecodeString(v.SignatureBase64)
	if e != nil {
		t.Fatal(e)
	}
	q, e := DecodeQuote(quote)
	if e != nil {
		t.Fatal(e)
	}
	publisher, e := ParseKey(v.Publisher)
	if e != nil {
		t.Fatal(e)
	}
	trust := Trust{Program: q.Program, Config: q.Config, Publisher: publisher, Genesis: q.Genesis, USDCMint: filled(11), Treasury: filled(12)}
	expected := Expected{JobID: q.JobID, Buyer: q.Buyer, Supplier: q.Supplier, InputCommitment: q.InputCommitment, ServiceID: q.ServiceID, MaxWorkUnits: q.MaxWorkUnits, Deadline: q.JobDeadline}
	return v, trust, expected, quote, sig
}
func filled(n byte) (k Key) {
	for i := range k {
		k[i] = n
	}
	return
}

func TestAnchorBorshSignatureAndPDAVectors(t *testing.T) {
	v, trust, expected, raw, sig := fixture(t)
	q, e := VerifyQuote(trust, raw, sig, expected, time.Unix(v.Now, 0))
	if e != nil || q.Price != 1000000 || q.MaxWorkUnits != 150 || len(raw) != 273 {
		t.Fatal("Anchor quote failed", e, q)
	}
	config, bump, e := PDA(q.Program, []byte("config"))
	if e != nil || config.String() != v.Config || bump != v.ConfigBump {
		t.Fatal("config PDA disagrees with Solana", e)
	}
	job, bump, e := PDA(q.Program, []byte("job"), q.JobID[:])
	if e != nil || job.String() != v.Job || bump != v.JobBump {
		t.Fatal("job PDA disagrees with Solana", e)
	}
	escrow, bump, e := PDA(q.Program, []byte("escrow"), job[:])
	if e != nil || escrow.String() != v.Escrow || bump != v.EscrowBump {
		t.Fatal("escrow PDA disagrees with Solana", e)
	}
	// A funded quote may be past quote expiry but still before the job deadline.
	if _, e = VerifyQuote(trust, raw, sig, expected, time.Unix(v.Now+30, 0)); e != nil {
		t.Fatal("funded quote prematurely expired", e)
	}
	if _, e = VerifyQuote(trust, raw, sig, expected, time.Unix(v.Now+60, 0)); e == nil {
		t.Fatal("exclusive job deadline accepted")
	}
}

func TestQuoteCannotChangeOwnerRequestServiceBoundsOrLocalPins(t *testing.T) {
	v, trust, expected, raw, sig := fixture(t)
	for name, edit := range map[string]func(*Expected){
		"job": func(e *Expected) { e.JobID[0] ^= 1 }, "buyer": func(e *Expected) { e.Buyer[0] ^= 1 }, "supplier": func(e *Expected) { e.Supplier[0] ^= 1 }, "request": func(e *Expected) { e.InputCommitment[0] ^= 1 }, "service": func(e *Expected) { e.ServiceID[0] ^= 1 }, "work bound": func(e *Expected) { e.MaxWorkUnits++ }, "deadline": func(e *Expected) { e.Deadline++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := expected
			edit(&bad)
			if _, e := VerifyQuote(trust, raw, sig, bad, time.Unix(v.Now, 0)); e == nil {
				t.Fatal("changed binding accepted")
			}
		})
	}
	for name, edit := range map[string]func(*Trust){"publisher": func(t *Trust) { t.Publisher[0] ^= 1 }, "program": func(t *Trust) { t.Program[0] ^= 1 }, "config": func(t *Trust) { t.Config[0] ^= 1 }, "genesis": func(t *Trust) { t.Genesis[0] ^= 1 }, "zero mint": func(t *Trust) { t.USDCMint = Key{} }, "zero treasury": func(t *Trust) { t.Treasury = Key{} }} {
		t.Run(name, func(t *testing.T) {
			bad := trust
			edit(&bad)
			if _, e := VerifyQuote(bad, raw, sig, expected, time.Unix(v.Now, 0)); e == nil {
				t.Fatal("changed local pin accepted")
			}
		})
	}
	for i := range raw {
		bad := append([]byte{}, raw...)
		bad[i] ^= 1
		if _, e := VerifyQuote(trust, bad, sig, expected, time.Unix(v.Now, 0)); e == nil {
			t.Fatalf("changed byte %d accepted", i)
		}
	}
	for _, bad := range [][]byte{nil, raw[:272], append(append([]byte{}, raw...), 0)} {
		if _, e := VerifyQuote(trust, bad, sig, expected, time.Unix(v.Now, 0)); e == nil {
			t.Fatal("wrong sized quote accepted")
		}
	}
	for _, bad := range [][]byte{nil, sig[:63], append(append([]byte{}, sig...), 0), make([]byte, 64)} {
		if _, e := VerifyQuote(trust, raw, bad, expected, time.Unix(v.Now, 0)); e == nil {
			t.Fatal("invalid signature accepted")
		}
	}
}

func TestSignedInvalidQuoteStillFailsSemanticChecks(t *testing.T) {
	v, trust, expected, raw, _ := fixture(t)
	// The signing seed is a public synthetic fixture, never a production key.
	seed := filled(7)
	private := ed25519.NewKeyFromSeed(seed[:])
	for name, edit := range map[string]func([]byte, *Expected){
		"old version":  func(b []byte, e *Expected) { b[0] = 1 },
		"self dealing": func(b []byte, e *Expected) { copy(b[161:193], b[129:161]); e.Supplier = e.Buyer },
		"zero price":   func(b []byte, e *Expected) { binary.LittleEndian.PutUint64(b[249:257], 0) },
		"zero work":    func(b []byte, e *Expected) { binary.LittleEndian.PutUint64(b[241:249], 0); e.MaxWorkUnits = 0 },
		"too much work": func(b []byte, e *Expected) {
			binary.LittleEndian.PutUint64(b[241:249], 1000000001)
			e.MaxWorkUnits = 1000000001
		},
		"expiry after deadline": func(b []byte, e *Expected) { binary.LittleEndian.PutUint64(b[257:265], e.Deadline+1) },
	} {
		t.Run(name, func(t *testing.T) {
			b := append([]byte{}, raw...)
			want := expected
			edit(b, &want)
			sig := ed25519.Sign(private, append([]byte(QuoteDomain), b...))
			if _, e := VerifyQuote(trust, b, sig, want, time.Unix(v.Now, 0)); e == nil {
				t.Fatal("signed invalid quote accepted")
			}
		})
	}
	b := append([]byte{}, raw...)
	binary.LittleEndian.PutUint64(b[257:265], expected.Deadline)
	sig := ed25519.Sign(private, append([]byte(QuoteDomain), b...))
	if _, e := VerifyQuote(trust, b, sig, expected, time.Unix(v.Now, 0)); e != nil {
		t.Fatal("protocol permits equal expiry/deadline", e)
	}
}

func TestCanonicalKeysAndSeedLimits(t *testing.T) {
	for _, key := range []Key{{}, filled(1), filled(255), {31: 1}} {
		value, e := ParseKey(key.String())
		if e != nil || value != key {
			t.Fatal("key roundtrip", e)
		}
	}
	for _, s := range []string{"", "0", "O", "111111111111111111111111111111111", "11111111111111111111111111111111111", filled(255).String() + "1"} {
		if _, e := ParseKey(s); e == nil {
			t.Fatal("invalid/noncanonical key accepted")
		}
	}
	if _, _, e := PDA(filled(1), make([]byte, 33)); e == nil {
		t.Fatal("oversized seed accepted")
	}
	if _, _, e := PDA(filled(1), make([][]byte, 16)...); e == nil {
		t.Fatal("too many seeds accepted")
	}
}
