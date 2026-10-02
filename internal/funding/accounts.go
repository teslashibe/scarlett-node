package funding

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

type Account struct {
	Address    Key
	Owner      Key
	Executable bool
	Data       []byte
}

const TokenProgram = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

func discriminator(data []byte, name string) bool {
	if len(data) < 8 {
		return false
	}
	h := sha256.Sum256([]byte("account:" + name))
	return bytes.Equal(data[:8], h[:8])
}
func keyAt(data []byte, offset int) (k Key) { copy(k[:], data[offset:offset+32]); return }

// CheckAccounts validates one consistent finalized account snapshot. All
// addresses, owners, discriminators, mint/treasury pins and immutable job terms
// must agree; a different escrow cannot stand in for this job's escrow.
func CheckAccounts(t Trust, q Quote, kind byte, config, job, escrow Account) error {
	if t.Validate() != nil || q.Version != 2 || q.Program != t.Program || q.Config != t.Config || q.Genesis != t.Genesis || kind > 1 || config.Owner != t.Program || job.Owner != t.Program || config.Executable || job.Executable || escrow.Executable || len(config.Data) != 338 || len(job.Data) != 218 || len(escrow.Data) != 165 || !discriminator(config.Data, "Config") || !discriminator(job.Data, "Job") {
		return ErrInvalid
	}
	configKey, bump, e := PDA(t.Program, []byte("config"))
	if e != nil || configKey != config.Address || configKey != t.Config {
		return ErrInvalid
	}
	jobKey, _, e := PDA(t.Program, []byte("job"), q.JobID[:])
	if e != nil || jobKey != job.Address {
		return ErrInvalid
	}
	escrowKey, _, e := PDA(t.Program, []byte("escrow"), jobKey[:])
	if e != nil || escrowKey != escrow.Address {
		return ErrInvalid
	}
	tokenProgram, e := ParseKey(TokenProgram)
	if e != nil || escrow.Owner != tokenProgram {
		return ErrInvalid
	}
	c := config.Data
	if keyAt(c, 8) != t.Publisher || keyAt(c, 40) != t.USDCMint || keyAt(c, 72) != t.Treasury || keyAt(c, 104) != t.Genesis || c[337] != bump || c[136] < 1 || c[136] > 8 {
		return ErrInvalid
	}
	seen := map[[16]byte]bool{}
	found := false
	for i := 0; i < int(c[136]); i++ {
		at := 137 + i*25
		var id [16]byte
		copy(id[:], c[at:at+16])
		serviceKind := c[at+16]
		units := binary.LittleEndian.Uint64(c[at+17 : at+25])
		if id == ([16]byte{}) || seen[id] || serviceKind > 1 || units == 0 || units > 1_000_000_000 {
			return ErrInvalid
		}
		seen[id] = true
		if id == q.ServiceID {
			if serviceKind != kind || q.MaxWorkUnits > units {
				return ErrInvalid
			}
			found = true
		}
	}
	if !found {
		return ErrInvalid
	}
	j := job.Data
	if keyAt(j, 8) != q.JobID || keyAt(j, 40) != q.Buyer || keyAt(j, 72) != q.Supplier || !bytes.Equal(j[104:120], q.ServiceID[:]) || j[120] != kind || keyAt(j, 121) != q.InputCommitment || keyAt(j, 153) != (Key{}) || binary.LittleEndian.Uint64(j[185:193]) != q.MaxWorkUnits || binary.LittleEndian.Uint64(j[193:201]) != 0 || binary.LittleEndian.Uint64(j[201:209]) != q.Price || binary.LittleEndian.Uint64(j[209:217]) != q.JobDeadline || j[217] != 0 {
		return ErrInvalid
	}
	a := escrow.Data
	if keyAt(a, 0) != t.USDCMint || keyAt(a, 32) != t.Config || binary.LittleEndian.Uint64(a[64:72]) < q.Price || binary.LittleEndian.Uint32(a[72:76]) != 0 || a[108] != 1 || binary.LittleEndian.Uint32(a[109:113]) != 0 || binary.LittleEndian.Uint64(a[121:129]) != 0 || binary.LittleEndian.Uint32(a[129:133]) != 0 {
		return ErrInvalid
	}
	return nil
}
