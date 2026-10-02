package funding

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func accountFixture(t *testing.T) (Trust, Quote, Account, Account, Account) {
	t.Helper()
	v, trust, _, raw, _ := fixture(t)
	q, e := DecodeQuote(raw)
	if e != nil {
		t.Fatal(e)
	}
	makeAccount := func(address string, owner Key, encoded string) Account {
		k, e := ParseKey(address)
		if e != nil {
			t.Fatal(e)
		}
		data, e := base64.StdEncoding.DecodeString(encoded)
		if e != nil {
			t.Fatal(e)
		}
		return Account{Address: k, Owner: owner, Data: data}
	}
	token, e := ParseKey(TokenProgram)
	if e != nil {
		t.Fatal(e)
	}
	return trust, q, makeAccount(v.Config, trust.Program, v.ConfigBase64), makeAccount(v.Job, trust.Program, v.JobBase64), makeAccount(v.Escrow, token, v.EscrowBase64)
}
func TestAnchorFundedAccountsAndExtraEscrowBalance(t *testing.T) {
	trust, q, c, j, a := accountFixture(t)
	if e := CheckAccounts(trust, q, 0, c, j, a); e != nil {
		t.Fatal("Anchor/SPL funded snapshot failed", e, len(c.Data), len(j.Data), len(a.Data))
	}
	binary.LittleEndian.PutUint64(a.Data[64:72], q.Price+1)
	if e := CheckAccounts(trust, q, 0, c, j, a); e != nil {
		t.Fatal("excess unsolicited escrow blocked valid job", e)
	}
}
func TestWrongFundedEvidenceNeverPasses(t *testing.T) {
	for name, edit := range map[string]func(*Trust, *Quote, *Account, *Account, *Account){
		"different escrow":      func(_ *Trust, _ *Quote, _ *Account, _ *Account, a *Account) { a.Address[0] ^= 1 },
		"different config":      func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) { c.Address[0] ^= 1 },
		"different job":         func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Address[0] ^= 1 },
		"foreign program":       func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Owner[0] ^= 1 },
		"foreign token program": func(_ *Trust, _ *Quote, _ *Account, _ *Account, a *Account) { a.Owner[0] ^= 1 },
		"executable account":    func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) { c.Executable = true },
		"publisher":             func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) { c.Data[8] ^= 1 },
		"mint":                  func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) { c.Data[40] ^= 1 },
		"treasury":              func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) { c.Data[72] ^= 1 },
		"genesis":               func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) { c.Data[104] ^= 1 },
		"too many policies":     func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) { c.Data[136] = 9 },
		"wrong service kind":    func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) { c.Data[153] = 1 },
		"duplicated policy":     func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) { copy(c.Data[162:178], c.Data[137:153]) },
		"policy work bound": func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) {
			binary.LittleEndian.PutUint64(c.Data[154:162], 1)
		},
		"config bump":            func(_ *Trust, _ *Quote, c *Account, _ *Account, _ *Account) { c.Data[337] ^= 1 },
		"job buyer":              func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[40] ^= 1 },
		"job supplier":           func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[72] ^= 1 },
		"job service":            func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[104] ^= 1 },
		"job request":            func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[121] ^= 1 },
		"job output already set": func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[153] = 1 },
		"job work already set":   func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[193] = 1 },
		"job price":              func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[201] ^= 1 },
		"job deadline":           func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[209] ^= 1 },
		"settled":                func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[217] = 1 },
		"refunded":               func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[217] = 2 },
		"short account":          func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data = j.Data[:217] },
		"wrong discriminator":    func(_ *Trust, _ *Quote, _ *Account, j *Account, _ *Account) { j.Data[0] ^= 1 },
		"escrow mint":            func(_ *Trust, _ *Quote, _ *Account, _ *Account, a *Account) { a.Data[0] ^= 1 },
		"escrow authority":       func(_ *Trust, _ *Quote, _ *Account, _ *Account, a *Account) { a.Data[32] ^= 1 },
		"insufficient escrow": func(_ *Trust, q *Quote, _ *Account, _ *Account, a *Account) {
			binary.LittleEndian.PutUint64(a.Data[64:72], q.Price-1)
		},
		"frozen escrow":   func(_ *Trust, _ *Quote, _ *Account, _ *Account, a *Account) { a.Data[108] = 2 },
		"delegate":        func(_ *Trust, _ *Quote, _ *Account, _ *Account, a *Account) { a.Data[72] = 1 },
		"native":          func(_ *Trust, _ *Quote, _ *Account, _ *Account, a *Account) { a.Data[109] = 1 },
		"close authority": func(_ *Trust, _ *Quote, _ *Account, _ *Account, a *Account) { a.Data[129] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			trust, q, c, j, a := accountFixture(t)
			edit(&trust, &q, &c, &j, &a)
			if e := CheckAccounts(trust, q, 0, c, j, a); e == nil {
				t.Fatal("wrong funded evidence accepted")
			}
		})
	}
}
