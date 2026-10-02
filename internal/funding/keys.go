// Package funding validates the pinned v2 protocol's signed quotes and account
// evidence. The current protocol is a test-USDC prototype; these checks alone
// do not establish real paid eligibility or authorize provider execution.
package funding

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"strings"

	"filippo.io/edwards25519"
)

type Key [32]byte

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var ErrInvalid = errors.New("invalid funding evidence")

func ParseKey(s string) (Key, error) {
	var key Key
	if len(s) < 32 || len(s) > 44 {
		return key, ErrInvalid
	}
	n := new(big.Int)
	radix := big.NewInt(58)
	for _, c := range s {
		i := strings.IndexRune(alphabet, c)
		if i < 0 {
			return key, ErrInvalid
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(i)))
	}
	raw := n.Bytes()
	if len(raw) > 32 {
		return key, ErrInvalid
	}
	copy(key[32-len(raw):], raw)
	if key.String() != s {
		return Key{}, ErrInvalid
	}
	return key, nil
}
func (k Key) String() string {
	n := new(big.Int).SetBytes(k[:])
	base := big.NewInt(58)
	r := new(big.Int)
	out := ""
	for n.Sign() > 0 {
		n.QuoRem(n, base, r)
		out = string(alphabet[r.Int64()]) + out
	}
	for _, b := range k {
		if b != 0 {
			break
		}
		out = "1" + out
	}
	return out
}

// PDA follows Solana's canonical descending bump search. The curve check uses
// the maintained Edwards decoder, including accepted noncanonical encodings.
func PDA(program Key, seeds ...[]byte) (Key, byte, error) {
	if len(seeds) > 15 {
		return Key{}, 0, ErrInvalid
	}
	for _, seed := range seeds {
		if len(seed) > 32 {
			return Key{}, 0, ErrInvalid
		}
	}
	for bump := 255; bump >= 0; bump-- {
		h := sha256.New()
		for _, seed := range seeds {
			h.Write(seed)
		}
		h.Write([]byte{byte(bump)})
		h.Write(program[:])
		h.Write([]byte("ProgramDerivedAddress"))
		var key Key
		copy(key[:], h.Sum(nil))
		if _, e := new(edwards25519.Point).SetBytes(key[:]); e != nil {
			return key, byte(bump), nil
		}
	}
	return Key{}, 0, ErrInvalid
}
