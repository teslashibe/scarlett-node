package update

import (
	"crypto/rand"
	"encoding/hex"
)

func randomSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
