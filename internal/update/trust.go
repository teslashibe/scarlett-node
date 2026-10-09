package update

import (
	"errors"
	"regexp"
)

// Trust is everything an update must prove before it is installed.
type Trust struct {
	Keys          []PublicKey
	MacSHA1       string
	MacSHA256     string
	WindowsSHA256 string
	// Rehearsal is set only in a rehearsal build that loaded throwaway pins.
	Rehearsal bool
}

var (
	sha1Pin   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pin = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// LoadTrust returns this build's pinned keys and certificates.
func LoadTrust() (Trust, error) {
	if trust, ok, err := rehearsalTrust(); ok || err != nil {
		return trust, err
	}
	return newTrust(releaseMinisignKeys, releaseMacCertificateSHA1, releaseMacCertificateSHA256, releaseWindowsCertificateSHA256)
}

func newTrust(keys []string, macSHA1, macSHA256, windowsSHA256 string) (Trust, error) {
	t := Trust{MacSHA1: macSHA1, MacSHA256: macSHA256, WindowsSHA256: windowsSHA256}
	if !sha1Pin.MatchString(macSHA1) || !sha256Pin.MatchString(macSHA256) || !sha256Pin.MatchString(windowsSHA256) || len(keys) > 4 {
		return Trust{}, errors.New("invalid updater pins")
	}
	seen := map[[8]byte]bool{}
	for _, text := range keys {
		key, err := ParsePublicKey(text)
		if err != nil || seen[key.ID] {
			return Trust{}, errors.New("invalid updater pins")
		}
		seen[key.ID] = true
		t.Keys = append(t.Keys, key)
	}
	return t, nil
}

// CanVerify reports whether this build trusts any update signing key.
func (t Trust) CanVerify() bool { return len(t.Keys) > 0 }

// MacRequirement is the designated requirement for one pinned identifier.
func (t Trust) MacRequirement(identifier string) string {
	return `identifier "` + identifier + `" and certificate leaf = H"` + t.MacSHA1 + `"`
}
