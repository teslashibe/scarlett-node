//go:build !rehearsal

package update

// Release builds never read throwaway pins.
func rehearsalTrust() (Trust, bool, error) { return Trust{}, false, nil }
