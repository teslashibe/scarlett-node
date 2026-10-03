//go:build !darwin && !windows

package browserx

import "context"

func pathProtected(string) bool                               { return false }
func nativeChromeKey(context.Context, string) ([]byte, error) { return nil, Unsupported }
