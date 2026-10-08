//go:build !darwin

package webruntime

// memoryPressure is not read outside macOS; the RSS or Pss kill threshold
// stands alone there.
func memoryPressure() int { return 0 }
