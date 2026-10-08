package webruntime

// Host memory pressure levels (macOS kern.memorystatus_vm_pressure_level).
// While a page is in flight, critical kills the helper at once, and warn
// lowers the kill size to the recycle size. Warn alone is not enough: a
// 64 GiB Mac with 41% of its memory free was measured at warn.
const (
	pressureWarn     = 2
	pressureCritical = 4
)
