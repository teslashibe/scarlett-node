package webruntime

// Host memory pressure levels (macOS kern.memorystatus_vm_pressure_level).
// While a page is in flight, critical kills the helper at once. Warn never
// kills: above the recycle size the helper drains as it does at any pressure,
// so a large page finishes first. Warn is common on healthy Macs: a 64 GiB
// Mac with 41% of its memory free was measured at warn, and html.spec.whatwg.org
// (3.7 GiB of tree) was killed at warn under the old rule.
const (
	pressureWarn     = 2
	pressureCritical = 4
)
