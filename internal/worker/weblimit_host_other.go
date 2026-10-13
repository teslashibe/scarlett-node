//go:build !darwin && !linux && !windows

package worker

import "time"

// unknownHost reports normal memory and unknown CPU: the adaptive web limit
// then rests on page latency and outcomes alone.
type unknownHost struct{}

// NewHostSampler samples this host for the adaptive web limit.
func NewHostSampler() HostSampler { return unknownHost{} }

func (unknownHost) Sample(time.Time) HostLoad { return HostLoad{Memory: MemoryNormal} }
