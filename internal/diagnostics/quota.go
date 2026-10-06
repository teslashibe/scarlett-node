package diagnostics

import "context"

// ObserveQuota retains at most one private numerical snapshot per exchange.
// There is no I/O and no opaque response/header text in this provider path.
const quotaSnapshotBytes = 512

func ObserveQuota(ctx context.Context, q QuotaSnapshot) {
	a := fromContext(ctx)
	if a == nil {
		return
	}
	s := a.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if !a.retained || a.finished || !validQuota(q, a.record.StartedAt) {
		return
	}
	for i := range a.record.QuotaSnapshots {
		if a.record.QuotaSnapshots[i].Exchange == q.Exchange {
			a.record.QuotaSnapshots[i] = q
			s.changedLocked()
			return
		}
	}
	if len(a.record.QuotaSnapshots) >= MaxExchanges || estimatedBytes(a.record)+quotaSnapshotBytes > MaxAttemptBytes || s.retainedBytes+quotaSnapshotBytes > MaxHistoryBytes {
		a.record.Truncated = true
		s.changedLocked()
		return
	}
	a.record.QuotaSnapshots = append(a.record.QuotaSnapshots, q)
	s.retainedBytes += quotaSnapshotBytes
	s.changedLocked()
}

func estimatedBytes(r Record) int {
	return 700 + len(r.Spans)*144 + len(r.QuotaSnapshots)*quotaSnapshotBytes
}
