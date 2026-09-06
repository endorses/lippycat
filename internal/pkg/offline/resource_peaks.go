package offline

// ResourcePeaks records exact high-water marks of admitted ledger bytes across
// all datasets, queries, and scratch files sharing a Storage. MemoryBytes is
// accounted cache/read memory, not process RSS or independently capped analyzers.
type ResourcePeaks struct {
	DiskBytes   uint64
	MemoryBytes uint64
}

// Peaks remains monotonic through releases and cleanup. Sampling Resources can
// miss short-lived coexistence during ordering, replacement, and query writes.
func (s *Storage) Peaks() ResourcePeaks {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peaks
}
