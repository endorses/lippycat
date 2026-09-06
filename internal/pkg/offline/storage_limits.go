package offline

// MemoryLimit is the shared cache, transient-read, prefetch and pin budget.
// Producers use it to size buffers before admission, leaving room for consumers
// that process their output under the same storage owner.
func (s *Storage) MemoryLimit() uint64 { return s.limits.CacheBytes }
