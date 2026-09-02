package detector

// Telemetry is a point-in-time detector telemetry snapshot. Entry counts are
// gauges. All counters are cumulative for the lifetime of the Detector and
// reset only when a new Detector is constructed. Last-eviction fields describe
// the most recent pressure episode and must not be summed across snapshots.
type Telemetry struct {
	FlowEntries                 uint64
	CacheEntries                uint64
	FlowEvictions               uint64
	CacheEvictions              uint64
	FlowExpiredRemovals         uint64
	CacheExpiredRemovals        uint64
	FlowPressureEpisodes        uint64
	CachePressureEpisodes       uint64
	FlowLastEvictionDurationNs  uint64
	CacheLastEvictionDurationNs uint64
	FlowLastEvictionBatchSize   uint64
	CacheLastEvictionBatchSize  uint64
}

// Telemetry returns a non-destructive snapshot. Counter loads are lock-free;
// entry gauges briefly take each component's read lock independently.
func (d *Detector) Telemetry() Telemetry {
	return Telemetry{
		FlowEntries:                 uint64(d.flows.Size()),
		CacheEntries:                uint64(d.cache.Size()),
		FlowEvictions:               d.flows.totalEvictions.Load(),
		CacheEvictions:              d.cache.totalEvictions.Load(),
		FlowExpiredRemovals:         d.flows.expiredRemovals.Load(),
		CacheExpiredRemovals:        d.cache.expiredRemovals.Load(),
		FlowPressureEpisodes:        d.flows.pressureEpisodes.Load(),
		CachePressureEpisodes:       d.cache.pressureEpisodes.Load(),
		FlowLastEvictionDurationNs:  d.flows.lastEvictionDurationNs.Load(),
		CacheLastEvictionDurationNs: d.cache.lastEvictionDurationNs.Load(),
		FlowLastEvictionBatchSize:   d.flows.lastEvictionBatchSize.Load(),
		CacheLastEvictionBatchSize:  d.cache.lastEvictionBatchSize.Load(),
	}
}
