package detector

import "github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"

// Telemetry is a point-in-time detector telemetry snapshot. Entry counts are
// gauges. Flow/cache counters are cumulative for the Detector lifetime; SIP
// pair counters are cumulative for the registered signature lifetime.
// Last-eviction fields describe
// the most recent pressure episode and must not be summed across snapshots.
type Telemetry struct {
	SIPIPPairEntries            uint64
	SIPIPPairMaxEntries         uint64
	SIPIPPairTTLEvictions       uint64
	SIPIPPairCapEvictions       uint64
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

// Telemetry returns a non-destructive snapshot. Components are sampled under
// their own locks; SIP pair counters belong to the registered SIP signature.
func (d *Detector) Telemetry() Telemetry {
	stats := Telemetry{
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
	for _, sig := range d.GetSignatures() {
		if provider, ok := sig.(interface {
			SIPIPPairTelemetry() voip.SIPIPPairTelemetry
		}); ok {
			pairs := provider.SIPIPPairTelemetry()
			stats.SIPIPPairEntries = pairs.Entries
			stats.SIPIPPairMaxEntries = pairs.MaxEntries
			stats.SIPIPPairTTLEvictions = pairs.TTLEvictions
			stats.SIPIPPairCapEvictions = pairs.CapEvictions
			break
		}
	}
	return stats
}
