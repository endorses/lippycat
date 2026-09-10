package capture

import "github.com/endorses/lippycat/internal/pkg/detector"

// defaultSIPIPPairHeartbeatFields observes detector state without enabling
// detection. Omit fields when no detector has been initialized.
func defaultSIPIPPairHeartbeatFields() []any {
	d := detector.GetDefaultIfInitialized()
	if d == nil {
		return nil
	}
	return sipIPPairHeartbeatFields(d.Telemetry())
}

// These process-wide values repeat on each interface heartbeat. Counters must
// be compared across time, not summed across interfaces.
func sipIPPairHeartbeatFields(stats detector.Telemetry) []any {
	return []any{
		"sip_ip_pair_entries", stats.SIPIPPairEntries,
		"sip_ip_pair_max_entries", stats.SIPIPPairMaxEntries,
		"sip_ip_pair_ttl_evictions", stats.SIPIPPairTTLEvictions,
		"sip_ip_pair_cap_evictions", stats.SIPIPPairCapEvictions,
	}
}
