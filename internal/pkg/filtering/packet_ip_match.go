package filtering

import (
	"net/netip"

	"github.com/endorses/lippycat/api/gen/management"
)

// MatchPacketIPs returns only direct address/CIDR evidence. An unresolved call
// must not inherit an identity filter, but independently matching IP selectors
// remain valid evidence for their own consumers.
func (m *SIPMatcher) MatchPacketIPs(source, destination netip.Addr, sourceID string) ([]string, error) {
	if m == nil {
		return nil, ErrSIPFilter
	}
	if sourceID == "" {
		return nil, ErrSIPSource
	}
	var ids []string
	for _, filter := range m.filters {
		if filter.kind == management.FilterType_FILTER_IP_ADDRESS && filter.matchesSource(sourceID) && (filter.matchesIP(source.Unmap()) || filter.matchesIP(destination.Unmap())) {
			ids = append(ids, filter.id)
		}
	}
	return ids, nil
}
