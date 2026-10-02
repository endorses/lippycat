package capture

import (
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/google/gopacket/layers"
	"time"
)

// FilterScopeProvider optionally partitions capture-side reassembly and decap
// state consistently with the attached filter's observation domains.
type FilterScopeProvider interface{ CaptureScope(string) uint32 }

type captureDomainState struct {
	ipv4      *IPv4Defragmenter
	ipv6      *IPv6Defragmenter
	esp       *ttlCache[uint32, layers.IPProtocol]
	fragments *ttlCache[uint32, ipv6FragInfo]
}

func captureScope(installer FilterInstaller, name string) uint32 {
	if provider, ok := installer.(FilterScopeProvider); ok {
		return provider.CaptureScope(name)
	}
	return 0
}
func newCaptureDomainStates(ifaces []pcaptypes.PcapInterface, installer FilterInstaller, base4 *IPv4Defragmenter, base6 *IPv6Defragmenter) (map[uint32]*captureDomainState, error) {
	states := map[uint32]*captureDomainState{0: {ipv4: base4, ipv6: base6, esp: espNullSPICache, fragments: ipv6FragIDCache}}
	if installer == nil {
		return states, nil
	}
	states[0].esp = newTTLCache[uint32, layers.IPProtocol](5 * time.Minute)
	states[0].fragments = newTTLCache[uint32, ipv6FragInfo](30 * time.Second)
	for _, iface := range ifaces {
		if iface == nil {
			continue
		}
		domain := captureScope(installer, iface.Name())
		if states[domain] != nil {
			continue
		}
		v4, err := NewIPv4DefragmenterWithConfig(base4.config)
		if err != nil {
			return nil, err
		}
		states[domain] = &captureDomainState{ipv4: v4, ipv6: NewIPv6Defragmenter(), esp: newTTLCache[uint32, layers.IPProtocol](5 * time.Minute), fragments: newTTLCache[uint32, ipv6FragInfo](30 * time.Second)}
	}
	return states, nil
}
func sumIPv4Defrag(states []*IPv4Defragmenter) IPv4DefragSnapshot {
	var out IPv4DefragSnapshot
	for _, state := range states {
		s := state.Snapshot()
		out.ObservedFragments += s.ObservedFragments
		out.CompletedDatagrams += s.CompletedDatagrams
		out.RejectedFragments += s.RejectedFragments
		out.ExpiredDatagrams += s.ExpiredDatagrams
		out.CapacityEvictions += s.CapacityEvictions
		out.InFlightDatagrams += s.InFlightDatagrams
		out.InFlightFragments += s.InFlightFragments
		out.InFlightPayloadBytes += s.InFlightPayloadBytes
	}
	return out
}
