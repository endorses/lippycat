//go:build tui || all

package filters

import (
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// MetadataFilter filters packets based on metadata presence
// Used to filter packets that have specific metadata attached (e.g., VoIP metadata)
type MetadataFilter struct {
	metadataType      string // "voip", etc.
	excludeParseError bool   // exclude packets with parse errors
}

// NewMetadataFilter creates a new metadata filter
func NewMetadataFilter(metadataType string) *MetadataFilter {
	return &MetadataFilter{
		metadataType:      metadataType,
		excludeParseError: true, // By default, exclude unparseable packets
	}
}

// Match checks if the packet has the specified metadata
func (f *MetadataFilter) Match(packet components.PacketDisplay) bool {
	switch f.metadataType {
	case "voip":
		// Check if packet has VoIP metadata OR is a VoIP protocol
		// VoIPData is set when full packet parsing is done (convertPacket)
		// but at high rates, convertPacketFast is used which only sets Protocol
		// The background processor uses Protocol to send to call aggregator,
		// so we should also accept packets based on Protocol for consistency.
		if packet.VoIPData != nil {
			return true
		}
		// Also match by protocol name for packets from fast conversion path
		return packet.Protocol == "SIP" || packet.Protocol == "RTP"

	default:
		return false
	}
}

// String returns a human-readable representation
func (f *MetadataFilter) String() string {
	return "has:" + f.metadataType
}

// Type returns the filter type
func (f *MetadataFilter) Type() string {
	return "metadata"
}

// Selectivity returns how selective this filter is (0.0-1.0)
// Metadata filters are highly selective
func (f *MetadataFilter) Selectivity() float64 {
	return 0.85
}
