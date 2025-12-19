//go:build tui || all
// +build tui all

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
		// Check if packet has VoIP metadata (set by hunter/processor)
		// This is more reliable than protocol detection because it's based on
		// the hunter's analysis of SIP signaling and RTP port tracking
		//
		// We trust the hunter/processor's analysis completely - if they marked
		// it as VoIP traffic, it IS VoIP traffic, even if the TUI can't parse
		// the link layer correctly.
		return packet.VoIPData != nil

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
