//go:build tui || all

package filters

// MetadataFilter filters packets based on metadata presence
// Used to filter packets that have specific metadata attached (e.g., VoIP metadata)
type MetadataFilter struct {
	metadataType      string // "voip", "dns", "tls", "http", "email"
	excludeParseError bool   // exclude packets with parse errors
}

// NewMetadataFilter creates a new metadata filter
func NewMetadataFilter(metadataType string) *MetadataFilter {
	return &MetadataFilter{
		metadataType:      metadataType,
		excludeParseError: true, // By default, exclude unparseable packets
	}
}

// Match checks if the record has the specified metadata
func (f *MetadataFilter) Match(record Filterable) bool {
	// Metadata filter only works on packets
	if record.RecordType() != "packet" {
		return false
	}

	switch f.metadataType {
	case "voip":
		// Check if packet has VoIP metadata using HasField
		if record.HasField("voip") {
			return true
		}
		// Also match by protocol name for packets from fast conversion path
		protocol := record.GetStringField("protocol")
		return protocol == "SIP" || protocol == "RTP"
	case "dns":
		return record.HasField("dns")
	case "tls":
		return record.HasField("tls")
	case "http":
		return record.HasField("http")
	case "email":
		return record.HasField("email")
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

// SupportedRecordTypes returns ["packet"] as MetadataFilter only works on packets
func (f *MetadataFilter) SupportedRecordTypes() []string {
	return []string{"packet"}
}
