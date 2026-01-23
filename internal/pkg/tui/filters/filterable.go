//go:build tui || all

package filters

// Filterable represents any record that can be filtered (packets, calls, etc.)
type Filterable interface {
	// GetStringField returns a string field value by name.
	// Returns empty string if field doesn't exist.
	GetStringField(name string) string

	// GetNumericField returns a numeric field value by name.
	// Returns 0 if field doesn't exist or isn't numeric.
	GetNumericField(name string) float64

	// HasField returns true if the record has the named field.
	HasField(name string) bool

	// RecordType returns the type identifier ("packet", "call", etc.)
	RecordType() string
}

// getCommonFields returns the common searchable string fields for a record type.
// Used by text filters to implement "search all" behavior.
func GetCommonFields(recordType string) []string {
	switch recordType {
	case "packet":
		return []string{"src", "dst", "srcport", "dstport", "protocol", "info", "node"}
	case "call":
		return []string{"callid", "from", "to", "state", "codec", "node"}
	default:
		return []string{}
	}
}
