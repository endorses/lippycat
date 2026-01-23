//go:build tui || all

package filters

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/simd"
)

// TextFilter filters records by text content
type TextFilter struct {
	searchText    string
	fields        []string // which fields to search: "all", "src", "dst", "info", "protocol", or generic fields
	searchAll     bool     // optimized flag for "all" field search
	searchSrc     bool
	searchDst     bool
	searchInfo    bool
	searchProto   bool
	genericFields []string // fields not matching packet-specific optimizations
}

// NewTextFilter creates a new text filter
func NewTextFilter(searchText string, fields []string) *TextFilter {
	if len(fields) == 0 {
		fields = []string{"all"}
	}

	f := &TextFilter{
		searchText:    strings.ToLower(searchText),
		fields:        fields,
		genericFields: make([]string, 0),
	}

	// Pre-calculate field flags for faster matching
	for _, field := range fields {
		switch field {
		case "all":
			f.searchAll = true
		case "src":
			f.searchSrc = true
		case "dst":
			f.searchDst = true
		case "info":
			f.searchInfo = true
		case "protocol":
			f.searchProto = true
		default:
			// Generic fields (call-specific: from, to, user, callid, codec, etc.)
			f.genericFields = append(f.genericFields, field)
		}
	}

	return f
}

// Match checks if the record matches the text filter
// Uses Filterable interface for generic record access
func (f *TextFilter) Match(record Filterable) bool {
	// Search all common fields for this record type
	if f.searchAll {
		commonFields := GetCommonFields(record.RecordType())
		for _, field := range commonFields {
			fieldValue := record.GetStringField(field)
			if simd.StringContains(strings.ToLower(fieldValue), f.searchText) {
				return true
			}
		}
		return false
	}

	// Search packet-specific fields (optimized paths)
	if f.searchSrc {
		if simd.StringContains(strings.ToLower(record.GetStringField("src")), f.searchText) ||
			simd.StringContains(strings.ToLower(record.GetStringField("srcport")), f.searchText) {
			return true
		}
	}

	if f.searchDst {
		if simd.StringContains(strings.ToLower(record.GetStringField("dst")), f.searchText) ||
			simd.StringContains(strings.ToLower(record.GetStringField("dstport")), f.searchText) {
			return true
		}
	}

	if f.searchInfo {
		if simd.StringContains(strings.ToLower(record.GetStringField("info")), f.searchText) {
			return true
		}
	}

	if f.searchProto {
		if simd.StringContains(strings.ToLower(record.GetStringField("protocol")), f.searchText) {
			return true
		}
	}

	// Search generic fields (call-specific: from, to, user, callid, codec, etc.)
	for _, field := range f.genericFields {
		fieldValue := record.GetStringField(field)
		if simd.StringContains(strings.ToLower(fieldValue), f.searchText) {
			return true
		}
	}

	return false
}

// String returns a human-readable representation
func (f *TextFilter) String() string {
	// If we have a single specific field, include it in the output
	if len(f.fields) == 1 && f.fields[0] != "all" {
		return f.fields[0] + ":" + f.searchText
	}
	return f.searchText
}

// Type returns the filter type
func (f *TextFilter) Type() string {
	return "text"
}

// Selectivity returns how selective this filter is (0.0-1.0)
// Text filters vary in selectivity based on fields searched
func (f *TextFilter) Selectivity() float64 {
	if f.searchAll {
		return 0.3 // Least selective - searches all fields
	}
	// Searching specific fields is more selective
	return 0.6
}

// SupportedRecordTypes returns nil to indicate this filter supports all record types
func (f *TextFilter) SupportedRecordTypes() []string {
	return nil // Generic filter - supports all record types
}
