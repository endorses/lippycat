//go:build tui || all

package filters

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/simd"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// TextFilter filters packets by text content
type TextFilter struct {
	searchText  string
	fields      []string // which fields to search: "all", "src", "dst", "info", "protocol"
	searchAll   bool     // optimized flag for "all" field search
	searchSrc   bool
	searchDst   bool
	searchInfo  bool
	searchProto bool
}

// NewTextFilter creates a new text filter
func NewTextFilter(searchText string, fields []string) *TextFilter {
	if len(fields) == 0 {
		fields = []string{"all"}
	}

	f := &TextFilter{
		searchText: strings.ToLower(searchText),
		fields:     fields,
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
		}
	}

	return f
}

// Match checks if the packet matches the text filter
// Optimized: no allocations, direct field checks with flags
func (f *TextFilter) Match(packet components.PacketDisplay) bool {
	// Fast path: check each field directly based on pre-calculated flags
	// Avoids slice allocation and repeated ToLower calls

	if f.searchAll {
		// Check all fields - use SIMD-optimized contains
		if simd.StringContains(strings.ToLower(packet.SrcIP), f.searchText) ||
			simd.StringContains(strings.ToLower(packet.DstIP), f.searchText) ||
			simd.StringContains(strings.ToLower(packet.SrcPort), f.searchText) ||
			simd.StringContains(strings.ToLower(packet.DstPort), f.searchText) ||
			simd.StringContains(strings.ToLower(packet.Protocol), f.searchText) ||
			simd.StringContains(strings.ToLower(packet.Info), f.searchText) {
			return true
		}
	}

	if f.searchSrc {
		if simd.StringContains(strings.ToLower(packet.SrcIP), f.searchText) ||
			simd.StringContains(strings.ToLower(packet.SrcPort), f.searchText) {
			return true
		}
	}

	if f.searchDst {
		if simd.StringContains(strings.ToLower(packet.DstIP), f.searchText) ||
			simd.StringContains(strings.ToLower(packet.DstPort), f.searchText) {
			return true
		}
	}

	if f.searchInfo {
		if simd.StringContains(strings.ToLower(packet.Info), f.searchText) {
			return true
		}
	}

	if f.searchProto {
		if simd.StringContains(strings.ToLower(packet.Protocol), f.searchText) {
			return true
		}
	}

	return false
}

// String returns a human-readable representation
func (f *TextFilter) String() string {
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
