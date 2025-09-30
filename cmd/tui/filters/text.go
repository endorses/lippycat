package filters

import (
	"strings"

	"github.com/endorses/lippycat/cmd/tui/components"
)

// TextFilter filters packets by text content
type TextFilter struct {
	searchText string
	fields     []string // which fields to search: "all", "src", "dst", "info", "protocol"
}

// NewTextFilter creates a new text filter
func NewTextFilter(searchText string, fields []string) *TextFilter {
	if len(fields) == 0 {
		fields = []string{"all"}
	}
	return &TextFilter{
		searchText: strings.ToLower(searchText),
		fields:     fields,
	}
}

// Match checks if the packet matches the text filter
func (f *TextFilter) Match(packet components.PacketDisplay) bool {
	searchIn := make([]string, 0)

	for _, field := range f.fields {
		switch field {
		case "all":
			searchIn = append(searchIn,
				packet.SrcIP,
				packet.DstIP,
				packet.SrcPort,
				packet.DstPort,
				packet.Protocol,
				packet.Info,
			)
		case "src":
			searchIn = append(searchIn, packet.SrcIP, packet.SrcPort)
		case "dst":
			searchIn = append(searchIn, packet.DstIP, packet.DstPort)
		case "info":
			searchIn = append(searchIn, packet.Info)
		case "protocol":
			searchIn = append(searchIn, packet.Protocol)
		}
	}

	// Check if any field contains the search text
	for _, text := range searchIn {
		if strings.Contains(strings.ToLower(text), f.searchText) {
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