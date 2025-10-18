//go:build tui || all
// +build tui all

package filtermanager

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// FilterItem wraps a management.Filter for use with bubbles list
type FilterItem struct {
	Filter *management.Filter
}

// FilterValue implements list.Item
func (i FilterItem) FilterValue() string {
	// Search across pattern, description, type, and targets
	searchable := []string{
		i.Filter.Pattern,
		i.Filter.Description,
		i.Filter.Type.String(),
		strings.Join(i.Filter.TargetHunters, " "),
	}
	return strings.ToLower(strings.Join(searchable, " "))
}

// FilterDelegate is a custom delegate for rendering filter items
type FilterDelegate struct {
	theme              themes.Theme
	hunterCapabilities *management.HunterCapabilities // nil for processor-level view
}

// NewFilterDelegate creates a new filter delegate
func NewFilterDelegate(theme themes.Theme) FilterDelegate {
	return FilterDelegate{
		theme:              theme,
		hunterCapabilities: nil,
	}
}

// SetHunterCapabilities sets the hunter capabilities for compatibility checking
func (d *FilterDelegate) SetHunterCapabilities(caps *management.HunterCapabilities) {
	d.hunterCapabilities = caps
}

// Height returns the height of a list item
func (d FilterDelegate) Height() int {
	return 1
}

// Spacing returns the spacing between list items
func (d FilterDelegate) Spacing() int {
	return 0
}

// Update handles updates for the delegate
func (d FilterDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd {
	return nil
}

// Render renders a filter item
func (d FilterDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	filterItem, ok := item.(FilterItem)
	if !ok {
		// Not a FilterItem, render nothing
		return
	}

	filter := filterItem.Filter
	isSelected := index == m.Index()

	// Enabled checkbox
	checkbox := "✗"
	if filter.Enabled {
		checkbox = "✓"
	}

	// Filter type (abbreviated)
	filterType := AbbreviateType(filter.Type)

	// Check compatibility if viewing hunter-specific filters
	compatIndicator := " "
	if d.hunterCapabilities != nil {
		// Check if this filter type is compatible with the hunter
		if IsVoIPFilterType(filter.Type) {
			// This is a VoIP filter - check if hunter supports it
			isCompatible := false
			for _, ft := range d.hunterCapabilities.FilterTypes {
				if ft == "sip_user" {
					isCompatible = true
					break
				}
			}
			if !isCompatible {
				compatIndicator = "⚠"
			}
		}
	}

	// Target hunters
	targets := "All hunters"
	if len(filter.TargetHunters) > 0 {
		if len(filter.TargetHunters) == 1 {
			targets = filter.TargetHunters[0]
		} else {
			targets = fmt.Sprintf("%s,+%d", filter.TargetHunters[0], len(filter.TargetHunters)-1)
		}
	}

	// Build row: [✓] | Compat | Type | Pattern | Targets
	row := fmt.Sprintf(" %s %s │ %-12s │ %-25s │ %s",
		checkbox,
		compatIndicator,
		filterType,
		TruncateString(filter.Pattern, 25),
		TruncateString(targets, 20),
	)

	// Get available width
	availableWidth := m.Width()
	if availableWidth <= 0 {
		availableWidth = 80 // fallback
	}

	if isSelected {
		selectedStyle := lipgloss.NewStyle().
			Foreground(d.theme.SelectionFg).
			Background(d.theme.SelectionBg).
			Bold(true).
			Width(availableWidth)
		fmt.Fprint(w, selectedStyle.Render(row))
	} else {
		normalStyle := lipgloss.NewStyle().
			Foreground(d.theme.Foreground).
			Width(availableWidth)
		fmt.Fprint(w, normalStyle.Render(row))
	}
}

// AbbreviateType returns abbreviated filter type name
func AbbreviateType(t management.FilterType) string {
	switch t {
	case management.FilterType_FILTER_SIP_USER:
		return "SIP User"
	case management.FilterType_FILTER_PHONE_NUMBER:
		return "Phone"
	case management.FilterType_FILTER_IP_ADDRESS:
		return "IP Address"
	case management.FilterType_FILTER_CALL_ID:
		return "Call-ID"
	case management.FilterType_FILTER_CODEC:
		return "Codec"
	case management.FilterType_FILTER_BPF:
		return "BPF"
	default:
		return "Unknown"
	}
}

// TruncateString truncates a string to max length
func TruncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// RenderSearchBarParams holds input parameters for rendering the search bar
type RenderSearchBarParams struct {
	SearchMode      bool
	SearchValue     string
	FilterByType    *management.FilterType
	FilterByEnabled *bool
	Theme           themes.Theme
}

// RenderSearchBar renders the search bar with filter indicators
func RenderSearchBar(params RenderSearchBarParams) string {
	var parts []string

	// Search input
	searchLabel := "Search: "
	if params.SearchMode {
		// In search mode, the caller will append the actual textinput view
		parts = append(parts, searchLabel)
	} else {
		// Show current search value if any
		if params.SearchValue != "" {
			parts = append(parts, fmt.Sprintf("Search: %s", params.SearchValue))
		} else {
			parts = append(parts, "Search: (press / to search)")
		}
	}

	// Type filter indicator
	typeFilterStr := "Type: All"
	if params.FilterByType != nil {
		typeFilterStr = "Type: " + AbbreviateType(*params.FilterByType)
	}
	parts = append(parts, typeFilterStr)

	// Enabled filter indicator
	enabledFilterStr := "Show: All"
	if params.FilterByEnabled != nil {
		if *params.FilterByEnabled {
			enabledFilterStr = "Show: ✓ Enabled"
		} else {
			enabledFilterStr = "Show: ✗ Disabled"
		}
	}
	parts = append(parts, enabledFilterStr)

	return strings.Join(parts, "  │  ")
}
