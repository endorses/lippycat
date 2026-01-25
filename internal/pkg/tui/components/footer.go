//go:build tui || all

package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/responsive"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/version"
)

// TabKeybind represents a single keybinding for a tab
type TabKeybind struct {
	Key         string // Display key (e.g., "/", "Space", "Enter")
	Description string // Action description (e.g., "filter", "pause")
	ShortDesc   string // Abbreviated description (e.g., "flt", "pse")
	Essential   bool   // If true, show even in narrow mode
}

// Footer displays the bottom footer bar with keybindings
type Footer struct {
	width                int
	theme                themes.Theme
	filterMode           bool
	hasFilter            bool
	filterCount          int     // Number of stacked filters
	streamingSave        bool    // True when streaming save is active
	activeTab            int     // Active tab index
	hasProtocolSelection bool    // True when a protocol is selected
	paused               bool    // True when capture is paused
	hasHelpSearch        bool    // True when Help tab has active search
	viewMode             string  // "packets" or "calls" for Capture tab
	callFilterMode       bool    // True when call filter input is active
	hasCallFilter        bool    // True when call filters are applied
	callFilterCount      int     // Number of stacked call filters
	statsSubView         SubView // Current sub-view in Statistics tab
}

// NewFooter creates a new footer component
func NewFooter() Footer {
	return Footer{
		width:      200, // Start with large default to show all keybinds; real size set by WindowSizeMsg
		theme:      themes.Solarized(),
		filterMode: false,
		hasFilter:  false,
	}
}

// SetTheme updates the theme
func (f *Footer) SetTheme(theme themes.Theme) {
	f.theme = theme
}

// SetWidth sets the footer width
func (f *Footer) SetWidth(width int) {
	f.width = width
}

// SetFilterMode sets whether filter input is active
func (f *Footer) SetFilterMode(active bool) {
	f.filterMode = active
}

// SetHasFilter sets whether filters are currently applied
func (f *Footer) SetHasFilter(hasFilter bool) {
	f.hasFilter = hasFilter
}

// SetFilterCount sets the number of stacked filters
func (f *Footer) SetFilterCount(count int) {
	f.filterCount = count
}

// SetStreamingSave sets whether a streaming save is currently active
func (f *Footer) SetStreamingSave(active bool) {
	f.streamingSave = active
}

// SetActiveTab sets the active tab index
func (f *Footer) SetActiveTab(index int) {
	f.activeTab = index
}

// SetHasProtocolSelection sets whether a protocol is currently selected
func (f *Footer) SetHasProtocolSelection(has bool) {
	f.hasProtocolSelection = has
}

// SetPaused sets whether capture is currently paused
func (f *Footer) SetPaused(paused bool) {
	f.paused = paused
}

// SetHasHelpSearch sets whether Help tab has an active search
func (f *Footer) SetHasHelpSearch(hasSearch bool) {
	f.hasHelpSearch = hasSearch
}

// SetViewMode sets the current view mode (packets/calls)
func (f *Footer) SetViewMode(mode string) {
	f.viewMode = mode
}

// SetCallFilterMode sets whether call filter input is active
func (f *Footer) SetCallFilterMode(active bool) {
	f.callFilterMode = active
}

// SetHasCallFilter sets whether call filters are currently applied
func (f *Footer) SetHasCallFilter(hasFilter bool) {
	f.hasCallFilter = hasFilter
}

// SetCallFilterCount sets the number of stacked call filters
func (f *Footer) SetCallFilterCount(count int) {
	f.callFilterCount = count
}

// SetStatsSubView sets the current statistics sub-view for context-sensitive keybindings
func (f *Footer) SetStatsSubView(sv SubView) {
	f.statsSubView = sv
}

// getTabColor returns the background color for a given tab index
func (f *Footer) getTabColor(tabIndex int) lipgloss.Color {
	// Map tab index to theme color
	// 0: Capture (red), 1: Nodes (yellow), 2: Statistics (green), 3: Settings (blue), 4: Help (magenta)
	tabColors := []lipgloss.Color{
		f.theme.ErrorColor,   // Tab 0: Capture
		f.theme.DNSColor,     // Tab 1: Nodes
		f.theme.SuccessColor, // Tab 2: Statistics
		f.theme.InfoColor,    // Tab 3: Settings
		f.theme.TLSColor,     // Tab 4: Help (magenta)
	}

	if tabIndex >= 0 && tabIndex < len(tabColors) {
		return tabColors[tabIndex]
	}
	return f.theme.BorderColor // Fallback
}

// getTabKeybinds returns the keybinds for a specific tab based on current state
func (f *Footer) getTabKeybinds(tabIndex int) []TabKeybind {
	switch tabIndex {
	case 0: // Capture tab
		keybinds := []TabKeybind{
			{Key: "/", Description: "filter", ShortDesc: "flt", Essential: true},
		}

		// Conditional keybinds based on view mode
		if f.viewMode == "calls" {
			// Calls view: use call filter state
			if f.hasCallFilter {
				keybinds = append(keybinds, TabKeybind{Key: "c", Description: "clear", ShortDesc: "clr", Essential: false})
				if f.callFilterCount > 1 {
					keybinds = append(keybinds, TabKeybind{Key: "C", Description: "clear all", ShortDesc: "all", Essential: false})
				}
			}
		} else {
			// Packets view: use packet filter state
			if f.hasFilter {
				keybinds = append(keybinds, TabKeybind{Key: "c", Description: "clear", ShortDesc: "clr", Essential: false})
				if f.filterCount > 1 {
					keybinds = append(keybinds, TabKeybind{Key: "C", Description: "clear all", ShortDesc: "all", Essential: false})
				}
			}
		}
		keybinds = append(keybinds, TabKeybind{Key: "d", Description: "details", ShortDesc: "det", Essential: true})

		if f.hasProtocolSelection {
			keybinds = append(keybinds, TabKeybind{Key: "v", Description: "view", ShortDesc: "vw", Essential: false})
		}
		keybinds = append(keybinds,
			TabKeybind{Key: "w", Description: "save", ShortDesc: "sav", Essential: true},
			TabKeybind{Key: "x", Description: "flush", ShortDesc: "flsh", Essential: false},
		)
		return keybinds

	case 1: // Nodes tab
		return []TabKeybind{
			{Key: "f", Description: "filters", ShortDesc: "flt", Essential: true},
			{Key: "a", Description: "add", ShortDesc: "add", Essential: true},
			{Key: "d", Description: "delete", ShortDesc: "del", Essential: false},
			{Key: "s", Description: "select", ShortDesc: "sel", Essential: true},
			{Key: "v", Description: "view", ShortDesc: "vw", Essential: false},
		}

	case 2: // Statistics tab
		keybinds := []TabKeybind{
			{Key: "v", Description: "view", ShortDesc: "vw", Essential: true},
			{Key: "1-5", Description: "sections", ShortDesc: "sec", Essential: false},
			{Key: "e", Description: "export", ShortDesc: "exp", Essential: false},
		}
		// Add filter keybind when in TopTalkers view
		if f.statsSubView == SubViewTopTalkers {
			keybinds = append(keybinds, TabKeybind{Key: "Enter", Description: "filter", ShortDesc: "flt", Essential: true})
		}
		return keybinds

	case 3: // Settings tab
		return []TabKeybind{
			{Key: "Enter", Description: "edit/toggle", ShortDesc: "edit", Essential: true},
			{Key: "Esc", Description: "cancel", ShortDesc: "esc", Essential: true},
			{Key: "←/→", Description: "switch", ShortDesc: "sw", Essential: false},
		}

	case 4: // Help tab
		keybinds := []TabKeybind{
			{Key: "/", Description: "search", ShortDesc: "srch", Essential: true},
		}
		if f.hasHelpSearch {
			keybinds = append(keybinds,
				TabKeybind{Key: "n/N", Description: "next/prev", ShortDesc: "n/p", Essential: true},
				TabKeybind{Key: "c", Description: "clear", ShortDesc: "clr", Essential: false},
			)
		}
		keybinds = append(keybinds, TabKeybind{Key: "1-3", Description: "sections", ShortDesc: "sec", Essential: false})
		return keybinds

	default:
		return []TabKeybind{}
	}
}

// getResponsiveKeybinds returns keybinds filtered and formatted for the current width
// Wide: all keybinds with full descriptions
// Medium: all keybinds with abbreviated descriptions
// Narrow: essential keybinds only, keys only (no descriptions)
func (f *Footer) getResponsiveKeybinds(tabIndex int) ([]TabKeybind, responsive.WidthClass) {
	keybinds := f.getTabKeybinds(tabIndex)
	widthClass := responsive.GetWidthClass(f.width)

	switch widthClass {
	case responsive.Narrow:
		// Filter to essential keybinds only
		essential := make([]TabKeybind, 0, len(keybinds))
		for _, kb := range keybinds {
			if kb.Essential {
				essential = append(essential, kb)
			}
		}
		return essential, widthClass
	default:
		// Wide and Medium return all keybinds (description format handled in render)
		return keybinds, widthClass
	}
}

// getGeneralKeybinds returns the general keybinds (Space, p, q) with responsive formatting
func (f *Footer) getGeneralKeybinds() []TabKeybind {
	pauseText := "pause"
	pauseShort := "pse"
	if f.paused {
		pauseText = "resume"
		pauseShort = "rsm"
	}

	return []TabKeybind{
		{Key: "Space", Description: pauseText, ShortDesc: pauseShort, Essential: true},
		{Key: "p", Description: "protocol", ShortDesc: "prt", Essential: true},
		{Key: "q", Description: "quit", ShortDesc: "qt", Essential: true},
	}
}

// renderTabSpecificSection renders the tab-specific keybinds section (left side)
func (f *Footer) renderTabSpecificSection(tabIndex int) string {
	keybinds, widthClass := f.getResponsiveKeybinds(tabIndex)
	if len(keybinds) == 0 {
		return "" // No keybinds for this tab
	}

	// Get tab color for text (instead of background)
	tabColor := f.getTabColor(tabIndex)

	// Styles for keys and descriptions (no background, colored text for keys)
	keyStyle := lipgloss.NewStyle().
		Foreground(tabColor).
		Bold(true)

	descStyle := lipgloss.NewStyle().
		Foreground(f.theme.Foreground)

	separatorStyle := lipgloss.NewStyle().
		Foreground(f.theme.BorderColor)

	// Build keybinds string with styled components based on width class
	var parts []string
	for _, kb := range keybinds {
		switch widthClass {
		case responsive.Narrow:
			// Keys only, no description
			parts = append(parts, keyStyle.Render(kb.Key))
		case responsive.Medium:
			// Use short description
			desc := kb.ShortDesc
			if desc == "" {
				desc = kb.Description // Fall back to full description
			}
			parts = append(parts, keyStyle.Render(kb.Key)+descStyle.Render(":"+desc))
		default: // Wide
			parts = append(parts, keyStyle.Render(kb.Key)+descStyle.Render(": "+kb.Description))
		}
	}

	// Join with separators (narrower separator for narrow width)
	var content string
	sep := separatorStyle.Render("  │  ")
	if widthClass == responsive.Narrow {
		sep = separatorStyle.Render(" │ ")
	} else if widthClass == responsive.Medium {
		sep = separatorStyle.Render(" │ ")
	}

	for i, part := range parts {
		if i > 0 {
			content += sep
		}
		content += part
	}

	// Wrap with padding
	containerStyle := lipgloss.NewStyle().Padding(0, 1)

	return containerStyle.Render(content)
}

// renderGeneralSection renders the general keybinds section (right side)
func (f *Footer) renderGeneralSection() string {
	widthClass := responsive.GetWidthClass(f.width)
	keybinds := f.getGeneralKeybinds()

	// Styles for general section (violet keys)
	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6c71c4")). // Solarized Violet
		Bold(true)

	descStyle := lipgloss.NewStyle().
		Foreground(f.theme.Foreground)

	separatorStyle := lipgloss.NewStyle().
		Foreground(f.theme.BorderColor)

	// Build bindings based on width class
	var parts []string
	for _, kb := range keybinds {
		switch widthClass {
		case responsive.Narrow:
			// Keys only, no description
			parts = append(parts, keyStyle.Render(kb.Key))
		case responsive.Medium:
			// Use short description
			desc := kb.ShortDesc
			if desc == "" {
				desc = kb.Description
			}
			parts = append(parts, keyStyle.Render(kb.Key)+descStyle.Render(":"+desc))
		default: // Wide
			parts = append(parts, keyStyle.Render(kb.Key)+descStyle.Render(": "+kb.Description))
		}
	}

	// Join bindings with separators (narrower for narrow/medium)
	sep := separatorStyle.Render("  │  ")
	if widthClass == responsive.Narrow || widthClass == responsive.Medium {
		sep = separatorStyle.Render(" │ ")
	}

	var content string
	for i, part := range parts {
		if i > 0 {
			content += sep
		}
		content += part
	}

	// Add padding
	containerStyle := lipgloss.NewStyle().
		Padding(0, 1)

	return containerStyle.Render(content)
}

// View renders the footer with two lines: horizontal separator + keybindings
func (f *Footer) View() string {
	// Special case: filter mode shows filter keybinds only
	if f.filterMode || f.callFilterMode {
		return f.renderFilterModeFooter()
	}

	// Render both sections
	tabSection := f.renderTabSpecificSection(f.activeTab)
	generalSection := f.renderGeneralSection()

	// Separator between tab-specific and general sections
	separatorStyle := lipgloss.NewStyle().
		Foreground(f.theme.BorderColor)
	separator := separatorStyle.Render(" ║ ")

	// Version info for far right (only show if enough space)
	versionText := fmt.Sprintf("🫦🐱 v%s ", version.GetVersion())
	versionStyle := lipgloss.NewStyle().
		Foreground(f.theme.BorderColor)
	versionRendered := versionStyle.Render(versionText)

	// Calculate widths
	tabSectionWidth := lipgloss.Width(tabSection)
	separatorWidth := lipgloss.Width(separator)
	generalSectionWidth := lipgloss.Width(generalSection)
	versionWidth := lipgloss.Width(versionRendered)

	// Build footer content with sections
	var footerContent string

	if tabSectionWidth+separatorWidth+generalSectionWidth+versionWidth <= f.width {
		// Enough space for all: tab section, separator, general section, and version
		spacerWidth := f.width - tabSectionWidth - separatorWidth - generalSectionWidth - versionWidth
		spacer := lipgloss.NewStyle().Width(spacerWidth).Render("")
		footerContent = tabSection + separator + generalSection + spacer + versionRendered
	} else if tabSectionWidth+separatorWidth+generalSectionWidth <= f.width {
		// Enough space for both sections with separator, skip version
		spacerWidth := f.width - tabSectionWidth - separatorWidth - generalSectionWidth
		spacer := lipgloss.NewStyle().Width(spacerWidth).Render("")
		footerContent = tabSection + separator + generalSection + spacer
	} else {
		// Not enough space - show tab section only and pad to width
		spacerWidth := f.width - tabSectionWidth
		if spacerWidth > 0 {
			spacer := lipgloss.NewStyle().Width(spacerWidth).Render("")
			footerContent = tabSection + spacer
		} else {
			footerContent = tabSection
		}
	}

	// Render horizontal line above footer content
	lineStyle := lipgloss.NewStyle().Foreground(f.theme.BorderColor)
	horizontalLine := lineStyle.Render(strings.Repeat("─", f.width))

	return horizontalLine + "\n" + footerContent
}

// renderFilterModeFooter renders the footer when filter input is active
func (f *Footer) renderFilterModeFooter() string {
	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6c71c4")). // Solarized Violet
		Bold(true)

	descStyle := lipgloss.NewStyle().
		Foreground(f.theme.Foreground)

	separatorStyle := lipgloss.NewStyle().
		Foreground(f.theme.BorderColor).
		Render("│")

	// Filter mode keybindings
	bindings := []string{
		keyStyle.Render("Enter") + descStyle.Render(": apply"),
		keyStyle.Render("Esc") + descStyle.Render(": cancel"),
		keyStyle.Render("↑↓") + descStyle.Render(": history"),
	}

	// Join bindings with separators
	var content string
	for i, binding := range bindings {
		if i > 0 {
			content += "  " + separatorStyle + "  "
		}
		content += binding
	}

	// Add padding
	baseStyle := lipgloss.NewStyle().Padding(0, 1)
	leftContent := baseStyle.Render(content)
	leftWidth := lipgloss.Width(leftContent)

	// Pad to full width
	var footerContent string
	if leftWidth < f.width {
		spacerWidth := f.width - leftWidth
		spacer := lipgloss.NewStyle().Width(spacerWidth).Render("")
		footerContent = leftContent + spacer
	} else {
		footerContent = leftContent
	}

	// Render horizontal line above footer content
	lineStyle := lipgloss.NewStyle().Foreground(f.theme.BorderColor)
	horizontalLine := lineStyle.Render(strings.Repeat("─", f.width))

	return horizontalLine + "\n" + footerContent
}
