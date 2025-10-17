//go:build tui || all
// +build tui all

package components

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/version"
)

// TabKeybind represents a single keybinding for a tab
type TabKeybind struct {
	Key         string // Display key (e.g., "/", "Space", "Enter")
	Description string // Action description (e.g., "filter", "pause")
}

// Footer displays the bottom footer bar with keybindings
type Footer struct {
	width                int
	theme                themes.Theme
	filterMode           bool
	hasFilter            bool
	filterCount          int  // Number of stacked filters
	streamingSave        bool // True when streaming save is active
	activeTab            int  // Active tab index
	hasProtocolSelection bool // True when a protocol is selected
}

// NewFooter creates a new footer component
func NewFooter() Footer {
	return Footer{
		width:      80,
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

// getTabColor returns the background color for a given tab index
func (f *Footer) getTabColor(tabIndex int) lipgloss.Color {
	// Map tab index to theme color
	// 0: Capture (red), 1: Nodes (yellow), 2: Statistics (green), 3: Settings (blue)
	tabColors := []lipgloss.Color{
		f.theme.ErrorColor,   // Tab 0: Capture
		f.theme.DNSColor,     // Tab 1: Nodes
		f.theme.SuccessColor, // Tab 2: Statistics
		f.theme.InfoColor,    // Tab 3: Settings
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
			{Key: "/", Description: "filter"},
			{Key: "w", Description: "save"},
			{Key: "d", Description: "details"},
		}
		// Conditional keybinds
		if f.hasFilter {
			keybinds = append(keybinds, TabKeybind{Key: "c", Description: "clear"})
			if f.filterCount > 1 {
				keybinds = append(keybinds, TabKeybind{Key: "C", Description: "remove last"})
			}
		}
		if f.hasProtocolSelection {
			keybinds = append(keybinds, TabKeybind{Key: "v", Description: "view"})
		}
		return keybinds

	case 1: // Nodes tab
		keybinds := []TabKeybind{
			{Key: "f", Description: "filters"},
			{Key: "n", Description: "add node"},
			{Key: "d", Description: "delete"},
			{Key: "s", Description: "hunters"},
			{Key: "v", Description: "view"},
		}
		return keybinds

	case 2: // Statistics tab
		keybinds := []TabKeybind{}
		keybinds = append(keybinds, TabKeybind{Key: "v", Description: "view"})
		return keybinds

	case 3: // Settings tab
		return []TabKeybind{
			{Key: "Enter", Description: "edit/toggle"},
			{Key: "Esc", Description: "cancel"},
			{Key: "←/→", Description: "switch mode"},
		}

	default:
		return []TabKeybind{}
	}
}

// renderTabSpecificSection renders the tab-specific keybinds section (left side)
func (f *Footer) renderTabSpecificSection(tabIndex int) string {
	keybinds := f.getTabKeybinds(tabIndex)
	if len(keybinds) == 0 {
		return "" // No keybinds for this tab
	}

	// Get tab color for background
	bgColor := f.getTabColor(tabIndex)

	// Create a base style with background for content
	baseStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#fdf6e3")). // Solarized Base3
		Background(bgColor)

	// Styles for keys and descriptions (inherit background)
	keyStyle := baseStyle.Bold(true)
	descStyle := baseStyle
	separatorStyle := baseStyle

	// Build keybinds string with styled components
	var parts []string
	for _, kb := range keybinds {
		parts = append(parts, keyStyle.Render(kb.Key)+descStyle.Render(": "+kb.Description))
	}

	// Join with separators that also have the background
	var content string
	for i, part := range parts {
		if i > 0 {
			content += separatorStyle.Render("  │  ")
		}
		content += part
	}

	// Wrap with padding (background will extend through padding)
	containerStyle := baseStyle.Padding(0, 1)

	//return containerStyle.Render(content)
	// Add manual padding with terminal background (not tab background)
	// Left padding: 2 spaces, right padding: 2 spaces
	return " " + containerStyle.Render(content) + " "
}

// renderGeneralSection renders the general keybinds section (right side)
func (f *Footer) renderGeneralSection() string {
	// Styles for general section (violet keys)
	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6c71c4")). // Solarized Violet
		Bold(true)

	descStyle := lipgloss.NewStyle().
		Foreground(f.theme.Foreground)

	separatorStyle := lipgloss.NewStyle().
		Foreground(f.theme.BorderColor).
		Render("│")

	// General keybinds (work on all tabs)
	bindings := []string{
		keyStyle.Render("Space") + descStyle.Render(": pause"),
		keyStyle.Render("p") + descStyle.Render(": protocol"),
		keyStyle.Render("q") + descStyle.Render(": quit"),
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
	containerStyle := lipgloss.NewStyle().
		Padding(0, 1)

	return containerStyle.Render(content)
}

// View renders the footer with two sections: tab-specific (left) and general (right)
func (f *Footer) View() string {
	// Special case: filter mode shows filter keybinds only
	if f.filterMode {
		return f.renderFilterModeFooter()
	}

	// Render both sections
	tabSection := f.renderTabSpecificSection(f.activeTab)
	generalSection := f.renderGeneralSection()

	// Version info for far right (only show if enough space)
	versionText := fmt.Sprintf("🫦🐱 %s ", version.GetVersion())
	versionStyle := lipgloss.NewStyle().
		Foreground(f.theme.BorderColor)
	versionRendered := versionStyle.Render(versionText)

	// Calculate widths
	tabSectionWidth := lipgloss.Width(tabSection)
	generalSectionWidth := lipgloss.Width(generalSection)
	versionWidth := lipgloss.Width(versionRendered)

	// Build footer with sections
	var footer string

	if tabSectionWidth+generalSectionWidth+versionWidth+4 <= f.width {
		// Enough space for all three: tab section, general section, and version
		spacerWidth := f.width - tabSectionWidth - generalSectionWidth - versionWidth
		spacer := lipgloss.NewStyle().Width(spacerWidth).Render("")
		footer = tabSection + generalSection + spacer + versionRendered
	} else if tabSectionWidth+generalSectionWidth+2 <= f.width {
		// Enough space for both sections, skip version
		spacerWidth := f.width - tabSectionWidth - generalSectionWidth
		spacer := lipgloss.NewStyle().Width(spacerWidth).Render("")
		footer = tabSection + generalSection + spacer
	} else {
		// Not enough space - show tab section only and pad to width
		spacerWidth := f.width - tabSectionWidth
		if spacerWidth > 0 {
			spacer := lipgloss.NewStyle().Width(spacerWidth).Render("")
			footer = tabSection + spacer
		} else {
			footer = tabSection
		}
	}

	return footer
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
	if leftWidth < f.width {
		spacerWidth := f.width - leftWidth
		spacer := lipgloss.NewStyle().Width(spacerWidth).Render("")
		return leftContent + spacer
	}

	return leftContent
}
