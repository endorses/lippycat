//go:build tui || all

package components

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
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
	hasEvents            bool    // True when the common Events view is available
	paused               bool    // True when capture is paused
	hasHelpSearch        bool    // True when Help tab has active search
	viewMode             string  // "packets" or "calls" for Capture tab
	callFilterMode       bool    // True when call filter input is active
	hasCallFilter        bool    // True when call filters are applied
	callFilterCount      int     // Number of stacked call filters
	eventFilterMode      bool    // True when event query input is active
	hasEventFilter       bool    // True when event filters are applied
	eventFilterCount     int     // Number of stacked event filters
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

// SetHasEvents controls whether Capture view cycling includes normalized events.
func (f *Footer) SetHasEvents(has bool) { f.hasEvents = has }

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

func (f *Footer) SetEventFilterMode(active bool) { f.eventFilterMode = active }
func (f *Footer) SetHasEventFilter(has bool)     { f.hasEventFilter = has }
func (f *Footer) SetEventFilterCount(count int)  { f.eventFilterCount = count }

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
		if f.viewMode == "events" {
			if f.hasEventFilter {
				keybinds = append(keybinds, TabKeybind{Key: "c", Description: "remove event filter", ShortDesc: "clr", Essential: false})
				if f.eventFilterCount > 1 {
					keybinds = append(keybinds, TabKeybind{Key: "C", Description: "clear event filters", ShortDesc: "all", Essential: false})
				}
			}
		} else if f.viewMode == "calls" {
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
		keybinds = append(keybinds,
			TabKeybind{Key: "d", Description: "details", ShortDesc: "det", Essential: true},
			TabKeybind{Key: "t", Description: "time", ShortDesc: "tm", Essential: false},
		)

		if f.hasProtocolSelection || f.hasEvents {
			keybinds = append(keybinds, TabKeybind{Key: "v", Description: "view", ShortDesc: "vw", Essential: false})
		}
		if f.streamingSave {
			keybinds = append(keybinds,
				TabKeybind{Key: "w", Description: "stop", ShortDesc: "stp", Essential: true},
			)
		} else {
			keybinds = append(keybinds,
				TabKeybind{Key: "w", Description: "save", ShortDesc: "sav", Essential: true},
			)
		}
		keybinds = append(keybinds,
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
			{Key: "1", Description: "overview", ShortDesc: "ovw", Essential: false},
			{Key: "2", Description: "distributed", ShortDesc: "dist", Essential: false},
			{Key: "e", Description: "export", ShortDesc: "exp", Essential: false},
		}
		return keybinds

	case 3: // Settings tab
		return []TabKeybind{
			{Key: "Enter", Description: "edit/toggle", ShortDesc: "edit", Essential: true},
			{Key: "Esc", Description: "cancel", ShortDesc: "esc", Essential: true},
			{Key: "←", Description: "previous", ShortDesc: "prev", Essential: false},
			{Key: "→", Description: "next", ShortDesc: "next", Essential: false},
		}

	case 4: // Help tab
		keybinds := []TabKeybind{
			{Key: "/", Description: "search", ShortDesc: "srch", Essential: true},
		}
		if f.hasHelpSearch {
			keybinds = append(keybinds,
				TabKeybind{Key: "n", Description: "next", ShortDesc: "next", Essential: true},
				TabKeybind{Key: "N", Description: "previous", ShortDesc: "prev", Essential: true},
				TabKeybind{Key: "c", Description: "clear", ShortDesc: "clr", Essential: false},
			)
		}
		keybinds = append(keybinds,
			TabKeybind{Key: "1", Description: "keys", ShortDesc: "keys", Essential: false},
			TabKeybind{Key: "2", Description: "filters", ShortDesc: "flt", Essential: false},
			TabKeybind{Key: "3", Description: "commands", ShortDesc: "cmd", Essential: false},
			TabKeybind{Key: "4", Description: "workflows", ShortDesc: "flow", Essential: false},
		)
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

// footerHit describes the terminal cells occupied by one complete hint. Padding
// and separators are deliberately outside these half-open ranges.
type footerHit struct {
	start int
	end   int
	key   string
}

type footerLayout struct {
	content string
	hits    []footerHit
}

// renderSection produces both styled text and hit regions from the same hints.
// A nonnegative limit drops complete trailing hints that would exceed it.
func (f *Footer) renderSection(bindings []TabKeybind, widthClass responsive.WidthClass, color lipgloss.Color, limit int) footerLayout {
	keyStyle := lipgloss.NewStyle().Foreground(color).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(f.theme.Foreground)
	separator := "  │  "
	if widthClass != responsive.Wide {
		separator = " │ "
	}
	separatorWidth := lipgloss.Width(separator)
	separator = lipgloss.NewStyle().Foreground(f.theme.BorderColor).Render(separator)

	layout := footerLayout{}
	var content strings.Builder
	content.WriteString(" ")
	width := 1
	for _, binding := range bindings {
		hint := keyStyle.Render(binding.Key)
		switch widthClass {
		case responsive.Medium:
			desc := binding.ShortDesc
			if desc == "" {
				desc = binding.Description
			}
			hint += descStyle.Render(":" + desc)
		case responsive.Wide:
			hint += descStyle.Render(": " + binding.Description)
		}
		hintWidth := lipgloss.Width(hint)
		start := width
		if len(layout.hits) > 0 {
			start += separatorWidth
		}
		// Reserve the section's trailing padding, too.
		if limit >= 0 && start+hintWidth+1 > limit {
			break
		}
		if len(layout.hits) > 0 {
			content.WriteString(separator)
		}
		content.WriteString(hint)
		width = start + hintWidth
		layout.hits = append(layout.hits, footerHit{start: start, end: width, key: binding.Key})
	}
	if len(layout.hits) > 0 {
		content.WriteString(" ")
		layout.content = content.String()
	}
	return layout
}

// layout is read-only so hit testing also works before the next View call.
func (f *Footer) layout() footerLayout {
	width := max(0, f.width)
	widthClass := responsive.GetWidthClass(width)
	generalColor := lipgloss.Color("#6c71c4") // Solarized Violet
	var layout footerLayout
	if f.filterMode || f.callFilterMode || f.eventFilterMode {
		layout = f.renderSection([]TabKeybind{
			{Key: "Enter", Description: "apply", ShortDesc: "apply"},
			{Key: "Esc", Description: "cancel", ShortDesc: "esc"},
			{Key: "↑", Description: "older history", ShortDesc: "older"},
			{Key: "↓", Description: "newer history", ShortDesc: "newer"},
		}, widthClass, generalColor, width)
	} else {
		bindings, _ := f.getResponsiveKeybinds(f.activeTab)
		layout = f.renderSection(bindings, widthClass, f.getTabColor(f.activeTab), -1)
		general := f.renderSection(f.getGeneralKeybinds(), widthClass, generalColor, -1)
		separator := ""
		if layout.content != "" {
			separator = lipgloss.NewStyle().Foreground(f.theme.BorderColor).Render(" ║ ")
		}
		generalStart := lipgloss.Width(layout.content) + lipgloss.Width(separator)
		if generalStart+lipgloss.Width(general.content) <= width {
			layout.content += separator + general.content
			for _, hit := range general.hits {
				hit.start += generalStart
				hit.end += generalStart
				layout.hits = append(layout.hits, hit)
			}
			versionText := fmt.Sprintf("🫦🐱 v%s ", version.GetVersion())
			spacerWidth := width - lipgloss.Width(layout.content) - lipgloss.Width(versionText)
			if spacerWidth >= 0 {
				layout.content += strings.Repeat(" ", spacerWidth) + lipgloss.NewStyle().Foreground(f.theme.BorderColor).Render(versionText)
			}
		} else if lipgloss.Width(layout.content) > width {
			layout = f.renderSection(bindings, widthClass, f.getTabColor(f.activeTab), width)
		}
	}
	layout.content += strings.Repeat(" ", width-lipgloss.Width(layout.content))
	return layout
}

// KeyAtX returns the key for a visible hint at a zero-based terminal column on
// the footer's keybinding row. The caller is responsible for checking the row.
func (f *Footer) KeyAtX(x int) (tea.KeyMsg, bool) {
	if x < 0 || x >= f.width {
		return tea.KeyMsg{}, false
	}
	for _, hit := range f.layout().hits {
		if x >= hit.start && x < hit.end {
			return footerKeyMessage(hit.key)
		}
	}
	return tea.KeyMsg{}, false
}

func footerKeyMessage(key string) (tea.KeyMsg, bool) {
	switch key {
	case "Enter":
		return tea.KeyMsg{Type: tea.KeyEnter}, true
	case "Esc":
		return tea.KeyMsg{Type: tea.KeyEsc}, true
	case "Space":
		return tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}, true
	case "←":
		return tea.KeyMsg{Type: tea.KeyLeft}, true
	case "→":
		return tea.KeyMsg{Type: tea.KeyRight}, true
	case "↑":
		return tea.KeyMsg{Type: tea.KeyUp}, true
	case "↓":
		return tea.KeyMsg{Type: tea.KeyDown}, true
	default:
		runes := []rune(key)
		if len(runes) == 1 {
			return tea.KeyMsg{Type: tea.KeyRunes, Runes: runes}, true
		}
		return tea.KeyMsg{}, false
	}
}

// View renders the footer with two lines: horizontal separator + keybindings.
func (f *Footer) View() string {
	horizontalLine := lipgloss.NewStyle().Foreground(f.theme.BorderColor).Render(strings.Repeat("─", max(0, f.width)))
	return horizontalLine + "\n" + f.layout().content
}
