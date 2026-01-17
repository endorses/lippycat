//go:build tui || all

package components

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/responsive"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// Tab represents a single tab
type Tab struct {
	Label      string // Full label for wide terminals (e.g., "Live Capture")
	ShortLabel string // Abbreviated label for medium terminals (e.g., "Capture")
	Icon       string // Icon/emoji (e.g., "📡")
}

// tabDisplayMode represents how tabs should be rendered
type tabDisplayMode int

const (
	tabDisplayWide   tabDisplayMode = iota // Icon + full label
	tabDisplayMedium                       // Icon + short label
	tabDisplayNarrow                       // Icon only
)

// Tabs displays a tab bar for switching views
type Tabs struct {
	tabs   []Tab
	active int
	width  int
	theme  themes.Theme
}

// NewTabs creates a new tabs component
func NewTabs(tabs []Tab) Tabs {
	return Tabs{
		tabs:   tabs,
		active: 0,
		width:  80,
		theme:  themes.Solarized(),
	}
}

// SetTheme updates the theme
func (t *Tabs) SetTheme(theme themes.Theme) {
	t.theme = theme
}

// SetWidth sets the tabs width
func (t *Tabs) SetWidth(width int) {
	t.width = width
}

// SetActive sets the active tab index
func (t *Tabs) SetActive(index int) {
	if index >= 0 && index < len(t.tabs) {
		t.active = index
	}
}

// GetActive returns the active tab index
func (t *Tabs) GetActive() int {
	return t.active
}

// GetTabAtX returns the tab index at the given X coordinate, or -1 if not on a tab
func (t *Tabs) GetTabAtX(x int) int {
	// Use the same display mode as rendering for accurate click detection
	displayMode := t.determineDisplayMode()

	currentX := 0

	for i, tab := range t.tabs {
		content := t.getTabContent(tab, displayMode)
		contentWidth := lipgloss.Width(content)

		// Tab width: left border(1) + left padding(3) + content + right padding(3) + right border(1)
		tabWidth := 1 + 3 + contentWidth + 3 + 1

		// Check if click is within this tab's bounds
		if x >= currentX && x < currentX+tabWidth {
			return i
		}

		// Move to next tab position (add 1 for the gap between tabs)
		currentX += tabWidth + 1
	}

	return -1
}

// Next switches to the next tab
func (t *Tabs) Next() {
	t.active = (t.active + 1) % len(t.tabs)
}

// Previous switches to the previous tab
func (t *Tabs) Previous() {
	t.active = (t.active - 1 + len(t.tabs)) % len(t.tabs)
}

// UpdateTab updates the label and icon of a tab at the given index
func (t *Tabs) UpdateTab(index int, label string, icon string) {
	if index >= 0 && index < len(t.tabs) {
		t.tabs[index].Label = label
		t.tabs[index].Icon = icon
	}
}

// getTabContent returns the content string for a tab at the given display mode
func (t *Tabs) getTabContent(tab Tab, mode tabDisplayMode) string {
	switch mode {
	case tabDisplayNarrow:
		return tab.Icon
	case tabDisplayMedium:
		label := tab.ShortLabel
		if label == "" {
			label = tab.Label // Fall back to full label if no short label
		}
		return tab.Icon + " " + label
	default: // tabDisplayWide
		return tab.Icon + " " + tab.Label
	}
}

// calculateTabsWidth calculates the total width needed for all tabs at a given display mode
// Active tabs have extra padding (0,3,1,3) vs inactive (0,3), plus 1 char gap between tabs
func (t *Tabs) calculateTabsWidth(mode tabDisplayMode) int {
	totalWidth := 0
	for i, tab := range t.tabs {
		content := t.getTabContent(tab, mode)
		contentWidth := lipgloss.Width(content)

		// Tab width: left border(1) + left padding(3) + content + right padding(3) + right border(1)
		tabWidth := 1 + 3 + contentWidth + 3 + 1

		totalWidth += tabWidth

		// Add gap between tabs (except after last)
		if i < len(t.tabs)-1 {
			totalWidth++
		}
	}
	return totalWidth
}

// determineDisplayMode determines the best display mode based on available width
// It starts with the mode suggested by breakpoints, then falls back to narrower modes if needed
func (t *Tabs) determineDisplayMode() tabDisplayMode {
	// Start with the mode based on terminal width breakpoints
	widthClass := responsive.GetWidthClass(t.width)

	var startMode tabDisplayMode
	switch widthClass {
	case responsive.Wide:
		startMode = tabDisplayWide
	case responsive.Medium:
		startMode = tabDisplayMedium
	default: // Narrow
		startMode = tabDisplayNarrow
	}

	// Check if we need to fall back to a narrower mode due to overflow
	for mode := startMode; mode <= tabDisplayNarrow; mode++ {
		if t.calculateTabsWidth(mode) <= t.width {
			return mode
		}
	}

	// Even narrow mode overflows, but we can't go narrower
	return tabDisplayNarrow
}

// View renders the tabs
func (t *Tabs) View() string {
	// Define tab colors: red, yellow, green, blue, magenta
	tabColors := []lipgloss.Color{
		t.theme.ErrorColor,   // Tab 0 (Live Capture): red
		t.theme.DNSColor,     // Tab 1 (Nodes): yellow
		t.theme.SuccessColor, // Tab 2 (Statistics): green
		t.theme.InfoColor,    // Tab 3 (Settings): blue
		t.theme.TLSColor,     // Tab 4 (Help): magenta
	}

	// Get the active tab's color for the horizontal line
	activeTabColor := tabColors[t.active]

	// Active tab style (will be customized per tab)
	getActiveStyle := func(tabIndex int) lipgloss.Style {
		borderColor := tabColors[tabIndex]
		return lipgloss.NewStyle().
			Foreground(t.theme.StatusBarFg).
			Bold(true).
			Padding(0, 3, 1, 3).
			Border(lipgloss.Border{
				Top:         "━",
				Bottom:      "",
				Left:        "┃",
				Right:       "┃",
				TopLeft:     "┏",
				TopRight:    "┓",
				BottomLeft:  "",
				BottomRight: "",
			}).
			BorderTop(true).
			BorderLeft(true).
			BorderRight(true).
			BorderBottom(false).
			BorderForeground(borderColor)
	}

	// Inactive tab style (will be customized per tab)
	getInactiveStyle := func(tabIndex int) lipgloss.Style {
		borderColor := tabColors[tabIndex]
		return lipgloss.NewStyle().
			Foreground(t.theme.StatusBarFg).
			Padding(0, 3).
			Border(lipgloss.Border{
				Top:         "─",
				Bottom:      "─",
				Left:        "│",
				Right:       "│",
				TopLeft:     "╭",
				TopRight:    "╮",
				BottomLeft:  "╰",
				BottomRight: "╯",
			}).
			BorderTop(true).
			BorderLeft(true).
			BorderRight(true).
			BorderBottom(true).
			BorderForeground(borderColor)
	}

	var tabParts []string

	// Determine the display mode based on width and overflow
	displayMode := t.determineDisplayMode()

	for i, tab := range t.tabs {
		var content string
		if i == t.active {
			// For active tab: apply underline styling to label (if visible)
			labelStyle := lipgloss.NewStyle().
				Underline(true).
				Bold(true).
				Foreground(t.theme.Foreground)

			switch displayMode {
			case tabDisplayNarrow:
				// Icon only - no label to underline
				content = tab.Icon
			case tabDisplayMedium:
				// Use short label if available
				label := tab.ShortLabel
				if label == "" {
					label = tab.Label
				}
				content = tab.Icon + " " + labelStyle.Render(label)
			default: // tabDisplayWide
				content = tab.Icon + " " + labelStyle.Render(tab.Label)
			}
			tabParts = append(tabParts, getActiveStyle(i).Render(content))
		} else {
			// For inactive tab: use getTabContent for consistent display
			content = t.getTabContent(tab, displayMode)
			tabParts = append(tabParts, getInactiveStyle(i).Render(content))
		}
	}

	// Join tabs - we'll manually modify the last line to add corners
	borderStyle := lipgloss.NewStyle().Foreground(activeTabColor)
	activeCornerStyle := lipgloss.NewStyle().Foreground(activeTabColor)
	activeBorderChar := "━" // Heavy horizontal line for entire bottom border

	// Split each tab into lines (now indices match t.tabs)
	tabLines := make([][]string, len(tabParts))
	for i := range tabParts {
		tabLines[i] = strings.Split(tabParts[i], "\n")
	}

	// Build all lines except the last
	maxLines := 0
	for i := range tabLines {
		if len(tabLines[i]) > maxLines {
			maxLines = len(tabLines[i])
		}
	}

	var result strings.Builder

	// Render all lines except the last
	for lineNum := range maxLines - 1 {
		for i := range t.tabs {
			if lineNum < len(tabLines[i])-1 {
				result.WriteString(tabLines[i][lineNum])
			} else {
				// Pad with spaces if this tab doesn't have this line
				if len(tabLines[i]) > 0 {
					lastLineWidth := lipgloss.Width(tabLines[i][len(tabLines[i])-1])
					result.WriteString(strings.Repeat(" ", lastLineWidth))
				}
			}
			// Add gap between tabs
			if i < len(t.tabs)-1 {
				result.WriteString(" ")
			}
		}
		result.WriteString("\n")
	}

	// Build the last line with corners and horizontal line
	for i := range t.tabs {
		lastLine := tabLines[i][len(tabLines[i])-1]
		tabWidth := lipgloss.Width(lastLine)

		if i == t.active {
			// Active tab: replace border chars with heavy corners
			if tabWidth >= 2 {
				if i == 0 {
					// First tab: left corner ┛, right corner ┗
					result.WriteString(activeCornerStyle.Render("┛"))
					if tabWidth > 2 {
						result.WriteString(strings.Repeat(" ", tabWidth-2))
					}
					result.WriteString(activeCornerStyle.Render("┗"))
				} else {
					// Other tabs: both corners ┛ and ┗
					result.WriteString(activeCornerStyle.Render("┛"))
					if tabWidth > 2 {
						result.WriteString(strings.Repeat(" ", tabWidth-2))
					}
					result.WriteString(activeCornerStyle.Render("┗"))
				}
			}
		} else {
			// Inactive tab: heavy horizontal line (consistent with active tab)
			if tabWidth > 0 {
				result.WriteString(borderStyle.Render(strings.Repeat(activeBorderChar, tabWidth)))
			}
		}

		// Add gap between tabs - always use heavy line for consistency
		if i < len(t.tabs)-1 {
			result.WriteString(borderStyle.Render(activeBorderChar))
		}
	}

	// Fill remaining width with heavy horizontal line
	currentWidth := lipgloss.Width(result.String()) - lipgloss.Width(result.String()[:strings.LastIndex(result.String(), "\n")+1])
	if currentWidth < t.width {
		result.WriteString(borderStyle.Render(strings.Repeat(activeBorderChar, t.width-currentWidth)))
	}

	return result.String()
}
