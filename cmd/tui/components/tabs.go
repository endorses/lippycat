package components

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// Tab represents a single tab
type Tab struct {
	Label string
	Icon  string
}

// Tabs displays a tab bar for switching views
type Tabs struct {
	tabs     []Tab
	active   int
	width    int
	theme    themes.Theme
}

// NewTabs creates a new tabs component
func NewTabs(tabs []Tab) Tabs {
	return Tabs{
		tabs:   tabs,
		active: 0,
		width:  80,
		theme:  themes.SolarizedDark(),
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

// Next switches to the next tab
func (t *Tabs) Next() {
	t.active = (t.active + 1) % len(t.tabs)
}

// Previous switches to the previous tab
func (t *Tabs) Previous() {
	t.active = (t.active - 1 + len(t.tabs)) % len(t.tabs)
}

// View renders the tabs
func (t *Tabs) View() string {
	// Active tab: no bottom border, sides extend down with one extra line
	activeStyle := lipgloss.NewStyle().
		Foreground(t.theme.InfoColor).
		Bold(true).
		Padding(0, 3, 1, 3).
		Border(lipgloss.Border{
			Top:         "─",
			Bottom:      "",
			Left:        "│",
			Right:       "│",
			TopLeft:     "╭",
			TopRight:    "╮",
			BottomLeft:  "",
			BottomRight: "",
		}).
		BorderTop(true).
		BorderLeft(true).
		BorderRight(true).
		BorderBottom(false).
		BorderForeground(t.theme.InfoColor)

	// Inactive tab: no background, muted, with visible bottom border
	inactiveStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
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
		BorderForeground(t.theme.BorderColor)

	var tabParts []string

	for i, tab := range t.tabs {
		label := tab.Icon + " " + tab.Label
		if i == t.active {
			tabParts = append(tabParts, activeStyle.Render(label))
		} else {
			tabParts = append(tabParts, inactiveStyle.Render(label))
		}
	}

	// Join tabs - we'll manually modify the last line to add corners
	borderStyle := lipgloss.NewStyle().Foreground(t.theme.InfoColor)
	activeCornerStyle := lipgloss.NewStyle().Foreground(t.theme.InfoColor)

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
	for lineNum := 0; lineNum < maxLines-1; lineNum++ {
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
			// Active tab: replace border chars with corners
			if tabWidth >= 2 {
				if i == 0 {
					// First tab: left corner ┘, right corner └
					result.WriteString(activeCornerStyle.Render("┘"))
					if tabWidth > 2 {
						result.WriteString(strings.Repeat(" ", tabWidth-2))
					}
					result.WriteString(activeCornerStyle.Render("└"))
				} else {
					// Other tabs: both corners ┘ and └
					result.WriteString(activeCornerStyle.Render("┘"))
					if tabWidth > 2 {
						result.WriteString(strings.Repeat(" ", tabWidth-2))
					}
					result.WriteString(activeCornerStyle.Render("└"))
				}
			}
		} else {
			// Inactive tab: horizontal line
			if tabWidth > 0 {
				result.WriteString(borderStyle.Render(strings.Repeat("─", tabWidth)))
			}
		}

		// Add gap between tabs
		if i < len(t.tabs)-1 {
			result.WriteString(borderStyle.Render("─"))
		}
	}

	// Fill remaining width with horizontal line
	currentWidth := lipgloss.Width(result.String()) - lipgloss.Width(result.String()[:strings.LastIndex(result.String(), "\n")+1])
	if currentWidth < t.width {
		result.WriteString(borderStyle.Render(strings.Repeat("─", t.width-currentWidth)))
	}

	return result.String()
}