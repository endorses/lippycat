//go:build tui || all
// +build tui all

package components

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/version"
)

// Footer displays the bottom footer bar with keybindings
type Footer struct {
	width      int
	theme      themes.Theme
	filterMode bool
	hasFilter  bool
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

// View renders the footer
func (f *Footer) View() string {
	baseStyle := lipgloss.NewStyle().
		Foreground(f.theme.Foreground).
		Padding(0, 1)

	keyStyle := lipgloss.NewStyle().
		Foreground(f.theme.InfoColor).
		Bold(true)

	descStyle := lipgloss.NewStyle().
		Foreground(f.theme.Foreground)

	separatorStyle := lipgloss.NewStyle().
		Foreground(f.theme.BorderColor).
		Render("│")

	// Build keybindings based on current mode
	var bindings []string

	if f.filterMode {
		// Filter mode keybindings
		bindings = []string{
			keyStyle.Render("Enter") + descStyle.Render(": apply"),
			keyStyle.Render("Esc") + descStyle.Render(": cancel"),
			keyStyle.Render("↑↓") + descStyle.Render(": history"),
		}
	} else {
		// Normal mode keybindings
		bindings = []string{
			keyStyle.Render("/") + descStyle.Render(": filter"),
			keyStyle.Render("n") + descStyle.Render(": add node"),
			keyStyle.Render("Space") + descStyle.Render(": pause"),
			keyStyle.Render("x") + descStyle.Render(": flush"),
			// keyStyle.Render("t") + descStyle.Render(": theme"),  // Commented out for now
			keyStyle.Render("Alt+1-4") + descStyle.Render(": tabs"),
			keyStyle.Render("←↓↑→/hjkl") + descStyle.Render(": nav"),
		}

		if f.hasFilter {
			bindings = append(bindings, keyStyle.Render("c")+descStyle.Render(": clear filter"))
		}

		bindings = append(bindings, keyStyle.Render("q")+descStyle.Render(": quit"))
	}

	// Join bindings with separators
	var content string
	for i, binding := range bindings {
		if i > 0 {
			content += "  " + separatorStyle + "  "
		}
		content += binding
	}

	// Version info for far right (only show if enough space)
	versionText := fmt.Sprintf("🫦🐱 v%s", version.GetVersion())
	versionStyle := lipgloss.NewStyle().
		Foreground(f.theme.BorderColor)
	versionRendered := versionStyle.Render(versionText)
	versionWidth := lipgloss.Width(versionRendered)

	// Calculate minimum width needed to show version (keybindings + padding + version + margins)
	leftContent := baseStyle.Render(content)
	leftWidth := lipgloss.Width(leftContent)
	minWidthForVersion := leftWidth + versionWidth + 4 // 4 chars for spacing

	var footer string
	if f.width >= minWidthForVersion {
		// Enough space - show version on far right
		paddingWidth := f.width - leftWidth - versionWidth
		paddingStr := lipgloss.NewStyle().Width(paddingWidth).Render("")
		footer = leftContent + paddingStr + versionRendered
	} else {
		// Not enough space - skip version, just show keybindings
		footer = leftContent
		footerWidth := lipgloss.Width(footer)
		if footerWidth < f.width {
			padding := f.width - footerWidth
			footer += baseStyle.Render(lipgloss.NewStyle().Width(padding).Render(""))
		}
	}

	return footer
}
