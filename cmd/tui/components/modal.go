package components

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// Modal displays a modal dialog overlay
type Modal struct {
	title   string
	content string
	width   int
	height  int
	theme   themes.Theme
	visible bool
}

// NewModal creates a new modal dialog
func NewModal() Modal {
	return Modal{
		title:   "",
		content: "",
		width:   80,
		height:  24,
		theme:   themes.Solarized(),
		visible: false,
	}
}

// SetTheme updates the theme
func (m *Modal) SetTheme(theme themes.Theme) {
	m.theme = theme
}

// SetSize sets the terminal size
func (m *Modal) SetSize(width, height int) {
	m.width = width
	m.height = height
}

// Show displays the modal with content
func (m *Modal) Show(title, content string) {
	m.title = title
	m.content = content
	m.visible = true
}

// Hide closes the modal
func (m *Modal) Hide() {
	m.visible = false
}

// IsVisible returns whether the modal is visible
func (m *Modal) IsVisible() bool {
	return m.visible
}

// View renders the modal as an overlay
func (m *Modal) View(underlayContent string) string {
	if !m.visible {
		return underlayContent
	}

	// Calculate modal dimensions (60% of screen)
	modalWidth := m.width * 6 / 10
	modalHeight := m.height * 6 / 10

	if modalWidth < 40 {
		modalWidth = 40
	}
	if modalHeight < 10 {
		modalHeight = 10
	}

	// Create semi-transparent overlay effect with dimmed background
	overlayStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	dimmedUnderlay := overlayStyle.Render(underlayContent)

	// Modal container
	modalStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(m.theme.InfoColor).
		Background(m.theme.Background).
		Foreground(m.theme.Foreground).
		Width(modalWidth - 4).
		Height(modalHeight - 4).
		Padding(1, 2)

	// Title bar
	titleStyle := lipgloss.NewStyle().
		Background(m.theme.InfoColor).
		Foreground(m.theme.SelectionFg).
		Bold(true).
		Padding(0, 2).
		Width(modalWidth - 4)

	title := titleStyle.Render(m.title)

	// Close hint
	closeHintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Align(lipgloss.Center).
		MarginTop(1)

	closeHint := closeHintStyle.Render("Press Esc or q to close")

	// Content with scrolling support
	contentStyle := lipgloss.NewStyle().
		Foreground(m.theme.Foreground).
		Width(modalWidth - 8).
		Height(modalHeight - 8)

	// Truncate content if too long
	lines := strings.Split(m.content, "\n")
	maxLines := modalHeight - 8
	if len(lines) > maxLines {
		lines = lines[:maxLines]
		lines = append(lines, "...")
	}
	displayContent := strings.Join(lines, "\n")

	content := contentStyle.Render(displayContent)

	// Assemble modal
	modalContent := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		content,
		closeHint,
	)

	modal := modalStyle.Render(modalContent)

	// Create centered modal
	centeredModal := lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		modal,
	)

	// Overlay on dimmed background
	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Left,
		lipgloss.Top,
		dimmedUnderlay+"\n"+centeredModal,
	)
}