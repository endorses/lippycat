//go:build tui || all
// +build tui all

package components

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// ConfirmDialogResult is sent when the user confirms or cancels
type ConfirmDialogResult struct {
	Confirmed bool
}

// ConfirmDialog is a simple yes/no confirmation modal
type ConfirmDialog struct {
	active  bool
	message string
	theme   themes.Theme
	width   int
	height  int
}

// NewConfirmDialog creates a new confirmation dialog
func NewConfirmDialog() ConfirmDialog {
	return ConfirmDialog{
		active: false,
		theme:  themes.Solarized(),
	}
}

// Activate shows the confirmation dialog with the given message
func (c *ConfirmDialog) Activate(message string) tea.Cmd {
	c.active = true
	c.message = message
	return nil
}

// Deactivate hides the confirmation dialog
func (c *ConfirmDialog) Deactivate() {
	c.active = false
}

// IsActive returns whether the dialog is currently active
func (c *ConfirmDialog) IsActive() bool {
	return c.active
}

// SetTheme updates the dialog's theme
func (c *ConfirmDialog) SetTheme(theme themes.Theme) {
	c.theme = theme
}

// SetSize updates the dialog's layout dimensions
func (c *ConfirmDialog) SetSize(width, height int) {
	c.width = width
	c.height = height
}

// Update handles messages for the confirmation dialog
func (c *ConfirmDialog) Update(msg tea.Msg) tea.Cmd {
	if !c.active {
		return nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y", "Y":
			// User confirmed
			c.Deactivate()
			return func() tea.Msg {
				return ConfirmDialogResult{Confirmed: true}
			}

		case "n", "N", "esc":
			// User cancelled
			c.Deactivate()
			return func() tea.Msg {
				return ConfirmDialogResult{Confirmed: false}
			}
		}
	}

	return nil
}

// View renders the confirmation dialog
func (c *ConfirmDialog) View() string {
	if !c.active {
		return ""
	}

	// Build dialog content
	var content strings.Builder

	// Add warning icon and message
	warningStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#cb4b16")). // Solarized orange
		Bold(true)
	content.WriteString(warningStyle.Render("⚠ Warning"))
	content.WriteString("\n\n")

	// Add the message (word-wrapped)
	messageStyle := lipgloss.NewStyle().
		Foreground(c.theme.Foreground).
		Width(50). // Wrap at 50 chars
		Align(lipgloss.Center)
	content.WriteString(messageStyle.Render(c.message))
	content.WriteString("\n\n")

	// Add prompt
	promptStyle := lipgloss.NewStyle().
		Foreground(c.theme.InfoColor).
		Bold(true)
	content.WriteString(promptStyle.Render("Continue?"))

	// Use unified modal rendering
	return RenderModal(ModalRenderOptions{
		Title:   "Confirmation",
		Content: content.String(),
		Footer:  "y: Yes | n/Esc: No",
		Width:   c.width,
		Height:  c.height,
		Theme:   c.theme,
	})
}
