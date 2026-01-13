//go:build tui || all

package components

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// ConfirmDialogType represents the type/severity of confirmation dialog
type ConfirmDialogType int

const (
	ConfirmDialogWarning ConfirmDialogType = iota
	ConfirmDialogDanger
	ConfirmDialogInfo
)

// ConfirmDialogResult is sent when the user confirms or cancels
type ConfirmDialogResult struct {
	Confirmed bool
	UserData  interface{} // Optional user data to pass through
}

// ConfirmDialogOptions configures the confirmation dialog appearance and behavior
type ConfirmDialogOptions struct {
	Type        ConfirmDialogType // Type of dialog (warning, danger, info)
	Title       string            // Dialog title
	Message     string            // Main message/question
	Details     []string          // Optional details to display
	ConfirmText string            // Text for confirm button (default "Yes")
	CancelText  string            // Text for cancel button (default "No")
	UserData    interface{}       // Optional data to pass through to result
}

// ConfirmDialog is a reusable yes/no confirmation modal with customizable styling
type ConfirmDialog struct {
	active      bool
	dialogType  ConfirmDialogType
	title       string
	message     string
	details     []string
	confirmText string
	cancelText  string
	userData    interface{}
	theme       themes.Theme
	width       int
	height      int
}

// NewConfirmDialog creates a new confirmation dialog
func NewConfirmDialog() ConfirmDialog {
	return ConfirmDialog{
		active:      false,
		dialogType:  ConfirmDialogWarning,
		confirmText: "Yes",
		cancelText:  "No",
		theme:       themes.Solarized(),
	}
}

// Activate shows the confirmation dialog with the given message (simple version)
// For backward compatibility. Use Show() for more control.
func (c *ConfirmDialog) Activate(message string) tea.Cmd {
	c.active = true
	c.dialogType = ConfirmDialogWarning
	c.title = "Confirmation"
	c.message = message
	c.details = nil
	c.confirmText = "Yes"
	c.cancelText = "No"
	c.userData = nil
	return nil
}

// Show activates the confirmation dialog with full options
func (c *ConfirmDialog) Show(opts ConfirmDialogOptions) tea.Cmd {
	c.active = true
	c.dialogType = opts.Type
	c.title = opts.Title
	c.message = opts.Message
	c.details = opts.Details
	c.userData = opts.UserData

	if opts.ConfirmText != "" {
		c.confirmText = opts.ConfirmText
	} else {
		c.confirmText = "Yes"
	}

	if opts.CancelText != "" {
		c.cancelText = opts.CancelText
	} else {
		c.cancelText = "No"
	}

	return nil
}

// Deactivate hides the confirmation dialog
func (c *ConfirmDialog) Deactivate() {
	c.active = false
	c.userData = nil
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
		case "y", "Y", "enter":
			// User confirmed
			userData := c.userData
			c.Deactivate()
			return func() tea.Msg {
				return ConfirmDialogResult{
					Confirmed: true,
					UserData:  userData,
				}
			}

		case "n", "N", "esc":
			// User cancelled
			userData := c.userData
			c.Deactivate()
			return func() tea.Msg {
				return ConfirmDialogResult{
					Confirmed: false,
					UserData:  userData,
				}
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

	var content strings.Builder

	// Icon and title based on type
	var icon string
	var iconColor lipgloss.Color

	switch c.dialogType {
	case ConfirmDialogDanger:
		icon = "⚠️"
		iconColor = c.theme.ErrorColor
	case ConfirmDialogWarning:
		icon = "⚠️"
		iconColor = c.theme.WarningColor
	case ConfirmDialogInfo:
		icon = "ℹ️"
		iconColor = c.theme.InfoColor
	}

	// Title with icon
	titleStyle := lipgloss.NewStyle().
		Foreground(iconColor).
		Bold(true)
	content.WriteString(titleStyle.Render(icon + "  " + c.title))
	content.WriteString("\n\n")

	// Message
	messageStyle := lipgloss.NewStyle().
		Foreground(c.theme.Foreground)
	content.WriteString(messageStyle.Render(c.message))

	// Details (if provided)
	if len(c.details) > 0 {
		content.WriteString("\n\n")
		detailStyle := lipgloss.NewStyle().
			Foreground(c.theme.Foreground)
		for _, detail := range c.details {
			content.WriteString(detailStyle.Render(detail))
			content.WriteString("\n")
		}
	}

	// Warning emphasis for danger type
	if c.dialogType == ConfirmDialogDanger {
		content.WriteString("\n\n")
		emphasisStyle := lipgloss.NewStyle().
			Foreground(c.theme.ErrorColor).
			Italic(true)
		content.WriteString(emphasisStyle.Render("This action cannot be undone."))
	}

	// Build footer with dynamic confirm/cancel text
	footer := c.confirmText + ": Confirm  " + c.cancelText + "/Esc: Cancel"

	// Use unified modal rendering
	return RenderModal(ModalRenderOptions{
		Title:      "",
		Content:    content.String(),
		Footer:     footer,
		Width:      c.width,
		Height:     c.height,
		Theme:      c.theme,
		ModalWidth: 60,
	})
}
