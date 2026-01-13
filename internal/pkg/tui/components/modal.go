//go:build tui || all

package components

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// ModalRenderOptions configures modal rendering
type ModalRenderOptions struct {
	Title       string       // Modal title (optional)
	Content     string       // Modal content (required)
	Footer      string       // Footer text (optional, e.g. keybindings)
	Width       int          // Terminal width
	Height      int          // Terminal height
	Theme       themes.Theme // Color theme
	ModalWidth  int          // Specific modal width (0 = auto-calculate)
	ShowOverlay bool         // Whether to show dimmed background overlay
}

// RenderModal is the unified modal rendering function.
// All modals in the codebase MUST use this function for consistent styling.
//
// Content components (ProtocolSelector, HunterSelector, FilterManager, etc.)
// should manage their own state and content rendering, then call this function
// to wrap their content in a consistent modal chrome.
//
// Example usage:
//
//	content := "My modal content..."
//	footer := "Enter: Select | Esc: Cancel"
//	return RenderModal(ModalRenderOptions{
//	    Title: "My Modal",
//	    Content: content,
//	    Footer: footer,
//	    Width: width,
//	    Height: height,
//	    Theme: theme,
//	})
func RenderModal(opts ModalRenderOptions) string {
	// Calculate modal width
	modalWidth := opts.ModalWidth
	if modalWidth == 0 {
		// Default: 60-80 characters, or 70% of screen width
		modalWidth = opts.Width * 7 / 10
		if modalWidth > 80 {
			modalWidth = 80
		}
		if modalWidth < 60 {
			modalWidth = 60
		}
	}

	// Ensure modal fits in terminal
	if modalWidth > opts.Width-4 {
		modalWidth = opts.Width - 4
	}
	if modalWidth < 40 {
		modalWidth = 40
	}

	// Modal container style
	modalStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(opts.Theme.InfoColor).
		Padding(1, 2).
		Width(modalWidth)

	// Title style (if provided)
	var titleRendered string
	if opts.Title != "" {
		titleStyle := lipgloss.NewStyle().
			Foreground(opts.Theme.HeaderBg).
			Bold(true).
			Padding(0, 1).
			Width(modalWidth - 4)
		titleRendered = titleStyle.Render(opts.Title) + "\n\n"
	}

	// Content style
	contentStyle := lipgloss.NewStyle().
		Foreground(opts.Theme.Foreground).
		Width(modalWidth - 4)
	contentRendered := contentStyle.Render(opts.Content)

	// Footer style (if provided)
	var footerRendered string
	if opts.Footer != "" {
		footerStyle := lipgloss.NewStyle().
			Foreground(opts.Theme.StatusBarFg).
			Italic(true).
			Width(modalWidth - 4)
		footerRendered = "\n\n" + footerStyle.Render(opts.Footer)
	}

	// Assemble modal content
	modalContent := titleRendered + contentRendered + footerRendered
	modal := modalStyle.Render(modalContent)

	// Center the modal
	centeredModal := lipgloss.Place(
		opts.Width,
		opts.Height,
		lipgloss.Center,
		lipgloss.Center,
		modal,
	)

	// Return with or without overlay
	if opts.ShowOverlay {
		// Create dimmed background overlay
		// Note: Actual dimming of underlay content must be handled by caller
		// as we don't have access to the underlay content here
		return centeredModal
	}

	return centeredModal
}
