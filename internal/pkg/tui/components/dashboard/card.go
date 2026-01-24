//go:build tui || all

// Package dashboard provides reusable dashboard UI components for the statistics view.
package dashboard

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// Card represents a dashboard card with a border, optional title/icon, and content.
type Card struct {
	Title   string         // Card title (displayed in header)
	Icon    string         // Optional icon prefix for title
	Width   int            // Card width in characters (0 = auto)
	Content string         // Pre-rendered content to display inside the card
	theme   themes.Theme   // Theme for styling
	style   lipgloss.Style // Optional custom style override
}

// CardOption is a functional option for configuring a Card.
type CardOption func(*Card)

// WithIcon sets the card icon.
func WithIcon(icon string) CardOption {
	return func(c *Card) {
		c.Icon = icon
	}
}

// WithWidth sets the card width.
func WithWidth(width int) CardOption {
	return func(c *Card) {
		c.Width = width
	}
}

// WithStyle sets a custom style override.
func WithStyle(style lipgloss.Style) CardOption {
	return func(c *Card) {
		c.style = style
	}
}

// NewCard creates a new Card with the given title and content.
func NewCard(title, content string, theme themes.Theme, opts ...CardOption) *Card {
	c := &Card{
		Title:   title,
		Content: content,
		theme:   theme,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// SetTheme updates the card theme.
func (c *Card) SetTheme(theme themes.Theme) {
	c.theme = theme
}

// SetContent updates the card content.
func (c *Card) SetContent(content string) {
	c.Content = content
}

// Render returns the styled card as a string.
func (c *Card) Render() string {
	// Build the title with optional icon
	var titleText string
	if c.Icon != "" {
		titleText = c.Icon + " " + c.Title
	} else {
		titleText = c.Title
	}

	// Calculate width
	width := c.Width
	if width <= 0 {
		// Auto-calculate based on content and title
		width = maxLineWidth(c.Content)
		titleLen := lipgloss.Width(titleText)
		if titleLen+4 > width { // +4 for border padding
			width = titleLen + 4
		}
		if width < 20 {
			width = 20 // minimum width
		}
	}

	// Title style
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(c.theme.InfoColor)

	// Border style
	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(c.theme.BorderColor).
		Width(width).
		Padding(0, 1)

	// If custom style is set, merge it
	if c.style.Value() != "" {
		borderStyle = c.style.Width(width).Padding(0, 1)
	}

	// Build card content
	var content strings.Builder
	if titleText != "" {
		content.WriteString(titleStyle.Render(titleText))
		content.WriteString("\n")
	}
	content.WriteString(c.Content)

	return borderStyle.Render(content.String())
}

// RenderInline returns the card without borders, suitable for inline display.
func (c *Card) RenderInline() string {
	var titleText string
	if c.Icon != "" {
		titleText = c.Icon + " " + c.Title
	} else {
		titleText = c.Title
	}

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(c.theme.InfoColor)

	var content strings.Builder
	if titleText != "" {
		content.WriteString(titleStyle.Render(titleText))
		content.WriteString("\n")
	}
	content.WriteString(c.Content)

	return content.String()
}

// maxLineWidth returns the maximum line width in a multi-line string.
func maxLineWidth(s string) int {
	maxWidth := 0
	for _, line := range strings.Split(s, "\n") {
		w := lipgloss.Width(line)
		if w > maxWidth {
			maxWidth = w
		}
	}
	return maxWidth
}
