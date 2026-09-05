//go:build tui || all

package components

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// paneStyleCache shares dimension/theme invalidation for packet and event panes.
// Both focus variants are prepared together so changing focus needs no rebuild.
type paneStyleCache struct {
	ready         bool
	theme         themes.Theme
	width, height int
	borders       [2]lipgloss.Style
}

func (c *paneStyleCache) prepare(theme themes.Theme, width, height int) {
	if c.ready && c.theme == theme && c.width == width && c.height == height {
		return
	}
	*c = paneStyleCache{ready: true, theme: theme, width: width, height: height}
	base := lipgloss.NewStyle().Padding(1, 2).Width(width).Height(height)
	c.borders[0] = base.Border(lipgloss.RoundedBorder()).BorderForeground(theme.BorderColor)
	c.borders[1] = base.Border(lipgloss.ThickBorder()).BorderForeground(theme.SelectionBg)
}
func (c paneStyleCache) border(focused bool) lipgloss.Style {
	if focused {
		return c.borders[1]
	}
	return c.borders[0]
}
