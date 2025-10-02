package components

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// HunterInfo represents a hunter node for display
type HunterInfo struct {
	ID              string
	Hostname        string
	RemoteAddr      string
	Status          management.HunterStatus
	ConnectedAt     int64
	LastHeartbeat   int64
	PacketsCaptured uint64
	PacketsMatched  uint64
	PacketsForwarded uint64
	PacketsDropped  uint64
	ActiveFilters   uint32
	Interfaces      []string
}

// NodesView displays connected hunter nodes in a table
type NodesView struct {
	hunters       []HunterInfo
	selectedIndex int
	width         int
	height        int
	theme         themes.Theme
	scrollOffset  int
}

// NewNodesView creates a new nodes view component
func NewNodesView() NodesView {
	return NodesView{
		hunters:       []HunterInfo{},
		selectedIndex: 0,
		width:         80,
		height:        20,
		theme:         themes.SolarizedDark(),
		scrollOffset:  0,
	}
}

// SetTheme updates the theme
func (n *NodesView) SetTheme(theme themes.Theme) {
	n.theme = theme
}

// SetSize updates the view dimensions
func (n *NodesView) SetSize(width, height int) {
	n.width = width
	n.height = height
}

// SetHunters updates the hunter list
func (n *NodesView) SetHunters(hunters []HunterInfo) {
	n.hunters = hunters
	// Reset selection if out of bounds
	if n.selectedIndex >= len(n.hunters) {
		n.selectedIndex = 0
	}
}

// SelectNext moves selection to next hunter
func (n *NodesView) SelectNext() {
	if len(n.hunters) > 0 {
		n.selectedIndex = (n.selectedIndex + 1) % len(n.hunters)
		n.adjustScroll()
	}
}

// SelectPrevious moves selection to previous hunter
func (n *NodesView) SelectPrevious() {
	if len(n.hunters) > 0 {
		n.selectedIndex = (n.selectedIndex - 1 + len(n.hunters)) % len(n.hunters)
		n.adjustScroll()
	}
}

// adjustScroll adjusts scroll offset to keep selected item visible
func (n *NodesView) adjustScroll() {
	visibleRows := n.height - 3 // Header + borders
	if n.selectedIndex < n.scrollOffset {
		n.scrollOffset = n.selectedIndex
	}
	if n.selectedIndex >= n.scrollOffset+visibleRows {
		n.scrollOffset = n.selectedIndex - visibleRows + 1
	}
}

// GetSelectedHunter returns the currently selected hunter
func (n *NodesView) GetSelectedHunter() *HunterInfo {
	if n.selectedIndex >= 0 && n.selectedIndex < len(n.hunters) {
		return &n.hunters[n.selectedIndex]
	}
	return nil
}

// View renders the nodes view
func (n *NodesView) View() string {
	if len(n.hunters) == 0 {
		emptyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Align(lipgloss.Center, lipgloss.Center).
			Width(n.width).
			Height(n.height)
		return emptyStyle.Render("No hunters connected\n\nStart a hunter with:\n  lippycat hunt --processor <processor-addr>")
	}

	var b strings.Builder

	// Table header
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(n.theme.InfoColor).
		PaddingLeft(1).
		PaddingRight(1)

	idCol := 20
	hostCol := 20
	statusCol := 10
	uptimeCol := 12
	capturedCol := 12
	forwardedCol := 12
	filtersCol := 10

	header := fmt.Sprintf(
		"%s %s %s %s %s %s %s",
		headerStyle.Width(idCol).Render("Hunter ID"),
		headerStyle.Width(hostCol).Render("Hostname"),
		headerStyle.Width(statusCol).Render("Status"),
		headerStyle.Width(uptimeCol).Render("Uptime"),
		headerStyle.Width(capturedCol).Render("Captured"),
		headerStyle.Width(forwardedCol).Render("Forwarded"),
		headerStyle.Width(filtersCol).Render("Filters"),
	)
	b.WriteString(header + "\n")

	// Separator
	sepStyle := lipgloss.NewStyle().Foreground(n.theme.BorderColor)
	separator := sepStyle.Render(strings.Repeat("─", n.width))
	b.WriteString(separator + "\n")

	// Table rows
	visibleRows := n.height - 3 // Header + separator + footer
	endIndex := n.scrollOffset + visibleRows
	if endIndex > len(n.hunters) {
		endIndex = len(n.hunters)
	}

	for i := n.scrollOffset; i < endIndex; i++ {
		hunter := n.hunters[i]

		// Status color
		statusStyle := lipgloss.NewStyle().PaddingLeft(1).PaddingRight(1)
		var statusText string
		switch hunter.Status {
		case management.HunterStatus_STATUS_HEALTHY:
			statusStyle = statusStyle.Foreground(n.theme.SuccessColor)
			statusText = "HEALTHY"
		case management.HunterStatus_STATUS_WARNING:
			statusStyle = statusStyle.Foreground(n.theme.WarningColor)
			statusText = "WARNING"
		case management.HunterStatus_STATUS_ERROR:
			statusStyle = statusStyle.Foreground(n.theme.ErrorColor)
			statusText = "ERROR"
		case management.HunterStatus_STATUS_STOPPING:
			statusStyle = statusStyle.Foreground(lipgloss.Color("240"))
			statusText = "STOPPING"
		}

		// Calculate uptime
		uptime := ""
		if hunter.ConnectedAt > 0 {
			duration := time.Since(time.Unix(0, hunter.ConnectedAt))
			if duration.Hours() >= 1 {
				uptime = fmt.Sprintf("%.0fh %.0fm", duration.Hours(), duration.Minutes()-duration.Hours()*60)
			} else if duration.Minutes() >= 1 {
				uptime = fmt.Sprintf("%.0fm %.0fs", duration.Minutes(), duration.Seconds()-duration.Minutes()*60)
			} else {
				uptime = fmt.Sprintf("%.0fs", duration.Seconds())
			}
		}

		// Row style
		rowStyle := lipgloss.NewStyle().PaddingLeft(1).PaddingRight(1)
		if i == n.selectedIndex {
			rowStyle = rowStyle.
				Background(n.theme.SelectionBg).
				Foreground(n.theme.SelectionFg)
			statusStyle = statusStyle.
				Background(n.theme.SelectionBg)
		}

		row := fmt.Sprintf(
			"%s %s %s %s %s %s %s",
			rowStyle.Width(idCol).Render(truncateString(hunter.ID, idCol-2)),
			rowStyle.Width(hostCol).Render(truncateString(hunter.Hostname, hostCol-2)),
			statusStyle.Width(statusCol).Render(statusText),
			rowStyle.Width(uptimeCol).Render(uptime),
			rowStyle.Width(capturedCol).Render(formatPacketNumber(hunter.PacketsCaptured)),
			rowStyle.Width(forwardedCol).Render(formatPacketNumber(hunter.PacketsForwarded)),
			rowStyle.Width(filtersCol).Render(fmt.Sprintf("%d", hunter.ActiveFilters)),
		)
		b.WriteString(row + "\n")
	}

	// Scroll indicator
	if len(n.hunters) > visibleRows {
		scrollInfo := fmt.Sprintf(" [%d/%d] ", n.selectedIndex+1, len(n.hunters))
		scrollStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Align(lipgloss.Right)
		b.WriteString(scrollStyle.Width(n.width).Render(scrollInfo))
	}

	return b.String()
}

// truncateString truncates a string to maxLen with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// formatPacketNumber formats a packet count with K/M/G suffixes
func formatPacketNumber(n uint64) string {
	if n >= 1000000000 {
		return fmt.Sprintf("%.1fG", float64(n)/1000000000)
	}
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}
