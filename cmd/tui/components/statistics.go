//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// Statistics holds aggregated packet statistics
type Statistics struct {
	ProtocolCounts map[string]int // Protocol -> packet count
	SourceCounts   map[string]int // Source IP -> packet count
	DestCounts     map[string]int // Dest IP -> packet count
	TotalBytes     int64
	TotalPackets   int
	MinPacketSize  int
	MaxPacketSize  int
}

// StatisticsView displays statistics
type StatisticsView struct {
	viewport viewport.Model
	width    int
	height   int
	theme    themes.Theme
	stats    *Statistics
	ready    bool
}

// NewStatisticsView creates a new statistics view
func NewStatisticsView() StatisticsView {
	return StatisticsView{
		width:  80,
		height: 20,
		theme:  themes.Solarized(),
		stats:  nil,
		ready:  false,
	}
}

// SetTheme updates the theme
func (s *StatisticsView) SetTheme(theme themes.Theme) {
	s.theme = theme
}

// SetSize sets the display size
func (s *StatisticsView) SetSize(width, height int) {
	s.width = width
	s.height = height

	if !s.ready {
		s.viewport = viewport.New(width, height)
		s.ready = true
		// Set initial content if stats are already available
		if s.stats != nil {
			s.viewport.SetContent(s.renderContent())
		}
	} else {
		s.viewport.Width = width
		s.viewport.Height = height
	}
}

// SetStatistics updates the statistics data
func (s *StatisticsView) SetStatistics(stats *Statistics) {
	s.stats = stats
	// Update viewport content when stats change (only if viewport is ready)
	if s.ready {
		s.viewport.SetContent(s.renderContent())
	}
}

// Update handles viewport messages for scrolling
func (s *StatisticsView) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	s.viewport, cmd = s.viewport.Update(msg)
	return cmd
}

// View renders the statistics view
func (s *StatisticsView) View() string {
	if !s.ready {
		return ""
	}

	if s.stats == nil || s.stats.TotalPackets == 0 {
		emptyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Align(lipgloss.Center, lipgloss.Center).
			Width(s.width).
			Height(s.height)
		return emptyStyle.Render("No statistics available yet...")
	}

	return s.viewport.View()
}

// renderContent generates the statistics content
func (s *StatisticsView) renderContent() string {
	if s.stats == nil || s.stats.TotalPackets == 0 {
		return ""
	}

	var result strings.Builder

	// Title style
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.InfoColor).
		MarginBottom(1)

	// Label style
	labelStyle := lipgloss.NewStyle().
		Foreground(s.theme.StatusBarFg).
		Bold(true)

	// Value style
	valueStyle := lipgloss.NewStyle().
		Foreground(s.theme.StatusBarFg)

	// Section: Overview
	result.WriteString(titleStyle.Render("📊 Overview"))
	result.WriteString("\n\n")
	result.WriteString(labelStyle.Render("Total Packets: "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%d", s.stats.TotalPackets)))
	result.WriteString("\n")
	result.WriteString(labelStyle.Render("Total Bytes: "))
	result.WriteString(valueStyle.Render(formatBytes(s.stats.TotalBytes)))
	result.WriteString("\n")
	result.WriteString(labelStyle.Render("Avg Packet Size: "))
	avgSize := 0
	if s.stats.TotalPackets > 0 {
		avgSize = int(s.stats.TotalBytes) / s.stats.TotalPackets
	}
	result.WriteString(valueStyle.Render(fmt.Sprintf("%d bytes", avgSize)))
	result.WriteString("\n")
	result.WriteString(labelStyle.Render("Min/Max Size: "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%d / %d bytes", s.stats.MinPacketSize, s.stats.MaxPacketSize)))
	result.WriteString("\n\n")

	// Section: Protocol Distribution
	result.WriteString(titleStyle.Render("🔌 Protocol Distribution"))
	result.WriteString("\n\n")

	// Sort protocols by count
	type protocolCount struct {
		protocol string
		count    int
	}
	var protocols []protocolCount
	for proto, count := range s.stats.ProtocolCounts {
		protocols = append(protocols, protocolCount{proto, count})
	}
	sort.Slice(protocols, func(i, j int) bool {
		return protocols[i].count > protocols[j].count
	})

	// Show top 5 protocols
	for i, pc := range protocols {
		if i >= 5 {
			break
		}
		percentage := float64(pc.count) / float64(s.stats.TotalPackets) * 100
		result.WriteString(fmt.Sprintf("  %-10s %6d packets  (%.1f%%)\n",
			pc.protocol, pc.count, percentage))
	}
	result.WriteString("\n")

	// Section: Top Sources
	result.WriteString(titleStyle.Render("⬆️  Top Source IPs"))
	result.WriteString("\n\n")

	// Sort sources by count
	type ipCount struct {
		ip    string
		count int
	}
	var sources []ipCount
	for ip, count := range s.stats.SourceCounts {
		sources = append(sources, ipCount{ip, count})
	}
	sort.Slice(sources, func(i, j int) bool {
		return sources[i].count > sources[j].count
	})

	// Show top 5 sources
	for i, sc := range sources {
		if i >= 5 {
			break
		}
		result.WriteString(fmt.Sprintf("  %-45s %6d packets\n", sc.ip, sc.count))
	}
	result.WriteString("\n")

	// Section: Top Destinations
	result.WriteString(titleStyle.Render("⬇️  Top Destination IPs"))
	result.WriteString("\n\n")

	// Sort destinations by count
	var dests []ipCount
	for ip, count := range s.stats.DestCounts {
		dests = append(dests, ipCount{ip, count})
	}
	sort.Slice(dests, func(i, j int) bool {
		return dests[i].count > dests[j].count
	})

	// Show top 5 destinations
	for i, dc := range dests {
		if i >= 5 {
			break
		}
		result.WriteString(fmt.Sprintf("  %-45s %6d packets\n", dc.ip, dc.count))
	}

	return result.String()
}

// formatBytes formats bytes into human-readable format
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}