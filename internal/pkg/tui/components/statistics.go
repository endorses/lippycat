//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// Statistics holds aggregated packet statistics
// Uses bounded counters to prevent unbounded memory growth
// Note: int64 counters ensure consistent behavior across 32-bit and 64-bit platforms
// and prevent overflow for long-running capture sessions.
type Statistics struct {
	ProtocolCounts *BoundedCounter // Protocol -> packet count (max 1000)
	SourceCounts   *BoundedCounter // Source IP -> packet count (max 10000)
	DestCounts     *BoundedCounter // Dest IP -> packet count (max 10000)
	TotalBytes     int64
	TotalPackets   int64
	MinPacketSize  int
	MaxPacketSize  int
}

// BridgeStatistics holds packet bridge statistics for diagnostics.
// These stats help identify backpressure issues where the TUI can't keep up
// with packet ingestion rate.
type BridgeStatistics struct {
	PacketsReceived  int64 // Total packets received from capture
	PacketsDisplayed int64 // Packets sent to TUI for display
	BatchesSent      int64 // Batches successfully queued for TUI
	BatchesDropped   int64 // Batches dropped due to TUI backpressure
	QueueDepth       int64 // Current batch queue depth
	MaxQueueDepth    int64 // Peak queue depth seen
	SamplingRatio    int64 // Current sampling ratio * 1000 (1000 = 100%)
	RecentDropRate   int64 // Recent drop rate * 1000 (last 5s, for throttling)
}

// StatisticsView displays statistics
type StatisticsView struct {
	viewport    viewport.Model
	width       int
	height      int
	theme       themes.Theme
	stats       *Statistics
	bridgeStats *BridgeStatistics
	ready       bool
	dirty       bool      // Content needs re-render
	lastRender  time.Time // Last time content was rendered
	isVisible   bool      // Tab is currently visible
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
	s.dirty = true // Mark for lazy re-render
}

// SetBridgeStats updates the bridge statistics data
func (s *StatisticsView) SetBridgeStats(bridgeStats *BridgeStatistics) {
	s.bridgeStats = bridgeStats
	s.dirty = true // Mark for lazy re-render
}

// SetVisible marks whether the statistics tab is currently visible
func (s *StatisticsView) SetVisible(visible bool) {
	s.isVisible = visible
	if visible {
		s.dirty = true // Force re-render when becoming visible
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

	// Lazy rendering: only re-render if dirty and throttle to max 2Hz (500ms)
	// This avoids expensive GetTopN() sorts on every 50ms tick
	const renderThrottle = 500 * time.Millisecond
	if s.dirty && time.Since(s.lastRender) >= renderThrottle {
		s.viewport.SetContent(s.renderContent())
		s.dirty = false
		s.lastRender = time.Now()
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
	var avgSize int64
	if s.stats.TotalPackets > 0 {
		avgSize = s.stats.TotalBytes / s.stats.TotalPackets
	}
	result.WriteString(valueStyle.Render(fmt.Sprintf("%d bytes", avgSize)))
	result.WriteString("\n")
	result.WriteString(labelStyle.Render("Min/Max Size: "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%d / %d bytes", s.stats.MinPacketSize, s.stats.MaxPacketSize)))
	result.WriteString("\n\n")

	// Section: Protocol Distribution
	result.WriteString(titleStyle.Render("🔌 Protocol Distribution"))
	result.WriteString("\n\n")

	// Show top 5 protocols
	topProtocols := s.stats.ProtocolCounts.GetTopN(5)
	for _, pc := range topProtocols {
		percentage := float64(pc.Count) / float64(s.stats.TotalPackets) * 100
		result.WriteString(fmt.Sprintf("  %-10s %6d packets  (%.1f%%)\n",
			pc.Key, pc.Count, percentage))
	}
	result.WriteString("\n")

	// Section: Top Sources
	result.WriteString(titleStyle.Render("⬆️  Top Source IPs"))
	result.WriteString("\n\n")

	// Show top 5 sources
	topSources := s.stats.SourceCounts.GetTopN(5)
	for _, sc := range topSources {
		result.WriteString(fmt.Sprintf("  %-45s %6d packets\n", sc.Key, sc.Count))
	}
	result.WriteString("\n")

	// Section: Top Destinations
	result.WriteString(titleStyle.Render("⬇️  Top Destination IPs"))
	result.WriteString("\n\n")

	// Show top 5 destinations
	topDests := s.stats.DestCounts.GetTopN(5)
	for _, dc := range topDests {
		result.WriteString(fmt.Sprintf("  %-45s %6d packets\n", dc.Key, dc.Count))
	}
	result.WriteString("\n")

	// Section: Bridge Performance (only if bridge stats available)
	if s.bridgeStats != nil && s.bridgeStats.PacketsReceived > 0 {
		result.WriteString(titleStyle.Render("🌉 Bridge Performance"))
		result.WriteString("\n\n")

		// Packets received vs displayed
		result.WriteString(labelStyle.Render("Packets Received: "))
		result.WriteString(valueStyle.Render(fmt.Sprintf("%d", s.bridgeStats.PacketsReceived)))
		result.WriteString("\n")
		result.WriteString(labelStyle.Render("Packets Displayed: "))
		result.WriteString(valueStyle.Render(fmt.Sprintf("%d", s.bridgeStats.PacketsDisplayed)))
		if s.bridgeStats.PacketsReceived > 0 {
			displayPct := float64(s.bridgeStats.PacketsDisplayed) / float64(s.bridgeStats.PacketsReceived) * 100
			result.WriteString(valueStyle.Render(fmt.Sprintf(" (%.1f%%)", displayPct)))
		}
		result.WriteString("\n")

		// Sampling ratio
		result.WriteString(labelStyle.Render("Sampling Ratio: "))
		samplingPct := float64(s.bridgeStats.SamplingRatio) / 10.0 // Convert from 1000-scale to percentage
		if samplingPct >= 100.0 {
			result.WriteString(valueStyle.Render("100% (full)"))
		} else {
			result.WriteString(valueStyle.Render(fmt.Sprintf("%.1f%%", samplingPct)))
		}
		result.WriteString("\n")

		// Batches dropped (backpressure indicator)
		result.WriteString(labelStyle.Render("Batches Sent/Dropped: "))
		result.WriteString(valueStyle.Render(fmt.Sprintf("%d / %d", s.bridgeStats.BatchesSent, s.bridgeStats.BatchesDropped)))
		if s.bridgeStats.BatchesDropped > 0 {
			dropPct := float64(s.bridgeStats.BatchesDropped) / float64(s.bridgeStats.BatchesSent+s.bridgeStats.BatchesDropped) * 100
			// Color-code based on drop rate
			if dropPct > 10 {
				warnStyle := lipgloss.NewStyle().Foreground(s.theme.ErrorColor)
				result.WriteString(warnStyle.Render(fmt.Sprintf(" (%.1f%% dropped)", dropPct)))
			} else if dropPct > 1 {
				warnStyle := lipgloss.NewStyle().Foreground(s.theme.WarningColor)
				result.WriteString(warnStyle.Render(fmt.Sprintf(" (%.1f%% dropped)", dropPct)))
			} else {
				result.WriteString(valueStyle.Render(fmt.Sprintf(" (%.1f%% dropped)", dropPct)))
			}
		}
		result.WriteString("\n")

		// Queue depth
		result.WriteString(labelStyle.Render("Queue Depth: "))
		result.WriteString(valueStyle.Render(fmt.Sprintf("%d (max: %d)", s.bridgeStats.QueueDepth, s.bridgeStats.MaxQueueDepth)))
		result.WriteString("\n")

		// Recent drop rate (used for throttling)
		result.WriteString(labelStyle.Render("Recent Drop Rate: "))
		recentDropPct := float64(s.bridgeStats.RecentDropRate) / 10.0 // Convert from 0-1000 to percentage
		if recentDropPct < 0.1 {
			result.WriteString(valueStyle.Render("0% (no throttling)"))
		} else if recentDropPct < 1.0 {
			result.WriteString(valueStyle.Render(fmt.Sprintf("%.1f%% (mild throttling)", recentDropPct)))
		} else if recentDropPct < 10.0 {
			warnStyle := lipgloss.NewStyle().Foreground(s.theme.WarningColor)
			result.WriteString(warnStyle.Render(fmt.Sprintf("%.1f%% (moderate throttling)", recentDropPct)))
		} else {
			warnStyle := lipgloss.NewStyle().Foreground(s.theme.ErrorColor)
			result.WriteString(warnStyle.Render(fmt.Sprintf("%.1f%% (heavy throttling)", recentDropPct)))
		}
		result.WriteString("\n")
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
