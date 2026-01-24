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

	// Phase 1: Core infrastructure
	rateTracker *RateTracker // Time-series rate sampling
	dropStats   *DropStats   // Aggregated drop statistics
	timeWindow  TimeWindow   // Current time window for display
	startTime   time.Time    // Session start time for "All" window
}

// NewStatisticsView creates a new statistics view
func NewStatisticsView() StatisticsView {
	return StatisticsView{
		width:       80,
		height:      20,
		theme:       themes.Solarized(),
		stats:       nil,
		ready:       false,
		rateTracker: DefaultRateTracker(),
		dropStats:   NewDropStats(),
		timeWindow:  TimeWindow1Min,
		startTime:   time.Now(),
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

// GetTimeWindow returns the current time window.
func (s *StatisticsView) GetTimeWindow() TimeWindow {
	return s.timeWindow
}

// SetTimeWindow sets the time window for statistics display.
func (s *StatisticsView) SetTimeWindow(tw TimeWindow) {
	s.timeWindow = tw
	s.dirty = true
}

// CycleTimeWindow advances to the next time window.
func (s *StatisticsView) CycleTimeWindow() TimeWindow {
	s.timeWindow = s.timeWindow.Next()
	s.dirty = true
	return s.timeWindow
}

// RecordRates records rate samples based on current statistics.
// Should be called periodically (e.g., every second) from the TUI update loop.
func (s *StatisticsView) RecordRates() {
	if s.stats == nil || s.rateTracker == nil {
		return
	}
	s.rateTracker.Record(s.stats.TotalPackets, s.stats.TotalBytes)
}

// GetRateStats returns current rate statistics.
func (s *StatisticsView) GetRateStats() RateStats {
	if s.rateTracker == nil {
		return RateStats{}
	}
	return s.rateTracker.GetStats()
}

// GetDropStats returns the drop statistics aggregator.
func (s *StatisticsView) GetDropStats() *DropStats {
	return s.dropStats
}

// GetDropSummary returns a summary of drop statistics.
func (s *StatisticsView) GetDropSummary() DropSummary {
	if s.dropStats == nil {
		return DropSummary{}
	}
	return s.dropStats.GetSummary()
}

// UpdateDropsFromBridge updates drop stats from bridge statistics.
func (s *StatisticsView) UpdateDropsFromBridge() {
	if s.dropStats != nil && s.bridgeStats != nil {
		s.dropStats.UpdateFromBridgeStats(s.bridgeStats)
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

	// Time window header
	result.WriteString(s.renderTimeWindowHeader())
	result.WriteString("\n\n")

	// Section: Overview
	result.WriteString(titleStyle.Render("📊 Overview"))
	result.WriteString("\n\n")
	result.WriteString(labelStyle.Render("Total Packets: "))
	result.WriteString(valueStyle.Render(formatNumber64(s.stats.TotalPackets)))
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
	result.WriteString("\n")
	result.WriteString(labelStyle.Render("Session Duration: "))
	result.WriteString(valueStyle.Render(formatDuration(time.Since(s.startTime))))
	result.WriteString("\n\n")

	// Section: Traffic Rate
	result.WriteString(s.renderRateSection(titleStyle, labelStyle, valueStyle))
	result.WriteString("\n")

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

// formatNumber64 formats an int64 number with thousand separators
func formatNumber64(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}

	// Build string from right to left with commas
	s := fmt.Sprintf("%d", n)
	result := make([]byte, 0, len(s)+len(s)/3)

	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm %ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh %dm", h, m)
}

// formatRate formats a rate value with appropriate units
func formatRate(rate float64) string {
	if rate < 1 {
		return fmt.Sprintf("%.2f", rate)
	}
	if rate < 1000 {
		return fmt.Sprintf("%.0f", rate)
	}
	if rate < 1000000 {
		return fmt.Sprintf("%.1fK", rate/1000)
	}
	return fmt.Sprintf("%.1fM", rate/1000000)
}

// formatBytesPerSec formats bytes/second with appropriate units
func formatBytesPerSec(bytesPerSec float64) string {
	if bytesPerSec < 1024 {
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	}
	if bytesPerSec < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", bytesPerSec/1024)
	}
	if bytesPerSec < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB/s", bytesPerSec/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB/s", bytesPerSec/(1024*1024*1024))
}

// renderTimeWindowHeader renders the time window selector header
func (s *StatisticsView) renderTimeWindowHeader() string {
	var result strings.Builder

	// Style for selected window
	selectedStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.SelectionFg)

	// Style for unselected windows
	normalStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	result.WriteString("Time Window: ")

	for _, tw := range AllTimeWindows() {
		if tw == s.timeWindow {
			result.WriteString(selectedStyle.Render("[" + tw.String() + "]"))
		} else {
			result.WriteString(normalStyle.Render(" " + tw.String() + " "))
		}
		result.WriteString(" ")
	}

	result.WriteString(normalStyle.Render("  (t to cycle)"))

	return result.String()
}

// renderRateSection renders the traffic rate section
func (s *StatisticsView) renderRateSection(titleStyle, labelStyle, valueStyle lipgloss.Style) string {
	var result strings.Builder

	rateStats := s.GetRateStats()

	result.WriteString(titleStyle.Render("📈 Traffic Rate"))
	result.WriteString("\n\n")

	// Current rates
	result.WriteString(labelStyle.Render("Current: "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%s pkt/s  |  %s",
		formatRate(rateStats.CurrentPacketsPerSec),
		formatBytesPerSec(rateStats.CurrentBytesPerSec))))
	result.WriteString("\n")

	// Average rates
	result.WriteString(labelStyle.Render("Average: "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%s pkt/s  |  %s",
		formatRate(rateStats.AvgPacketsPerSec),
		formatBytesPerSec(rateStats.AvgBytesPerSec))))
	result.WriteString("\n")

	// Peak rates
	result.WriteString(labelStyle.Render("Peak:    "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%s pkt/s  |  %s",
		formatRate(rateStats.PeakPacketsPerSec),
		formatBytesPerSec(rateStats.PeakBytesPerSec))))
	result.WriteString("\n")

	return result.String()
}
