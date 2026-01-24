//go:build tui || all

package components

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// SubView represents a sub-view within the Statistics tab.
type SubView int

const (
	// SubViewOverview shows the overview dashboard with all sections
	SubViewOverview SubView = iota
	// SubViewTraffic shows traffic rate details
	SubViewTraffic
	// SubViewHealth shows system health details
	SubViewHealth
	// SubViewTopTalkers shows top sources/destinations with selection
	SubViewTopTalkers
	// SubViewDistributed shows distributed mode aggregates
	SubViewDistributed
)

// String returns a human-readable label for the sub-view.
func (sv SubView) String() string {
	switch sv {
	case SubViewOverview:
		return "Overview"
	case SubViewTraffic:
		return "Traffic"
	case SubViewHealth:
		return "Health"
	case SubViewTopTalkers:
		return "Top Talkers"
	case SubViewDistributed:
		return "Distributed"
	default:
		return "?"
	}
}

// ShortString returns a short label for the sub-view header.
func (sv SubView) ShortString() string {
	switch sv {
	case SubViewOverview:
		return "Ovw"
	case SubViewTraffic:
		return "Trf"
	case SubViewHealth:
		return "Hlt"
	case SubViewTopTalkers:
		return "Top"
	case SubViewDistributed:
		return "Dst"
	default:
		return "?"
	}
}

// Next cycles to the next sub-view.
func (sv SubView) Next() SubView {
	switch sv {
	case SubViewOverview:
		return SubViewTraffic
	case SubViewTraffic:
		return SubViewHealth
	case SubViewHealth:
		return SubViewTopTalkers
	case SubViewTopTalkers:
		return SubViewDistributed
	case SubViewDistributed:
		return SubViewOverview
	default:
		return SubViewOverview
	}
}

// AllSubViews returns all available sub-views for UI rendering.
func AllSubViews() []SubView {
	return []SubView{
		SubViewOverview,
		SubViewTraffic,
		SubViewHealth,
		SubViewTopTalkers,
		SubViewDistributed,
	}
}

// TalkerSection identifies which section in TopTalkers view is selected.
type TalkerSection int

const (
	TalkerSectionSources TalkerSection = iota
	TalkerSectionDestinations
)

// ApplyFilterMsg is sent when a filter should be applied from statistics.
type ApplyFilterMsg struct {
	Filter string // The filter expression to apply (e.g., "host 192.168.1.100")
}

// ExportStatsMsg is sent when statistics should be exported to JSON.
type ExportStatsMsg struct {
	Path    string // Path where JSON was written
	Success bool
	Error   error
}

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

	// Phase 2: Visualization components
	queueBar        *UtilizationBar  // Queue depth progress bar
	healthIndicator *HealthIndicator // Health status indicator

	// Phase 3: Interactivity
	currentSubView  SubView       // Current sub-view being displayed
	talkerSection   TalkerSection // Which section in TopTalkers is active
	selectedIndex   int           // Selected item index in TopTalkers
	maxTalkersShown int           // Number of top talkers to show (default 10)
}

// NewStatisticsView creates a new statistics view
func NewStatisticsView() StatisticsView {
	return StatisticsView{
		width:           80,
		height:          20,
		theme:           themes.Solarized(),
		stats:           nil,
		ready:           false,
		rateTracker:     DefaultRateTracker(),
		dropStats:       NewDropStats(),
		timeWindow:      TimeWindow1Min,
		startTime:       time.Now(),
		queueBar:        NewUtilizationBar(30),
		healthIndicator: NewHealthIndicator(),
		currentSubView:  SubViewOverview,
		talkerSection:   TalkerSectionSources,
		selectedIndex:   0,
		maxTalkersShown: 10,
	}
}

// SetTheme updates the theme
func (s *StatisticsView) SetTheme(theme themes.Theme) {
	s.theme = theme
	if s.queueBar != nil {
		s.queueBar.SetTheme(theme)
	}
	if s.healthIndicator != nil {
		s.healthIndicator.SetTheme(theme)
	}
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

// GetSubView returns the current sub-view.
func (s *StatisticsView) GetSubView() SubView {
	return s.currentSubView
}

// SetSubView sets the current sub-view.
func (s *StatisticsView) SetSubView(sv SubView) {
	s.currentSubView = sv
	s.dirty = true
	// Reset selection when changing sub-views
	s.selectedIndex = 0
}

// CycleSubView advances to the next sub-view.
func (s *StatisticsView) CycleSubView() SubView {
	s.currentSubView = s.currentSubView.Next()
	s.dirty = true
	// Reset selection when changing sub-views
	s.selectedIndex = 0
	return s.currentSubView
}

// GetTalkerSection returns the current talker section.
func (s *StatisticsView) GetTalkerSection() TalkerSection {
	return s.talkerSection
}

// ToggleTalkerSection toggles between sources and destinations.
func (s *StatisticsView) ToggleTalkerSection() {
	if s.talkerSection == TalkerSectionSources {
		s.talkerSection = TalkerSectionDestinations
	} else {
		s.talkerSection = TalkerSectionSources
	}
	s.selectedIndex = 0
	s.dirty = true
}

// GetSelectedIndex returns the currently selected index in TopTalkers view.
func (s *StatisticsView) GetSelectedIndex() int {
	return s.selectedIndex
}

// MoveSelectionUp moves the selection up in TopTalkers view.
func (s *StatisticsView) MoveSelectionUp() {
	if s.selectedIndex > 0 {
		s.selectedIndex--
		s.dirty = true
	}
}

// MoveSelectionDown moves the selection down in TopTalkers view.
func (s *StatisticsView) MoveSelectionDown() {
	maxIndex := s.maxTalkersShown - 1
	if s.selectedIndex < maxIndex {
		s.selectedIndex++
		s.dirty = true
	}
}

// GetSelectedFilter returns the filter expression for the currently selected talker.
// Returns empty string if no valid selection.
func (s *StatisticsView) GetSelectedFilter() string {
	if s.stats == nil || s.currentSubView != SubViewTopTalkers {
		return ""
	}

	var items []KeyCount
	if s.talkerSection == TalkerSectionSources {
		items = s.stats.SourceCounts.GetTopN(s.maxTalkersShown)
	} else {
		items = s.stats.DestCounts.GetTopN(s.maxTalkersShown)
	}

	if s.selectedIndex >= len(items) {
		return ""
	}

	ip := items[s.selectedIndex].Key
	return fmt.Sprintf("host %s", ip)
}

// ExportJSON exports statistics to JSON format.
func (s *StatisticsView) ExportJSON() ([]byte, error) {
	if s.stats == nil {
		return nil, fmt.Errorf("no statistics available")
	}

	rateStats := s.GetRateStats()
	dropSummary := s.GetDropSummary()

	export := struct {
		Timestamp    string `json:"timestamp"`
		TimeWindow   string `json:"time_window"`
		SessionStart string `json:"session_start"`

		Overview struct {
			TotalPackets  int64  `json:"total_packets"`
			TotalBytes    int64  `json:"total_bytes"`
			AvgPacketSize int64  `json:"avg_packet_size"`
			MinPacketSize int    `json:"min_packet_size"`
			MaxPacketSize int    `json:"max_packet_size"`
			Duration      string `json:"duration"`
		} `json:"overview"`

		TrafficRate struct {
			CurrentPacketsPerSec float64 `json:"current_packets_per_sec"`
			CurrentBytesPerSec   float64 `json:"current_bytes_per_sec"`
			AvgPacketsPerSec     float64 `json:"avg_packets_per_sec"`
			AvgBytesPerSec       float64 `json:"avg_bytes_per_sec"`
			PeakPacketsPerSec    float64 `json:"peak_packets_per_sec"`
			PeakBytesPerSec      float64 `json:"peak_bytes_per_sec"`
		} `json:"traffic_rate"`

		Drops struct {
			TotalDrops    int64   `json:"total_drops"`
			TotalDropRate float64 `json:"total_drop_rate"`
		} `json:"drops"`

		Protocols []struct {
			Name       string  `json:"name"`
			Count      int64   `json:"count"`
			Percentage float64 `json:"percentage"`
		} `json:"protocols"`

		TopSources []struct {
			IP    string `json:"ip"`
			Count int64  `json:"count"`
		} `json:"top_sources"`

		TopDestinations []struct {
			IP    string `json:"ip"`
			Count int64  `json:"count"`
		} `json:"top_destinations"`
	}{
		Timestamp:    time.Now().Format(time.RFC3339),
		TimeWindow:   s.timeWindow.String(),
		SessionStart: s.startTime.Format(time.RFC3339),
	}

	// Overview
	export.Overview.TotalPackets = s.stats.TotalPackets
	export.Overview.TotalBytes = s.stats.TotalBytes
	if s.stats.TotalPackets > 0 {
		export.Overview.AvgPacketSize = s.stats.TotalBytes / s.stats.TotalPackets
	}
	export.Overview.MinPacketSize = s.stats.MinPacketSize
	export.Overview.MaxPacketSize = s.stats.MaxPacketSize
	export.Overview.Duration = formatDuration(time.Since(s.startTime))

	// Traffic rate
	export.TrafficRate.CurrentPacketsPerSec = rateStats.CurrentPacketsPerSec
	export.TrafficRate.CurrentBytesPerSec = rateStats.CurrentBytesPerSec
	export.TrafficRate.AvgPacketsPerSec = rateStats.AvgPacketsPerSec
	export.TrafficRate.AvgBytesPerSec = rateStats.AvgBytesPerSec
	export.TrafficRate.PeakPacketsPerSec = rateStats.PeakPacketsPerSec
	export.TrafficRate.PeakBytesPerSec = rateStats.PeakBytesPerSec

	// Drops
	export.Drops.TotalDrops = dropSummary.TotalDrops
	export.Drops.TotalDropRate = dropSummary.TotalDropRate

	// Protocols
	for _, p := range s.stats.ProtocolCounts.GetTopN(20) {
		var pct float64
		if s.stats.TotalPackets > 0 {
			pct = float64(p.Count) / float64(s.stats.TotalPackets) * 100
		}
		export.Protocols = append(export.Protocols, struct {
			Name       string  `json:"name"`
			Count      int64   `json:"count"`
			Percentage float64 `json:"percentage"`
		}{Name: p.Key, Count: p.Count, Percentage: pct})
	}

	// Top sources
	for _, src := range s.stats.SourceCounts.GetTopN(20) {
		export.TopSources = append(export.TopSources, struct {
			IP    string `json:"ip"`
			Count int64  `json:"count"`
		}{IP: src.Key, Count: src.Count})
	}

	// Top destinations
	for _, dst := range s.stats.DestCounts.GetTopN(20) {
		export.TopDestinations = append(export.TopDestinations, struct {
			IP    string `json:"ip"`
			Count int64  `json:"count"`
		}{IP: dst.Key, Count: dst.Count})
	}

	return json.MarshalIndent(export, "", "  ")
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

// renderContent generates the statistics content based on current sub-view
func (s *StatisticsView) renderContent() string {
	if s.stats == nil || s.stats.TotalPackets == 0 {
		return ""
	}

	var result strings.Builder

	// Render sub-view navigation header
	result.WriteString(s.renderSubViewHeader())
	result.WriteString("\n")

	// Time window header
	result.WriteString(s.renderTimeWindowHeader())
	result.WriteString("\n\n")

	// Render content based on current sub-view
	switch s.currentSubView {
	case SubViewOverview:
		result.WriteString(s.renderOverviewSubView())
	case SubViewTraffic:
		result.WriteString(s.renderTrafficSubView())
	case SubViewHealth:
		result.WriteString(s.renderHealthSubView())
	case SubViewTopTalkers:
		result.WriteString(s.renderTopTalkersSubView())
	case SubViewDistributed:
		result.WriteString(s.renderDistributedSubView())
	}

	return result.String()
}

// renderSubViewHeader renders the sub-view navigation header
func (s *StatisticsView) renderSubViewHeader() string {
	var result strings.Builder

	// Style for selected view
	selectedStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.SelectionFg).
		Background(s.theme.SuccessColor).
		Padding(0, 1)

	// Style for unselected views
	normalStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Padding(0, 1)

	// Style for number keys
	keyStyle := lipgloss.NewStyle().
		Foreground(s.theme.InfoColor).
		Bold(true)

	result.WriteString("View: ")

	for i, sv := range AllSubViews() {
		keyNum := fmt.Sprintf("%d", i+1)
		if sv == s.currentSubView {
			result.WriteString(selectedStyle.Render(keyNum + ":" + sv.ShortString()))
		} else {
			result.WriteString(normalStyle.Render(keyStyle.Render(keyNum) + ":" + sv.ShortString()))
		}
		result.WriteString(" ")
	}

	hintStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	result.WriteString(hintStyle.Render("  (v to cycle)"))

	return result.String()
}

// renderOverviewSubView renders the overview dashboard with all sections
func (s *StatisticsView) renderOverviewSubView() string {
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

	// Section: Traffic Rate (compact)
	result.WriteString(s.renderRateSection(titleStyle, labelStyle, valueStyle))
	result.WriteString("\n")

	// Section: Protocol Distribution
	result.WriteString(titleStyle.Render("🔌 Protocol Distribution"))
	result.WriteString("\n\n")

	topProtocols := s.stats.ProtocolCounts.GetTopN(5)
	for _, pc := range topProtocols {
		percentage := float64(pc.Count) / float64(s.stats.TotalPackets) * 100
		result.WriteString(fmt.Sprintf("  %-10s %6d packets  (%.1f%%)\n",
			pc.Key, pc.Count, percentage))
	}
	result.WriteString("\n")

	// Section: Top Sources (compact, 5 items)
	result.WriteString(titleStyle.Render("⬆️  Top Source IPs"))
	result.WriteString("\n\n")

	topSources := s.stats.SourceCounts.GetTopN(5)
	for _, sc := range topSources {
		result.WriteString(fmt.Sprintf("  %-45s %6d packets\n", sc.Key, sc.Count))
	}
	result.WriteString("\n")

	// Section: Top Destinations (compact, 5 items)
	result.WriteString(titleStyle.Render("⬇️  Top Destination IPs"))
	result.WriteString("\n\n")

	topDests := s.stats.DestCounts.GetTopN(5)
	for _, dc := range topDests {
		result.WriteString(fmt.Sprintf("  %-45s %6d packets\n", dc.Key, dc.Count))
	}
	result.WriteString("\n")

	// Section: System Health (compact)
	result.WriteString(s.renderHealthSection(titleStyle))

	return result.String()
}

// renderTrafficSubView renders detailed traffic rate information
func (s *StatisticsView) renderTrafficSubView() string {
	var result strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.InfoColor).
		MarginBottom(1)

	labelStyle := lipgloss.NewStyle().
		Foreground(s.theme.StatusBarFg).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(s.theme.StatusBarFg)

	result.WriteString(titleStyle.Render("📈 Traffic Rate Details"))
	result.WriteString("\n\n")

	rateStats := s.GetRateStats()

	// Current rates
	result.WriteString(labelStyle.Render("Current Packet Rate: "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%s packets/sec", formatRate(rateStats.CurrentPacketsPerSec))))
	result.WriteString("\n")
	result.WriteString(labelStyle.Render("Current Byte Rate:   "))
	result.WriteString(valueStyle.Render(formatBytesPerSec(rateStats.CurrentBytesPerSec)))
	result.WriteString("\n\n")

	// Average rates
	result.WriteString(labelStyle.Render("Average Packet Rate: "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%s packets/sec", formatRate(rateStats.AvgPacketsPerSec))))
	result.WriteString("\n")
	result.WriteString(labelStyle.Render("Average Byte Rate:   "))
	result.WriteString(valueStyle.Render(formatBytesPerSec(rateStats.AvgBytesPerSec)))
	result.WriteString("\n\n")

	// Peak rates
	result.WriteString(labelStyle.Render("Peak Packet Rate:    "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%s packets/sec", formatRate(rateStats.PeakPacketsPerSec))))
	result.WriteString("\n")
	result.WriteString(labelStyle.Render("Peak Byte Rate:      "))
	result.WriteString(valueStyle.Render(formatBytesPerSec(rateStats.PeakBytesPerSec)))
	result.WriteString("\n\n")

	// Render sparkline for packet rate trend (larger)
	if s.rateTracker != nil && s.rateTracker.SampleCount() > 2 {
		sparklineWidth := 60
		if s.width > 0 && s.width < 100 {
			sparklineWidth = s.width - 20
		}

		rates := s.rateTracker.GetRatesForWindow(s.timeWindow, sparklineWidth)
		if len(rates) > 0 {
			result.WriteString(labelStyle.Render("Packet Rate Trend:"))
			result.WriteString("\n")
			sparkline := RenderRateSparkline(rates, sparklineWidth, 5, s.theme, rateStats.PeakPacketsPerSec)
			result.WriteString(sparkline)
			result.WriteString("\n")
		}
	}

	// Protocol distribution
	result.WriteString("\n")
	result.WriteString(titleStyle.Render("🔌 Protocol Distribution"))
	result.WriteString("\n\n")

	topProtocols := s.stats.ProtocolCounts.GetTopN(10)
	for _, pc := range topProtocols {
		percentage := float64(pc.Count) / float64(s.stats.TotalPackets) * 100
		result.WriteString(fmt.Sprintf("  %-12s %8d packets  (%5.1f%%)\n",
			pc.Key, pc.Count, percentage))
	}

	return result.String()
}

// renderHealthSubView renders detailed system health information
func (s *StatisticsView) renderHealthSubView() string {
	var result strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.InfoColor).
		MarginBottom(1)

	labelStyle := lipgloss.NewStyle().
		Foreground(s.theme.StatusBarFg).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(s.theme.StatusBarFg)

	result.WriteString(titleStyle.Render("🩺 System Health"))
	result.WriteString("\n\n")

	// Health summary
	result.WriteString(s.renderHealthSection(titleStyle))
	result.WriteString("\n")

	// Bridge Performance (detailed)
	if s.bridgeStats != nil && s.bridgeStats.PacketsReceived > 0 {
		result.WriteString(titleStyle.Render("🌉 Bridge Performance"))
		result.WriteString("\n\n")

		// Packets received vs displayed
		result.WriteString(labelStyle.Render("Packets Received:   "))
		result.WriteString(valueStyle.Render(fmt.Sprintf("%d", s.bridgeStats.PacketsReceived)))
		result.WriteString("\n")
		result.WriteString(labelStyle.Render("Packets Displayed:  "))
		result.WriteString(valueStyle.Render(fmt.Sprintf("%d", s.bridgeStats.PacketsDisplayed)))
		if s.bridgeStats.PacketsReceived > 0 {
			displayPct := float64(s.bridgeStats.PacketsDisplayed) / float64(s.bridgeStats.PacketsReceived) * 100
			result.WriteString(valueStyle.Render(fmt.Sprintf(" (%.1f%%)", displayPct)))
		}
		result.WriteString("\n")

		// Sampling ratio
		result.WriteString(labelStyle.Render("Sampling Ratio:     "))
		samplingPct := float64(s.bridgeStats.SamplingRatio) / 10.0
		if samplingPct >= 100.0 {
			result.WriteString(valueStyle.Render("100% (full)"))
		} else {
			result.WriteString(valueStyle.Render(fmt.Sprintf("%.1f%%", samplingPct)))
		}
		result.WriteString("\n")

		// Batches dropped
		result.WriteString(labelStyle.Render("Batches Sent:       "))
		result.WriteString(valueStyle.Render(fmt.Sprintf("%d", s.bridgeStats.BatchesSent)))
		result.WriteString("\n")
		result.WriteString(labelStyle.Render("Batches Dropped:    "))
		result.WriteString(valueStyle.Render(fmt.Sprintf("%d", s.bridgeStats.BatchesDropped)))
		if s.bridgeStats.BatchesDropped > 0 {
			dropPct := float64(s.bridgeStats.BatchesDropped) / float64(s.bridgeStats.BatchesSent+s.bridgeStats.BatchesDropped) * 100
			if dropPct > 10 {
				warnStyle := lipgloss.NewStyle().Foreground(s.theme.ErrorColor)
				result.WriteString(warnStyle.Render(fmt.Sprintf(" (%.1f%%)", dropPct)))
			} else if dropPct > 1 {
				warnStyle := lipgloss.NewStyle().Foreground(s.theme.WarningColor)
				result.WriteString(warnStyle.Render(fmt.Sprintf(" (%.1f%%)", dropPct)))
			} else {
				result.WriteString(valueStyle.Render(fmt.Sprintf(" (%.1f%%)", dropPct)))
			}
		}
		result.WriteString("\n\n")

		// Queue depth with progress bar
		if s.bridgeStats.MaxQueueDepth > 0 && s.queueBar != nil {
			result.WriteString(s.queueBar.RenderQueue(
				s.bridgeStats.QueueDepth,
				s.bridgeStats.MaxQueueDepth,
				"Queue Depth"))
			result.WriteString("\n\n")
		}

		// Recent drop rate
		result.WriteString(labelStyle.Render("Recent Drop Rate:   "))
		recentDropPct := float64(s.bridgeStats.RecentDropRate) / 10.0
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
	} else {
		result.WriteString(valueStyle.Render("  No bridge statistics available\n"))
	}

	return result.String()
}

// renderTopTalkersSubView renders top sources/destinations with selection
func (s *StatisticsView) renderTopTalkersSubView() string {
	var result strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.InfoColor).
		MarginBottom(1)

	// Tab style for section toggle
	activeTabStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.SelectionFg).
		Background(s.theme.SuccessColor).
		Padding(0, 1)

	inactiveTabStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Padding(0, 1)

	selectedStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.SelectionFg).
		Background(s.theme.SelectionBg)

	normalStyle := lipgloss.NewStyle().
		Foreground(s.theme.StatusBarFg)

	hintStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	result.WriteString(titleStyle.Render("🔝 Top Talkers"))
	result.WriteString("\n\n")

	// Section toggle
	result.WriteString("Section: ")
	if s.talkerSection == TalkerSectionSources {
		result.WriteString(activeTabStyle.Render("⬆️ Sources"))
		result.WriteString(" ")
		result.WriteString(inactiveTabStyle.Render("⬇️ Destinations"))
	} else {
		result.WriteString(inactiveTabStyle.Render("⬆️ Sources"))
		result.WriteString(" ")
		result.WriteString(activeTabStyle.Render("⬇️ Destinations"))
	}
	result.WriteString(hintStyle.Render("  (Tab to switch, Enter to filter)"))
	result.WriteString("\n\n")

	// Get items based on section
	var items []KeyCount
	if s.talkerSection == TalkerSectionSources {
		items = s.stats.SourceCounts.GetTopN(s.maxTalkersShown)
	} else {
		items = s.stats.DestCounts.GetTopN(s.maxTalkersShown)
	}

	// Render items with selection highlighting
	for i, item := range items {
		prefix := "  "
		line := fmt.Sprintf("%-45s %8d packets", item.Key, item.Count)

		if i == s.selectedIndex {
			result.WriteString(selectedStyle.Render("▶ " + line))
		} else {
			result.WriteString(prefix)
			result.WriteString(normalStyle.Render(line))
		}
		result.WriteString("\n")
	}

	// Navigation hint
	result.WriteString("\n")
	result.WriteString(hintStyle.Render("j/k or ↑/↓ to navigate"))

	return result.String()
}

// renderDistributedSubView renders distributed mode statistics
func (s *StatisticsView) renderDistributedSubView() string {
	var result strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(s.theme.InfoColor).
		MarginBottom(1)

	valueStyle := lipgloss.NewStyle().
		Foreground(s.theme.StatusBarFg)

	result.WriteString(titleStyle.Render("🌐 Distributed Mode Statistics"))
	result.WriteString("\n\n")

	// Placeholder for Phase 4
	result.WriteString(valueStyle.Render("  Distributed mode statistics will be available in Phase 4.\n"))
	result.WriteString(valueStyle.Render("  Connect to a processor node to see:\n"))
	result.WriteString(valueStyle.Render("    • Fleet overview (hunters/processors)\n"))
	result.WriteString(valueStyle.Render("    • Combined throughput\n"))
	result.WriteString(valueStyle.Render("    • Per-hunter contribution\n"))
	result.WriteString(valueStyle.Render("    • Load distribution\n"))

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

// renderRateSection renders the traffic rate section with sparklines
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
	result.WriteString("\n\n")

	// Render sparkline for packet rate trend
	if s.rateTracker != nil && s.rateTracker.SampleCount() > 2 {
		// Get rate data for the current time window
		sparklineWidth := 50
		if s.width > 0 && s.width < 80 {
			sparklineWidth = s.width - 20
		}

		rates := s.rateTracker.GetRatesForWindow(s.timeWindow, sparklineWidth)
		if len(rates) > 0 {
			result.WriteString(labelStyle.Render("Packet Rate Trend:"))
			result.WriteString("\n")
			sparkline := RenderRateSparkline(rates, sparklineWidth, 3, s.theme, rateStats.PeakPacketsPerSec)
			result.WriteString(sparkline)
			result.WriteString("\n")
		}
	}

	return result.String()
}

// renderHealthSection renders the system health summary section
func (s *StatisticsView) renderHealthSection(titleStyle lipgloss.Style) string {
	var result strings.Builder

	result.WriteString(titleStyle.Render("🩺 System Health"))
	result.WriteString("\n\n")

	if s.healthIndicator == nil {
		return result.String()
	}

	// Calculate health levels based on available metrics
	var items []struct {
		Label string
		Level HealthLevel
	}

	// Drop rate health (inverted: high drop rate = bad)
	dropSummary := s.GetDropSummary()
	if s.stats != nil && s.stats.TotalPackets > 0 {
		dropLevel := HealthFromRatio(dropSummary.TotalDropRate/100, 0.01, 0.05, true)
		items = append(items, struct {
			Label string
			Level HealthLevel
		}{"Drops", dropLevel})
	}

	// Queue depth health (if available)
	if s.bridgeStats != nil && s.bridgeStats.MaxQueueDepth > 0 {
		queueRatio := float64(s.bridgeStats.QueueDepth) / float64(s.bridgeStats.MaxQueueDepth)
		queueLevel := HealthFromRatio(queueRatio, 0.5, 0.85, true)
		items = append(items, struct {
			Label string
			Level HealthLevel
		}{"Queue", queueLevel})
	}

	// Sampling health (inverted: low sampling = bad)
	if s.bridgeStats != nil && s.bridgeStats.SamplingRatio > 0 {
		samplingRatio := float64(s.bridgeStats.SamplingRatio) / 1000.0 // Convert from 1000-scale
		samplingLevel := HealthFromRatio(samplingRatio, 0.5, 0.2, false)
		items = append(items, struct {
			Label string
			Level HealthLevel
		}{"Sampling", samplingLevel})
	}

	// Throttling health
	if s.bridgeStats != nil {
		recentDropPct := float64(s.bridgeStats.RecentDropRate) / 1000.0 // Convert from 1000-scale
		throttleLevel := HealthFromRatio(recentDropPct, 0.01, 0.10, true)
		items = append(items, struct {
			Label string
			Level HealthLevel
		}{"Throttle", throttleLevel})
	}

	// Render health indicators
	if len(items) > 0 {
		result.WriteString(RenderHealthSummary(s.theme, items))
		result.WriteString("\n")
	} else {
		result.WriteString("  No health data available\n")
	}

	return result.String()
}
