//go:build tui || all

package components

import (
	"encoding/json"
	"fmt"
	"sort"
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

// HunterContribution represents a hunter's contribution to overall traffic.
type HunterContribution struct {
	ID               string
	Hostname         string
	ProcessorAddr    string
	Status           string // "healthy", "warning", "error"
	PacketsCaptured  uint64
	PacketsForwarded uint64
	PacketsDropped   uint64
	DropRate         float64 // Percentage of packets dropped
	Contribution     float64 // Percentage of total fleet packets
	CPUPercent       float64
	MemoryRSSBytes   uint64
	MemoryLimitBytes uint64
}

// ProcessorSummary represents aggregated stats for a processor.
type ProcessorSummary struct {
	Address          string
	ProcessorID      string
	Status           string // "healthy", "warning", "error", "disconnected"
	HunterCount      int
	TotalPackets     uint64
	TotalDropped     uint64
	AvgCPUPercent    float64
	TotalMemoryRSS   uint64
	TotalMemoryLimit uint64
}

// DistributedStats holds aggregated statistics from distributed nodes.
type DistributedStats struct {
	// Fleet overview
	TotalProcessors   int
	HealthyProcessors int
	TotalHunters      int
	HealthyHunters    int
	WarningHunters    int
	ErrorHunters      int

	// Combined throughput
	TotalPacketsCaptured  uint64
	TotalPacketsForwarded uint64
	TotalPacketsDropped   uint64
	OverallDropRate       float64 // Percentage

	// Resource usage
	FleetCPUPercent    float64 // Average CPU across all hunters
	FleetMemoryRSS     uint64  // Sum of memory RSS across all hunters
	FleetMemoryLimit   uint64  // Sum of memory limits across all hunters
	FleetMemoryPercent float64 // Overall memory usage percentage

	// Per-hunter contributions (sorted by packets captured, descending)
	HunterContributions []HunterContribution

	// Per-processor summaries
	ProcessorSummaries []ProcessorSummary

	// Last update timestamp
	LastUpdate time.Time
}

// NewDistributedStats creates an empty DistributedStats instance.
func NewDistributedStats() *DistributedStats {
	return &DistributedStats{
		HunterContributions: make([]HunterContribution, 0),
		ProcessorSummaries:  make([]ProcessorSummary, 0),
		LastUpdate:          time.Now(),
	}
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

	// Phase 4: Distributed mode
	distributedStats *DistributedStats // Aggregated distributed fleet statistics

	// Phase 5: Protocol-specific stats
	protocolRegistry *ProtocolStatsRegistry // Registry of protocol stats providers
	voipProvider     *VoIPStatsProvider     // VoIP-specific stats provider
	selectedProtocol string                 // Currently selected protocol filter

	// Phase 6: TUI process metrics
	cpuTracker *CPUTracker // CPU usage history for sparkline
	tuiMetrics *TUIMetrics // Current TUI process metrics
}

// TUIMetrics holds the current TUI process resource usage.
type TUIMetrics struct {
	CPUPercent     float64 // CPU usage as percentage (0-100, -1 if unavailable)
	MemoryRSSBytes uint64  // Resident set size in bytes
}

// NewStatisticsView creates a new statistics view
func NewStatisticsView() StatisticsView {
	// Create protocol stats registry and register providers
	registry := NewProtocolStatsRegistry()
	voipProvider := NewVoIPStatsProvider()
	registry.Register(voipProvider)

	return StatisticsView{
		width:            80,
		height:           20,
		theme:            themes.Solarized(),
		stats:            nil,
		ready:            false,
		rateTracker:      DefaultRateTracker(),
		dropStats:        NewDropStats(),
		timeWindow:       TimeWindow1Min,
		startTime:        time.Now(),
		queueBar:         NewUtilizationBar(30),
		healthIndicator:  NewHealthIndicator(),
		currentSubView:   SubViewOverview,
		talkerSection:    TalkerSectionSources,
		selectedIndex:    0,
		maxTalkersShown:  10,
		distributedStats: NewDistributedStats(),
		protocolRegistry: registry,
		voipProvider:     voipProvider,
		selectedProtocol: "All",
		cpuTracker:       DefaultCPUTracker(),
		tuiMetrics:       &TUIMetrics{CPUPercent: -1},
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
	if s.protocolRegistry != nil {
		s.protocolRegistry.SetTheme(theme)
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

// UpdateTUIMetrics updates the TUI process resource metrics.
// Should be called periodically (e.g., every second) with metrics from sysmetrics.Collector.
func (s *StatisticsView) UpdateTUIMetrics(cpuPercent float64, memoryRSSBytes uint64) {
	if s.tuiMetrics == nil {
		s.tuiMetrics = &TUIMetrics{CPUPercent: -1}
	}
	s.tuiMetrics.CPUPercent = cpuPercent
	s.tuiMetrics.MemoryRSSBytes = memoryRSSBytes

	// Record CPU sample for sparkline
	if s.cpuTracker != nil {
		s.cpuTracker.Record(cpuPercent)
	}

	s.dirty = true
}

// GetTUIMetrics returns the current TUI process metrics.
func (s *StatisticsView) GetTUIMetrics() *TUIMetrics {
	return s.tuiMetrics
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

// GetDistributedStats returns the distributed fleet statistics.
func (s *StatisticsView) GetDistributedStats() *DistributedStats {
	return s.distributedStats
}

// UpdateDistributedStats updates the distributed stats from hunter/processor data.
// This is called when HunterStatusMsg is received.
func (s *StatisticsView) UpdateDistributedStats(hunters []HunterInfo, processors []ProcessorInfo) {
	if s.distributedStats == nil {
		s.distributedStats = NewDistributedStats()
	}

	ds := s.distributedStats

	// Reset counters
	ds.TotalProcessors = len(processors)
	ds.HealthyProcessors = 0
	ds.TotalHunters = 0
	ds.HealthyHunters = 0
	ds.WarningHunters = 0
	ds.ErrorHunters = 0
	ds.TotalPacketsCaptured = 0
	ds.TotalPacketsForwarded = 0
	ds.TotalPacketsDropped = 0
	ds.FleetMemoryRSS = 0
	ds.FleetMemoryLimit = 0

	var totalCPU float64
	var cpuCount int

	// Aggregate processor summaries
	ds.ProcessorSummaries = make([]ProcessorSummary, 0, len(processors))
	for _, proc := range processors {
		summary := ProcessorSummary{
			Address:     proc.Address,
			ProcessorID: proc.ProcessorID,
			HunterCount: len(proc.Hunters),
		}

		// Map processor status
		switch proc.ConnectionState {
		case ProcessorConnectionStateConnected:
			switch proc.Status {
			case 0: // PROCESSOR_HEALTHY
				summary.Status = "healthy"
				ds.HealthyProcessors++
			case 1: // PROCESSOR_WARNING
				summary.Status = "warning"
			case 2: // PROCESSOR_ERROR
				summary.Status = "error"
			default:
				summary.Status = "unknown"
			}
		case ProcessorConnectionStateDisconnected, ProcessorConnectionStateFailed:
			summary.Status = "disconnected"
		case ProcessorConnectionStateConnecting:
			summary.Status = "connecting"
		default:
			summary.Status = "unknown"
		}

		// Aggregate hunter stats for this processor
		var procCPU float64
		var procCPUCount int
		for _, hunter := range proc.Hunters {
			summary.TotalPackets += hunter.PacketsCaptured
			summary.TotalDropped += hunter.PacketsDropped
			summary.TotalMemoryRSS += hunter.MemoryRSSBytes
			summary.TotalMemoryLimit += hunter.MemoryLimitBytes
			if hunter.CPUPercent >= 0 {
				procCPU += hunter.CPUPercent
				procCPUCount++
			}
		}
		if procCPUCount > 0 {
			summary.AvgCPUPercent = procCPU / float64(procCPUCount)
		}

		ds.ProcessorSummaries = append(ds.ProcessorSummaries, summary)
	}

	// Aggregate hunter contributions
	ds.HunterContributions = make([]HunterContribution, 0, len(hunters))
	for _, hunter := range hunters {
		ds.TotalHunters++
		ds.TotalPacketsCaptured += hunter.PacketsCaptured
		ds.TotalPacketsForwarded += hunter.PacketsForwarded
		ds.TotalPacketsDropped += hunter.PacketsDropped
		ds.FleetMemoryRSS += hunter.MemoryRSSBytes
		ds.FleetMemoryLimit += hunter.MemoryLimitBytes

		if hunter.CPUPercent >= 0 {
			totalCPU += hunter.CPUPercent
			cpuCount++
		}

		// Count by status
		var statusStr string
		switch hunter.Status {
		case 0: // HUNTER_HEALTHY
			statusStr = "healthy"
			ds.HealthyHunters++
		case 1: // HUNTER_WARNING
			statusStr = "warning"
			ds.WarningHunters++
		case 2: // HUNTER_ERROR
			statusStr = "error"
			ds.ErrorHunters++
		default:
			statusStr = "unknown"
		}

		var dropRate float64
		if hunter.PacketsCaptured > 0 {
			dropRate = float64(hunter.PacketsDropped) / float64(hunter.PacketsCaptured) * 100
		}

		contrib := HunterContribution{
			ID:               hunter.ID,
			Hostname:         hunter.Hostname,
			ProcessorAddr:    hunter.ProcessorAddr,
			Status:           statusStr,
			PacketsCaptured:  hunter.PacketsCaptured,
			PacketsForwarded: hunter.PacketsForwarded,
			PacketsDropped:   hunter.PacketsDropped,
			DropRate:         dropRate,
			CPUPercent:       hunter.CPUPercent,
			MemoryRSSBytes:   hunter.MemoryRSSBytes,
			MemoryLimitBytes: hunter.MemoryLimitBytes,
		}
		ds.HunterContributions = append(ds.HunterContributions, contrib)
	}

	// Calculate contribution percentages
	if ds.TotalPacketsCaptured > 0 {
		for i := range ds.HunterContributions {
			ds.HunterContributions[i].Contribution = float64(ds.HunterContributions[i].PacketsCaptured) / float64(ds.TotalPacketsCaptured) * 100
		}
	}

	// Sort hunters by packets captured (descending)
	sort.Slice(ds.HunterContributions, func(i, j int) bool {
		return ds.HunterContributions[i].PacketsCaptured > ds.HunterContributions[j].PacketsCaptured
	})

	// Calculate fleet averages
	if cpuCount > 0 {
		ds.FleetCPUPercent = totalCPU / float64(cpuCount)
	}
	if ds.FleetMemoryLimit > 0 {
		ds.FleetMemoryPercent = float64(ds.FleetMemoryRSS) / float64(ds.FleetMemoryLimit) * 100
	}
	if ds.TotalPacketsCaptured > 0 {
		ds.OverallDropRate = float64(ds.TotalPacketsDropped) / float64(ds.TotalPacketsCaptured) * 100
	}

	ds.LastUpdate = time.Now()
	s.dirty = true
}

// HasDistributedData returns true if there is distributed data available.
func (s *StatisticsView) HasDistributedData() bool {
	return s.distributedStats != nil && s.distributedStats.TotalHunters > 0
}

// UpdateVoIPCalls updates the VoIP stats provider with current call data.
// This should be called whenever the call list changes.
func (s *StatisticsView) UpdateVoIPCalls(calls []Call) {
	if s.voipProvider != nil {
		s.voipProvider.UpdateCalls(calls)
		s.dirty = true
	}
}

// SetSelectedProtocol sets the currently selected protocol filter.
func (s *StatisticsView) SetSelectedProtocol(protocolName string) {
	s.selectedProtocol = protocolName
	s.dirty = true
}

// GetSelectedProtocol returns the currently selected protocol filter.
func (s *StatisticsView) GetSelectedProtocol() string {
	return s.selectedProtocol
}

// HasProtocolStats returns true if there are protocol-specific stats to show.
func (s *StatisticsView) HasProtocolStats() bool {
	if s.protocolRegistry == nil || s.selectedProtocol == "All" {
		return false
	}
	provider := s.protocolRegistry.Get(s.selectedProtocol)
	return provider != nil && provider.IsActive()
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

	// Section: TUI Process Metrics
	result.WriteString(s.renderTUIMetrics(titleStyle, labelStyle, valueStyle))
	result.WriteString("\n")

	// Section: Protocol Distribution
	result.WriteString(titleStyle.Render("🔌 Protocol Distribution"))
	result.WriteString("\n\n")

	result.WriteString(s.renderProtocolDistribution(5))
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

	// Section: Protocol-Specific Stats (if protocol filter is active)
	if s.HasProtocolStats() {
		result.WriteString(s.renderProtocolStats())
		result.WriteString("\n")
	}

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

	result.WriteString(s.renderProtocolDistribution(10))

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
	result.WriteString(hintStyle.Render("  (h/l or ←/→ to switch, Enter to filter)"))
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

	labelStyle := lipgloss.NewStyle().
		Foreground(s.theme.StatusBarFg).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(s.theme.StatusBarFg)

	dimStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	healthyStyle := lipgloss.NewStyle().
		Foreground(s.theme.SuccessColor).
		Bold(true)

	warningStyle := lipgloss.NewStyle().
		Foreground(s.theme.WarningColor).
		Bold(true)

	errorStyle := lipgloss.NewStyle().
		Foreground(s.theme.ErrorColor).
		Bold(true)

	result.WriteString(titleStyle.Render("🌐 Distributed Mode Statistics"))
	result.WriteString("\n\n")

	// Check if we have distributed data
	if s.distributedStats == nil || s.distributedStats.TotalHunters == 0 {
		result.WriteString(valueStyle.Render("  No distributed nodes connected.\n"))
		result.WriteString(valueStyle.Render("  Connect to a processor node to see:\n"))
		result.WriteString(dimStyle.Render("    • Fleet overview (hunters/processors)\n"))
		result.WriteString(dimStyle.Render("    • Combined throughput\n"))
		result.WriteString(dimStyle.Render("    • Per-hunter contribution\n"))
		result.WriteString(dimStyle.Render("    • Load distribution\n"))
		return result.String()
	}

	ds := s.distributedStats

	// Fleet Overview Section
	result.WriteString(titleStyle.Render("📊 Fleet Overview"))
	result.WriteString("\n\n")

	// Processors status
	result.WriteString(labelStyle.Render("Processors: "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%d total", ds.TotalProcessors)))
	if ds.HealthyProcessors > 0 {
		result.WriteString("  ")
		result.WriteString(healthyStyle.Render(fmt.Sprintf("✓ %d healthy", ds.HealthyProcessors)))
	}
	if ds.TotalProcessors-ds.HealthyProcessors > 0 {
		result.WriteString("  ")
		result.WriteString(warningStyle.Render(fmt.Sprintf("⚠ %d issues", ds.TotalProcessors-ds.HealthyProcessors)))
	}
	result.WriteString("\n")

	// Hunters status
	result.WriteString(labelStyle.Render("Hunters:    "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%d total", ds.TotalHunters)))
	if ds.HealthyHunters > 0 {
		result.WriteString("  ")
		result.WriteString(healthyStyle.Render(fmt.Sprintf("✓ %d healthy", ds.HealthyHunters)))
	}
	if ds.WarningHunters > 0 {
		result.WriteString("  ")
		result.WriteString(warningStyle.Render(fmt.Sprintf("⚠ %d warning", ds.WarningHunters)))
	}
	if ds.ErrorHunters > 0 {
		result.WriteString("  ")
		result.WriteString(errorStyle.Render(fmt.Sprintf("✗ %d error", ds.ErrorHunters)))
	}
	result.WriteString("\n\n")

	// Fleet Health Summary
	result.WriteString(s.renderFleetHealthSummary())
	result.WriteString("\n")

	// Combined Throughput Section
	result.WriteString(titleStyle.Render("📈 Combined Throughput"))
	result.WriteString("\n\n")

	result.WriteString(labelStyle.Render("Packets Captured:  "))
	result.WriteString(valueStyle.Render(formatNumber64(int64(ds.TotalPacketsCaptured))))
	result.WriteString("\n")

	result.WriteString(labelStyle.Render("Packets Forwarded: "))
	result.WriteString(valueStyle.Render(formatNumber64(int64(ds.TotalPacketsForwarded))))
	result.WriteString("\n")

	result.WriteString(labelStyle.Render("Packets Dropped:   "))
	result.WriteString(valueStyle.Render(formatNumber64(int64(ds.TotalPacketsDropped))))
	if ds.OverallDropRate > 0 {
		dropColor := s.theme.SuccessColor
		if ds.OverallDropRate > 1 {
			dropColor = s.theme.WarningColor
		}
		if ds.OverallDropRate > 5 {
			dropColor = s.theme.ErrorColor
		}
		dropStyle := lipgloss.NewStyle().Foreground(dropColor)
		result.WriteString(dropStyle.Render(fmt.Sprintf(" (%.2f%%)", ds.OverallDropRate)))
	}
	result.WriteString("\n\n")

	// Resource Usage
	result.WriteString(titleStyle.Render("💻 Fleet Resources"))
	result.WriteString("\n\n")

	result.WriteString(labelStyle.Render("Avg CPU Usage:     "))
	if ds.FleetCPUPercent >= 0 {
		cpuColor := s.theme.SuccessColor
		if ds.FleetCPUPercent > 70 {
			cpuColor = s.theme.WarningColor
		}
		if ds.FleetCPUPercent > 90 {
			cpuColor = s.theme.ErrorColor
		}
		cpuStyle := lipgloss.NewStyle().Foreground(cpuColor)
		result.WriteString(cpuStyle.Render(fmt.Sprintf("%.1f%%", ds.FleetCPUPercent)))
	} else {
		result.WriteString(dimStyle.Render("N/A"))
	}
	result.WriteString("\n")

	result.WriteString(labelStyle.Render("Total Memory RSS:  "))
	result.WriteString(valueStyle.Render(formatBytes(int64(ds.FleetMemoryRSS))))
	if ds.FleetMemoryLimit > 0 {
		memColor := s.theme.SuccessColor
		if ds.FleetMemoryPercent > 70 {
			memColor = s.theme.WarningColor
		}
		if ds.FleetMemoryPercent > 90 {
			memColor = s.theme.ErrorColor
		}
		memStyle := lipgloss.NewStyle().Foreground(memColor)
		result.WriteString(memStyle.Render(fmt.Sprintf(" (%.1f%% of %s)", ds.FleetMemoryPercent, formatBytes(int64(ds.FleetMemoryLimit)))))
	}
	result.WriteString("\n\n")

	// Load Distribution Section (horizontal bar chart)
	result.WriteString(titleStyle.Render("📊 Load Distribution"))
	result.WriteString("\n\n")
	result.WriteString(s.renderLoadDistribution())

	// Last update
	result.WriteString("\n")
	result.WriteString(dimStyle.Render(fmt.Sprintf("Last update: %s", ds.LastUpdate.Format("15:04:05"))))
	result.WriteString("\n")

	return result.String()
}

// renderFleetHealthSummary renders a health summary with color-coded indicators
func (s *StatisticsView) renderFleetHealthSummary() string {
	if s.distributedStats == nil {
		return ""
	}

	ds := s.distributedStats

	// Calculate overall fleet health
	var items []struct {
		Label string
		Level HealthLevel
	}

	// Drop rate health
	dropLevel := HealthFromRatio(ds.OverallDropRate/100, 0.01, 0.05, true)
	items = append(items, struct {
		Label string
		Level HealthLevel
	}{"Drops", dropLevel})

	// CPU health
	if ds.FleetCPUPercent >= 0 {
		cpuLevel := HealthFromRatio(ds.FleetCPUPercent/100, 0.7, 0.9, true)
		items = append(items, struct {
			Label string
			Level HealthLevel
		}{"CPU", cpuLevel})
	}

	// Memory health
	if ds.FleetMemoryPercent > 0 {
		memLevel := HealthFromRatio(ds.FleetMemoryPercent/100, 0.7, 0.9, true)
		items = append(items, struct {
			Label string
			Level HealthLevel
		}{"Memory", memLevel})
	}

	// Hunter health ratio
	if ds.TotalHunters > 0 {
		healthyRatio := float64(ds.HealthyHunters) / float64(ds.TotalHunters)
		hunterLevel := HealthFromRatio(healthyRatio, 0.9, 0.5, false) // Inverted: high healthy = good
		items = append(items, struct {
			Label string
			Level HealthLevel
		}{"Hunters", hunterLevel})
	}

	if len(items) > 0 {
		return RenderHealthSummary(s.theme, items)
	}
	return ""
}

// renderLoadDistribution renders a horizontal bar chart showing per-hunter contribution
func (s *StatisticsView) renderLoadDistribution() string {
	if s.distributedStats == nil || len(s.distributedStats.HunterContributions) == 0 {
		return "  No hunter data available\n"
	}

	var result strings.Builder
	ds := s.distributedStats

	// Show top 5 hunters by contribution
	maxHunters := 5
	if len(ds.HunterContributions) < maxHunters {
		maxHunters = len(ds.HunterContributions)
	}

	// Find max contribution for scaling
	maxContrib := 0.0
	for i := 0; i < maxHunters; i++ {
		if ds.HunterContributions[i].Contribution > maxContrib {
			maxContrib = ds.HunterContributions[i].Contribution
		}
	}
	if maxContrib < 1 {
		maxContrib = 100 // Avoid division by zero
	}

	barWidth := 30 // Width of the bar in characters
	labelWidth := 20

	for i := 0; i < maxHunters; i++ {
		contrib := ds.HunterContributions[i]

		// Truncate or pad hostname/ID
		label := contrib.Hostname
		if label == "" {
			label = contrib.ID
		}
		if len(label) > labelWidth-1 {
			label = label[:labelWidth-4] + "..."
		}

		// Status indicator
		statusIcon := "●"
		var statusStyle lipgloss.Style
		switch contrib.Status {
		case "healthy":
			statusStyle = lipgloss.NewStyle().Foreground(s.theme.SuccessColor)
		case "warning":
			statusStyle = lipgloss.NewStyle().Foreground(s.theme.WarningColor)
		case "error":
			statusStyle = lipgloss.NewStyle().Foreground(s.theme.ErrorColor)
		default:
			statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		}

		// Calculate bar length
		barLen := int(contrib.Contribution / maxContrib * float64(barWidth))
		if barLen < 1 && contrib.Contribution > 0 {
			barLen = 1
		}

		// Build the bar
		bar := strings.Repeat("█", barLen)
		empty := strings.Repeat("░", barWidth-barLen)

		barStyle := lipgloss.NewStyle().Foreground(s.theme.InfoColor)
		emptyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		labelStyle := lipgloss.NewStyle().Foreground(s.theme.StatusBarFg)
		pctStyle := lipgloss.NewStyle().Foreground(s.theme.StatusBarFg).Bold(true)

		result.WriteString("  ")
		result.WriteString(statusStyle.Render(statusIcon))
		result.WriteString(" ")
		result.WriteString(labelStyle.Render(fmt.Sprintf("%-*s", labelWidth, label)))
		result.WriteString(" ")
		result.WriteString(barStyle.Render(bar))
		result.WriteString(emptyStyle.Render(empty))
		result.WriteString(" ")
		result.WriteString(pctStyle.Render(fmt.Sprintf("%5.1f%%", contrib.Contribution)))
		result.WriteString("\n")
	}

	if len(ds.HunterContributions) > maxHunters {
		dimStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
		result.WriteString(dimStyle.Render(fmt.Sprintf("  ... and %d more hunters\n", len(ds.HunterContributions)-maxHunters)))
	}

	return result.String()
}

// getProtocolColor returns the theme color for a protocol
func (s *StatisticsView) getProtocolColor(protocol string) lipgloss.Color {
	switch protocol {
	case "TCP":
		return s.theme.TCPColor
	case "UDP":
		return s.theme.UDPColor
	case "SIP":
		return s.theme.SIPColor
	case "RTP":
		return s.theme.RTPColor
	case "DNS":
		return s.theme.DNSColor
	case "HTTP", "HTTPS", "HTTP2", "gRPC":
		return s.theme.HTTPColor
	case "TLS", "SSL":
		return s.theme.TLSColor
	case "SSH":
		return s.theme.SSHColor
	case "ICMP":
		return s.theme.ICMPColor
	case "ICMPv6":
		return s.theme.ICMPv6Color
	case "ARP":
		return s.theme.ARPColor
	case "OpenVPN", "WireGuard", "IKEv2", "IKEv1", "L2TP", "PPTP":
		return s.theme.VPNColor
	case "NTP":
		return s.theme.InfoColor
	default:
		return s.theme.Foreground
	}
}

// renderProtocolDistribution renders a horizontal bar chart showing protocol distribution
func (s *StatisticsView) renderProtocolDistribution(maxProtocols int) string {
	topProtocols := s.stats.ProtocolCounts.GetTopN(maxProtocols)
	if len(topProtocols) == 0 {
		return "  No protocol data available\n"
	}

	var result strings.Builder

	// Find max count for scaling
	maxCount := int64(0)
	for _, pc := range topProtocols {
		if pc.Count > maxCount {
			maxCount = pc.Count
		}
	}
	if maxCount < 1 {
		maxCount = 1 // Avoid division by zero
	}

	barWidth := 30
	labelWidth := 10

	emptyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	pctStyle := lipgloss.NewStyle().Foreground(s.theme.StatusBarFg).Bold(true)

	for _, pc := range topProtocols {
		// Get protocol-specific color
		protocolColor := s.getProtocolColor(pc.Key)
		barStyle := lipgloss.NewStyle().Foreground(protocolColor)
		labelStyle := lipgloss.NewStyle().Foreground(protocolColor)

		// Calculate bar length
		barLen := int(float64(pc.Count) / float64(maxCount) * float64(barWidth))
		if barLen < 1 && pc.Count > 0 {
			barLen = 1
		}

		// Build the bar
		bar := strings.Repeat("█", barLen)
		empty := strings.Repeat("░", barWidth-barLen)

		// Calculate percentage
		percentage := float64(pc.Count) / float64(s.stats.TotalPackets) * 100

		result.WriteString("  ")
		result.WriteString(labelStyle.Render(fmt.Sprintf("%-*s", labelWidth, pc.Key)))
		result.WriteString(" ")
		result.WriteString(barStyle.Render(bar))
		result.WriteString(emptyStyle.Render(empty))
		result.WriteString(" ")
		result.WriteString(pctStyle.Render(fmt.Sprintf("%5.1f%%", percentage)))
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

// renderTUIMetrics renders the TUI process CPU and memory metrics with sparkline.
func (s *StatisticsView) renderTUIMetrics(titleStyle, labelStyle, valueStyle lipgloss.Style) string {
	var result strings.Builder

	result.WriteString(titleStyle.Render("🖥 TUI Process"))
	result.WriteString("\n\n")

	if s.tuiMetrics == nil {
		result.WriteString("  No metrics available\n")
		return result.String()
	}

	// CPU percentage
	cpuStr := "N/A"
	if s.tuiMetrics.CPUPercent >= 0 {
		cpuStr = fmt.Sprintf("%.1f%%", s.tuiMetrics.CPUPercent)
	}

	// Memory RSS
	memStr := formatBytes(int64(s.tuiMetrics.MemoryRSSBytes))

	// Render metrics inline
	result.WriteString(labelStyle.Render("  CPU: "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%-8s", cpuStr)))
	result.WriteString(labelStyle.Render("  RAM: "))
	result.WriteString(valueStyle.Render(memStr))
	result.WriteString("\n\n")

	// Render CPU sparkline if we have enough samples
	if s.cpuTracker != nil && s.cpuTracker.SampleCount() > 2 {
		sparklineWidth := 30
		if s.width > 0 && s.width < 80 {
			sparklineWidth = s.width - 20
		}

		samples := s.cpuTracker.GetSamples(sparklineWidth)
		if len(samples) > 0 {
			sparkline := RenderCPUSparkline(samples, sparklineWidth, 2, s.theme)
			result.WriteString(sparkline)
			result.WriteString("\n")
		}
	}

	return result.String()
}

// renderProtocolStats renders protocol-specific statistics from the active provider.
func (s *StatisticsView) renderProtocolStats() string {
	if s.protocolRegistry == nil || s.selectedProtocol == "All" {
		return ""
	}

	provider := s.protocolRegistry.Get(s.selectedProtocol)
	if provider == nil || !provider.IsActive() {
		return ""
	}

	return provider.Render(s.width, s.theme)
}
