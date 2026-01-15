//go:build tui || all

package tui

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// getPacketsInOrder returns packets from the circular buffer in chronological order
func (m *Model) getPacketsInOrder() []components.PacketDisplay {
	return m.packetStore.GetPacketsInOrder()
}

// updateDetailsPanel updates the details panel with the currently selected packet
func (m *Model) updateDetailsPanel() {
	// Use the packet list that's already loaded in the PacketList component
	// This ensures we're working with the exact same list that's displayed
	packets := m.uiState.PacketList.GetPackets()

	if len(packets) == 0 {
		m.uiState.DetailsPanel.SetPacket(nil)
		return
	}

	selectedIdx := m.uiState.PacketList.GetCursor()
	if selectedIdx >= 0 && selectedIdx < len(packets) {
		pkt := packets[selectedIdx]
		m.uiState.DetailsPanel.SetPacket(&pkt)
	} else {
		m.uiState.DetailsPanel.SetPacket(nil)
	}
}

// updateStatistics updates statistics with a new packet
func (m *Model) updateStatistics(pkt components.PacketDisplay) {
	// Update protocol counts (bounded - evicts lowest count when full)
	m.statistics.ProtocolCounts.Increment(pkt.Protocol)

	// Update source counts (bounded - evicts lowest count when full)
	m.statistics.SourceCounts.Increment(pkt.SrcIP)

	// Update destination counts (bounded - evicts lowest count when full)
	m.statistics.DestCounts.Increment(pkt.DstIP)

	// Update total bytes and packets
	m.statistics.TotalBytes += int64(pkt.Length)
	m.statistics.TotalPackets++

	// Update min/max packet size
	if pkt.Length < m.statistics.MinPacketSize {
		m.statistics.MinPacketSize = pkt.Length
	}
	if pkt.Length > m.statistics.MaxPacketSize {
		m.statistics.MaxPacketSize = pkt.Length
	}

	// Update statistics view with new data
	m.uiState.StatisticsView.SetStatistics(m.statistics)

	// Update bridge statistics
	m.updateBridgeStats()
}

// updateBridgeStats updates the bridge statistics in the statistics view
func (m *Model) updateBridgeStats() {
	stats := GetBridgeStats()
	m.uiState.StatisticsView.SetBridgeStats(&components.BridgeStatistics{
		PacketsReceived:  stats.PacketsReceived,
		PacketsDisplayed: stats.PacketsDisplayed,
		BatchesSent:      stats.BatchesSent,
		BatchesDropped:   stats.BatchesDropped,
		QueueDepth:       stats.QueueDepth,
		MaxQueueDepth:    stats.MaxQueueDepth,
		SamplingRatio:    stats.SamplingRatio,
	})
}

// generateDefaultFilename creates a timestamp-based filename for saving captures
func (m *Model) generateDefaultFilename() string {
	return fmt.Sprintf("capture_%s.pcap", time.Now().Format("20060102_150405"))
}

// updatePacketListIncremental updates the packet list using incremental sync.
// This is more efficient than full updates for normal packet flow.
// Falls back to full update when filter changes or buffer wraps significantly.
func (m *Model) updatePacketListIncremental() {
	hasFilter := m.packetStore.HasFilter()

	// Detect filter state change (requires full refresh)
	filterStateChanged := hasFilter != m.lastFilterState
	m.lastFilterState = hasFilter

	if filterStateChanged {
		// Filter was added or removed - do full refresh
		m.doFullPacketListRefresh(hasFilter)
		return
	}

	if !hasFilter {
		// Unfiltered mode - use incremental sync based on TotalPackets
		m.updatePacketListUnfiltered()
	} else {
		// Filtered mode - use incremental sync based on filtered count
		m.updatePacketListFiltered()
	}
}

// updatePacketListUnfiltered handles incremental updates in unfiltered mode
func (m *Model) updatePacketListUnfiltered() {
	newPackets, newTotal, needsFullRefresh := m.packetStore.GetNewPackets(m.lastSyncedTotal)

	if needsFullRefresh {
		// Buffer wrapped significantly - do full refresh
		m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
		m.lastSyncedTotal = newTotal
		return
	}

	if len(newPackets) == 0 {
		// No new packets
		return
	}

	// Check if we need to trim old packets (buffer at capacity)
	maxPackets := m.packetStore.MaxPackets
	currentListLen := m.uiState.PacketList.Len()
	newListLen := currentListLen + len(newPackets)

	if newListLen > maxPackets {
		// Need to trim old packets from the front
		trimCount := newListLen - maxPackets
		m.uiState.PacketList.TrimOldPackets(trimCount)
	}

	// Append new packets
	m.uiState.PacketList.AppendPackets(newPackets)
	m.lastSyncedTotal = newTotal
}

// updatePacketListFiltered handles incremental updates in filtered mode
func (m *Model) updatePacketListFiltered() {
	newPackets, newCount, needsFullRefresh := m.packetStore.GetNewFilteredPackets(m.lastSyncedFilteredCount)

	if needsFullRefresh {
		// Significant trimming occurred - do full refresh
		m.uiState.PacketList.SetPackets(m.packetStore.GetFilteredPackets())
		m.lastSyncedFilteredCount = newCount
		return
	}

	if len(newPackets) == 0 {
		// No new filtered packets
		return
	}

	// Check if we need to trim old packets (buffer at capacity)
	maxPackets := m.packetStore.MaxPackets
	currentListLen := m.uiState.PacketList.Len()
	newListLen := currentListLen + len(newPackets)

	if newListLen > maxPackets {
		// Need to trim old packets from the front
		trimCount := newListLen - maxPackets
		m.uiState.PacketList.TrimOldPackets(trimCount)
	}

	// Append new filtered packets
	m.uiState.PacketList.AppendPackets(newPackets)
	m.lastSyncedFilteredCount = newCount
}

// doFullPacketListRefresh performs a full packet list refresh
func (m *Model) doFullPacketListRefresh(hasFilter bool) {
	if !hasFilter {
		m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
		_, _, total, _ := m.packetStore.GetBufferInfo()
		m.lastSyncedTotal = total
		m.lastSyncedFilteredCount = 0
	} else {
		m.uiState.PacketList.SetPackets(m.packetStore.GetFilteredPackets())
		m.lastSyncedFilteredCount = m.packetStore.FilteredCount()
		m.lastSyncedTotal = 0
	}
}
