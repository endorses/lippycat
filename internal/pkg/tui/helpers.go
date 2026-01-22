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
		RecentDropRate:   stats.RecentDropRate,
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
	newPackets, newTotal, needsFullRefresh := m.packetStore.GetNewFilteredPackets(m.lastSyncedFilteredCount)

	if needsFullRefresh {
		// Buffer wrapped significantly - do full refresh
		m.uiState.PacketList.SetPackets(m.packetStore.GetFilteredPackets())
		m.lastSyncedFilteredCount = newTotal
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
	m.lastSyncedFilteredCount = newTotal
}

// processPendingPackets processes packets pulled from the pending buffer.
// This is the core of the pull-based architecture - TUI pulls when ready.
func (m *Model) processPendingPackets(packets []components.PacketDisplay) {
	// Ensure call aggregator is initialized for VoIP tracking (lazy initialization)
	// This is the main packet processing path for live/offline capture
	m.ensureCallAggregator()

	// Filter packets by capture mode and set NodeID
	filteredPackets := make([]components.PacketDisplay, 0, len(packets))
	for i := range packets {
		packet := &packets[i]

		// Set NodeID to "Local" if not already set (for local/offline capture)
		if packet.NodeID == "" {
			packet.NodeID = "Local"
		}

		// Only process packets that match current capture mode
		if m.captureMode == components.CaptureModeRemote {
			if packet.NodeID == "Local" {
				continue
			}
		} else {
			if packet.NodeID != "Local" {
				continue
			}
		}

		filteredPackets = append(filteredPackets, *packet)
	}

	if len(filteredPackets) == 0 {
		return
	}

	// Add packets to store in batch (single lock acquisition)
	m.packetStore.AddPacketBatch(filteredPackets)

	// Update statistics for all packets in batch (single view update at the end)
	for i := range filteredPackets {
		pkt := filteredPackets[i]

		// Update counters without triggering view rebuild
		m.statistics.ProtocolCounts.Increment(pkt.Protocol)
		m.statistics.SourceCounts.Increment(pkt.SrcIP)
		m.statistics.DestCounts.Increment(pkt.DstIP)
		m.statistics.TotalBytes += int64(pkt.Length)
		m.statistics.TotalPackets++
		if pkt.Length < m.statistics.MinPacketSize {
			m.statistics.MinPacketSize = pkt.Length
		}
		if pkt.Length > m.statistics.MaxPacketSize {
			m.statistics.MaxPacketSize = pkt.Length
		}

		// Write to streaming save if active (must be synchronous)
		if m.activeWriter != nil {
			_ = m.activeWriter.WritePacket(pkt)
		}
	}

	// Update statistics view ONCE after processing entire batch
	m.uiState.StatisticsView.SetStatistics(m.statistics)
	m.updateBridgeStats()

	// Process VoIP packets for call aggregation
	// For offline mode: process synchronously to ensure all packets are handled
	// For live mode: use background processor (non-blocking, may drop under load)
	if m.captureMode == components.CaptureModeOffline {
		// Synchronous processing for offline mode - ensures reliable call tracking
		callAgg := m.offlineCallAggregator
		if callAgg != nil {
			for i := range filteredPackets {
				callAgg.ProcessPacket(&filteredPackets[i])
			}
		}
	} else if m.backgroundProcessor != nil && len(filteredPackets) > 0 {
		// Async processing for live mode - non-blocking, acceptable to drop under load
		linkType := filteredPackets[0].LinkType
		m.backgroundProcessor.SubmitBatch(filteredPackets, linkType)
	}

	// Note: Packet list and details panel are updated in handleTickMsg
	// after all pending packets are processed. This keeps the logic simple
	// and ensures consistent display.
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
		_, _, _, matchedPackets := m.packetStore.GetBufferInfo()
		m.lastSyncedFilteredCount = matchedPackets
		m.lastSyncedTotal = 0
	}
}
