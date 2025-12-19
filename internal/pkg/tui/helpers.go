//go:build tui || all
// +build tui all

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
}

// generateDefaultFilename creates a timestamp-based filename for saving captures
func (m *Model) generateDefaultFilename() string {
	return fmt.Sprintf("capture_%s.pcap", time.Now().Format("20060102_150405"))
}
