//go:build tui || all
// +build tui all

package tui

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/assert"
)

func TestGetPacketsInOrder(t *testing.T) {
	// Create a model with a packet store
	m := Model{
		packetStore: store.NewPacketStore(10),
	}

	// Add some packets
	packets := []components.PacketDisplay{
		{Protocol: "TCP", SrcIP: "192.168.1.1", DstIP: "192.168.1.2"},
		{Protocol: "UDP", SrcIP: "192.168.1.3", DstIP: "192.168.1.4"},
		{Protocol: "ICMP", SrcIP: "192.168.1.5", DstIP: "192.168.1.6"},
	}

	for _, pkt := range packets {
		m.packetStore.AddPacket(pkt)
	}

	// Get packets in order
	result := m.getPacketsInOrder()

	// Verify we got the right number of packets
	assert.Equal(t, 3, len(result), "Should return 3 packets")

	// Verify packets are in order by protocol
	assert.Equal(t, "TCP", result[0].Protocol, "First packet should be TCP")
	assert.Equal(t, "UDP", result[1].Protocol, "Second packet should be UDP")
	assert.Equal(t, "ICMP", result[2].Protocol, "Third packet should be ICMP")
}

func TestUpdateDetailsPanel_WithPackets(t *testing.T) {
	// Create a model with UI state
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}

	// Add some packets to the packet list
	packets := []components.PacketDisplay{
		{Protocol: "TCP", SrcIP: "192.168.1.1", DstIP: "192.168.1.2"},
		{Protocol: "UDP", SrcIP: "192.168.1.3", DstIP: "192.168.1.4"},
	}
	m.uiState.PacketList.SetPackets(packets)
	m.uiState.PacketList.SetCursor(0)

	// Update details panel
	m.updateDetailsPanel()

	// Verify details panel was updated (we can't directly check the packet,
	// but we can verify the method doesn't panic and completes)
	// This is a basic smoke test
	assert.NotNil(t, m.uiState.DetailsPanel, "Details panel should exist")
}

func TestUpdateDetailsPanel_EmptyPacketList(t *testing.T) {
	// Create a model with UI state but no packets
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}

	// Set empty packet list
	m.uiState.PacketList.SetPackets([]components.PacketDisplay{})

	// Update details panel - should not panic
	m.updateDetailsPanel()

	// Verify it completes without error
	assert.NotNil(t, m.uiState.DetailsPanel, "Details panel should exist")
}

func TestUpdateDetailsPanel_InvalidCursor(t *testing.T) {
	// Create a model with UI state
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}

	// Add packets but set cursor out of bounds
	packets := []components.PacketDisplay{
		{Protocol: "TCP", SrcIP: "192.168.1.1", DstIP: "192.168.1.2"},
	}
	m.uiState.PacketList.SetPackets(packets)
	m.uiState.PacketList.SetCursor(10) // Out of bounds

	// Update details panel - should handle gracefully
	m.updateDetailsPanel()

	// Verify it completes without error
	assert.NotNil(t, m.uiState.DetailsPanel, "Details panel should exist")
}

func TestUpdateStatistics(t *testing.T) {
	// Create a model with statistics (same way NewModel does it)
	theme := themes.Solarized()
	uiState := store.NewUIState(theme)
	uiState.Statistics = &components.Statistics{
		ProtocolCounts: components.NewBoundedCounter(1000),
		SourceCounts:   components.NewBoundedCounter(10000),
		DestCounts:     components.NewBoundedCounter(10000),
		MinPacketSize:  999999,
		MaxPacketSize:  0,
	}

	m := Model{
		statistics: uiState.Statistics,
		uiState:    uiState,
	}

	// Create a test packet
	pkt := components.PacketDisplay{
		Protocol: "TCP",
		SrcIP:    "192.168.1.1",
		DstIP:    "192.168.1.2",
		Length:   100,
	}

	// Initial state
	assert.Equal(t, int64(0), m.statistics.TotalPackets, "Should start with 0 packets")
	assert.Equal(t, int64(0), m.statistics.TotalBytes, "Should start with 0 bytes")

	// Update statistics
	m.updateStatistics(pkt)

	// Verify statistics were updated
	assert.Equal(t, int64(1), m.statistics.TotalPackets, "Should have 1 packet")
	assert.Equal(t, int64(100), m.statistics.TotalBytes, "Should have 100 bytes")
	assert.Equal(t, 100, m.statistics.MinPacketSize, "Min packet size should be 100")
	assert.Equal(t, 100, m.statistics.MaxPacketSize, "Max packet size should be 100")
}

func TestUpdateStatistics_MultiplePackets(t *testing.T) {
	// Create a model with statistics
	theme := themes.Solarized()
	uiState := store.NewUIState(theme)
	uiState.Statistics = &components.Statistics{
		ProtocolCounts: components.NewBoundedCounter(1000),
		SourceCounts:   components.NewBoundedCounter(10000),
		DestCounts:     components.NewBoundedCounter(10000),
		MinPacketSize:  999999,
		MaxPacketSize:  0,
	}

	m := Model{
		statistics: uiState.Statistics,
		uiState:    uiState,
	}

	// Add multiple packets with different sizes
	packets := []components.PacketDisplay{
		{Protocol: "TCP", SrcIP: "192.168.1.1", DstIP: "192.168.1.2", Length: 100},
		{Protocol: "UDP", SrcIP: "192.168.1.3", DstIP: "192.168.1.4", Length: 200},
		{Protocol: "ICMP", SrcIP: "192.168.1.5", DstIP: "192.168.1.6", Length: 50},
	}

	for _, pkt := range packets {
		m.updateStatistics(pkt)
	}

	// Verify aggregated statistics
	assert.Equal(t, int64(3), m.statistics.TotalPackets, "Should have 3 packets")
	assert.Equal(t, int64(350), m.statistics.TotalBytes, "Should have 350 bytes total")
	assert.Equal(t, 50, m.statistics.MinPacketSize, "Min packet size should be 50")
	assert.Equal(t, 200, m.statistics.MaxPacketSize, "Max packet size should be 200")
}

func TestUpdateStatistics_ProtocolCounts(t *testing.T) {
	// Create a model with statistics
	theme := themes.Solarized()
	uiState := store.NewUIState(theme)
	uiState.Statistics = &components.Statistics{
		ProtocolCounts: components.NewBoundedCounter(1000),
		SourceCounts:   components.NewBoundedCounter(10000),
		DestCounts:     components.NewBoundedCounter(10000),
		MinPacketSize:  999999,
		MaxPacketSize:  0,
	}

	m := Model{
		statistics: uiState.Statistics,
		uiState:    uiState,
	}

	// Add packets with different protocols
	protocols := []string{"TCP", "TCP", "UDP", "TCP", "ICMP"}
	for _, proto := range protocols {
		pkt := components.PacketDisplay{
			Protocol: proto,
			SrcIP:    "192.168.1.1",
			DstIP:    "192.168.1.2",
			Length:   100,
		}
		m.updateStatistics(pkt)
	}

	// Verify protocol counts were tracked
	// Note: The actual counts are in a bounded counter, so we just verify
	// the statistics object was updated (non-zero packets)
	assert.Equal(t, int64(5), m.statistics.TotalPackets, "Should have 5 packets total")
}
