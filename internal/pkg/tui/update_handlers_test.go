//go:build tui || all

package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/assert"
)

func TestHandleWindowSizeMsg(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}
	// Initialize SettingsView (required for SetSize)
	m.uiState.SettingsView = components.NewSettingsView("", 100, false, "", "")

	// Test window resize
	msg := tea.WindowSizeMsg{
		Width:  100,
		Height: 50,
	}

	updatedModel, _ := m.handleWindowSizeMsg(msg)

	assert.Equal(t, 100, updatedModel.uiState.Width, "Width should be updated")
	assert.Equal(t, 50, updatedModel.uiState.Height, "Height should be updated")
}

func TestHandleTickMsg_WhenPaused(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState:     store.NewUIState(theme),
		packetStore: store.NewPacketStore(100),
	}
	m.uiState.Paused = true
	m.uiState.Capturing = true

	updatedModel, cmd := m.handleTickMsg(TickMsg{})

	// When paused, should continue slow ticking to update TUI metrics (CPU chart)
	assert.NotNil(t, cmd, "Should schedule slow tick when paused to update TUI metrics")
	assert.Equal(t, true, updatedModel.uiState.Paused, "Model should remain paused")
}

func TestHandleTickMsg_WhenActive(t *testing.T) {
	// Clear any leftover state from previous tests
	ClearPendingPackets()

	theme := themes.Solarized()
	uiState := store.NewUIState(theme)
	m := Model{
		uiState:     uiState,
		packetStore: store.NewPacketStore(100),
		statistics:  uiState.Statistics,
	}
	m.uiState.Paused = false
	m.uiState.Capturing = true
	m.uiState.NeedsUIUpdate = false

	updatedModel, cmd := m.handleTickMsg(TickMsg{})

	// When active, tick should schedule next tick
	assert.NotNil(t, cmd, "Should schedule next tick when active")
	assert.Equal(t, false, updatedModel.uiState.Paused, "Model should remain unpaused")
}

func TestHandleUpdateBufferSizeMsg(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState:     store.NewUIState(theme),
		packetStore: store.NewPacketStore(100),
	}
	// Initialize SettingsView (required for SaveBufferSize)
	m.uiState.SettingsView = components.NewSettingsView("", 100, false, "", "")

	// Add some packets
	for i := 0; i < 10; i++ {
		m.packetStore.AddPacket(components.PacketDisplay{
			Protocol: "TCP",
			SrcIP:    "192.168.1.1",
			DstIP:    "192.168.1.2",
		})
	}

	msg := components.UpdateBufferSizeMsg{Size: 200}
	updatedModel, _ := m.handleUpdateBufferSizeMsg(msg)

	// Verify buffer was resized (can't directly check size, but verify no panic)
	assert.NotNil(t, updatedModel.packetStore, "Packet store should still exist")
}

func TestHandleAddNodeMsg_NewProcessor(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState:       store.NewUIState(theme),
		connectionMgr: store.NewConnectionManager(),
	}

	msg := components.AddNodeMsg{Address: "processor1:55555"}
	updatedModel, cmd := m.handleAddNodeMsg(msg)

	// Should add processor and trigger connection
	assert.Contains(t, updatedModel.connectionMgr.Processors, "processor1:55555",
		"Processor should be added to connection manager")
	assert.NotNil(t, cmd, "Should return reconnect command")
}

func TestHandleAddNodeMsg_DuplicateProcessor(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState:       store.NewUIState(theme),
		connectionMgr: store.NewConnectionManager(),
	}

	// Add processor first time
	m.connectionMgr.Processors["processor1:55555"] = &store.ProcessorConnection{
		Address: "processor1:55555",
		State:   store.ProcessorStateConnected,
	}

	// Try to add same processor again
	msg := components.AddNodeMsg{Address: "processor1:55555"}
	_, cmd := m.handleAddNodeMsg(msg)

	// Should show warning toast, not add duplicate
	assert.NotNil(t, cmd, "Should return toast command")
}

func TestHandleNodesLoadedMsg(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}

	msg := NodesLoadedMsg{
		NodeCount: 3,
		FilePath:  "/path/to/nodes.yaml",
	}
	_, cmd := m.handleNodesLoadedMsg(msg)

	// Should show success toast
	assert.NotNil(t, cmd, "Should return toast command")
}

func TestHandleNodesLoadFailedMsg(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}

	msg := NodesLoadFailedMsg{
		Error:    assert.AnError,
		FilePath: "/path/to/nodes.yaml",
	}
	_, cmd := m.handleNodesLoadFailedMsg(msg)

	// Should show error toast
	assert.NotNil(t, cmd, "Should return toast command")
}

func TestHandleProtocolSelectedMsg_AllProtocol(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState:     store.NewUIState(theme),
		packetStore: store.NewPacketStore(100),
	}

	// Add some packets
	for i := 0; i < 5; i++ {
		m.packetStore.AddPacket(components.PacketDisplay{
			Protocol: "TCP",
		})
	}

	// Apply "All" filter (should clear filters)
	msg := components.ProtocolSelectedMsg{
		Protocol: components.Protocol{
			Name:      "All",
			BPFFilter: "",
		},
	}
	updatedModel, cmd := m.handleProtocolSelectedMsg(msg)

	assert.Equal(t, "All", updatedModel.uiState.SelectedProtocol.Name,
		"Selected protocol should be 'All'")
	assert.NotNil(t, cmd, "Should return toast command")
}

func TestHandleProtocolSelectedMsg_VoIPProtocol(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState:     store.NewUIState(theme),
		packetStore: store.NewPacketStore(100),
	}

	// Select VoIP protocol (should switch to calls view)
	msg := components.ProtocolSelectedMsg{
		Protocol: components.Protocol{
			Name:      "VoIP (SIP/RTP)",
			BPFFilter: "udp port 5060",
		},
	}
	updatedModel, _ := m.handleProtocolSelectedMsg(msg)

	assert.Equal(t, "calls", updatedModel.uiState.ViewMode,
		"Should switch to calls view for VoIP protocol")
}

func TestHandleConfirmDialogResult_Confirmed(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState:         store.NewUIState(theme),
		packetStore:     store.NewPacketStore(100),
		pendingSavePath: "/tmp/test.pcap",
		statistics:      &components.Statistics{},
	}

	msg := components.ConfirmDialogResult{Confirmed: true}
	updatedModel, cmd := m.handleConfirmDialogResult(msg)

	// Should clear pending path and proceed with save
	assert.Equal(t, "", updatedModel.pendingSavePath,
		"Pending save path should be cleared")
	assert.NotNil(t, cmd, "Should return save command")
}

func TestHandleConfirmDialogResult_Cancelled(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState:         store.NewUIState(theme),
		packetStore:     store.NewPacketStore(100),
		pendingSavePath: "/tmp/test.pcap",
	}

	msg := components.ConfirmDialogResult{Confirmed: false}
	updatedModel, cmd := m.handleConfirmDialogResult(msg)

	// Should clear pending path and do nothing
	assert.Equal(t, "", updatedModel.pendingSavePath,
		"Pending save path should be cleared")
	assert.Nil(t, cmd, "Should not return any command")
}

func TestHandleSaveCompleteMsg_Success(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}
	m.uiState.SaveInProgress = true

	msg := SaveCompleteMsg{
		Success:      true,
		Path:         "/tmp/test.pcap",
		PacketsSaved: 100,
		Streaming:    false,
	}
	updatedModel, cmd := m.handleSaveCompleteMsg(msg)

	// Should clear save in progress and show success toast
	assert.False(t, updatedModel.uiState.SaveInProgress,
		"Save in progress should be cleared")
	assert.NotNil(t, cmd, "Should return toast command")
}

func TestHandleSaveCompleteMsg_Failure(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}
	m.uiState.SaveInProgress = true

	msg := SaveCompleteMsg{
		Success: false,
		Path:    "/tmp/test.pcap",
		Error:   assert.AnError,
	}
	updatedModel, cmd := m.handleSaveCompleteMsg(msg)

	// Should clear save in progress and show error toast
	assert.False(t, updatedModel.uiState.SaveInProgress,
		"Save in progress should be cleared")
	assert.NotNil(t, cmd, "Should return toast command")
}

func TestHandleFilterOperationResultMsg_Success(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}

	msg := components.FilterOperationResultMsg{
		Success:       true,
		Operation:     "create",
		FilterPattern: "tcp port 80",
	}
	_, cmd := m.handleFilterOperationResultMsg(msg)

	// Should show success toast
	assert.NotNil(t, cmd, "Should return toast command")
}

func TestHandleFilterOperationResultMsg_Failure(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}

	msg := components.FilterOperationResultMsg{
		Success:       false,
		Operation:     "create",
		FilterPattern: "tcp port 80",
		Error:         "invalid filter",
	}
	_, cmd := m.handleFilterOperationResultMsg(msg)

	// Failure returns toast command with error message
	assert.NotNil(t, cmd, "Should return toast command on failure")
}

func TestHandleHuntersLoadedMsg(t *testing.T) {
	theme := themes.Solarized()
	m := Model{
		uiState: store.NewUIState(theme),
	}

	hunters := []components.HunterSelectorItem{
		{HunterID: "hunter1", Hostname: "host1"},
		{HunterID: "hunter2", Hostname: "host2"},
	}

	msg := components.HuntersLoadedMsg{
		ProcessorAddr: "processor1:55555",
		Hunters:       hunters,
	}
	updatedModel, cmd := m.handleHuntersLoadedMsg(msg)

	// Should update hunter selector (verify no panic)
	assert.NotNil(t, updatedModel.uiState.HunterSelector,
		"Hunter selector should exist")
	assert.Nil(t, cmd, "Should not return any command")
}
