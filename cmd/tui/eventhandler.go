//go:build tui || all
// +build tui all

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// TUIEventHandler adapts types.EventHandler to Bubbletea's tea.Program
// This bridges the gap between the infrastructure layer (remotecapture)
// and the presentation layer (TUI) without creating a dependency violation.
type TUIEventHandler struct {
	program *tea.Program
}

// NewTUIEventHandler creates a new TUI event handler
func NewTUIEventHandler(program *tea.Program) *TUIEventHandler {
	return &TUIEventHandler{program: program}
}

// OnPacketBatch sends PacketBatchMsg to TUI
func (h *TUIEventHandler) OnPacketBatch(packets []types.PacketDisplay) {
	if h.program != nil {
		// Convert to components.PacketDisplay (which is now an alias)
		// and send as PacketBatchMsg
		h.program.Send(PacketBatchMsg{Packets: packets})
	}
}

// OnHunterStatus sends HunterStatusMsg to TUI
func (h *TUIEventHandler) OnHunterStatus(hunters []types.HunterInfo, processorID string, processorStatus management.ProcessorStatus) {
	if h.program != nil {
		// Convert to components.HunterInfo (which is now an alias)
		// and send as HunterStatusMsg
		h.program.Send(HunterStatusMsg{
			Hunters:         hunters,
			ProcessorID:     processorID,
			ProcessorStatus: processorStatus,
		})
	}
}

// OnCallUpdate sends CallUpdateMsg to TUI
func (h *TUIEventHandler) OnCallUpdate(calls []types.CallInfo) {
	if h.program != nil {
		h.program.Send(CallUpdateMsg{Calls: calls})
	}
}

// OnCorrelatedCallUpdate sends CorrelatedCallUpdateMsg to TUI
func (h *TUIEventHandler) OnCorrelatedCallUpdate(correlatedCalls []types.CorrelatedCallInfo) {
	if h.program != nil {
		h.program.Send(CorrelatedCallUpdateMsg{CorrelatedCalls: correlatedCalls})
	}
}

// OnDisconnect sends ProcessorDisconnectedMsg to TUI
func (h *TUIEventHandler) OnDisconnect(address string, err error) {
	if h.program != nil {
		h.program.Send(ProcessorDisconnectedMsg{
			Address: address,
			Error:   err,
		})
	}
}

// PacketBatchMsg is sent when multiple packets are captured
type PacketBatchMsg struct {
	Packets []components.PacketDisplay
}

// HunterStatusMsg is sent with hunter status updates from remote processor
type HunterStatusMsg struct {
	Hunters         []components.HunterInfo
	ProcessorID     string
	ProcessorStatus management.ProcessorStatus
}

// CallUpdateMsg is sent with updated call state
type CallUpdateMsg struct {
	Calls []types.CallInfo
}

// CorrelatedCallUpdateMsg is sent with correlated call updates
type CorrelatedCallUpdateMsg struct {
	CorrelatedCalls []types.CorrelatedCallInfo
}

// ProcessorDisconnectedMsg is sent when a processor connection is lost
type ProcessorDisconnectedMsg struct {
	Address string
	Error   error
}
