package types

import (
	"time"

	"github.com/endorses/lippycat/api/gen/management"
)

// EventHandler defines the interface for receiving remote capture events.
// This allows remotecapture to be decoupled from TUI-specific implementations.
type EventHandler interface {
	// OnPacketBatch is called when a batch of packets is received
	OnPacketBatch(packets []PacketDisplay)

	// OnHunterStatus is called when hunter status is updated
	OnHunterStatus(hunters []HunterInfo, processorID string, processorStatus management.ProcessorStatus)

	// OnCallUpdate is called when call state is updated
	OnCallUpdate(calls []CallInfo)

	// OnDisconnect is called when connection is lost
	OnDisconnect(address string, err error)
}

// CallInfo represents a VoIP call for display
type CallInfo struct {
	CallID      string
	From        string
	To          string
	State       string // "NEW", "RINGING", "ACTIVE", "ENDED", "FAILED"
	StartTime   time.Time
	EndTime     time.Time
	Duration    time.Duration
	Codec       string
	PacketCount int
	PacketLoss  float64
	Jitter      float64
	MOS         float64 // Mean Opinion Score
	NodeID      string  // Processor or "Local"
	Hunters     []string
}

// NoopEventHandler is a no-op implementation of EventHandler for testing
type NoopEventHandler struct{}

func (n *NoopEventHandler) OnPacketBatch(packets []PacketDisplay) {}
func (n *NoopEventHandler) OnHunterStatus(hunters []HunterInfo, processorID string, processorStatus management.ProcessorStatus) {
}
func (n *NoopEventHandler) OnCallUpdate(calls []CallInfo)          {}
func (n *NoopEventHandler) OnDisconnect(address string, err error) {}
