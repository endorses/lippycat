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

	// OnCorrelatedCallUpdate is called when correlated call data is updated
	OnCorrelatedCallUpdate(correlatedCalls []CorrelatedCallInfo)

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

// CorrelatedCallInfo represents a correlated call across multiple hops/hunters
type CorrelatedCallInfo struct {
	CorrelationID string
	TagPair       [2]string // Normalized [tag1, tag2]
	FromUser      string
	ToUser        string
	Legs          []CallLegInfo
	StartTime     time.Time
	LastSeen      time.Time
	State         string // "TRYING", "RINGING", "ESTABLISHED", "ENDED"
}

// CallLegInfo represents one leg of a multi-hop call
type CallLegInfo struct {
	CallID       string
	HunterID     string
	SrcIP        string
	DstIP        string
	Method       string
	ResponseCode uint32
	PacketCount  int
	StartTime    time.Time
	LastSeen     time.Time
}

// NoopEventHandler is a no-op implementation of EventHandler for testing
type NoopEventHandler struct{}

func (n *NoopEventHandler) OnPacketBatch(packets []PacketDisplay) {}
func (n *NoopEventHandler) OnHunterStatus(hunters []HunterInfo, processorID string, processorStatus management.ProcessorStatus) {
}
func (n *NoopEventHandler) OnCallUpdate(calls []CallInfo)                               {}
func (n *NoopEventHandler) OnCorrelatedCallUpdate(correlatedCalls []CorrelatedCallInfo) {}
func (n *NoopEventHandler) OnDisconnect(address string, err error)                      {}
