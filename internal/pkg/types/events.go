package types

import (
	"time"

	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/events"
)

// EventBatch is one decoded delivery from the normalized protocol-event
// stream. It deliberately contains events rather than packet display values so
// non-TUI clients can consume the same callback without a presentation-layer
// dependency.
type EventBatch struct {
	Events                 []events.Event
	Losses                 []EventLoss
	CompatibilityOmissions uint64
	StreamID               string
	DeliverySequence       uint64
}

// EventLoss describes an explicitly reported gap in event delivery.
type EventLoss struct {
	Kind              eventsv1.LossKind
	Count             uint64
	SourceNodeID      string
	ProducerSessionID string
	SequenceRanges    []EventSequenceRange
}

type EventSequenceRange struct {
	First uint64
	Last  uint64
}

// EventHandler defines the interface for receiving remote capture events.
// This allows remotecapture to be decoupled from TUI-specific implementations.
type EventHandler interface {
	// OnPacketBatch is called when a batch of packets is received
	OnPacketBatch(packets []PacketDisplay)

	// OnEventBatch is called for decoded events and event-stream loss reports.
	OnEventBatch(batch EventBatch)

	// OnHunterStatus is called when hunter status is updated
	// processorAddr is the address of the processor being queried
	// upstreamProcessor is the address of that processor's upstream (if any)
	OnHunterStatus(hunters []HunterInfo, processorID string, processorStatus management.ProcessorStatus, processorAddr string, upstreamProcessor string)

	// OnCallUpdate is called when call state is updated
	OnCallUpdate(calls []CallInfo)

	// OnCorrelatedCallUpdate is called when correlated call data is updated
	OnCorrelatedCallUpdate(correlatedCalls []CorrelatedCallInfo)

	// OnDisconnect is called when connection is lost
	OnDisconnect(address string, err error)

	// OnTopologyUpdate is called when topology changes are received
	OnTopologyUpdate(update *management.TopologyUpdate, processorAddr string)
}

// CallInfo represents a VoIP call for display
type CallInfo struct {
	CallID           string
	From             string
	To               string
	State            string // "NEW", "RINGING", "ACTIVE", "ENDED", "FAILED"
	LastResponseCode uint32 // Last SIP response code (for failed/busy calls, e.g., 401, 486, 503)
	StartTime        time.Time
	EndTime          time.Time
	Duration         time.Duration
	Codec            string
	PacketCount      int
	PacketLoss       float64
	Jitter           float64
	MOS              float64 // Mean Opinion Score
	NodeID           string  // Processor or "Local"
	Hunters          []string
	SDPEndpoints     []string // RTP endpoints from SDP (IP:port) for debugging correlation
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
func (n *NoopEventHandler) OnEventBatch(batch EventBatch)         {}
func (n *NoopEventHandler) OnHunterStatus(hunters []HunterInfo, processorID string, processorStatus management.ProcessorStatus, processorAddr string, upstreamProcessor string) {
}
func (n *NoopEventHandler) OnCallUpdate(calls []CallInfo)                               {}
func (n *NoopEventHandler) OnCorrelatedCallUpdate(correlatedCalls []CorrelatedCallInfo) {}
func (n *NoopEventHandler) OnDisconnect(address string, err error)                      {}
func (n *NoopEventHandler) OnTopologyUpdate(update *management.TopologyUpdate, processorAddr string) {
}
