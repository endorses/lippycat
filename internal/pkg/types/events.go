package types

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/sms"
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
	SMS              []SMSRecord
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

// MediaAdmissionStatusHandler optionally receives sanitized processor/tap admission
// diagnostics. Existing EventHandler implementations need not support them.
type MediaAdmissionStatusHandler interface {
	OnMediaAdmissionStatus(status *management.MediaAdmissionStatus, processorAddr string)
}

// SMSRecord associates one SMS segment or control observation with its SIP
// transaction. Message content is owned by the record and never mutated after
// publication.
type SMSRecord struct {
	TransactionID string
	Message       *sms.Message
}

// SMSRecordLimit bounds retained content independently of the packet ring.
const SMSRecordLimit = 32
const smsRecordByteLimit = 256 << 10

// SMSContentCallLimit and SMSContentByteLimit bound retained presentation text
// across a capture session, independently of the number of ordinary calls.
const SMSContentCallLimit = 1000
const SMSContentByteLimit = 16 << 20

// SMSTransactionID scopes retransmission identity to the source and SIP
// transaction, retaining RP control observations separately from user content.
func SMSTransactionID(scope, callID string, cseq uint64, branch string, message *sms.Message) string {
	if message == nil {
		return ""
	}
	return fmt.Sprintf("%q/%q/%d/%q/%s/%d/%d", scope, callID, cseq, branch, message.Direction, message.RPType, message.Reference)
}

// CloneSMSRecords creates independent message ownership across async boundaries.
func CloneSMSRecords(records []SMSRecord) []SMSRecord {
	if records == nil {
		return nil
	}
	result := make([]SMSRecord, len(records))
	for i, record := range records {
		result[i] = SMSRecord{TransactionID: record.TransactionID, Message: sms.Clone(record.Message)}
	}
	return result
}

// MergeSMSRecords preserves earlier transactions when a response-only update
// replaces call state. Retransmissions replace their existing record in place.
// Oldest records are released when either retention bound is reached.
func MergeSMSRecords(existing, incoming []SMSRecord) []SMSRecord {
	result := CloneSMSRecords(existing)
	for _, record := range incoming {
		if record.Message == nil || smsRecordBytes(record) > smsRecordByteLimit {
			continue
		}
		index := -1
		for i := range result {
			if result[i].TransactionID == record.TransactionID {
				index = i
				break
			}
		}
		owned := SMSRecord{TransactionID: record.TransactionID, Message: sms.Clone(record.Message)}
		if index >= 0 {
			previous := result[index].Message
			if previous != nil && previous.Status == sms.StatusDecoded {
				if owned.Message.Status != sms.StatusDecoded {
					continue
				}
				if owned.Message.Text != previous.Text {
					owned.Message = sms.Clone(previous)
					owned.Message.Assembly.Status = sms.AssemblyConflict
				} else if previous.Assembly.Status == sms.AssemblyComplete && owned.Message.Assembly.Status == sms.AssemblyPending {
					owned.Message.Assembly = sms.Clone(previous).Assembly
				}
			}
			result[index] = owned
		} else {
			result = append(result, owned)
		}
	}
	retained := 0
	start := len(result)
	for start > 0 && len(result)-start < SMSRecordLimit {
		size := smsRecordBytes(result[start-1])
		if retained+size > smsRecordByteLimit {
			break
		}
		retained += size
		start--
	}
	return append([]SMSRecord(nil), result[start:]...)
}

// UpdateSMSAssembly updates related segments without merging their SIP calls or
// changing per-segment text. The result has independent ownership.
func UpdateSMSAssembly(records []SMSRecord, message *sms.Message) []SMSRecord {
	return updateSMSAssembly(records, message, false)
}

// UpdateSuppliedSMSAssembly applies authoritative producer outcomes, including
// a negative outcome that supersedes previously supplied completion metadata.
func UpdateSuppliedSMSAssembly(records []SMSRecord, message *sms.Message) []SMSRecord {
	return updateSMSAssembly(records, message, true)
}

func updateSMSAssembly(records []SMSRecord, message *sms.Message, supplied bool) []SMSRecord {
	result := CloneSMSRecords(records)
	if message == nil || message.Assembly.ID == "" {
		return result
	}
	for i := range result {
		if result[i].Message != nil && result[i].Message.Assembly.ID == message.Assembly.ID {
			if !supplied && result[i].Message.Assembly.Status == sms.AssemblyComplete && message.Assembly.Status == sms.AssemblyExpired {
				continue
			}
			assembly := sms.Clone(message).Assembly
			result[i].Message.Assembly = assembly
		}
	}
	return MergeSMSRecords(nil, result)
}

func smsRecordBytes(record SMSRecord) int {
	if record.Message == nil {
		return len(record.TransactionID)
	}
	m := record.Message
	return 256 + len(record.TransactionID) + len(m.Text) + len(m.Assembly.Text) + len(m.Header) + len(m.From) + len(m.To) + len(m.Encoding) + len(m.Status) + len(m.Direction) + len(m.Assembly.ID) + len(m.Assembly.Status) + len(m.Assembly.Received) + len(m.Assembly.Missing)
}

// SMSRecordsBytes conservatively measures retained owned SMS content.
func SMSRecordsBytes(records []SMSRecord) int {
	total := 0
	for _, record := range records {
		total += smsRecordBytes(record)
	}
	return total
}

// SMSDisplayAssembler adapts reusable SMS assembly to presentation records. It
// namespaces producer-provided group IDs and maps supplied completion updates
// back to locally observed generations. Callers serialize access alongside their
// call state.
type SMSDisplayAssembler struct {
	assembler  *sms.Assembler
	aliases    map[string]smsDisplayAlias
	closed     bool
	nextExpiry time.Time
}

type smsDisplayAlias struct {
	id      string
	expires time.Time
}

const smsDisplayLifetime = 5 * time.Minute

// Add preserves supplied terminal assembly outcomes and assembles observed
// segments when only local progress is available. Returned messages have
// independent ownership.
func (a *SMSDisplayAssembler) Add(scope string, message *sms.Message, now time.Time) *sms.Message {
	result := sms.Clone(message)
	if result == nil {
		return nil
	}
	upstreamID := result.Assembly.ID
	if upstreamID != "" {
		upstreamID = fmt.Sprintf("%q/%s", scope, upstreamID)
		result.Assembly.ID = upstreamID
	}
	switch result.Assembly.Status {
	case sms.AssemblyComplete, sms.AssemblyConflict, sms.AssemblyExpired, sms.AssemblyResourceLimited:
		// Producer terminal outcomes are authoritative even when this subscriber
		// missed the observations that caused a conflict, expiry, or resource loss.
		if upstreamID != "" {
			for local, alias := range a.aliases {
				if alias.id == upstreamID {
					result.Assembly.ID = local
					if result.Assembly.Status != sms.AssemblyComplete && a.assembler != nil {
						a.assembler.Forget(local)
					}
					break
				}
			}
		}
		return result
	}
	if a.closed {
		if result.Concat != nil {
			result.Assembly.Status = sms.AssemblyResourceLimited
		}
		return result
	}
	if result.Status != sms.StatusDecoded {
		return result
	}

	if a.assembler == nil {
		a.assembler = sms.NewAssembler(sms.Config{Lifetime: smsDisplayLifetime})
	}
	result = a.assembler.Add(scope, result, now)
	localID := result.Assembly.ID
	if localID != "" {
		if result.Assembly.Status == sms.AssemblyResourceLimited {
			delete(a.aliases, localID)
		} else {
			if a.aliases == nil {
				a.aliases = make(map[string]smsDisplayAlias)
			}
			alias, exists := a.aliases[localID]
			if !exists {
				alias = smsDisplayAlias{expires: now.Add(smsDisplayLifetime)}
			}
			if alias.id == "" {
				alias.id = upstreamID
			}
			a.aliases[localID] = alias
			if a.nextExpiry.IsZero() || alias.expires.Before(a.nextExpiry) {
				a.nextExpiry = alias.expires
			}
		}
	}
	return result
}

// Expire advances capture time, releasing incomplete groups and completed
// deduplication aliases while preserving completed text in existing call records.
func (a *SMSDisplayAssembler) Expire(now time.Time) []*sms.Message {
	if a.assembler == nil || a.nextExpiry.IsZero() || now.Before(a.nextExpiry) {
		return nil
	}
	expired := a.assembler.Expire(now)
	a.nextExpiry = time.Time{}
	for local, alias := range a.aliases {
		if !now.Before(alias.expires) {
			delete(a.aliases, local)
		} else if a.nextExpiry.IsZero() || alias.expires.Before(a.nextExpiry) {
			a.nextExpiry = alias.expires
		}
	}
	return expired
}

// Forget releases a group's retained segment text when a contributing call is
// evicted or reset. Remaining call records retain their owned display content.
func (a *SMSDisplayAssembler) Forget(message *sms.Message) *sms.Message {
	if a.assembler == nil || message == nil || message.Assembly.ID == "" {
		return nil
	}
	delete(a.aliases, message.Assembly.ID)
	a.assembler.Forget(message.Assembly.ID)
	if message.Assembly.Status == sms.AssemblyPending {
		lost := sms.Clone(message)
		lost.Assembly.Status = sms.AssemblyResourceLimited
		return lost
	}
	return nil
}

// Close releases pending segments and aliases. A new tracker is required for a
// new capture lifecycle.
func (a *SMSDisplayAssembler) Close() {
	a.closed = true
	if a.assembler != nil {
		a.assembler.Close()
	}
	a.aliases = nil
	a.nextExpiry = time.Time{}
}
