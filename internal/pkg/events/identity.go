package events

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"sync"
	"sync/atomic"
)

const producerSessionBytes = 16

// OfflineSession describes the stable inputs that define one offline analysis
// run. SourceOrdering must contain source identities in the order in which
// packets are analyzed. Changing the input, profile, or order starts a distinct
// producer session.
type OfflineSession struct {
	InputIdentity   string
	AnalysisProfile string
	SourceOrdering  []string
}

// Producer assigns immutable delivery identity to normalized events. A
// Producer belongs to exactly one effective node ID and producer session.
// Event sequences begin at one and follow assignment order, which is dispatcher
// admission order for production pipelines.
type Producer struct {
	nodeID    string
	sessionID string
	sequence  atomic.Uint64
}

// ProducerSet assigns one random live session per effective source node. It is
// used by packet-mode processors, which originate events for multiple
// registered hunter identities during one process lifetime.
type ProducerSet struct {
	mu         sync.Mutex
	seed       [32]byte
	generation map[string]uint64
	producers  map[string]*Producer
}

func NewLiveProducerSet() (*ProducerSet, error) {
	set := &ProducerSet{generation: make(map[string]uint64), producers: make(map[string]*Producer)}
	if _, err := io.ReadFull(rand.Reader, set.seed[:]); err != nil {
		return nil, fmt.Errorf("create live event producer set: %w", err)
	}
	return set, nil
}

func (s *ProducerSet) Assign(event Event) Event {
	if s == nil || isNilEvent(event) {
		return event
	}
	nodeID := event.Envelope().NodeID
	if nodeID == "" {
		return event
	}
	s.mu.Lock()
	producer := s.producers[nodeID]
	if producer == nil {
		producer = s.producer(nodeID, s.generation[nodeID])
		s.producers[nodeID] = producer
	}
	s.mu.Unlock()
	return producer.Assign(event)
}

// Rotate starts a fresh live producer session for nodeID. It is safe to call
// only after callers have stopped event admission and flushed the old session;
// concurrent Assign calls after Rotate returns use the replacement producer.
// The previous session is empty when the node has not produced an event yet.
func (s *ProducerSet) Rotate(nodeID string) (previousSessionID, newSessionID string, err error) {
	if s == nil || nodeID == "" {
		return "", "", fmt.Errorf("rotate live event producer: node ID is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous := s.producers[nodeID]; previous != nil {
		previousSessionID = previous.SessionID()
	}
	s.generation[nodeID]++
	producer := s.producer(nodeID, s.generation[nodeID])
	s.producers[nodeID] = producer
	return previousSessionID, producer.SessionID(), nil
}

func (s *ProducerSet) producer(nodeID string, generation uint64) *Producer {
	h := sha256.New()
	_, _ = h.Write(s.seed[:])
	writeIdentityPart(h, nodeID)
	var encodedGeneration [8]byte
	binary.BigEndian.PutUint64(encodedGeneration[:], generation)
	_, _ = h.Write(encodedGeneration[:])
	sum := h.Sum(nil)
	return &Producer{nodeID: nodeID, sessionID: hex.EncodeToString(sum[:producerSessionBytes])}
}

// isNilEvent handles typed nil pointers stored in an Event interface. Event is
// intentionally closed to the concrete event types in this package, so this
// exhaustive check avoids reflection on the capture hot path.
func isNilEvent(event Event) bool {
	if event == nil {
		return true
	}
	switch ev := event.(type) {
	case *DNSEvent:
		return ev == nil
	case *SMTPEvent:
		return ev == nil
	case *TLSEvent:
		return ev == nil
	case *HTTPEvent:
		return ev == nil
	case *ConnEvent:
		return ev == nil
	case *FileMetadataEvent:
		return ev == nil
	case *FileContentEvent:
		return ev == nil
	default:
		return false
	}
}

// NewLiveProducer creates a producer with a cryptographically random 128-bit
// session ID. A live process must create a new Producer after restart or an
// analysis-authority boundary.
func NewLiveProducer(nodeID string) (*Producer, error) {
	return newLiveProducer(nodeID, rand.Reader)
}

// ResumeLiveProducer restores a crash-recovered producer identity. Callers
// must obtain sessionID and lastSequence from their checksummed durable spool.
func ResumeLiveProducer(nodeID, sessionID string, lastSequence uint64) (*Producer, error) {
	if nodeID == "" || sessionID == "" {
		return nil, fmt.Errorf("resume live event producer: node and session IDs are required")
	}
	if _, err := hex.DecodeString(sessionID); err != nil || len(sessionID) != producerSessionBytes*2 {
		return nil, fmt.Errorf("resume live event producer: invalid session ID")
	}
	p := &Producer{nodeID: nodeID, sessionID: sessionID}
	p.sequence.Store(lastSequence)
	return p, nil
}

func newLiveProducer(nodeID string, random io.Reader) (*Producer, error) {
	if nodeID == "" {
		return nil, fmt.Errorf("create live event producer: node ID is required")
	}
	var session [producerSessionBytes]byte
	if _, err := io.ReadFull(random, session[:]); err != nil {
		return nil, fmt.Errorf("create live event producer session: %w", err)
	}
	return &Producer{nodeID: nodeID, sessionID: hex.EncodeToString(session[:])}, nil
}

// NewOfflineProducer creates a repeatable producer session. The session hash
// intentionally excludes nodeID because the node is a separate component of
// delivery identity. Callers must pass sources in their actual analysis order
// and construct events in deterministic capture order (including deterministic
// tie breaking for equal timestamps).
func NewOfflineProducer(nodeID string, session OfflineSession) (*Producer, error) {
	if nodeID == "" {
		return nil, fmt.Errorf("create offline event producer: node ID is required")
	}
	if session.InputIdentity == "" {
		return nil, fmt.Errorf("create offline event producer: input identity is required")
	}
	if session.AnalysisProfile == "" {
		return nil, fmt.Errorf("create offline event producer: analysis profile is required")
	}
	h := sha256.New()
	writeIdentityPart(h, session.InputIdentity)
	writeIdentityPart(h, session.AnalysisProfile)
	for _, source := range session.SourceOrdering {
		writeIdentityPart(h, source)
	}
	sum := h.Sum(nil)
	return &Producer{nodeID: nodeID, sessionID: hex.EncodeToString(sum[:producerSessionBytes])}, nil
}

func writeIdentityPart(h hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(value))
}

func (p *Producer) NodeID() string    { return p.nodeID }
func (p *Producer) SessionID() string { return p.sessionID }

func (p *Producer) envelope(env Envelope) Envelope {
	if HasValidDeliveryIdentity(env) {
		return env
	}
	sequence := p.sequence.Add(1)
	if env.NodeID != "" && env.NodeID != p.nodeID && env.Provenance.CaptureSource == "" {
		env.Provenance.CaptureSource = env.NodeID
	}
	env.NodeID = p.nodeID
	env.ProducerSessionID = p.sessionID
	env.EventSequence = sequence
	env.EventID = eventID(env.NodeID, p.sessionID, sequence)
	return env
}

// Assign returns a copy of event with delivery identity. Already identified
// events are returned unchanged, which preserves identity through retries and
// relay. Dispatcher uses this immediately before admitting an event to its
// queue, so every accepted production event is identified.
func (p *Producer) Assign(event Event) Event {
	if p == nil || event == nil {
		return event
	}
	switch ev := event.(type) {
	case DNSEvent:
		ev.eventBase.EventEnvelope = p.envelope(ev.EventEnvelope)
		return ev
	case *DNSEvent:
		if ev == nil {
			return ev
		}
		copy := *ev
		copy.eventBase.EventEnvelope = p.envelope(copy.EventEnvelope)
		return copy
	case SMTPEvent:
		ev.eventBase.EventEnvelope = p.envelope(ev.EventEnvelope)
		return ev
	case *SMTPEvent:
		if ev == nil {
			return ev
		}
		copy := *ev
		copy.eventBase.EventEnvelope = p.envelope(copy.EventEnvelope)
		return copy
	case TLSEvent:
		ev.eventBase.EventEnvelope = p.envelope(ev.EventEnvelope)
		return ev
	case *TLSEvent:
		if ev == nil {
			return ev
		}
		copy := *ev
		copy.eventBase.EventEnvelope = p.envelope(copy.EventEnvelope)
		return copy
	case HTTPEvent:
		ev.eventBase.EventEnvelope = p.envelope(ev.EventEnvelope)
		return ev
	case *HTTPEvent:
		if ev == nil {
			return ev
		}
		copy := *ev
		copy.eventBase.EventEnvelope = p.envelope(copy.EventEnvelope)
		return copy
	case ConnEvent:
		ev.eventBase.EventEnvelope = p.envelope(ev.EventEnvelope)
		return ev
	case *ConnEvent:
		if ev == nil {
			return ev
		}
		copy := *ev
		copy.eventBase.EventEnvelope = p.envelope(copy.EventEnvelope)
		return copy
	case FileMetadataEvent:
		ev.eventBase.EventEnvelope = p.envelope(ev.EventEnvelope)
		return ev
	case *FileMetadataEvent:
		if ev == nil {
			return ev
		}
		copy := *ev
		copy.eventBase.EventEnvelope = p.envelope(copy.EventEnvelope)
		return copy
	case FileContentEvent:
		ev.eventBase.EventEnvelope = p.envelope(ev.EventEnvelope)
		return ev
	case *FileContentEvent:
		if ev == nil {
			return ev
		}
		copy := *ev
		copy.eventBase.EventEnvelope = p.envelope(copy.EventEnvelope)
		return copy
	default:
		return event
	}
}

func eventID(nodeID, sessionID string, sequence uint64) string {
	value := make([]byte, 0, len(nodeID)+len(sessionID)+10)
	value = binary.AppendUvarint(value, uint64(len(nodeID)))
	value = append(value, nodeID...)
	value = binary.AppendUvarint(value, uint64(len(sessionID)))
	value = append(value, sessionID...)
	value = binary.BigEndian.AppendUint64(value, sequence)
	return base64.RawURLEncoding.EncodeToString(value)
}

// DeliveryEventID returns the canonical opaque ID for a delivery identity.
func DeliveryEventID(nodeID, sessionID string, sequence uint64) string {
	if nodeID == "" || sessionID == "" || sequence == 0 {
		return ""
	}
	return eventID(nodeID, sessionID, sequence)
}

// HasValidDeliveryIdentity reports whether EventID canonically represents the
// event's node, producer session, and sequence.
func HasValidDeliveryIdentity(env Envelope) bool {
	return env.EventID != "" && env.ProducerSessionID != "" && env.EventSequence != 0 && env.NodeID != "" &&
		env.EventID == DeliveryEventID(env.NodeID, env.ProducerSessionID, env.EventSequence)
}

func (p *Producer) NewDNSEvent(env Envelope) DNSEvent {
	return NewDNSEvent(p.envelope(env))
}

func (p *Producer) NewSMTPEvent(env Envelope) SMTPEvent {
	return NewSMTPEvent(p.envelope(env))
}

func (p *Producer) NewTLSEvent(env Envelope) TLSEvent {
	return NewTLSEvent(p.envelope(env))
}

func (p *Producer) NewHTTPEvent(env Envelope) HTTPEvent {
	return NewHTTPEvent(p.envelope(env))
}

func (p *Producer) NewConnEvent(env Envelope) ConnEvent {
	return NewConnEvent(p.envelope(env))
}

func (p *Producer) NewFileMetadataEvent(env Envelope) FileMetadataEvent {
	return NewFileMetadataEvent(p.envelope(env))
}

func (p *Producer) NewFileContentEvent(env Envelope) FileContentEvent {
	return NewFileContentEvent(p.envelope(env))
}
