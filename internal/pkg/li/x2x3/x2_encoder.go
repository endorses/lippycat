// Package x2x3 implements ETSI TS 103 221-2 X2/X3 binary TLV encoding.
package x2x3

import (
	"errors"
	"hash/fnv"
	"net/netip"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// X2 Encoder errors.
var (
	// ErrNotVoIP is returned when the packet has no VoIP metadata.
	ErrNotVoIP = errors.New("packet has no VoIP metadata")

	// ErrNoCallID is returned when the packet has no Call-ID.
	ErrNoCallID = errors.New("packet has no Call-ID")

	// ErrUnknownIRIType is returned when the SIP message doesn't map to a known IRI type.
	ErrUnknownIRIType = errors.New("unknown IRI type for SIP message")
)

// X2Encoder encodes VoIP signaling events into X2 IRI PDUs.
//
// X2 carries Intercept Related Information (IRI), which includes:
//   - Session Begin (SIP INVITE)
//   - Session Answer (SIP 200 OK to INVITE)
//   - Session End (SIP BYE)
//   - Session Attempt (failed call attempts)
//   - Registration (SIP REGISTER)
//
// The encoder is safe for concurrent use.
type X2Encoder struct {
	// seqNum is the global sequence number for X2 PDUs.
	seqNum atomic.Uint32

	// attrBuilder is used to construct TLV attributes.
	attrBuilder *AttributeBuilder
}

// NewX2Encoder creates a new X2 encoder.
func NewX2Encoder() *X2Encoder {
	return &X2Encoder{
		attrBuilder: NewAttributeBuilder(),
	}
}

// EncodeIRI encodes a VoIP packet into an X2 IRI PDU.
//
// The packet must have VoIPMetadata with a valid CallID.
// The XID identifies the intercept task this IRI belongs to.
//
// Returns nil PDU if the SIP message type doesn't require an IRI event
// (e.g., provisional responses like 180 Ringing).
func (e *X2Encoder) EncodeIRI(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}

	voip := pkt.VoIPData
	if voip.CallID == "" {
		return nil, ErrNoCallID
	}

	// Determine IRI type from SIP message
	iriType, ok := e.classifyIRIType(voip)
	if !ok {
		// Not all SIP messages generate IRI events
		return nil, nil
	}

	// Generate correlation ID from Call-ID (deterministic hash)
	correlationID := e.generateCorrelationID(voip.CallID)

	// Create PDU
	pdu := NewPDU(PDUTypeX2, xid, correlationID)

	// Add common attributes
	e.addCommonAttributes(pdu, pkt, iriType)

	// Add SIP-specific attributes
	e.addSIPAttributes(pdu, voip)

	// Add network layer attributes
	e.addNetworkAttributes(pdu, pkt)

	return pdu, nil
}

// classifyIRIType determines the IRI type from the SIP message.
// Returns false if no IRI event should be generated.
func (e *X2Encoder) classifyIRIType(voip *types.VoIPMetadata) (IRIType, bool) {
	// Handle SIP requests
	switch voip.Method {
	case "INVITE":
		return IRISessionBegin, true
	case "BYE":
		return IRISessionEnd, true
	case "CANCEL":
		// CANCEL generates SessionAttempt (call was not answered)
		return IRISessionAttempt, true
	case "REGISTER":
		return IRIRegistration, true
	}

	// Handle SIP responses
	if voip.Status > 0 {
		switch {
		case voip.Status >= 200 && voip.Status < 300:
			// 2xx responses indicate success
			// For INVITE dialogs, 200 OK = SessionAnswer
			// For REGISTER, 200 OK is captured with the request
			// We check if this looks like an INVITE response by
			// the presence of both From and To tags (established dialog)
			if voip.ToTag != "" {
				return IRISessionAnswer, true
			}
			// 200 OK to REGISTER - captured as part of registration
			return IRIRegistration, true

		case voip.Status >= 400 && voip.Status < 700:
			// 4xx/5xx/6xx = call failure
			// This is a SessionAttempt (failed before answer)
			return IRISessionAttempt, true
		}
		// 1xx provisional responses don't generate IRIs
		// 3xx redirects are handled at signaling layer
	}

	return 0, false
}

// generateCorrelationID creates a deterministic correlation ID from Call-ID.
// All IRIs for the same call will have the same correlation ID.
func (e *X2Encoder) generateCorrelationID(callID string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(callID))
	return h.Sum64()
}

// addCommonAttributes adds standard attributes to the PDU.
func (e *X2Encoder) addCommonAttributes(pdu *PDU, pkt *types.PacketDisplay, iriType IRIType) {
	// Timestamp from packet capture
	pdu.AddAttribute(e.attrBuilder.Timestamp(pkt.Timestamp))

	// Sequence number (monotonically increasing)
	seq := e.seqNum.Add(1)
	pdu.AddAttribute(e.attrBuilder.SequenceNumber(seq))

	// IRI type
	pdu.AddAttribute(TLVAttribute{
		Type:  AttrIRIType,
		Value: []byte{byte(iriType >> 8), byte(iriType)},
	})
}

// addSIPAttributes adds SIP-specific attributes to the PDU.
func (e *X2Encoder) addSIPAttributes(pdu *PDU, voip *types.VoIPMetadata) {
	encoder := TLVEncoder{}

	// Call-ID (required)
	pdu.AddAttribute(encoder.EncodeString(AttrSIPCallID, voip.CallID))

	// From URI
	if voip.From != "" {
		pdu.AddAttribute(encoder.EncodeString(AttrSIPFromURI, voip.From))
	}

	// To URI
	if voip.To != "" {
		pdu.AddAttribute(encoder.EncodeString(AttrSIPToURI, voip.To))
	}

	// SIP Method (for requests)
	if voip.Method != "" {
		pdu.AddAttribute(encoder.EncodeString(AttrSIPMethod, voip.Method))
	}

	// Response code (for responses)
	if voip.Status > 0 {
		pdu.AddAttribute(encoder.EncodeUint16(AttrSIPResponseCode, uint16(voip.Status)))
	}

	// From tag
	if voip.FromTag != "" {
		pdu.AddAttribute(encoder.EncodeString(AttrSIPFromTag, voip.FromTag))
	}

	// To tag
	if voip.ToTag != "" {
		pdu.AddAttribute(encoder.EncodeString(AttrSIPToTag, voip.ToTag))
	}
}

// addNetworkAttributes adds network layer attributes to the PDU.
func (e *X2Encoder) addNetworkAttributes(pdu *PDU, pkt *types.PacketDisplay) {
	// Source IP
	if pkt.SrcIP != "" {
		if addr, err := netip.ParseAddr(pkt.SrcIP); err == nil {
			if attr, err := e.attrBuilder.SourceIP(addr); err == nil {
				pdu.AddAttribute(attr)
			}
		}
	}

	// Destination IP
	if pkt.DstIP != "" {
		if addr, err := netip.ParseAddr(pkt.DstIP); err == nil {
			if attr, err := e.attrBuilder.DestIP(addr); err == nil {
				pdu.AddAttribute(attr)
			}
		}
	}

	// Source port
	if pkt.SrcPort != "" {
		if port, ok := parsePort(pkt.SrcPort); ok {
			pdu.AddAttribute(e.attrBuilder.SourcePort(port))
		}
	}

	// Destination port
	if pkt.DstPort != "" {
		if port, ok := parsePort(pkt.DstPort); ok {
			pdu.AddAttribute(e.attrBuilder.DestPort(port))
		}
	}
}

// parsePort parses a port string to uint16.
func parsePort(s string) (uint16, bool) {
	if len(s) == 0 || len(s) > 5 {
		return 0, false
	}

	var port uint32 // Use uint32 to detect overflow
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		port = port*10 + uint32(c-'0')
	}

	if port == 0 || port > 65535 {
		return 0, false
	}
	return uint16(port), true
}

// EncodeSessionBegin creates a Session Begin IRI for a SIP INVITE.
func (e *X2Encoder) EncodeSessionBegin(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}

	voip := pkt.VoIPData
	correlationID := e.generateCorrelationID(voip.CallID)

	pdu := NewPDU(PDUTypeX2, xid, correlationID)
	e.addCommonAttributes(pdu, pkt, IRISessionBegin)
	e.addSIPAttributes(pdu, voip)
	e.addNetworkAttributes(pdu, pkt)

	return pdu, nil
}

// EncodeSessionAnswer creates a Session Answer IRI for a SIP 200 OK.
func (e *X2Encoder) EncodeSessionAnswer(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}

	voip := pkt.VoIPData
	correlationID := e.generateCorrelationID(voip.CallID)

	pdu := NewPDU(PDUTypeX2, xid, correlationID)
	e.addCommonAttributes(pdu, pkt, IRISessionAnswer)
	e.addSIPAttributes(pdu, voip)
	e.addNetworkAttributes(pdu, pkt)

	return pdu, nil
}

// EncodeSessionEnd creates a Session End IRI for a SIP BYE.
func (e *X2Encoder) EncodeSessionEnd(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}

	voip := pkt.VoIPData
	correlationID := e.generateCorrelationID(voip.CallID)

	pdu := NewPDU(PDUTypeX2, xid, correlationID)
	e.addCommonAttributes(pdu, pkt, IRISessionEnd)
	e.addSIPAttributes(pdu, voip)
	e.addNetworkAttributes(pdu, pkt)

	return pdu, nil
}

// EncodeSessionAttempt creates a Session Attempt IRI for failed calls.
func (e *X2Encoder) EncodeSessionAttempt(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}

	voip := pkt.VoIPData
	correlationID := e.generateCorrelationID(voip.CallID)

	pdu := NewPDU(PDUTypeX2, xid, correlationID)
	e.addCommonAttributes(pdu, pkt, IRISessionAttempt)
	e.addSIPAttributes(pdu, voip)
	e.addNetworkAttributes(pdu, pkt)

	return pdu, nil
}

// EncodeRegistration creates a Registration IRI for a SIP REGISTER.
func (e *X2Encoder) EncodeRegistration(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}

	voip := pkt.VoIPData
	correlationID := e.generateCorrelationID(voip.CallID)

	pdu := NewPDU(PDUTypeX2, xid, correlationID)
	e.addCommonAttributes(pdu, pkt, IRIRegistration)
	e.addSIPAttributes(pdu, voip)
	e.addNetworkAttributes(pdu, pkt)

	return pdu, nil
}

// GetSequenceNumber returns the current sequence number (for testing/debugging).
func (e *X2Encoder) GetSequenceNumber() uint32 {
	return e.seqNum.Load()
}
