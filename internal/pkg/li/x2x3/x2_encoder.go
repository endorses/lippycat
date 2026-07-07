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

	// Determine whether this SIP message generates an IRI event. The IRI type
	// itself is derived by the MDF from the raw SIP payload (per TS 103 221-2,
	// SIP semantics are conveyed via Payload Format 9 + the raw payload, not via
	// proprietary attributes); we only use it here to gate emission.
	if _, ok := e.classifyIRIType(voip); !ok {
		// Not all SIP messages generate IRI events
		return nil, nil
	}

	return e.buildSIPPDU(pkt, xid, voip), nil
}

// NewX2SIPPDU creates an X2 PDU carrying a raw SIP message: PDU Type 1,
// Payload Format 9 (SIP Message), Payload Direction Unknown (the MDF derives
// direction and IRI type from the SIP payload).
func NewX2SIPPDU(xid uuid.UUID, correlationID uint64) *PDU {
	pdu := NewPDU(PDUTypeX2, xid, correlationID)
	pdu.Header.PayloadFormat = PayloadFormatSIP
	pdu.Header.PayloadDirection = PayloadDirectionUnknown
	return pdu
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
	case "MESSAGE":
		// SMS-over-IMS, instant messaging
		return IRIMessage, true
	case "SUBSCRIBE":
		// Presence, MWI, dialog event subscriptions
		return IRISubscription, true
	case "NOTIFY":
		// Subscription notifications
		return IRINotification, true
	case "PUBLISH":
		// Presence state publication
		return IRIPresence, true
	case "REFER":
		// Call transfer initiation
		return IRITransfer, true
	case "INFO", "UPDATE", "PRACK", "ACK":
		// Mid-dialog signaling
		return IRISessionContinue, true
	case "OPTIONS":
		// Capability query / keepalive
		return IRIReport, true
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

// addCommonAttributes adds the standard conditional attributes (timestamp and
// sequence number) to the PDU per the ETSI TS 103 221-2 attribute dictionary.
func (e *X2Encoder) addCommonAttributes(pdu *PDU, pkt *types.PacketDisplay) {
	// Timestamp from packet capture (attribute 9)
	pdu.AddAttribute(e.attrBuilder.Timestamp(pkt.Timestamp))

	// Sequence number (attribute 8, monotonically increasing)
	seq := e.seqNum.Add(1)
	pdu.AddAttribute(e.attrBuilder.SequenceNumber(seq))
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

// buildSIPPDU builds an X2 SIP PDU (Payload Format 9) with the standard
// conditional attributes and the raw SIP message as payload. All IRI-type and
// SIP-header semantics are recovered by the MDF from the raw payload.
func (e *X2Encoder) buildSIPPDU(pkt *types.PacketDisplay, xid uuid.UUID, voip *types.VoIPMetadata) *PDU {
	correlationID := e.generateCorrelationID(voip.CallID)

	pdu := NewX2SIPPDU(xid, correlationID)
	e.addCommonAttributes(pdu, pkt)
	e.addNetworkAttributes(pdu, pkt)
	e.setSIPPayload(pdu, pkt, voip)

	return pdu
}

// setSIPPayload attaches the raw SIP message to the PDU, falling back to
// scanning the raw packet data for a SIP start line.
func (e *X2Encoder) setSIPPayload(pdu *PDU, pkt *types.PacketDisplay, voip *types.VoIPMetadata) {
	if len(voip.RawSIP) > 0 {
		pdu.SetPayload(voip.RawSIP)
		return
	}
	if len(pkt.RawData) > 0 {
		if sipStart := findSIPStart(pkt.RawData); sipStart >= 0 {
			pdu.SetPayload(pkt.RawData[sipStart:])
		}
	}
}

// EncodeSessionBegin creates a Session Begin IRI for a SIP INVITE.
func (e *X2Encoder) EncodeSessionBegin(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDU(pkt, xid, pkt.VoIPData), nil
}

// EncodeSessionAnswer creates a Session Answer IRI for a SIP 200 OK.
func (e *X2Encoder) EncodeSessionAnswer(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDU(pkt, xid, pkt.VoIPData), nil
}

// EncodeSessionEnd creates a Session End IRI for a SIP BYE.
func (e *X2Encoder) EncodeSessionEnd(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDU(pkt, xid, pkt.VoIPData), nil
}

// EncodeSessionAttempt creates a Session Attempt IRI for failed calls.
func (e *X2Encoder) EncodeSessionAttempt(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDU(pkt, xid, pkt.VoIPData), nil
}

// EncodeRegistration creates a Registration IRI for a SIP REGISTER.
func (e *X2Encoder) EncodeRegistration(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDU(pkt, xid, pkt.VoIPData), nil
}

// GetSequenceNumber returns the current sequence number (for testing/debugging).
func (e *X2Encoder) GetSequenceNumber() uint32 {
	return e.seqNum.Load()
}

// findSIPStart finds the start of a SIP message in raw packet data.
// Returns the byte offset of the SIP message, or -1 if not found.
func findSIPStart(data []byte) int {
	// Look for common SIP request methods and "SIP/2.0" response prefix
	markers := [][]byte{
		[]byte("INVITE "),
		[]byte("BYE "),
		[]byte("ACK "),
		[]byte("CANCEL "),
		[]byte("REGISTER "),
		[]byte("OPTIONS "),
		[]byte("NOTIFY "),
		[]byte("SUBSCRIBE "),
		[]byte("MESSAGE "),
		[]byte("INFO "),
		[]byte("UPDATE "),
		[]byte("REFER "),
		[]byte("PRACK "),
		[]byte("PUBLISH "),
		[]byte("SIP/2.0 "),
	}
	for _, marker := range markers {
		for i := 0; i <= len(data)-len(marker); i++ {
			if bytesEqual(data[i:i+len(marker)], marker) {
				return i
			}
		}
	}
	return -1
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
