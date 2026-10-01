// Package x2x3 implements ETSI TS 103 221-2 X2/X3 binary TLV encoding.
package x2x3

import (
	"bytes"
	"errors"
	"hash/fnv"
	"net/netip"
	"strings"
	"sync/atomic"

	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// X2 Encoder errors.
var (
	// ErrNotVoIP is returned when the packet has no VoIP metadata.
	ErrNotVoIP = errors.New("packet has no VoIP metadata")

	// ErrNoCallID is returned when the packet has no Call-ID.
	ErrNoCallID = errors.New("packet has no Call-ID")

	// ErrNoSIPPayload is returned when no complete SIP message can be recovered.
	ErrNoSIPPayload = errors.New("no SIP payload available")
)

// X2Encoder encodes VoIP signaling events into X2 IRI PDUs.
//
// Every complete, admitted SIP request or response is carried as Payload Format
// 9. The MDF derives request/response and IRI record semantics from the payload.
// Task authorization and delivery-type checks belong to the processor.
//
// The encoder is safe for concurrent use.
type X2Encoder struct {
	// attrBuilder is used to construct TLV attributes.
	attrBuilder *AttributeBuilder
	sequencer   *Sequencer
	domainID    string
	nfID        string
	lastSeq     atomic.Uint32
}

// NewX2Encoder creates a new X2 encoder.
func NewX2Encoder() *X2Encoder {
	return NewX2EncoderWithSequencer(NewSequencer(0), "", "")
}

func NewX2EncoderWithSequencer(sequencer *Sequencer, domainID, nfID string) *X2Encoder {
	if sequencer == nil {
		sequencer = NewSequencer(0)
	}
	return &X2Encoder{
		attrBuilder: NewAttributeBuilder(),
		sequencer:   sequencer,
		domainID:    domainID,
		nfID:        nfID,
	}
}

// EncodeIRI encodes a VoIP packet into an X2 IRI PDU.
//
// The packet must have VoIPMetadata with a valid CallID.
// The XID identifies the intercept task this IRI belongs to.
//
// Raw SIP is validated before allocating a product sequence number.
func (e *X2Encoder) EncodeIRI(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	return e.EncodeIRIWithPolicy(pkt, xid, SIPContentFull)
}

// SIPContentPolicy selects the content that an admitted task may receive.
type SIPContentPolicy uint8

const (
	SIPContentFull SIPContentPolicy = iota
	// SIPContentIRIOnly preserves SDP signalling and withholds every other body,
	// including SMS MESSAGE, extension methods, and response bodies. This is a
	// conservative local authorization policy, not SMS TPDU redaction.
	SIPContentIRIOnly
)

// EncodeIRIWithPolicy applies a task's content authorization without changing
// the packet shared with other tasks or with media-direction learning.
func (e *X2Encoder) EncodeIRIWithPolicy(pkt *types.PacketDisplay, xid uuid.UUID, policy SIPContentPolicy) (*PDU, error) {
	if pkt == nil || pkt.VoIPData == nil || pkt.VoIPData.IsRTP {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDUWithPolicy(pkt, xid, pkt.VoIPData, policy)
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

// generateCorrelationID creates a deterministic correlation ID from Call-ID.
// All IRIs for the same call will have the same correlation ID.
func (e *X2Encoder) generateCorrelationID(callID string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(callID))
	return h.Sum64()
}

// addCommonAttributes adds the standard conditional attributes (timestamp and
// sequence number) to the PDU per the ETSI TS 103 221-2 attribute dictionary.
func (e *X2Encoder) addCommonAttributes(pdu *PDU, pkt *types.PacketDisplay) error {
	// Timestamp from packet capture (attribute 9)
	pdu.AddAttribute(e.attrBuilder.Timestamp(pkt.Timestamp))
	if e.domainID != "" {
		pdu.AddAttribute(e.attrBuilder.DomainID(e.domainID))
	}
	if e.nfID != "" {
		pdu.AddAttribute(e.attrBuilder.NFID(e.nfID))
	}
	if pkt.NodeID != "" {
		pdu.AddAttribute(e.attrBuilder.IPID(pkt.NodeID))
	}
	seq, err := e.sequencer.Next(SequenceContext{
		PDUType: PDUTypeX2, XID: pdu.Header.XID, DomainID: e.domainID,
		NFID: e.nfID, IPID: pkt.NodeID, CorrelationID: pdu.Header.CorrelationID,
	})
	if err != nil {
		return err
	}
	e.lastSeq.Store(seq)
	pdu.AddAttribute(e.attrBuilder.SequenceNumber(seq))
	return nil
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
func (e *X2Encoder) buildSIPPDU(pkt *types.PacketDisplay, xid uuid.UUID, voip *types.VoIPMetadata) (*PDU, error) {
	return e.buildSIPPDUWithPolicy(pkt, xid, voip, SIPContentFull)
}

func (e *X2Encoder) buildSIPPDUWithPolicy(pkt *types.PacketDisplay, xid uuid.UUID, voip *types.VoIPMetadata, policy SIPContentPolicy) (*PDU, error) {
	correlationID := e.generateCorrelationID(voip.CallID)

	pdu := NewX2SIPPDU(xid, correlationID)
	if err := e.setSIPPayload(pdu, pkt, voip, policy); err != nil {
		return nil, err
	}
	if err := e.addCommonAttributes(pdu, pkt); err != nil {
		return nil, err
	}
	e.addNetworkAttributes(pdu, pkt)

	return pdu, nil
}

// setSIPPayload attaches the raw SIP message to the PDU, falling back to
// recovering a complete SIP message from the raw packet data.
func (e *X2Encoder) setSIPPayload(pdu *PDU, pkt *types.PacketDisplay, voip *types.VoIPMetadata, policy SIPContentPolicy) error {
	var message []byte
	if len(voip.RawSIP) > 0 {
		// RawSIP is already framed. Never search past an invalid first message.
		if FindSIPStart(voip.RawSIP) != 0 {
			return ErrNoSIPPayload
		}
		message = FindSIPMessage(voip.RawSIP)
	} else {
		message = FindSIPMessage(pkt.RawData)
	}
	if len(message) == 0 {
		return ErrNoSIPPayload
	}
	parsed, err := sip.Parse(message, sip.ParseOptions{})
	if err != nil {
		return ErrNoSIPPayload
	}
	if policy == SIPContentIRIOnly && len(parsed.Body) > 0 && len(parsed.SDP) == 0 {
		message = withholdSIPBody(message)
	}
	pdu.SetPayload(message)
	return nil
}

// withholdSIPBody retains headers and their original line endings, rewrites
// every long/compact Content-Length (including folded values), and adds it if
// absent. No body bytes can survive via a stale or duplicate length field.
func withholdSIPBody(message []byte) []byte {
	separator, newline := []byte("\r\n\r\n"), []byte("\r\n")
	headerEnd := bytes.Index(message, separator)
	if headerEnd < 0 {
		separator, newline = []byte("\n\n"), []byte("\n")
		headerEnd = bytes.Index(message, separator)
	}
	lines := bytes.Split(message[:headerEnd], newline)
	result := make([][]byte, 0, len(lines)+1)
	found, lengthContinuation := false, false
	for _, line := range lines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && lengthContinuation {
			continue
		}
		lengthContinuation = false
		colon := bytes.IndexByte(line, ':')
		if colon > 0 {
			name := strings.TrimSpace(string(line[:colon]))
			if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "l") {
				line = append(append([]byte(nil), line[:colon+1]...), []byte(" 0")...)
				found, lengthContinuation = true, true
			}
		}
		result = append(result, line)
	}
	if !found {
		result = append(result, []byte("Content-Length: 0"))
	}
	return append(bytes.Join(result, newline), separator...)
}

// FindSIPMessage recovers the first complete SIP message from raw packet
// bytes. Content-Length, when present, bounds the body and excludes any
// following transport bytes.
func FindSIPMessage(data []byte) []byte {
	start := FindSIPStart(data)
	if start < 0 {
		return nil
	}
	message := data[start:]
	if len(message) > sip.MaxMessageSize {
		message = message[:sip.MaxMessageSize]
	}
	headerEnd := bytes.Index(message, []byte("\r\n\r\n"))
	separatorLength := 4
	if headerEnd < 0 {
		headerEnd = bytes.Index(message, []byte("\n\n"))
		separatorLength = 2
	}
	if headerEnd < 0 {
		return nil
	}
	parsed, err := sip.Parse(message, sip.ParseOptions{})
	if err != nil {
		return nil
	}
	return message[:headerEnd+separatorLength+len(parsed.Body)]
}

// EncodeSessionBegin creates a Session Begin IRI for a SIP INVITE.
func (e *X2Encoder) EncodeSessionBegin(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDU(pkt, xid, pkt.VoIPData)
}

// EncodeSessionAnswer creates a Session Answer IRI for a SIP 200 OK.
func (e *X2Encoder) EncodeSessionAnswer(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDU(pkt, xid, pkt.VoIPData)
}

// EncodeSessionEnd creates a Session End IRI for a SIP BYE.
func (e *X2Encoder) EncodeSessionEnd(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDU(pkt, xid, pkt.VoIPData)
}

// EncodeSessionAttempt creates a Session Attempt IRI for failed calls.
func (e *X2Encoder) EncodeSessionAttempt(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDU(pkt, xid, pkt.VoIPData)
}

// EncodeRegistration creates a Registration IRI for a SIP REGISTER.
func (e *X2Encoder) EncodeRegistration(pkt *types.PacketDisplay, xid uuid.UUID) (*PDU, error) {
	if pkt.VoIPData == nil {
		return nil, ErrNotVoIP
	}
	if pkt.VoIPData.CallID == "" {
		return nil, ErrNoCallID
	}
	return e.buildSIPPDU(pkt, xid, pkt.VoIPData)
}

// GetSequenceNumber returns the current sequence number (for testing/debugging).
func (e *X2Encoder) GetSequenceNumber() uint32 {
	return e.lastSeq.Load()
}

// FindSIPStart finds the start of a SIP message in raw packet data.
// Returns the byte offset of the SIP message, or -1 if not found.
func FindSIPStart(data []byte) int {
	// Frames have binary link/IP/transport headers before their SIP payload.
	// Within textual data, only a line boundary can begin another message.
	// Search in wire order so a response preceding "INVITE " in a header or
	// body wins over that later method token.
	const maxScanBytes = sip.MaxMessageSize + 4096 // SIP message plus packet headers
	if len(data) > maxScanBytes {
		data = data[:maxScanBytes]
	}
	binaryPrefix := false
	lineEnd := -1
	for i := 0; i < len(data); i++ {
		if data[i] < 0x20 && data[i] != '\r' && data[i] != '\n' && data[i] != '\t' {
			binaryPrefix = true
		}
		// Find the end of each line once. In particular, an uppercase run
		// without a newline cannot trigger a repeated suffix search.
		if i > lineEnd {
			nextNewline := bytes.IndexByte(data[i:], '\n')
			if nextNewline < 0 {
				return -1
			}
			lineEnd = i + nextNewline
		}
		if i > 0 && data[i-1] != '\n' && !binaryPrefix {
			continue
		}
		if !sip.IsRequestMethod(string(data[i : i+1])) {
			continue
		}
		if lineEnd-i > 1024 {
			continue
		}
		line := bytes.TrimSuffix(data[i:lineEnd], []byte{'\r'})
		if !sip.IsStartLine(string(line)) {
			continue
		}
		if _, err := sip.Parse(line, sip.ParseOptions{}); err == nil {
			return i
		}
	}
	return -1
}

// bytesEqual is retained for the package's binary golden-file comparisons.
func bytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}
