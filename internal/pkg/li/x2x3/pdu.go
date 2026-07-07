// Package x2x3 implements ETSI TS 103 221-2 X2/X3 binary TLV encoding.
//
// The X2 interface delivers IRI (Intercept Related Information) containing
// signaling metadata. The X3 interface delivers CC (Content of Communication)
// containing the actual content.
//
// Both interfaces use the same PDU (Protocol Data Unit) format with TLV
// (Type-Length-Value) encoded attributes. All multi-byte integers use network
// byte order (big-endian).
package x2x3

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
)

// Protocol version per ETSI TS 103 221-2.
// Version field: upper 8 bits = major, lower 8 bits = minor.
// The major version 5 is the value mandated by the current published spec
// (TS 103 221-2 V1.7.1, clause 5.2); it is incremented only on a
// backwards-incompatible change to the X2/X3 PDU structure.
const (
	VersionMajor = 5
	VersionMinor = 0
	Version      = (VersionMajor << 8) | VersionMinor
)

// PDUType identifies the PDU per ETSI TS 103 221-2 clause 5.3.
type PDUType uint16

const (
	// PDUTypeX2 indicates an X2 PDU carrying IRI (Intercept Related Information).
	PDUTypeX2 PDUType = 1
	// PDUTypeX3 indicates an X3 PDU carrying CC (Content of Communication).
	PDUTypeX3 PDUType = 2
	// PDUTypeKeepalive is a keepalive PDU (nil XID, empty payload).
	PDUTypeKeepalive PDUType = 3
	// PDUTypeKeepaliveAck acknowledges a keepalive PDU.
	PDUTypeKeepaliveAck PDUType = 4
)

// String returns the string representation of the PDU type.
func (t PDUType) String() string {
	switch t {
	case PDUTypeX2:
		return "X2"
	case PDUTypeX3:
		return "X3"
	case PDUTypeKeepalive:
		return "Keepalive"
	case PDUTypeKeepaliveAck:
		return "KeepaliveAck"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// PayloadFormat identifies the format of the PDU payload per the ETSI
// TS 103 221-2 Payload Format registry (clause 5.4).
type PayloadFormat uint16

const (
	// PayloadFormatKeepalive marks a keepalive PDU payload (empty).
	PayloadFormatKeepalive PayloadFormat = 0
	// PayloadFormatETSI102232 indicates an ETSI TS 102 232-1 payload.
	PayloadFormatETSI102232 PayloadFormat = 1
	// PayloadFormat33128 indicates a 3GPP TS 33.128 payload.
	PayloadFormat33128 PayloadFormat = 2
	// PayloadFormat33108 indicates an ETSI TS 133 108 payload.
	PayloadFormat33108 PayloadFormat = 3
	// PayloadFormatProprietary indicates a proprietary payload.
	PayloadFormatProprietary PayloadFormat = 4
	// PayloadFormatIPv4 indicates a raw IPv4 packet.
	PayloadFormatIPv4 PayloadFormat = 5
	// PayloadFormatIPv6 indicates a raw IPv6 packet.
	PayloadFormatIPv6 PayloadFormat = 6
	// PayloadFormatEthernet indicates a raw Ethernet frame.
	PayloadFormatEthernet PayloadFormat = 7
	// PayloadFormatRTP indicates a raw RTP packet (header + media).
	PayloadFormatRTP PayloadFormat = 8
	// PayloadFormatSIP indicates a raw SIP message.
	PayloadFormatSIP PayloadFormat = 9
	// PayloadFormatDHCP indicates a DHCP message.
	PayloadFormatDHCP PayloadFormat = 10
	// PayloadFormatRADIUS indicates a RADIUS packet.
	PayloadFormatRADIUS PayloadFormat = 11
	// PayloadFormatGTPU indicates a GTP-U message.
	PayloadFormatGTPU PayloadFormat = 12
	// PayloadFormatMSRP indicates an MSRP message.
	PayloadFormatMSRP PayloadFormat = 13
)

// PayloadDirection identifies the direction of the payload relative to the
// target per the ETSI TS 103 221-2 Payload Direction registry (clause 5.5).
type PayloadDirection uint16

const (
	// PayloadDirectionKeepalive is used on keepalive PDUs.
	PayloadDirectionKeepalive PayloadDirection = 0
	// PayloadDirectionUnknown indicates the direction could not be determined.
	PayloadDirectionUnknown PayloadDirection = 1
	// PayloadDirectionToTarget indicates traffic sent to the target.
	PayloadDirectionToTarget PayloadDirection = 2
	// PayloadDirectionFromTarget indicates traffic sent from the target.
	PayloadDirectionFromTarget PayloadDirection = 3
	// PayloadDirectionMultiple indicates traffic in multiple directions.
	PayloadDirectionMultiple PayloadDirection = 4
	// PayloadDirectionNotApplicable indicates direction does not apply.
	PayloadDirectionNotApplicable PayloadDirection = 5
)

// Fixed sizes for PDU components.
const (
	// HeaderMinSize is the fixed header size without conditional attributes,
	// per ETSI TS 103 221-2 clause 5.2:
	//   Version(2) + PDUType(2) + HeaderLen(4) + PayloadLen(4) +
	//   PayloadFormat(2) + PayloadDirection(2) + XID(16) + CorrelationID(8) = 40 bytes
	HeaderMinSize = 40

	// TLVHeaderSize is the size of a TLV attribute header (Type + Length).
	TLVHeaderSize = 4

	// UUIDSize is the size of a UUID in bytes.
	UUIDSize = 16

	// CorrelationIDSize is the size of the correlation ID field.
	CorrelationIDSize = 8
)

// Errors returned by PDU encoding/decoding functions.
var (
	ErrBufferTooSmall    = errors.New("buffer too small for PDU")
	ErrInvalidHeader     = errors.New("invalid PDU header")
	ErrInvalidVersion    = errors.New("unsupported PDU version")
	ErrInvalidPDUType    = errors.New("invalid PDU type")
	ErrTLVTooLarge       = errors.New("TLV value exceeds maximum size")
	ErrTLVBufferTooSmall = errors.New("buffer too small for TLV")
)

// PDUHeader represents the fixed header portion of an X2/X3 PDU per
// ETSI TS 103 221-2 clause 5.2.
//
// Wire format (40 bytes, all fields big-endian):
//
//	Offset  Size    Field
//	------  ----    -----
//	0       2       Version (major << 8 | minor)
//	2       2       PDU Type (1=X2, 2=X3, 3=Keepalive, 4=KeepaliveAck)
//	4       4       Header Length (total header including conditional attributes)
//	8       4       Payload Length
//	12      2       Payload Format
//	14      2       Payload Direction
//	16      16      XID (UUID, network byte order)
//	32      8       Correlation ID
//	40      var     Conditional Attributes (TLV encoded)
type PDUHeader struct {
	// Version is the protocol version (major << 8 | minor).
	Version uint16

	// Type identifies whether this is X2 (IRI), X3 (CC) or a keepalive.
	Type PDUType

	// HeaderLength is the total header size including conditional attributes.
	HeaderLength uint32

	// PayloadLength is the size of the payload in bytes.
	PayloadLength uint32

	// PayloadFormat identifies the payload encoding format.
	PayloadFormat PayloadFormat

	// PayloadDirection identifies the direction of the payload relative to
	// the target.
	PayloadDirection PayloadDirection

	// XID is the task identifier (X1 Identifier) as a UUID.
	XID uuid.UUID

	// CorrelationID links related PDUs (e.g., IRI and CC for same communication).
	CorrelationID uint64
}

// NewPDUHeader creates a new PDU header with default version.
func NewPDUHeader(pduType PDUType, xid uuid.UUID, correlationID uint64) *PDUHeader {
	return &PDUHeader{
		Version:          Version,
		Type:             pduType,
		HeaderLength:     HeaderMinSize,
		PayloadFormat:    PayloadFormatETSI102232,
		PayloadDirection: PayloadDirectionUnknown,
		XID:              xid,
		CorrelationID:    correlationID,
	}
}

// MarshalBinary encodes the PDU header to binary format.
// This only encodes the fixed header; conditional attributes and payload
// must be appended separately.
func (h *PDUHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, HeaderMinSize)
	h.encodeTo(buf)
	return buf, nil
}

// encodeTo writes the header to the provided buffer.
// The buffer must be at least HeaderMinSize bytes.
func (h *PDUHeader) encodeTo(buf []byte) {
	binary.BigEndian.PutUint16(buf[0:2], h.Version)
	binary.BigEndian.PutUint16(buf[2:4], uint16(h.Type))
	binary.BigEndian.PutUint32(buf[4:8], h.HeaderLength)
	binary.BigEndian.PutUint32(buf[8:12], h.PayloadLength)
	binary.BigEndian.PutUint16(buf[12:14], uint16(h.PayloadFormat))
	binary.BigEndian.PutUint16(buf[14:16], uint16(h.PayloadDirection))
	copy(buf[16:32], h.XID[:])
	binary.BigEndian.PutUint64(buf[32:40], h.CorrelationID)
}

// UnmarshalBinary decodes a PDU header from binary format.
func (h *PDUHeader) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderMinSize {
		return ErrBufferTooSmall
	}

	h.Version = binary.BigEndian.Uint16(data[0:2])
	h.Type = PDUType(binary.BigEndian.Uint16(data[2:4]))
	h.HeaderLength = binary.BigEndian.Uint32(data[4:8])
	h.PayloadLength = binary.BigEndian.Uint32(data[8:12])
	h.PayloadFormat = PayloadFormat(binary.BigEndian.Uint16(data[12:14]))
	h.PayloadDirection = PayloadDirection(binary.BigEndian.Uint16(data[14:16]))
	copy(h.XID[:], data[16:32])
	h.CorrelationID = binary.BigEndian.Uint64(data[32:40])

	// Validate
	if h.Version>>8 > VersionMajor {
		return ErrInvalidVersion
	}
	if h.Type != PDUTypeX2 && h.Type != PDUTypeX3 &&
		h.Type != PDUTypeKeepalive && h.Type != PDUTypeKeepaliveAck {
		return ErrInvalidPDUType
	}
	if h.HeaderLength < HeaderMinSize {
		return ErrInvalidHeader
	}

	return nil
}

// AttributeType identifies the type of a conditional TLV attribute per the
// ETSI TS 103 221-2 attribute dictionary (clause 5.6, table 6). Values are the
// normative ETSI numbering; SIP/RTP semantics are NOT carried as attributes but
// via the Payload Format field plus the raw payload.
type AttributeType uint16

const (
	// AttrETSI102232Container carries an ETSI TS 102 232-1 defined attribute.
	AttrETSI102232Container AttributeType = 1

	// AttrETSI33128Container carries a 3GPP TS 33.128 defined attribute.
	AttrETSI33128Container AttributeType = 2

	// AttrETSI33108Container carries an ETSI TS 133 108 defined attribute.
	AttrETSI33108Container AttributeType = 3

	// AttrProprietary carries a vendor-defined proprietary attribute.
	AttrProprietary AttributeType = 4

	// AttrDomainID contains the Domain ID (DID).
	AttrDomainID AttributeType = 5

	// AttrNFID contains the Network Function Identifier (variable-length string).
	// Identifies the NE/NF associated with the POI to the MDF.
	AttrNFID AttributeType = 6

	// AttrIPID contains the Interception Point Identifier (variable-length string).
	// Identifies the specific POI within the NF.
	AttrIPID AttributeType = 7

	// AttrSequenceNumber contains a 4-byte (uint32) sequence number.
	AttrSequenceNumber AttributeType = 8

	// AttrTimestamp contains a POSIX timespec (seconds + nanoseconds).
	AttrTimestamp AttributeType = 9

	// AttrSourceIPv4 contains a 4-byte IPv4 address.
	AttrSourceIPv4 AttributeType = 10

	// AttrDestIPv4 contains a 4-byte IPv4 address.
	AttrDestIPv4 AttributeType = 11

	// AttrSourceIPv6 contains a 16-byte IPv6 address.
	AttrSourceIPv6 AttributeType = 12

	// AttrDestIPv6 contains a 16-byte IPv6 address.
	AttrDestIPv6 AttributeType = 13

	// AttrSourcePort contains a 2-byte port number.
	AttrSourcePort AttributeType = 14

	// AttrDestPort contains a 2-byte port number.
	AttrDestPort AttributeType = 15

	// AttrIPProtocol contains a 1-byte IP protocol number.
	AttrIPProtocol AttributeType = 16

	// AttrMatchedTargetIdentifier contains the target identifier that matched
	// (variable-length string).
	AttrMatchedTargetIdentifier AttributeType = 17

	// AttrOtherTargetIdentifier contains a non-matched target identifier
	// (variable-length string).
	AttrOtherTargetIdentifier AttributeType = 18
)

// IRIType identifies the type of Intercept Related Information event.
type IRIType uint16

const (
	// IRISessionBegin indicates the start of a communication session (SIP INVITE).
	IRISessionBegin IRIType = 1

	// IRISessionAnswer indicates the session was answered (SIP 200 OK to INVITE).
	IRISessionAnswer IRIType = 2

	// IRISessionEnd indicates the end of a communication session (SIP BYE).
	IRISessionEnd IRIType = 3

	// IRISessionAttempt indicates a session attempt that was not answered.
	// Generated when a session ends before being answered (e.g., CANCEL, 4xx/5xx/6xx).
	IRISessionAttempt IRIType = 4

	// IRIRegistration indicates a SIP REGISTER event.
	IRIRegistration IRIType = 5

	// IRIRegistrationEnd indicates a SIP de-registration event.
	IRIRegistrationEnd IRIType = 6

	// IRISessionContinue indicates mid-dialog signaling (INFO, UPDATE, PRACK, ACK, re-INVITE).
	IRISessionContinue IRIType = 7

	// IRIMessage indicates a SIP MESSAGE event (SMS-over-IMS, instant messaging).
	IRIMessage IRIType = 8

	// IRISubscription indicates a SIP SUBSCRIBE event (presence, MWI, dialog events).
	IRISubscription IRIType = 9

	// IRINotification indicates a SIP NOTIFY event (subscription notification).
	IRINotification IRIType = 10

	// IRIPresence indicates a SIP PUBLISH event (presence state publication).
	IRIPresence IRIType = 11

	// IRITransfer indicates a SIP REFER event (call transfer initiation).
	IRITransfer IRIType = 12

	// IRIReport indicates a non-session SIP event (OPTIONS, other diagnostic).
	IRIReport IRIType = 13
)

// String returns the string representation of the IRI type.
func (t IRIType) String() string {
	switch t {
	case IRISessionBegin:
		return "SessionBegin"
	case IRISessionAnswer:
		return "SessionAnswer"
	case IRISessionEnd:
		return "SessionEnd"
	case IRISessionAttempt:
		return "SessionAttempt"
	case IRIRegistration:
		return "Registration"
	case IRIRegistrationEnd:
		return "RegistrationEnd"
	case IRISessionContinue:
		return "SessionContinue"
	case IRIMessage:
		return "Message"
	case IRISubscription:
		return "Subscription"
	case IRINotification:
		return "Notification"
	case IRIPresence:
		return "Presence"
	case IRITransfer:
		return "Transfer"
	case IRIReport:
		return "Report"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// TLVAttribute represents a Type-Length-Value encoded attribute.
//
// Wire format:
//
//	Offset  Size    Field
//	------  ----    -----
//	0       2       Type (attribute identifier)
//	2       2       Length (length of Value in octets)
//	4       var     Value (attribute contents)
type TLVAttribute struct {
	Type  AttributeType
	Value []byte
}

// Size returns the total encoded size of the TLV attribute.
func (a *TLVAttribute) Size() int {
	return TLVHeaderSize + len(a.Value)
}

// MarshalBinary encodes the TLV attribute to binary format.
func (a *TLVAttribute) MarshalBinary() ([]byte, error) {
	if len(a.Value) > 0xFFFF {
		return nil, ErrTLVTooLarge
	}

	buf := make([]byte, TLVHeaderSize+len(a.Value))
	binary.BigEndian.PutUint16(buf[0:2], uint16(a.Type))
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(a.Value)))
	copy(buf[4:], a.Value)
	return buf, nil
}

// EncodeTo writes the TLV attribute to the provided buffer.
// Returns the number of bytes written or an error if the buffer is too small.
func (a *TLVAttribute) EncodeTo(buf []byte) (int, error) {
	size := a.Size()
	if len(buf) < size {
		return 0, ErrTLVBufferTooSmall
	}
	if len(a.Value) > 0xFFFF {
		return 0, ErrTLVTooLarge
	}

	binary.BigEndian.PutUint16(buf[0:2], uint16(a.Type))
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(a.Value)))
	copy(buf[4:], a.Value)
	return size, nil
}

// UnmarshalBinary decodes a TLV attribute from binary format.
func (a *TLVAttribute) UnmarshalBinary(data []byte) error {
	if len(data) < TLVHeaderSize {
		return ErrBufferTooSmall
	}

	a.Type = AttributeType(binary.BigEndian.Uint16(data[0:2]))
	length := binary.BigEndian.Uint16(data[2:4])

	if len(data) < TLVHeaderSize+int(length) {
		return ErrBufferTooSmall
	}

	a.Value = make([]byte, length)
	copy(a.Value, data[TLVHeaderSize:TLVHeaderSize+int(length)])
	return nil
}

// PDU represents a complete X2 or X3 Protocol Data Unit.
type PDU struct {
	Header     PDUHeader
	Attributes []TLVAttribute
	Payload    []byte
}

// NewPDU creates a new PDU with the given parameters.
func NewPDU(pduType PDUType, xid uuid.UUID, correlationID uint64) *PDU {
	return &PDU{
		Header: PDUHeader{
			Version:          Version,
			Type:             pduType,
			HeaderLength:     HeaderMinSize,
			PayloadFormat:    PayloadFormatETSI102232,
			PayloadDirection: PayloadDirectionUnknown,
			XID:              xid,
			CorrelationID:    correlationID,
		},
	}
}

// NewKeepalivePDU creates a keepalive PDU (PDU Type 3) per ETSI TS 103 221-2.
// It carries a nil XID, empty payload, Payload Format 0 and Payload Direction 0.
func NewKeepalivePDU() *PDU {
	return &PDU{
		Header: PDUHeader{
			Version:          Version,
			Type:             PDUTypeKeepalive,
			HeaderLength:     HeaderMinSize,
			PayloadFormat:    PayloadFormatKeepalive,
			PayloadDirection: PayloadDirectionKeepalive,
			XID:              uuid.Nil,
			CorrelationID:    0,
		},
	}
}

// AddAttribute adds a TLV attribute to the PDU.
func (p *PDU) AddAttribute(attr TLVAttribute) {
	p.Attributes = append(p.Attributes, attr)
	p.Header.HeaderLength += uint32(attr.Size())
}

// SetPayload sets the PDU payload.
func (p *PDU) SetPayload(payload []byte) {
	p.Payload = payload
	p.Header.PayloadLength = uint32(len(payload))
}

// Size returns the total encoded size of the PDU.
func (p *PDU) Size() int {
	return int(p.Header.HeaderLength) + len(p.Payload)
}

// MarshalBinary encodes the complete PDU to binary format.
func (p *PDU) MarshalBinary() ([]byte, error) {
	buf := make([]byte, p.Size())
	n, err := p.EncodeTo(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// EncodeTo writes the complete PDU to the provided buffer.
// Returns the number of bytes written or an error.
func (p *PDU) EncodeTo(buf []byte) (int, error) {
	size := p.Size()
	if len(buf) < size {
		return 0, ErrBufferTooSmall
	}

	// Encode header
	p.Header.encodeTo(buf)
	offset := HeaderMinSize

	// Encode attributes
	for _, attr := range p.Attributes {
		n, err := attr.EncodeTo(buf[offset:])
		if err != nil {
			return 0, err
		}
		offset += n
	}

	// Encode payload
	if len(p.Payload) > 0 {
		copy(buf[offset:], p.Payload)
		offset += len(p.Payload)
	}

	return offset, nil
}

// WriteTo writes the PDU to the provided writer.
func (p *PDU) WriteTo(w io.Writer) (int64, error) {
	data, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	return int64(n), err
}

// UnmarshalBinary decodes a complete PDU from binary format.
func (p *PDU) UnmarshalBinary(data []byte) error {
	if err := p.Header.UnmarshalBinary(data); err != nil {
		return err
	}

	// Parse conditional attributes
	attrEnd := int(p.Header.HeaderLength)
	if attrEnd > len(data) {
		return ErrBufferTooSmall
	}

	offset := HeaderMinSize
	for offset < attrEnd {
		var attr TLVAttribute
		if err := attr.UnmarshalBinary(data[offset:]); err != nil {
			return err
		}
		p.Attributes = append(p.Attributes, attr)
		offset += attr.Size()
	}

	// Parse payload
	payloadEnd := attrEnd + int(p.Header.PayloadLength)
	if payloadEnd > len(data) {
		return ErrBufferTooSmall
	}
	if p.Header.PayloadLength > 0 {
		p.Payload = make([]byte, p.Header.PayloadLength)
		copy(p.Payload, data[attrEnd:payloadEnd])
	}

	return nil
}

// TLVEncoder provides helper methods for encoding common attribute types.
type TLVEncoder struct{}

// EncodeUint16 creates a TLV attribute with a uint16 value.
func (e *TLVEncoder) EncodeUint16(attrType AttributeType, value uint16) TLVAttribute {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, value)
	return TLVAttribute{Type: attrType, Value: buf}
}

// EncodeUint32 creates a TLV attribute with a uint32 value.
func (e *TLVEncoder) EncodeUint32(attrType AttributeType, value uint32) TLVAttribute {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	return TLVAttribute{Type: attrType, Value: buf}
}

// EncodeUint64 creates a TLV attribute with a uint64 value.
func (e *TLVEncoder) EncodeUint64(attrType AttributeType, value uint64) TLVAttribute {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value)
	return TLVAttribute{Type: attrType, Value: buf}
}

// EncodeBytes creates a TLV attribute with raw bytes.
func (e *TLVEncoder) EncodeBytes(attrType AttributeType, value []byte) TLVAttribute {
	return TLVAttribute{Type: attrType, Value: value}
}

// EncodeString creates a TLV attribute with a UTF-8 string.
func (e *TLVEncoder) EncodeString(attrType AttributeType, value string) TLVAttribute {
	return TLVAttribute{Type: attrType, Value: []byte(value)}
}

// EncodeUint8 creates a TLV attribute with a uint8 value.
func (e *TLVEncoder) EncodeUint8(attrType AttributeType, value uint8) TLVAttribute {
	return TLVAttribute{Type: attrType, Value: []byte{value}}
}

// TLVDecoder provides helper methods for decoding common attribute types.
type TLVDecoder struct{}

// DecodeUint16 extracts a uint16 from a TLV attribute value.
func (d *TLVDecoder) DecodeUint16(attr *TLVAttribute) (uint16, error) {
	if len(attr.Value) < 2 {
		return 0, ErrBufferTooSmall
	}
	return binary.BigEndian.Uint16(attr.Value), nil
}

// DecodeUint32 extracts a uint32 from a TLV attribute value.
func (d *TLVDecoder) DecodeUint32(attr *TLVAttribute) (uint32, error) {
	if len(attr.Value) < 4 {
		return 0, ErrBufferTooSmall
	}
	return binary.BigEndian.Uint32(attr.Value), nil
}

// DecodeUint64 extracts a uint64 from a TLV attribute value.
func (d *TLVDecoder) DecodeUint64(attr *TLVAttribute) (uint64, error) {
	if len(attr.Value) < 8 {
		return 0, ErrBufferTooSmall
	}
	return binary.BigEndian.Uint64(attr.Value), nil
}

// DecodeString extracts a UTF-8 string from a TLV attribute value.
func (d *TLVDecoder) DecodeString(attr *TLVAttribute) string {
	return string(attr.Value)
}

// DecodeUint8 extracts a uint8 from a TLV attribute value.
func (d *TLVDecoder) DecodeUint8(attr *TLVAttribute) (uint8, error) {
	if len(attr.Value) < 1 {
		return 0, ErrBufferTooSmall
	}
	return attr.Value[0], nil
}
