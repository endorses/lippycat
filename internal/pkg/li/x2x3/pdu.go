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
const (
	VersionMajor = 5
	VersionMinor = 0
	Version      = (VersionMajor << 8) | VersionMinor
)

// PDUType identifies whether the PDU carries X2 (IRI) or X3 (CC) content.
type PDUType uint16

const (
	// PDUTypeX2 indicates an X2 PDU carrying IRI (Intercept Related Information).
	PDUTypeX2 PDUType = 1
	// PDUTypeX3 indicates an X3 PDU carrying CC (Content of Communication).
	PDUTypeX3 PDUType = 2
)

// String returns the string representation of the PDU type.
func (t PDUType) String() string {
	switch t {
	case PDUTypeX2:
		return "X2"
	case PDUTypeX3:
		return "X3"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// PayloadFormat identifies the format of the PDU payload.
type PayloadFormat uint16

const (
	// PayloadFormatEtsi indicates ETSI-defined payload format.
	PayloadFormatEtsi PayloadFormat = 1
	// PayloadFormatNational indicates national/proprietary payload format.
	PayloadFormatNational PayloadFormat = 2
)

// Fixed sizes for PDU components.
const (
	// HeaderMinSize is the minimum header size without conditional attributes.
	// Version(2) + PDUType(2) + HeaderLen(2) + PayloadFormat(2) + PayloadLen(4) + XID(16) + CorrelationID(8) = 36 bytes
	HeaderMinSize = 36

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

// PDUHeader represents the fixed header portion of an X2/X3 PDU.
//
// Wire format (all fields big-endian):
//
//	Offset  Size    Field
//	------  ----    -----
//	0       2       Version (major << 8 | minor)
//	2       2       PDU Type (1=X2, 2=X3)
//	4       2       Header Length (total header including attributes)
//	6       2       Payload Format
//	8       4       Payload Length
//	12      16      XID (UUID, network byte order)
//	28      8       Correlation ID
//	36      var     Conditional Attributes (TLV encoded)
type PDUHeader struct {
	// Version is the protocol version (major << 8 | minor).
	Version uint16

	// Type identifies whether this is X2 (IRI) or X3 (CC).
	Type PDUType

	// HeaderLength is the total header size including conditional attributes.
	HeaderLength uint16

	// PayloadFormat identifies the payload encoding format.
	PayloadFormat PayloadFormat

	// PayloadLength is the size of the payload in bytes.
	PayloadLength uint32

	// XID is the task identifier (X1 Identifier) as a UUID.
	XID uuid.UUID

	// CorrelationID links related PDUs (e.g., IRI and CC for same communication).
	CorrelationID uint64
}

// NewPDUHeader creates a new PDU header with default version.
func NewPDUHeader(pduType PDUType, xid uuid.UUID, correlationID uint64) *PDUHeader {
	return &PDUHeader{
		Version:       Version,
		Type:          pduType,
		HeaderLength:  HeaderMinSize,
		PayloadFormat: PayloadFormatEtsi,
		XID:           xid,
		CorrelationID: correlationID,
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
	binary.BigEndian.PutUint16(buf[4:6], h.HeaderLength)
	binary.BigEndian.PutUint16(buf[6:8], uint16(h.PayloadFormat))
	binary.BigEndian.PutUint32(buf[8:12], h.PayloadLength)
	copy(buf[12:28], h.XID[:])
	binary.BigEndian.PutUint64(buf[28:36], h.CorrelationID)
}

// UnmarshalBinary decodes a PDU header from binary format.
func (h *PDUHeader) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderMinSize {
		return ErrBufferTooSmall
	}

	h.Version = binary.BigEndian.Uint16(data[0:2])
	h.Type = PDUType(binary.BigEndian.Uint16(data[2:4]))
	h.HeaderLength = binary.BigEndian.Uint16(data[4:6])
	h.PayloadFormat = PayloadFormat(binary.BigEndian.Uint16(data[6:8]))
	h.PayloadLength = binary.BigEndian.Uint32(data[8:12])
	copy(h.XID[:], data[12:28])
	h.CorrelationID = binary.BigEndian.Uint64(data[28:36])

	// Validate
	if h.Version>>8 > VersionMajor {
		return ErrInvalidVersion
	}
	if h.Type != PDUTypeX2 && h.Type != PDUTypeX3 {
		return ErrInvalidPDUType
	}
	if h.HeaderLength < HeaderMinSize {
		return ErrInvalidHeader
	}

	return nil
}

// AttributeType identifies the type of a TLV attribute.
type AttributeType uint16

// Common attribute types per ETSI TS 103 221-2.
const (
	// AttrTimestamp contains a POSIX timespec (seconds + nanoseconds).
	AttrTimestamp AttributeType = 0x0001

	// AttrSequenceNumber contains a 4-byte sequence number.
	AttrSequenceNumber AttributeType = 0x0002

	// AttrSourceIPv4 contains a 4-byte IPv4 address.
	AttrSourceIPv4 AttributeType = 0x0003

	// AttrDestIPv4 contains a 4-byte IPv4 address.
	AttrDestIPv4 AttributeType = 0x0004

	// AttrSourceIPv6 contains a 16-byte IPv6 address.
	AttrSourceIPv6 AttributeType = 0x0005

	// AttrDestIPv6 contains a 16-byte IPv6 address.
	AttrDestIPv6 AttributeType = 0x0006

	// AttrSourcePort contains a 2-byte port number.
	AttrSourcePort AttributeType = 0x0007

	// AttrDestPort contains a 2-byte port number.
	AttrDestPort AttributeType = 0x0008

	// AttrIPProtocol contains a 1-byte IP protocol number.
	AttrIPProtocol AttributeType = 0x0009

	// AttrTargetIdentifier contains the matched target identifier (variable length string).
	AttrTargetIdentifier AttributeType = 0x000A

	// AttrDirection indicates traffic direction (1 byte: 0=unknown, 1=from target, 2=to target).
	AttrDirection AttributeType = 0x000B

	// AttrNFID contains the Network Function Identifier per ETSI TS 103 221-2.
	// Identifies the NE/NF associated with the POI to the MDF.
	// Variable length string (e.g., processor-id or tap-id).
	AttrNFID AttributeType = 0x000C

	// AttrIPID contains the Interception Point Identifier per ETSI TS 103 221-2.
	// Identifies the specific POI within the NF.
	// Variable length string (e.g., hunter-id for distributed capture).
	AttrIPID AttributeType = 0x000D

	// AttrNationalParameter is reserved for national extensions.
	AttrNationalParameter AttributeType = 0xFFFF

	// SIP/VoIP-specific attribute types per ETSI TS 103 221-2.
	// These are used in X2 IRI PDUs for VoIP interception.

	// AttrSIPCallID contains the SIP Call-ID header value.
	AttrSIPCallID AttributeType = 0x0100

	// AttrSIPFromURI contains the SIP From header URI (user@domain).
	AttrSIPFromURI AttributeType = 0x0101

	// AttrSIPToURI contains the SIP To header URI (user@domain).
	AttrSIPToURI AttributeType = 0x0102

	// AttrSIPMethod contains the SIP request method (INVITE, BYE, etc.).
	AttrSIPMethod AttributeType = 0x0103

	// AttrSIPResponseCode contains the SIP response status code (200, 404, etc.).
	AttrSIPResponseCode AttributeType = 0x0104

	// AttrSIPFromTag contains the tag parameter from the From header.
	AttrSIPFromTag AttributeType = 0x0105

	// AttrSIPToTag contains the tag parameter from the To header.
	AttrSIPToTag AttributeType = 0x0106

	// AttrIRIType identifies the type of IRI event.
	AttrIRIType AttributeType = 0x0110

	// AttrCorrelationNumber contains a call correlation identifier.
	// Used to link multiple IRIs belonging to the same communication session.
	AttrCorrelationNumber AttributeType = 0x0111

	// RTP/Media-specific attribute types for X3 CC (Content of Communication).
	// These are used in X3 PDUs for voice/media interception.

	// AttrRTPSSRC contains the RTP SSRC (Synchronization Source) identifier.
	// 4 bytes, identifies the synchronization source.
	AttrRTPSSRC AttributeType = 0x0200

	// AttrRTPSequenceNumber contains the RTP sequence number.
	// 2 bytes, used for packet ordering and loss detection.
	AttrRTPSequenceNumber AttributeType = 0x0201

	// AttrRTPTimestamp contains the RTP timestamp.
	// 4 bytes, sampling instant of the first octet in the RTP data packet.
	AttrRTPTimestamp AttributeType = 0x0202

	// AttrRTPPayloadType contains the RTP payload type.
	// 1 byte, identifies the format of the RTP payload.
	AttrRTPPayloadType AttributeType = 0x0203

	// AttrMediaPayload contains the raw media payload.
	// Variable length, the actual audio/video content.
	AttrMediaPayload AttributeType = 0x0204

	// AttrStreamID contains an identifier linking X3 CC to corresponding X2 IRI.
	// 8 bytes, typically derived from Call-ID or SSRC for correlation.
	AttrStreamID AttributeType = 0x0210
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
			Version:       Version,
			Type:          pduType,
			HeaderLength:  HeaderMinSize,
			PayloadFormat: PayloadFormatEtsi,
			XID:           xid,
			CorrelationID: correlationID,
		},
	}
}

// AddAttribute adds a TLV attribute to the PDU.
func (p *PDU) AddAttribute(attr TLVAttribute) {
	p.Attributes = append(p.Attributes, attr)
	p.Header.HeaderLength += uint16(attr.Size())
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
