package x2x3

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

// Attribute size constants.
const (
	// TimestampSize is the size of a POSIX timespec timestamp (seconds + nanoseconds).
	// 8 bytes for seconds (int64) + 4 bytes for nanoseconds (int32) = 12 bytes
	TimestampSize = 12

	// IPv4Size is the size of an IPv4 address.
	IPv4Size = 4

	// IPv6Size is the size of an IPv6 address.
	IPv6Size = 16

	// SequenceNumberSize is the size of a sequence number.
	SequenceNumberSize = 4

	// CorrelationAttrIDSize is the size of the correlation ID attribute.
	CorrelationAttrIDSize = 8

	// PortSize is the size of a port number.
	PortSize = 2

	// ProtocolSize is the size of an IP protocol number.
	ProtocolSize = 1

	// DirectionSize is the size of a direction indicator.
	DirectionSize = 1
)

// Direction indicates the direction of traffic relative to the target.
type Direction uint8

const (
	// DirectionUnknown indicates unknown direction.
	DirectionUnknown Direction = 0
	// DirectionFromTarget indicates traffic originating from the target.
	DirectionFromTarget Direction = 1
	// DirectionToTarget indicates traffic destined to the target.
	DirectionToTarget Direction = 2
)

// Errors for attribute encoding/decoding.
var (
	ErrInvalidIPAddress  = errors.New("invalid IP address")
	ErrInvalidIPv4       = errors.New("invalid IPv4 address")
	ErrInvalidIPv6       = errors.New("invalid IPv6 address")
	ErrInvalidTimestamp  = errors.New("invalid timestamp data")
	ErrInvalidAttrLength = errors.New("invalid attribute length")
)

// Timestamp represents a POSIX.1-2017 timespec timestamp.
//
// Wire format (12 bytes, big-endian):
//
//	Offset  Size    Field
//	------  ----    -----
//	0       8       Seconds since Unix epoch (int64)
//	8       4       Nanoseconds (int32, 0-999999999)
type Timestamp struct {
	Seconds     int64
	Nanoseconds int32
}

// NewTimestamp creates a Timestamp from a time.Time value.
func NewTimestamp(t time.Time) Timestamp {
	return Timestamp{
		Seconds:     t.Unix(),
		Nanoseconds: int32(t.Nanosecond()),
	}
}

// Time converts the Timestamp to a time.Time value.
func (ts Timestamp) Time() time.Time {
	return time.Unix(ts.Seconds, int64(ts.Nanoseconds))
}

// MarshalBinary encodes the timestamp to binary format.
func (ts Timestamp) MarshalBinary() ([]byte, error) {
	buf := make([]byte, TimestampSize)
	binary.BigEndian.PutUint64(buf[0:8], uint64(ts.Seconds))
	binary.BigEndian.PutUint32(buf[8:12], uint32(ts.Nanoseconds))
	return buf, nil
}

// UnmarshalBinary decodes the timestamp from binary format.
func (ts *Timestamp) UnmarshalBinary(data []byte) error {
	if len(data) < TimestampSize {
		return ErrInvalidTimestamp
	}
	ts.Seconds = int64(binary.BigEndian.Uint64(data[0:8]))
	ts.Nanoseconds = int32(binary.BigEndian.Uint32(data[8:12]))
	return nil
}

// AttributeBuilder provides methods for building common X2/X3 attributes.
// It wraps TLVEncoder with domain-specific methods.
type AttributeBuilder struct {
	encoder TLVEncoder
}

// NewAttributeBuilder creates a new AttributeBuilder.
func NewAttributeBuilder() *AttributeBuilder {
	return &AttributeBuilder{}
}

// Timestamp creates a timestamp attribute from a time.Time value.
func (b *AttributeBuilder) Timestamp(t time.Time) TLVAttribute {
	ts := NewTimestamp(t)
	data, _ := ts.MarshalBinary() // Cannot fail for valid Timestamp
	return TLVAttribute{Type: AttrTimestamp, Value: data}
}

// TimestampNow creates a timestamp attribute with the current time.
func (b *AttributeBuilder) TimestampNow() TLVAttribute {
	return b.Timestamp(time.Now())
}

// SequenceNumber creates a sequence number attribute.
func (b *AttributeBuilder) SequenceNumber(seq uint32) TLVAttribute {
	return b.encoder.EncodeUint32(AttrSequenceNumber, seq)
}

// SourceIPv4 creates a source IPv4 address attribute.
func (b *AttributeBuilder) SourceIPv4(addr netip.Addr) (TLVAttribute, error) {
	if !addr.Is4() {
		return TLVAttribute{}, ErrInvalidIPv4
	}
	ip4 := addr.As4()
	return TLVAttribute{Type: AttrSourceIPv4, Value: ip4[:]}, nil
}

// DestIPv4 creates a destination IPv4 address attribute.
func (b *AttributeBuilder) DestIPv4(addr netip.Addr) (TLVAttribute, error) {
	if !addr.Is4() {
		return TLVAttribute{}, ErrInvalidIPv4
	}
	ip4 := addr.As4()
	return TLVAttribute{Type: AttrDestIPv4, Value: ip4[:]}, nil
}

// SourceIPv6 creates a source IPv6 address attribute.
func (b *AttributeBuilder) SourceIPv6(addr netip.Addr) (TLVAttribute, error) {
	if !addr.Is6() {
		return TLVAttribute{}, ErrInvalidIPv6
	}
	ip6 := addr.As16()
	return TLVAttribute{Type: AttrSourceIPv6, Value: ip6[:]}, nil
}

// DestIPv6 creates a destination IPv6 address attribute.
func (b *AttributeBuilder) DestIPv6(addr netip.Addr) (TLVAttribute, error) {
	if !addr.Is6() {
		return TLVAttribute{}, ErrInvalidIPv6
	}
	ip6 := addr.As16()
	return TLVAttribute{Type: AttrDestIPv6, Value: ip6[:]}, nil
}

// SourceIP creates a source IP address attribute (IPv4 or IPv6).
func (b *AttributeBuilder) SourceIP(addr netip.Addr) (TLVAttribute, error) {
	if addr.Is4() {
		return b.SourceIPv4(addr)
	}
	if addr.Is6() {
		return b.SourceIPv6(addr)
	}
	return TLVAttribute{}, ErrInvalidIPAddress
}

// DestIP creates a destination IP address attribute (IPv4 or IPv6).
func (b *AttributeBuilder) DestIP(addr netip.Addr) (TLVAttribute, error) {
	if addr.Is4() {
		return b.DestIPv4(addr)
	}
	if addr.Is6() {
		return b.DestIPv6(addr)
	}
	return TLVAttribute{}, ErrInvalidIPAddress
}

// SourcePort creates a source port attribute.
func (b *AttributeBuilder) SourcePort(port uint16) TLVAttribute {
	return b.encoder.EncodeUint16(AttrSourcePort, port)
}

// DestPort creates a destination port attribute.
func (b *AttributeBuilder) DestPort(port uint16) TLVAttribute {
	return b.encoder.EncodeUint16(AttrDestPort, port)
}

// IPProtocol creates an IP protocol number attribute.
func (b *AttributeBuilder) IPProtocol(proto uint8) TLVAttribute {
	return b.encoder.EncodeUint8(AttrIPProtocol, proto)
}

// TargetIdentifier creates a target identifier attribute.
func (b *AttributeBuilder) TargetIdentifier(id string) TLVAttribute {
	return b.encoder.EncodeString(AttrTargetIdentifier, id)
}

// TrafficDirection creates a direction attribute.
func (b *AttributeBuilder) TrafficDirection(dir Direction) TLVAttribute {
	return b.encoder.EncodeUint8(AttrDirection, uint8(dir))
}

// CorrelationAttrID creates a correlation ID attribute.
// Note: This is different from the header correlation ID field.
// This attribute is used for additional correlation within the PDU.
func (b *AttributeBuilder) CorrelationAttrID(id uint64) TLVAttribute {
	// Use a dedicated attribute type if needed, for now reuse timestamp type
	// for the ID. In practice, you'd define AttrCorrelationID.
	return b.encoder.EncodeUint64(AttrTimestamp, id)
}

// AttributeParser provides methods for parsing common X2/X3 attributes.
type AttributeParser struct {
	decoder TLVDecoder
}

// NewAttributeParser creates a new AttributeParser.
func NewAttributeParser() *AttributeParser {
	return &AttributeParser{}
}

// ParseTimestamp extracts a timestamp from an attribute.
func (p *AttributeParser) ParseTimestamp(attr *TLVAttribute) (time.Time, error) {
	if attr.Type != AttrTimestamp {
		return time.Time{}, ErrInvalidAttrLength
	}
	var ts Timestamp
	if err := ts.UnmarshalBinary(attr.Value); err != nil {
		return time.Time{}, err
	}
	return ts.Time(), nil
}

// ParseSequenceNumber extracts a sequence number from an attribute.
func (p *AttributeParser) ParseSequenceNumber(attr *TLVAttribute) (uint32, error) {
	if attr.Type != AttrSequenceNumber {
		return 0, ErrInvalidAttrLength
	}
	return p.decoder.DecodeUint32(attr)
}

// ParseSourceIPv4 extracts a source IPv4 address from an attribute.
func (p *AttributeParser) ParseSourceIPv4(attr *TLVAttribute) (netip.Addr, error) {
	if attr.Type != AttrSourceIPv4 || len(attr.Value) != IPv4Size {
		return netip.Addr{}, ErrInvalidIPv4
	}
	return netip.AddrFrom4([4]byte(attr.Value)), nil
}

// ParseDestIPv4 extracts a destination IPv4 address from an attribute.
func (p *AttributeParser) ParseDestIPv4(attr *TLVAttribute) (netip.Addr, error) {
	if attr.Type != AttrDestIPv4 || len(attr.Value) != IPv4Size {
		return netip.Addr{}, ErrInvalidIPv4
	}
	return netip.AddrFrom4([4]byte(attr.Value)), nil
}

// ParseSourceIPv6 extracts a source IPv6 address from an attribute.
func (p *AttributeParser) ParseSourceIPv6(attr *TLVAttribute) (netip.Addr, error) {
	if attr.Type != AttrSourceIPv6 || len(attr.Value) != IPv6Size {
		return netip.Addr{}, ErrInvalidIPv6
	}
	return netip.AddrFrom16([16]byte(attr.Value)), nil
}

// ParseDestIPv6 extracts a destination IPv6 address from an attribute.
func (p *AttributeParser) ParseDestIPv6(attr *TLVAttribute) (netip.Addr, error) {
	if attr.Type != AttrDestIPv6 || len(attr.Value) != IPv6Size {
		return netip.Addr{}, ErrInvalidIPv6
	}
	return netip.AddrFrom16([16]byte(attr.Value)), nil
}

// ParseSourcePort extracts a source port from an attribute.
func (p *AttributeParser) ParseSourcePort(attr *TLVAttribute) (uint16, error) {
	if attr.Type != AttrSourcePort {
		return 0, ErrInvalidAttrLength
	}
	return p.decoder.DecodeUint16(attr)
}

// ParseDestPort extracts a destination port from an attribute.
func (p *AttributeParser) ParseDestPort(attr *TLVAttribute) (uint16, error) {
	if attr.Type != AttrDestPort {
		return 0, ErrInvalidAttrLength
	}
	return p.decoder.DecodeUint16(attr)
}

// ParseIPProtocol extracts an IP protocol number from an attribute.
func (p *AttributeParser) ParseIPProtocol(attr *TLVAttribute) (uint8, error) {
	if attr.Type != AttrIPProtocol {
		return 0, ErrInvalidAttrLength
	}
	return p.decoder.DecodeUint8(attr)
}

// ParseTargetIdentifier extracts a target identifier from an attribute.
func (p *AttributeParser) ParseTargetIdentifier(attr *TLVAttribute) (string, error) {
	if attr.Type != AttrTargetIdentifier {
		return "", ErrInvalidAttrLength
	}
	return p.decoder.DecodeString(attr), nil
}

// ParseDirection extracts a direction from an attribute.
func (p *AttributeParser) ParseDirection(attr *TLVAttribute) (Direction, error) {
	if attr.Type != AttrDirection {
		return DirectionUnknown, ErrInvalidAttrLength
	}
	val, err := p.decoder.DecodeUint8(attr)
	return Direction(val), err
}

// FindAttribute searches for an attribute by type in a slice of attributes.
func FindAttribute(attrs []TLVAttribute, attrType AttributeType) *TLVAttribute {
	for i := range attrs {
		if attrs[i].Type == attrType {
			return &attrs[i]
		}
	}
	return nil
}

// FindAllAttributes returns all attributes matching the given type.
func FindAllAttributes(attrs []TLVAttribute, attrType AttributeType) []TLVAttribute {
	var result []TLVAttribute
	for _, attr := range attrs {
		if attr.Type == attrType {
			result = append(result, attr)
		}
	}
	return result
}
