package x2x3

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/types"
)

// CaptureSourceOwner identifies the organization defining this proprietary
// attribute, as an ASCII FQDN per TS 103 221-2 clause 5.3.5.
const CaptureSourceOwner = "lippy.cat"

// Version 2 wire format (network byte order): owner length u8, owner ASCII,
// subtype u8 (1), version u8 (2), flags u8 (bit 0: domain known), node length u16,
// interface length u16, domain u32, node UTF-8 bytes, interface UTF-8 bytes.
// No padding or trailing bytes are permitted. Each identifier is 1..4096 bytes,
// and the whole value must fit the uint16-length TLV. Unknown domain is zero.
const captureSourceOwnerSize = 1 + len(CaptureSourceOwner)
const captureSourceHeaderSize = captureSourceOwnerSize + 11
const captureSourceSubtype = 1
const captureSourceVersion = 2

// MaxCaptureSourceAttributeBytes bounds the complete private attribute value.
const MaxCaptureSourceAttributeBytes = captureSourceHeaderSize + 2*types.MaxCaptureSourceStringBytes

// ErrInvalidCaptureSourceAttribute rejects malformed or unsupported source data.
var ErrInvalidCaptureSourceAttribute = errors.New("invalid capture-source attribute")

// EncodeCaptureSource freezes a validated source in a proprietary TLV.
func EncodeCaptureSource(source types.CaptureSource) (TLVAttribute, error) {
	domain, known := source.ObservationDomain()
	if _, err := types.NewCaptureSource(source.NodeID(), source.Interface(), domain, known); err != nil {
		return TLVAttribute{}, fmt.Errorf("%w: %w", ErrInvalidCaptureSourceAttribute, err)
	}
	size := uint64(captureSourceHeaderSize) + uint64(len(source.NodeID())) + uint64(len(source.Interface()))
	if size > 0xffff || size > uint64(MaxCaptureSourceAttributeBytes) {
		return TLVAttribute{}, ErrInvalidCaptureSourceAttribute
	}
	value := make([]byte, int(size))
	value[0] = byte(len(CaptureSourceOwner))
	copy(value[1:], CaptureSourceOwner)
	offset := captureSourceOwnerSize
	value[offset], value[offset+1] = captureSourceSubtype, captureSourceVersion
	if known {
		value[offset+2] = 1
	}
	binary.BigEndian.PutUint16(value[offset+3:], uint16(len(source.NodeID())))
	binary.BigEndian.PutUint16(value[offset+5:], uint16(len(source.Interface())))
	binary.BigEndian.PutUint32(value[offset+7:], domain)
	copy(value[captureSourceHeaderSize:], source.NodeID())
	copy(value[captureSourceHeaderSize+len(source.NodeID()):], source.Interface())
	return TLVAttribute{Type: AttrProprietary, Value: value}, nil
}

// DecodeCaptureSource ignores absent metadata, malformed owner fields, unrelated
// owners and unknown subtypes. Duplicate recognized attributes and malformed or
// unsupported capture-source bodies are errors. The original NUL-prefixed draft
// is not recognized; journaled products are never rewritten here.
func DecodeCaptureSource(pdu *PDU) (types.CaptureSource, bool, error) {
	if pdu == nil {
		return types.CaptureSource{}, false, ErrInvalidCaptureSourceAttribute
	}
	var result types.CaptureSource
	found := false
	for _, attr := range pdu.Attributes {
		if attr.Type != AttrProprietary {
			continue
		}
		value := attr.Value
		if len(value) == 0 || value[0] == 0 || int(value[0]) > len(value)-1 {
			continue
		}
		offset := 1 + int(value[0])
		// Only this exact owner can identify capture-source metadata. Invalid
		// ASCII/FQDN spellings cannot match it and remain unrelated values.
		if string(value[1:offset]) != CaptureSourceOwner {
			continue
		}
		if len(value) == offset {
			return types.CaptureSource{}, false, ErrInvalidCaptureSourceAttribute
		}
		if value[offset] != captureSourceSubtype {
			continue
		}
		if found {
			return types.CaptureSource{}, false, fmt.Errorf("%w: duplicate", ErrInvalidCaptureSourceAttribute)
		}
		found = true
		if len(value) < captureSourceHeaderSize || len(value) > MaxCaptureSourceAttributeBytes {
			return types.CaptureSource{}, false, ErrInvalidCaptureSourceAttribute
		}
		if value[offset+1] != captureSourceVersion || value[offset+2] & ^byte(1) != 0 {
			return types.CaptureSource{}, false, ErrInvalidCaptureSourceAttribute
		}
		nodeLen := int(binary.BigEndian.Uint16(value[offset+3:]))
		intfLen := int(binary.BigEndian.Uint16(value[offset+5:]))
		if nodeLen > types.MaxCaptureSourceStringBytes || intfLen > types.MaxCaptureSourceStringBytes || uint64(captureSourceHeaderSize)+uint64(nodeLen)+uint64(intfLen) != uint64(len(value)) {
			return types.CaptureSource{}, false, ErrInvalidCaptureSourceAttribute
		}
		domain := binary.BigEndian.Uint32(value[offset+7:])
		var err error
		result, err = types.NewCaptureSource(string(value[captureSourceHeaderSize:captureSourceHeaderSize+nodeLen]), string(value[captureSourceHeaderSize+nodeLen:]), domain, value[offset+2] == 1)
		if err != nil {
			return types.CaptureSource{}, false, fmt.Errorf("%w: %w", ErrInvalidCaptureSourceAttribute, err)
		}
	}
	return result, found, nil
}

// DecodeProductCaptureSource inspects one complete live or journaled product.
// It never synthesizes metadata into historical product bytes.
func DecodeProductCaptureSource(data []byte) (types.CaptureSource, bool, error) {
	var header PDUHeader
	if err := header.UnmarshalBinary(data); err != nil {
		return types.CaptureSource{}, false, err
	}
	if uint64(header.HeaderLength)+uint64(header.PayloadLength) != uint64(len(data)) {
		return types.CaptureSource{}, false, ErrInvalidCaptureSourceAttribute
	}
	// Bound attribute decoding to the header. A TLV must never borrow bytes from
	// payload to satisfy its length, even if its source namespace is unrelated.
	for offset := uint64(HeaderMinSize); offset < uint64(header.HeaderLength); {
		if uint64(header.HeaderLength)-offset < TLVHeaderSize {
			return types.CaptureSource{}, false, ErrInvalidCaptureSourceAttribute
		}
		size := uint64(binary.BigEndian.Uint16(data[offset+2:])) + TLVHeaderSize
		if size > uint64(header.HeaderLength)-offset {
			return types.CaptureSource{}, false, ErrInvalidCaptureSourceAttribute
		}
		offset += size
	}
	var product PDU
	if err := product.UnmarshalBinary(data); err != nil {
		return types.CaptureSource{}, false, err
	}
	return DecodeCaptureSource(&product)
}

func packetCaptureSource(pkt *types.PacketDisplay) (TLVAttribute, error) {
	source, err := types.NewCaptureSource(pkt.NodeID, pkt.Interface, pkt.ObservationDomain, pkt.ObservationDomainKnown)
	if err != nil {
		return TLVAttribute{}, err
	}
	return EncodeCaptureSource(source)
}
