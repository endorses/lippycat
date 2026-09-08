// Package radius provides owned, validated observations of visible UDP RADIUS.
package radius

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	MinMessageLength = 20
	MaxMessageLength = 4096
	DSLForumVendorID = 3561
)

var (
	ErrMalformed   = errors.New("malformed RADIUS message")
	ErrUnsupported = errors.New("unsupported RADIUS message")
)

// Message retains the exact declared message, excluding UDP trailing padding.
// Raw and attribute slices share owned storage, independent of the input buffer.
// Treat all fields as immutable after publication; clone before modifying them.
type Message struct {
	Code          uint8
	Identifier    uint8
	Length        uint16
	Authenticator [16]byte
	Raw           []byte
	Attributes    []Attribute
}

// Attribute preserves each AVP, including unknowns and repeats, in wire order.
// VendorAttributes is populated only for the validated DSL Forum vendor format.
type Attribute struct {
	Type             uint8
	Value            []byte
	Raw              []byte
	VendorID         uint32
	VendorAttributes []VendorAttribute
}

type VendorAttribute struct {
	Type  uint8
	Value []byte
	Raw   []byte
}

// Decode explicitly decodes one complete UDP payload regardless of service port.
// The caller must first reject fragments and truncated IP/UDP datagrams. No
// partial message escapes on any error, so early identity AVPs cannot bypass a
// malformed later attribute. This function owns no counters or attribution state.
func Decode(payload []byte) (*Message, error) {
	if len(payload) < MinMessageLength {
		return nil, fmt.Errorf("%w: header has %d bytes", ErrMalformed, len(payload))
	}
	length := int(binary.BigEndian.Uint16(payload[2:4]))
	if length < MinMessageLength || length > MaxMessageLength || length > len(payload) {
		return nil, fmt.Errorf("%w: declared length %d with %d captured bytes", ErrMalformed, length, len(payload))
	}
	// Bound and copy before calling gopacket: its padding treatment and borrowed
	// BaseLayer contents do not satisfy our capture ownership contract.
	raw := append([]byte(nil), payload[:length]...)
	var decoded layers.RADIUS
	if err := decoded.DecodeFromBytes(raw, gopacket.NilDecodeFeedback); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	message := &Message{
		Code: uint8(decoded.Code), Identifier: uint8(decoded.Identifier),
		Length: uint16(decoded.Length), Authenticator: [16]byte(decoded.Authenticator), Raw: raw,
	}
	// Do not use gopacket's attribute list: it omits zero-value AVPs. Its
	// decoder has already checked every outer boundary, but not vendor data.
	for offset := MinMessageLength; offset < length; {
		size := int(raw[offset+1])
		avp := raw[offset : offset+size : offset+size]
		attribute := Attribute{Type: avp[0], Raw: avp, Value: avp[2:]}
		if err := validateAttribute(&attribute); err != nil {
			return nil, fmt.Errorf("%w: attribute at offset %d: %v", ErrMalformed, offset, err)
		}
		message.Attributes = append(message.Attributes, attribute)
		offset += size
	}
	switch message.Code {
	case 1, 2, 3, 4, 5, 11:
		return message, nil
	default:
		return nil, fmt.Errorf("%w: code %d", ErrUnsupported, message.Code)
	}
}

func validateAttribute(attribute *Attribute) error {
	switch attribute.Type {
	case 4: // NAS-IP-Address
		if len(attribute.Value) != 4 {
			return fmt.Errorf("NAS-IP-Address requires four value bytes")
		}
	case 95: // NAS-IPv6-Address
		if len(attribute.Value) != 16 {
			return fmt.Errorf("NAS-IPv6-Address requires sixteen value bytes")
		}
	case 26:
		if len(attribute.Value) < 5 || attribute.Value[0] != 0 {
			return fmt.Errorf("invalid vendor header or missing vendor data")
		}
		attribute.VendorID = binary.BigEndian.Uint32(attribute.Value[:4])
		if attribute.VendorID != DSLForumVendorID {
			return nil // Other vendors may use different inner encodings.
		}
		for data := attribute.Value[4:]; len(data) > 0; {
			if len(data) < 2 || int(data[1]) < 2 || int(data[1]) > len(data) {
				return fmt.Errorf("invalid DSL Forum sub-attribute boundary")
			}
			size := int(data[1])
			if data[0] == 1 && (size < 3 || size > 65) {
				return fmt.Errorf("Agent-Circuit-Id requires 1–63 value bytes")
			}
			raw := data[:size:size]
			attribute.VendorAttributes = append(attribute.VendorAttributes, VendorAttribute{
				Type: raw[0], Raw: raw, Value: raw[2:],
			})
			data = data[size:]
		}
	}
	return nil
}
