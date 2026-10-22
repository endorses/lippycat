//go:build li

package li

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/radius"
)

// MatchedTargetFormat selects the representation of conditional attribute 17.
type MatchedTargetFormat string

const (
	MatchedTargetFormatBare             MatchedTargetFormat = "bare"
	MatchedTargetFormatTargetIdentifier MatchedTargetFormat = "target-identifier"
)

// ParseMatchedTargetFormat preserves compatibility for an unset configuration.
func ParseMatchedTargetFormat(value string) (MatchedTargetFormat, error) {
	switch MatchedTargetFormat(value) {
	case "", MatchedTargetFormatBare:
		return MatchedTargetFormatBare, nil
	case MatchedTargetFormatTargetIdentifier:
		return MatchedTargetFormatTargetIdentifier, nil
	default:
		return "", errors.New("matched target format must be bare or target-identifier")
	}
}

var ErrInvalidTargetIdentifier = errors.New("invalid target identifier")

// MarshalTargetIdentifier returns the UTF-8 contents of the X1 TargetIdentifier
// choice for TS 103 221-2 attribute 17, without an enclosing element. An empty
// result deliberately omits a username whose provisioned schema type is unknown.
// Values are validated independently of provisioning; serialization cannot add
// support for a target family at the authorization boundary.
func MarshalTargetIdentifier(target TargetIdentity) (string, error) {
	if target.Type == TargetTypeUsername {
		return "", nil
	}
	name, value, err := targetIdentifierValue(target)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidTargetIdentifier, target.Type)
	}
	if !validTargetXML(value) {
		return "", fmt.Errorf("%w: invalid XML text", ErrInvalidTargetIdentifier)
	}
	var output bytes.Buffer
	encoder := xml.NewEncoder(&output)
	start := xml.StartElement{Name: xml.Name{Local: name}}
	if target.Type == TargetTypeIPv4CIDR {
		// IPCIDR is defined in the common schema; its choice child is qualified
		// there even though the outer ipv4Cidr belongs to X1.
		child := struct {
			Value string `xml:"http://uri.etsi.org/03280/common/2017/07 IPv4CIDR"`
		}{value}
		err = encoder.EncodeElement(child, start)
	} else {
		err = encoder.EncodeElement(value, start)
	}
	if err != nil {
		return "", fmt.Errorf("serialize target identifier: %w", err)
	}
	return output.String(), nil
}

func targetIdentifierValue(target TargetIdentity) (string, string, error) {
	value := target.Value
	invalid := func() (string, string, error) { return "", "", ErrInvalidTargetIdentifier }
	switch target.Type {
	case TargetTypeSIPURI:
		body, ok := strings.CutPrefix(value, "sip:")
		if !ok {
			body, ok = strings.CutPrefix(value, "sips:")
		}
		if !ok || !validTargetURI(body) {
			return invalid()
		}
		return "sipUri", value, nil
	case TargetTypeTELURI:
		// Compatibility with persisted identities that previously represented
		// e164Number as a TEL target containing bare digits or a leading '+'.
		if number := strings.TrimPrefix(value, "+"); schema.ValidE164Number(number) {
			return "e164Number", number, nil
		}
		body, ok := strings.CutPrefix(value, "tel:")
		if !ok || !validTargetURI(body) {
			return invalid()
		}
		return "telUri", value, nil
	case TargetTypeE164:
		if !schema.ValidE164Number(value) {
			return invalid()
		}
		return "e164Number", value, nil
	case TargetTypeNAI:
		if radius.ValidateNAI(value) != nil {
			return invalid()
		}
		return "nai", value, nil
	case TargetTypeIPv4Address, TargetTypeIPv6Address:
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return invalid()
		}
		if target.Type == TargetTypeIPv4Address {
			if !address.Is4() {
				return invalid()
			}
			return "ipv4Address", address.String(), nil
		}
		if !address.Is6() || address.Is4In6() {
			return invalid()
		}
		return "ipv6Address", expandedIPv6(address), nil
	case TargetTypeIPv4CIDR, TargetTypeIPv6CIDR:
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return invalid()
		}
		if target.Type == TargetTypeIPv4CIDR {
			if !prefix.Addr().Is4() {
				return invalid()
			}
			return "ipv4Cidr", prefix.String(), nil
		}
		// The bundled IPv6CIDR lexical type permits prefix lengths 1..128.
		if !prefix.Addr().Is6() || prefix.Addr().Is4In6() || prefix.Bits() == 0 {
			return invalid()
		}
		return "ipv6Cidr", fmt.Sprintf("%s/%d", expandedIPv6(prefix.Addr()), prefix.Bits()), nil
	case TargetTypeIMSI:
		if !targetDigits(value, 6, 15) {
			return invalid()
		}
		return "imsi", value, nil
	case TargetTypeIMEI:
		if !targetDigits(value, 14, 14) {
			return invalid()
		}
		return "imei", value, nil
	case TargetTypeMACAddress:
		if strings.Contains(value, ":") {
			if len(value) != 17 {
				return invalid()
			}
			for i := 2; i < len(value); i += 3 {
				if value[i] != ':' {
					return invalid()
				}
			}
			value = strings.ReplaceAll(value, ":", "")
		}
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != 6 {
			return invalid()
		}
		parts := make([]string, len(raw))
		for i, octet := range raw {
			parts[i] = fmt.Sprintf("%02x", octet)
		}
		return "macAddress", strings.Join(parts, ":"), nil
	case TargetTypeRADIUSAttribute:
		predicate, err := radius.CompilePredicate(radius.PredicateSpec{Kind: radius.PredicateAttribute, Value: value})
		if err != nil {
			return invalid()
		}
		return "radiusAttribute", predicate.Spec().Value, nil
	default:
		return invalid()
	}
}

func targetDigits(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// This is the character repertoire in the bundled SIPURI/TELURI XSD types.
func validTargetURI(value string) bool {
	if value == "" {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'()*+,-./:;=?@[]_~", c)) {
			return false
		}
	}
	return true
}

func validTargetXML(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if !(c == '\t' || c == '\n' || c == '\r' || c >= 0x20 && c <= 0xd7ff || c >= 0xe000 && c <= 0xfffd || c >= 0x10000 && c <= 0x10ffff) {
			return false
		}
	}
	return true
}

func expandedIPv6(address netip.Addr) string {
	raw := address.As16()
	parts := make([]string, 8)
	for i := range parts {
		parts[i] = fmt.Sprintf("%04x", binary.BigEndian.Uint16(raw[i*2:]))
	}
	return strings.Join(parts, ":")
}
