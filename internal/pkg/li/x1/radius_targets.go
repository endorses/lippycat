//go:build li

package x1

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
	"github.com/endorses/lippycat/internal/pkg/radius"
)

// ValidateRADIUSTaskDetails applies X1 capability checks to RADIUS ADMF
// responses too, so restoration cannot discard unsupported scope or criteria.
func ValidateRADIUSTaskDetails(details *schema.TaskDetails) error {
	if details == nil || details.TargetIdentifiers == nil {
		return nil
	}
	for _, target := range details.TargetIdentifiers.TargetIdentifier {
		if target != nil && (target.Nai != nil || target.MacAddress != nil || target.RadiusAttribute != nil) {
			if err := validateTaskCapabilities(details, false); err != nil {
				return err
			}
			return nil
		}
	}
	return nil
}

// ParseRADIUSTarget validates and converts the supported RADIUS X1 choices.
// It is also used by ADMF restoration, preserving the same byte semantics.
func ParseRADIUSTarget(target *schema.TargetIdentifier) (*TargetIdentity, error) {
	if target == nil {
		return nil, fmt.Errorf("nil RADIUS target")
	}
	if err := validateTargetChoice(target); err != nil {
		return nil, err
	}
	return parseRADIUSTarget(target)
}

func parseRADIUSTarget(target *schema.TargetIdentifier) (*TargetIdentity, error) {
	switch {
	case target.Nai != nil:
		value := string(*target.Nai)
		if err := radius.ValidateNAI(value); err != nil {
			return nil, err
		}
		return &TargetIdentity{Type: TargetTypeNAI, Value: value}, nil
	case target.MacAddress != nil:
		// TS 103 280 MACAddress is an xs:token of six lowercase colon-separated octets.
		value := strings.Trim(string(*target.MacAddress), " \t\r\n")
		if len(value) != 17 {
			return nil, fmt.Errorf("macAddress requires six lowercase colon-separated octets")
		}
		for i, c := range []byte(value) {
			if i%3 == 2 {
				if c != ':' {
					return nil, fmt.Errorf("invalid macAddress separator")
				}
			} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return nil, fmt.Errorf("invalid macAddress hex digit")
			}
		}
		return &TargetIdentity{Type: TargetTypeMACAddress, Value: strings.ToUpper(strings.ReplaceAll(value, ":", ""))}, nil
	case target.RadiusAttribute != nil:
		predicate, err := radius.CompilePredicate(radius.PredicateSpec{Kind: radius.PredicateAttribute, Value: *target.RadiusAttribute})
		if err != nil {
			return nil, err
		}
		return &TargetIdentity{Type: TargetTypeRADIUSAttribute, Value: predicate.Spec().Value}, nil
	default:
		return nil, fmt.Errorf("not a supported RADIUS target")
	}
}

func macSchemaValue(value string) string {
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != 6 {
		return ""
	}
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}
