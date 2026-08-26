//go:build li

package x1

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

// capabilityError preserves the ETSI error class while keeping all
// enforcement-affecting feature checks in one fail-closed layer.
type capabilityError struct {
	code    int
	details string
}

func (e *capabilityError) Error() string { return e.details }

func unsupportedCapability(format string, args ...any) *capabilityError {
	return &capabilityError{code: ErrorCodeTargetNotSupported, details: fmt.Sprintf(format, args...)}
}

func invalidCapability(format string, args ...any) *capabilityError {
	return &capabilityError{code: ErrorCodeRequestSyntaxError, details: fmt.Sprintf(format, args...)}
}

func validateTaskCapabilities(details *schema.TaskDetails, modification bool) *capabilityError {
	if details == nil {
		return nil
	}
	if details.ProductID != nil || details.CorrelationID != nil ||
		(details.ListOfServiceTypes != nil && len(details.ListOfServiceTypes.ServiceType) != 0) ||
		len(details.TaskDetailsExtensions) != 0 {
		return unsupportedCapability("unsupported task scoping capability")
	}
	if hasTrafficPolicyReferences(details.ListOfTrafficPolicyReferences) {
		return unsupportedCapability("traffic policy references are not supported")
	}
	if details.ListOfMediationDetails != nil {
		for i, mediation := range details.ListOfMediationDetails.MediationDetails {
			if mediation == nil {
				continue
			}
			if hasTrafficPolicyReferences(mediation.ListOfTrafficPolicyReferences) {
				return unsupportedCapability("mediation entry %d uses unsupported traffic policy references", i)
			}
			// lippycat currently models one task-level LIID (the XID), delivery
			// type, and DID set. Accepting mediation-level overrides would make
			// the acknowledgement claim semantics that are never enforced.
			if mediation.LIID != nil {
				return unsupportedCapability("mediation entry %d uses an unsupported mediation-level LIID", i)
			}
			if mediation.DeliveryType != "" {
				return unsupportedCapability("mediation entry %d uses an unsupported mediation-level delivery type", i)
			}
			if mediation.ListOfDIDs != nil && len(mediation.ListOfDIDs.DId) != 0 {
				return unsupportedCapability("mediation entry %d uses unsupported mediation-level destination IDs", i)
			}
			if mediation.ServiceScopingOptions != nil && len(mediation.ServiceScopingOptions.ServiceScopingOptions) != 0 {
				return unsupportedCapability("mediation entry %d uses unsupported service scoping", i)
			}
			if len(mediation.MediationDetailsExtensions) != 0 {
				return unsupportedCapability("mediation entry %d uses unsupported extensions", i)
			}
		}
	}
	if details.TargetIdentifiers == nil {
		return nil
	}
	if modification && len(details.TargetIdentifiers.TargetIdentifier) == 0 {
		return invalidCapability("target identifier list must not be empty")
	}
	for i, target := range details.TargetIdentifiers.TargetIdentifier {
		if target == nil {
			return invalidCapability("target identifier %d is nil", i)
		}
		if err := validateTargetChoice(target); err != nil {
			return err
		}
	}
	return nil
}

func hasTrafficPolicyReferences(refs *schema.ListOfTrafficPolicyReferences) bool {
	return refs != nil && len(refs.TrafficPolicyReference) != 0
}

func validateTargetChoice(target *schema.TargetIdentifier) *capabilityError {
	populated := 0
	for _, present := range []bool{
		target.E164Number != nil, target.Imsi != nil, target.Imei != nil, target.MacAddress != nil,
		target.Ipv4Address != nil, target.Ipv6Address != nil, target.Ipv4Cidr != nil, target.Ipv6Cidr != nil,
		target.TcpPort != nil, target.TcpPortRange != nil, target.TcpPortList != nil,
		target.UdpPort != nil, target.UdpPortRange != nil, target.UdpPortList != nil,
		target.EmailAddress != nil, target.InternationalizedEmailAddress != nil, target.SipUri != nil,
		target.TelUri != nil, target.H323Uri != nil, target.Impu != nil, target.Impi != nil,
		target.Nai != nil, target.RadiusAttribute != nil, target.GtpuTunnelId != nil,
		target.GtpcTunnelId != nil, target.CallPartyRole != nil, target.NonLocalIdentifier != nil,
		target.Supiimsi != nil, target.Supinai != nil, target.Suci != nil, target.PeiImei != nil,
		target.PeiImeiCheckDigit != nil, target.PeiImeisv != nil, target.GpsiMsisdn != nil,
		target.GpsiNai != nil, target.Eui64 != nil, target.ServiceAccessIdentifier != nil,
		target.HashedIdentifier != nil, target.TargetIdentifierExtension != nil, target.Vrf != nil,
	} {
		if present {
			populated++
		}
	}
	if populated != 1 {
		return invalidCapability("target identifier choice has %d populated members; exactly one is required", populated)
	}

	switch {
	case target.SipUri != nil, target.TelUri != nil, target.E164Number != nil, target.Nai != nil:
		var value string
		switch {
		case target.SipUri != nil:
			value = string(*target.SipUri)
		case target.TelUri != nil:
			value = string(*target.TelUri)
		case target.E164Number != nil:
			value = string(*target.E164Number)
		default:
			value = string(*target.Nai)
		}
		if strings.TrimSpace(value) == "" {
			return invalidCapability("target identifier value is empty")
		}
		return nil
	case target.Ipv4Address != nil:
		addr, err := netip.ParseAddr(string(*target.Ipv4Address))
		if err != nil || !addr.Is4() {
			return invalidCapability("invalid IPv4 target")
		}
		return unsupportedCapability("IPv4 targets require raw-IP interception, whose correlated IRI/CC session model is not implemented")
	case target.Ipv6Address != nil:
		addr, err := netip.ParseAddr(string(*target.Ipv6Address))
		if err != nil || !addr.Is6() {
			return invalidCapability("invalid IPv6 target")
		}
		return unsupportedCapability("IPv6 targets require raw-IP interception, whose correlated IRI/CC session model is not implemented")
	case target.Ipv4Cidr != nil:
		if target.Ipv4Cidr.IPv4CIDR == nil {
			return invalidCapability("empty IPv4 CIDR target")
		}
		prefix, err := netip.ParsePrefix(*target.Ipv4Cidr.IPv4CIDR)
		if err != nil || !prefix.Addr().Is4() {
			return invalidCapability("invalid IPv4 CIDR target")
		}
		return unsupportedCapability("IPv4 CIDR targets require raw-IP interception, whose correlated IRI/CC session model is not implemented")
	case target.Ipv6Cidr != nil:
		prefix, err := netip.ParsePrefix(string(*target.Ipv6Cidr))
		if err != nil || !prefix.Addr().Is6() {
			return invalidCapability("invalid IPv6 CIDR target")
		}
		return unsupportedCapability("IPv6 CIDR targets require raw-IP interception, whose correlated IRI/CC session model is not implemented")
	default:
		return unsupportedCapability("target identifier type cannot be converted to an exact lippycat filter")
	}
}

func validateDestinationCapabilities(details *schema.DestinationDetails, modification bool) *capabilityError {
	if details == nil {
		return nil
	}
	if len(details.DestinationDetailsExtensions) != 0 {
		return &capabilityError{code: ErrorCodeDeliveryNotPossible, details: "destination extensions are not supported"}
	}
	if details.DeliveryType == "" {
		if !modification {
			return invalidCapability("missing destination delivery type")
		}
	} else if parseDeliveryType(details.DeliveryType) == 0 {
		return &capabilityError{code: ErrorCodeDeliveryTypeNotSupport, details: "unsupported destination delivery type: " + details.DeliveryType}
	}
	if details.DeliveryAddress == nil {
		return nil
	}
	da := details.DeliveryAddress
	choices := 0
	for _, present := range []bool{da.IpAddressAndPort != nil, da.E164Number != nil, da.Uri != nil, da.EmailAddress != nil} {
		if present {
			choices++
		}
	}
	if choices != 1 {
		return invalidCapability("delivery address choice has %d populated members; exactly one is required", choices)
	}
	if da.IpAddressAndPort == nil {
		return &capabilityError{code: ErrorCodeDeliveryNotPossible, details: "only IP address and TCP port destinations are supported"}
	}
	ipap := da.IpAddressAndPort
	if ipap.Address == nil || ipap.Port == nil {
		return invalidCapability("destination requires an IP address and TCP port")
	}
	addressChoices := 0
	if ipap.Address.IPv4Address != nil {
		addressChoices++
	}
	if ipap.Address.IPv6Address != nil {
		addressChoices++
	}
	if addressChoices != 1 {
		return invalidCapability("destination IP address choice has %d populated members; exactly one is required", addressChoices)
	}
	if ipap.Port.TCPPort == nil || ipap.Port.UDPPort != nil {
		return &capabilityError{code: ErrorCodeDeliveryNotPossible, details: "destination requires exactly one TCP port"}
	}
	if *ipap.Port.TCPPort < 1 || *ipap.Port.TCPPort > 65535 {
		return invalidCapability("destination TCP port is out of range")
	}
	return nil
}
