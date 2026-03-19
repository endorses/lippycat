//go:build li

package li

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/li/x1/schema"
)

// TaskResponseDetailsToInterceptTask converts an ETSI X1 TaskResponseDetails
// to an internal InterceptTask. This is used during state sync to restore
// tasks from ADMF query responses.
func TaskResponseDetailsToInterceptTask(details *schema.TaskResponseDetails) (*InterceptTask, error) {
	if details == nil {
		return nil, fmt.Errorf("task response details is nil")
	}

	td := details.TaskDetails
	if td == nil {
		return nil, fmt.Errorf("task details is nil")
	}

	if td.XId == nil {
		return nil, fmt.Errorf("task XID is nil")
	}

	// Parse XID.
	xid, err := uuid.Parse(string(*td.XId))
	if err != nil {
		return nil, fmt.Errorf("parse XID: %w", err)
	}

	// Extract target identifiers.
	targets, err := convertTargetIdentifiers(td.TargetIdentifiers)
	if err != nil {
		return nil, fmt.Errorf("convert target identifiers: %w", err)
	}

	// Parse delivery type.
	deliveryType, err := parseDeliveryTypeString(td.DeliveryType)
	if err != nil {
		return nil, fmt.Errorf("convert delivery type: %w", err)
	}

	// Extract destination IDs.
	destIDs, err := convertDestinationIDs(td.ListOfDIDs)
	if err != nil {
		return nil, fmt.Errorf("convert destination IDs: %w", err)
	}

	task := &InterceptTask{
		XID:            xid,
		Targets:        targets,
		DestinationIDs: destIDs,
		DeliveryType:   deliveryType,
	}

	// Parse implicit deactivation allowed.
	if td.ImplicitDeactivationAllowed != nil {
		task.ImplicitDeactivationAllowed = *td.ImplicitDeactivationAllowed
	}

	// Parse ProductID if present (stored as part of task metadata, but InterceptTask
	// does not have a ProductID field — this is noted for future extension).

	// Set status from TaskStatus.ProvisioningStatus if available.
	if details.TaskStatus != nil {
		task.Status = convertProvisioningStatus(details.TaskStatus.ProvisioningStatus)
	}

	return task, nil
}

// DestinationResponseDetailsToDestination converts an ETSI X1
// DestinationResponseDetails to an internal Destination.
func DestinationResponseDetailsToDestination(details *schema.DestinationResponseDetails) (*Destination, error) {
	if details == nil {
		return nil, fmt.Errorf("destination response details is nil")
	}

	dd := details.DestinationDetails
	if dd == nil {
		return nil, fmt.Errorf("destination details is nil")
	}

	if dd.DId == nil {
		return nil, fmt.Errorf("destination DID is nil")
	}

	// Parse DID.
	did, err := uuid.Parse(string(*dd.DId))
	if err != nil {
		return nil, fmt.Errorf("parse DID: %w", err)
	}

	// Extract delivery address.
	address, port, err := convertDeliveryAddress(dd.DeliveryAddress)
	if err != nil {
		return nil, fmt.Errorf("convert delivery address: %w", err)
	}

	dest := &Destination{
		DID:       did,
		Address:   address,
		Port:      port,
		X2Enabled: dd.DeliveryType == "X2Only" || dd.DeliveryType == "X2andX3",
		X3Enabled: dd.DeliveryType == "X3Only" || dd.DeliveryType == "X2andX3",
	}

	if dd.FriendlyName != nil {
		dest.Description = *dd.FriendlyName
	}

	return dest, nil
}

// convertTargetIdentifiers converts a list of ETSI target identifiers to
// internal TargetIdentity values.
func convertTargetIdentifiers(list *schema.ListOfTargetIdentifiers) ([]TargetIdentity, error) {
	if list == nil {
		return nil, nil
	}

	var targets []TargetIdentity
	for _, ti := range list.TargetIdentifier {
		if ti == nil {
			continue
		}

		target, err := convertTargetIdentifier(ti)
		if err != nil {
			return nil, err
		}
		if target != nil {
			targets = append(targets, *target)
		}
	}

	return targets, nil
}

// convertTargetIdentifier converts a single ETSI TargetIdentifier CHOICE to
// an internal TargetIdentity. The CHOICE fields are checked in priority order
// matching the server's parseTargetIdentifier logic.
func convertTargetIdentifier(ti *schema.TargetIdentifier) (*TargetIdentity, error) {
	if ti == nil {
		return nil, nil
	}

	// SIP URI
	if ti.SipUri != nil && *ti.SipUri != "" {
		return &TargetIdentity{
			Type:  TargetTypeSIPURI,
			Value: string(*ti.SipUri),
		}, nil
	}

	// TEL URI
	if ti.TelUri != nil && *ti.TelUri != "" {
		return &TargetIdentity{
			Type:  TargetTypeTELURI,
			Value: string(*ti.TelUri),
		}, nil
	}

	// E.164 Number — maps to TEL URI type (E.164 is essentially TEL URI without prefix).
	if ti.E164Number != nil && *ti.E164Number != "" {
		return &TargetIdentity{
			Type:  TargetTypeTELURI,
			Value: string(*ti.E164Number),
		}, nil
	}

	// IPv4 Address
	if ti.Ipv4Address != nil && *ti.Ipv4Address != "" {
		return &TargetIdentity{
			Type:  TargetTypeIPv4Address,
			Value: string(*ti.Ipv4Address),
		}, nil
	}

	// IPv6 Address
	if ti.Ipv6Address != nil && *ti.Ipv6Address != "" {
		return &TargetIdentity{
			Type:  TargetTypeIPv6Address,
			Value: string(*ti.Ipv6Address),
		}, nil
	}

	// IPv4 CIDR
	if ti.Ipv4Cidr != nil {
		if ti.Ipv4Cidr.IPv4CIDR != nil && *ti.Ipv4Cidr.IPv4CIDR != "" {
			return &TargetIdentity{
				Type:  TargetTypeIPv4CIDR,
				Value: *ti.Ipv4Cidr.IPv4CIDR,
			}, nil
		}
	}

	// IPv6 CIDR
	if ti.Ipv6Cidr != nil && *ti.Ipv6Cidr != "" {
		return &TargetIdentity{
			Type:  TargetTypeIPv6CIDR,
			Value: string(*ti.Ipv6Cidr),
		}, nil
	}

	// NAI (Network Access Identifier)
	if ti.Nai != nil && *ti.Nai != "" {
		return &TargetIdentity{
			Type:  TargetTypeNAI,
			Value: string(*ti.Nai),
		}, nil
	}

	return nil, fmt.Errorf("unsupported target identifier type")
}

// parseDeliveryTypeString parses an ETSI delivery type string to an internal DeliveryType.
func parseDeliveryTypeString(dt string) (DeliveryType, error) {
	switch dt {
	case "X2Only":
		return DeliveryX2Only, nil
	case "X3Only":
		return DeliveryX3Only, nil
	case "X2andX3":
		return DeliveryX2andX3, nil
	default:
		return 0, fmt.Errorf("unsupported delivery type: %q", dt)
	}
}

// convertDestinationIDs extracts destination UUIDs from a ListOfDids.
func convertDestinationIDs(list *schema.ListOfDids) ([]uuid.UUID, error) {
	if list == nil {
		return nil, nil
	}

	var destIDs []uuid.UUID
	for _, did := range list.DId {
		if did == nil {
			continue
		}
		id, err := uuid.Parse(string(*did))
		if err != nil {
			return nil, fmt.Errorf("invalid destination ID format: %w", err)
		}
		destIDs = append(destIDs, id)
	}

	return destIDs, nil
}

// convertProvisioningStatus maps an ETSI provisioning status string to an
// internal TaskStatus.
func convertProvisioningStatus(status string) TaskStatus {
	switch status {
	case "active":
		return TaskStatusActive
	case "pending":
		return TaskStatusPending
	case "suspended":
		return TaskStatusSuspended
	case "deactivated":
		return TaskStatusDeactivated
	case "failed":
		return TaskStatusFailed
	default:
		return TaskStatusPending
	}
}

// convertDeliveryAddress extracts address and port from a DeliveryAddress.
// This mirrors the extractDeliveryAddress logic in the X1 server.
func convertDeliveryAddress(da *schema.DeliveryAddress) (string, int, error) {
	if da == nil {
		return "", 0, fmt.Errorf("missing delivery address")
	}

	// Try IP address and port.
	if da.IpAddressAndPort != nil {
		ipap := da.IpAddressAndPort

		var address string
		if ipap.Address != nil {
			if ipap.Address.IPv4Address != nil {
				address = *ipap.Address.IPv4Address
			} else if ipap.Address.IPv6Address != nil {
				address = *ipap.Address.IPv6Address
			}
		}

		if address == "" {
			return "", 0, fmt.Errorf("missing IP address in delivery address")
		}

		var port int
		if ipap.Port != nil {
			if ipap.Port.TCPPort != nil {
				port = *ipap.Port.TCPPort
			} else if ipap.Port.UDPPort != nil {
				port = *ipap.Port.UDPPort
			}
		}

		if port == 0 {
			return "", 0, fmt.Errorf("missing port in delivery address")
		}

		return address, port, nil
	}

	// Try URI.
	if da.Uri != nil && *da.Uri != "" {
		return *da.Uri, 443, nil
	}

	return "", 0, fmt.Errorf("unsupported delivery address format")
}
