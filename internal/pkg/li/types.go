// Package li provides ETSI X1/X2/X3 lawful interception support for lippycat.
//
// This package implements the internal network interfaces defined in ETSI TS 103 221:
//   - X1: Administration interface (XML/HTTPS) for task management
//   - X2: IRI delivery (binary TLV/TLS) for signaling metadata
//   - X3: CC delivery (binary TLV/TLS) for content of communication
//
// The package is enabled via the "li" build tag.
package li

import (
	"crypto/tls"
	"time"

	"github.com/google/uuid"
)

// DeliveryType specifies what content should be delivered for an intercept task.
type DeliveryType int

const (
	// DeliveryX2Only delivers only IRI (Intercept Related Information) - signaling metadata.
	DeliveryX2Only DeliveryType = iota + 1
	// DeliveryX3Only delivers only CC (Content of Communication) - media content.
	DeliveryX3Only
	// DeliveryX2andX3 delivers both IRI and CC.
	DeliveryX2andX3
)

// String returns the string representation of DeliveryType.
func (d DeliveryType) String() string {
	switch d {
	case DeliveryX2Only:
		return "X2Only"
	case DeliveryX3Only:
		return "X3Only"
	case DeliveryX2andX3:
		return "X2andX3"
	default:
		return "Unknown"
	}
}

// TaskStatus represents the lifecycle state of an intercept task.
type TaskStatus int

const (
	// TaskStatusPending indicates the task has been received but not yet activated.
	TaskStatusPending TaskStatus = iota
	// TaskStatusActive indicates the task is actively intercepting traffic.
	TaskStatusActive
	// TaskStatusSuspended indicates the task is temporarily suspended.
	TaskStatusSuspended
	// TaskStatusDeactivated indicates the task has been explicitly deactivated.
	TaskStatusDeactivated
	// TaskStatusFailed indicates the task failed to activate or encountered a fatal error.
	TaskStatusFailed
)

// String returns the string representation of TaskStatus.
func (s TaskStatus) String() string {
	switch s {
	case TaskStatusPending:
		return "Pending"
	case TaskStatusActive:
		return "Active"
	case TaskStatusSuspended:
		return "Suspended"
	case TaskStatusDeactivated:
		return "Deactivated"
	case TaskStatusFailed:
		return "Failed"
	default:
		return "Unknown"
	}
}

// TargetType specifies the type of target identifier per ETSI TS 103 280.
type TargetType int

const (
	// TargetTypeSIPURI identifies a target by SIP URI (sip:user@domain).
	TargetTypeSIPURI TargetType = iota + 1
	// TargetTypeTELURI identifies a target by telephone URI (tel:+number).
	TargetTypeTELURI
	// TargetTypeNAI identifies a target by Network Access Identifier (user@realm).
	TargetTypeNAI
	// TargetTypeIPv4Address identifies a target by IPv4 address.
	TargetTypeIPv4Address
	// TargetTypeIPv4CIDR identifies a target by IPv4 CIDR range.
	TargetTypeIPv4CIDR
	// TargetTypeIPv6Address identifies a target by IPv6 address.
	TargetTypeIPv6Address
	// TargetTypeIPv6CIDR identifies a target by IPv6 CIDR range.
	TargetTypeIPv6CIDR
	// TargetTypeUsername identifies a target by username (SIP user part).
	TargetTypeUsername
)

// String returns the string representation of TargetType.
func (t TargetType) String() string {
	switch t {
	case TargetTypeSIPURI:
		return "SIPURI"
	case TargetTypeTELURI:
		return "TELURI"
	case TargetTypeNAI:
		return "NAI"
	case TargetTypeIPv4Address:
		return "IPv4Address"
	case TargetTypeIPv4CIDR:
		return "IPv4CIDR"
	case TargetTypeIPv6Address:
		return "IPv6Address"
	case TargetTypeIPv6CIDR:
		return "IPv6CIDR"
	case TargetTypeUsername:
		return "Username"
	default:
		return "Unknown"
	}
}

// InterceptTask represents an active lawful interception task per ETSI TS 103 221-1.
//
// Each task is identified by a unique XID (X1 Identifier) and specifies:
//   - What to intercept (Targets)
//   - Where to deliver (DestinationIDs referencing Destination objects)
//   - What content to deliver (DeliveryType)
//   - When the task is valid (StartTime, EndTime)
type InterceptTask struct {
	// XID is the unique identifier for this task (UUID v4 per ETSI spec).
	XID uuid.UUID

	// Targets specifies the identities to intercept.
	Targets []TargetIdentity

	// DestinationIDs references the Destination objects for X2/X3 delivery.
	// These are DIDs (Destination Identifiers) that map to Destination structs.
	DestinationIDs []uuid.UUID

	// DeliveryType specifies whether to deliver X2 (IRI), X3 (CC), or both.
	DeliveryType DeliveryType

	// StartTime is when the intercept should begin.
	// If zero, the task starts immediately upon activation.
	StartTime time.Time

	// EndTime is when the intercept should end.
	// If zero, the task runs indefinitely until explicit deactivation.
	EndTime time.Time

	// ImplicitDeactivationAllowed indicates whether the NE may autonomously
	// deactivate the task (e.g., when EndTime is reached). If false, only
	// explicit ADMF DeactivateTask or a terminating fault can end the task.
	ImplicitDeactivationAllowed bool

	// Status is the current lifecycle state of the task.
	Status TaskStatus

	// ActivatedAt records when the task was activated.
	ActivatedAt time.Time

	// DeactivatedAt records when the task was deactivated (if applicable).
	DeactivatedAt time.Time

	// LastError contains the most recent error message (if any).
	LastError string
}

// TargetIdentity specifies a single target to intercept.
type TargetIdentity struct {
	// Type specifies the format of the Value field.
	Type TargetType

	// Value contains the target identifier in the format specified by Type.
	// Examples:
	//   - SIPURI: "sip:alice@example.com"
	//   - TELURI: "tel:+15551234567"
	//   - IPv4Address: "192.168.1.100"
	//   - IPv4CIDR: "10.0.0.0/8"
	Value string
}

// Destination represents an X2/X3 delivery endpoint.
//
// Each destination is identified by a DID (Destination Identifier) and
// specifies where intercepted content should be delivered.
type Destination struct {
	// DID is the unique identifier for this destination (UUID v4).
	DID uuid.UUID

	// Address is the hostname or IP address of the MDF endpoint.
	Address string

	// Port is the TCP port for the TLS connection.
	Port int

	// TLSConfig contains the TLS configuration for the connection.
	// This includes client certificates for mutual TLS authentication.
	TLSConfig *tls.Config

	// X2Enabled indicates this destination accepts X2 (IRI) traffic.
	X2Enabled bool

	// X3Enabled indicates this destination accepts X3 (CC) traffic.
	X3Enabled bool

	// Description is an optional human-readable description.
	Description string

	// CreatedAt records when the destination was created.
	CreatedAt time.Time
}

// IsExpired returns true if the task's EndTime has passed.
// If ImplicitDeactivationAllowed is false, this returns false regardless of EndTime.
func (t *InterceptTask) IsExpired() bool {
	if !t.ImplicitDeactivationAllowed {
		return false
	}
	if t.EndTime.IsZero() {
		return false
	}
	return time.Now().After(t.EndTime)
}

// IsActive returns true if the task is in an active state.
func (t *InterceptTask) IsActive() bool {
	return t.Status == TaskStatusActive
}

// ShouldStart returns true if the task's StartTime has been reached.
func (t *InterceptTask) ShouldStart() bool {
	if t.StartTime.IsZero() {
		return true
	}
	return time.Now().After(t.StartTime) || time.Now().Equal(t.StartTime)
}
