// Package mediaadmission owns bounded, topology-neutral media admission state.
// Admission permits candidates; it never assigns call identity or authorizes output.
package mediaadmission

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

type DomainID uint32

type EndpointKey struct {
	Domain DomainID
	Addr   netip.Addr
	Port   uint16
}

func NewEndpoint(domain DomainID, addr netip.Addr, port uint16) (EndpointKey, error) {
	if !addr.IsValid() || addr.Zone() != "" || addr.IsUnspecified() || port == 0 {
		return EndpointKey{}, fmt.Errorf("invalid media endpoint")
	}
	return EndpointKey{Domain: domain, Addr: addr.Unmap(), Port: port}, nil
}

func (k EndpointKey) Validate() error {
	normalized, err := NewEndpoint(k.Domain, k.Addr, k.Port)
	if err != nil {
		return err
	}
	if normalized != k {
		return errors.New("media endpoint is not normalized")
	}
	return nil
}

type KernelMode uint32

const (
	KernelEnforce KernelMode = iota
	KernelShadow
	KernelOpen
)

type Control struct {
	Mode       KernelMode
	Generation uint64
}

// Backend methods must not reenter Controller. A failed mutation may have taken
// effect: enumeration is required before recovery can claim synchronization.
// Domain controls must be preallocated independently of endpoint capacity.
type Backend interface {
	PutEndpoint(context.Context, EndpointKey) error
	DeleteEndpoint(context.Context, EndpointKey) error
	ListEndpoints(context.Context, DomainID) ([]EndpointKey, error)
	SetControl(context.Context, DomainID, Control) error
}

type SelectorBackend interface {
	ReplaceSelectors(context.Context, DomainID, []netip.Prefix, bool) error
}

type OwnerID struct {
	Session    uint64
	Generation uint64
	CallID     string
}

type State string

const (
	StateDisabled       State = "disabled"
	StateInitializing   State = "initializing"
	StateShadow         State = "shadow"
	StateEnforcing      State = "enforcing"
	StateDegradedOpen   State = "degraded-open"
	StateDegradedClosed State = "degraded-closed"
	StateRecovery       State = "recovery"
	StateControlFailed  State = "control-failed"
	StateClosed         State = "closed"
)

var (
	ErrClosed        = errors.New("media admission controller closed")
	ErrUnknownDomain = errors.New("unknown media admission domain")
	ErrStaleOwner    = errors.New("inactive or stale media owner")
	ErrCapacity      = errors.New("media admission capacity exceeded")
	ErrDisabled      = errors.New("media admission disabled")
)

// ScopeStatus separates desired publication from the last confirmed kernel
// control. ControlUncertain means a failed write may have changed that control.
type ScopeStatus struct {
	PublicationStarted  time.Time
	LastPublished       time.Time
	Domain              DomainID
	State               State
	LastConfirmed       Control
	ControlUncertain    bool
	DesiredGeneration   uint64
	InstalledGeneration uint64
	Owners              int
	DesiredEndpoints    int
	InstalledEndpoints  int
	PendingUpdates      int
	UpdateErrors        uint64
	ControlErrors       uint64
	Recoveries          uint64
	StaleUpdates        uint64
	Reason              string
	DegradedSince       time.Time
	OpenDuration        time.Duration
}
