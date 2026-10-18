// Package mediarules owns bounded, ephemeral media selection state. Call
// selection, SIP validation, authentication and packet output remain with the
// caller; a media rule is neither a SIP parser nor an output authorization.
package mediarules

import (
	"errors"
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
)

type Revision uint64

// Session identifies the issuing processor's current control generation.
type Session struct {
	ProcessorID string
	Generation  uint64
}

// Control is a connection-local capability, returned only after StartSession.
// Reconnecting invalidates callbacks carrying the previous connection's token,
// even when the remote session did not change.
type Control struct {
	session Session
	local   uint64
	store   *Store
}

type Scope struct {
	HunterID string
	Domain   mediaadmission.DomainID
}

type MediaKind uint8

const (
	RTP MediaKind = iota
	RTCP
	RTPAndRTCP
)

type Endpoint struct {
	Key  mediaadmission.EndpointKey
	Kind MediaKind
}

// CallAssociation carries already verified selection/dialog evidence. The
// opaque registry lifetime prevents a reused SIP Call-ID inheriting selection.
// ResolveDialog assists forwarding only; its result does not validate a SIP
// transaction or authorize ending/changing a call.
type SelectionRef struct {
	ID       string
	Revision uint64
}

type CallAssociation struct {
	Lifetime              callregistry.Lifetime
	CallID                string
	FromTag               string
	ToTag                 string
	SelectionRevision     uint64
	CapturePolicyRevision uint64
	FilterIDs             []string
	SelectionGrants       []SelectionRef
}

type Rule struct {
	ID               string
	Session          Session
	Revision         Revision
	Call             CallAssociation
	Scope            []Scope
	Endpoints        []Endpoint
	NotBefore        time.Time
	ExpiresAt        time.Time
	CaptureSignature []byte
}

// Clock separates wall time used to validate remote timestamps from monotonic
// elapsed time used to enforce installed deadlines.
type Clock interface {
	Now() time.Time
	Elapsed() time.Duration
}

type systemClock struct{ start time.Time }

func (c systemClock) Now() time.Time         { return time.Now() }
func (c systemClock) Elapsed() time.Duration { return time.Since(c.start) }

type Config struct {
	ProcessorID string
	// Empty HunterID is publisher mode, retaining rules for every hunter.
	HunterID string
	Domains  []mediaadmission.DomainID
	MaxRules int
	MaxBytes int
	// Endpoint limits count associations, including shared endpoints.
	MaxEndpoints        int
	MaxEndpointsPerRule int
	MaxSubscribers      int
	SubscriptionBuffer  int
	MaxLifetime         time.Duration
	// ClockUncertainty shortens expiry and delays activation conservatively.
	ClockUncertainty time.Duration
	Clock            Clock
	Observer         Observer
}

func (c Config) validate() error {
	if c.ProcessorID == "" || c.MaxRules <= 0 || c.MaxBytes <= 0 || c.MaxEndpoints <= 0 || c.MaxEndpointsPerRule <= 0 || c.MaxSubscribers <= 0 || c.SubscriptionBuffer <= 0 || c.MaxLifetime <= 0 || c.ClockUncertainty < 0 {
		return errors.New("media rules require an issuer and positive configured resource/lifetime limits")
	}
	if c.HunterID != "" && len(c.Domains) == 0 {
		return errors.New("hunter media rules require explicit observation domains")
	}
	seen := make(map[mediaadmission.DomainID]struct{}, len(c.Domains))
	for _, domain := range c.Domains {
		if _, ok := seen[domain]; ok {
			return fmt.Errorf("duplicate media-rule domain %d", domain)
		}
		seen[domain] = struct{}{}
	}
	return nil
}

var (
	ErrAuthority = errors.New("media-rule issuer is not the configured authenticated processor")
	ErrSession   = errors.New("stale media-rule control session")
	ErrRevision  = errors.New("stale or discontinuous media-rule revision")
	ErrNotReady  = errors.New("media rules require a complete snapshot")
	ErrCapacity  = errors.New("media-rule configured capacity exceeded")
	ErrScope     = errors.New("media rule does not belong to the configured capture scope")
	ErrInvalid   = errors.New("invalid media rule")
	ErrClosed    = errors.New("media-rule store closed")
)

type RemovalReason string

const (
	RemovedExplicit RemovalReason = "removed"
	RemovedExpired  RemovalReason = "expired"
	RemovedSnapshot RemovalReason = "snapshot"
	RemovedSession  RemovalReason = "session"
)

type Removal struct {
	Rule   Rule
	Reason RemovalReason
}

type Snapshot struct {
	Session  Session
	Revision Revision
	Sequence uint64
	Ready    bool
	// Rules includes not-yet-active rules; ActiveRules enforces local deadlines.
	Rules []Rule
}

// Change is an owned, revisioned desired-state observation. A receiver should
// reconcile its admission owner set from Active, rejecting older Sequence
// values. Observers run outside Store locks and may reenter; concurrent callers
// may deliver callbacks out of order.
type Change struct {
	Snapshot
	Active         []Rule
	Removed        []Removal
	ResyncRequired bool
}

type Observer interface{ OnMediaRulesChanged(Change) }

type Resolution struct {
	// Rule is an owned exact media rule for the unambiguous resolved owner.
	Rule      *Rule
	Call      CallAssociation
	Resolved  bool
	Ambiguous bool
}

type Status struct {
	Session      Session
	Revision     Revision
	Sequence     uint64
	Ready        bool
	Rules        int
	Bytes        int
	Endpoints    int
	Subscribers  int
	Expired      uint64
	StaleUpdates uint64
	Resyncs      uint64
}
