// Package learnedrules owns bounded, ephemeral capture relationships. Protocol
// interpretation and output authorization belong to registered adapters.
package learnedrules

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"
)

type DomainID uint32
type Revision uint64

type Session struct {
	ProcessorID string
	Generation  uint64
}

// Control belongs to one authenticated subscription. Reconnection invalidates
// callbacks carrying an older token without extending installed deadlines.
type Control struct {
	session Session
	local   uint64
	store   *Store
}

type Scope struct {
	HunterID string
	Domain   DomainID
}

type Subject struct {
	ID          string
	Incarnation string
}

type IntentRef struct {
	ID       string
	Revision uint64
}

type Protocol uint8

const (
	TCP Protocol = 6
	UDP Protocol = 17
)

type Direction uint8

const (
	Either Direction = iota
	Source
	Destination
)

type Qualifier struct {
	ID      string
	Version uint32
}

// Selector is conjunctive. A binding's selector list is a union; qualifiers
// apply to their own branch and can never be bypassed by another branch.
type Selector struct {
	Domain    DomainID
	Address   netip.Addr
	Port      uint16
	Protocol  Protocol
	Direction Direction
	Qualifier Qualifier
}

func (s Selector) Validate() error {
	if !s.Address.IsValid() || s.Address.Zone() != "" || s.Address.IsUnspecified() || s.Address != s.Address.Unmap() || s.Port == 0 || (s.Protocol != UDP && s.Protocol != TCP) || s.Direction > Destination || (s.Qualifier.ID == "") != (s.Qualifier.Version == 0) {
		return ErrInvalid
	}
	return nil
}

// Binding context is immutable, versioned adapter data. The registry validates
// it before store publication. Proof bytes remain the original signed artifact.
type Binding struct {
	ID                 string
	Session            Session
	Revision           Revision
	AdapterID          string
	ContextVersion     uint32
	Subject            Subject
	AttributionContext string
	Intents            []IntentRef
	EvidenceRefs       []string
	Scope              []Scope
	Selectors          []Selector
	Context            []byte
	Proof              []byte
	NotBefore          time.Time
	ExpiresAt          time.Time
}

type Endpoint struct {
	Address netip.Addr
	Port    uint16
}

// Packet is an owned-call view of packet facts, never an ownership assertion.
// Payload is borrowed only for the duration of a synchronous match operation.
type Packet struct {
	Domain      DomainID
	Protocol    Protocol
	Source      Endpoint
	Destination Endpoint
	Payload     []byte
}

// Adapter callbacks must be pure, bounded and must not reenter the store. They
// run against owned binding values. Publication authorization represents the
// current configured intent; cryptographic and output checks remain separate.
type Adapter struct {
	ID                 string
	Version            uint32
	Qualifiers         []Qualifier
	Validate           func(Binding) error
	Authorize          func(Binding) error
	ValidateTransition func(Binding, Binding) error
	Qualify            func(Binding, Selector, Packet) bool
}

type Registry struct{ adapters map[adapterKey]Adapter }
type adapterKey struct {
	id      string
	version uint32
}

func NewRegistry(adapters ...Adapter) (*Registry, error) {
	if len(adapters) == 0 || len(adapters) > 64 {
		return nil, ErrInvalid
	}
	r := &Registry{adapters: make(map[adapterKey]Adapter, len(adapters))}
	for _, a := range adapters {
		key := adapterKey{a.ID, a.Version}
		if a.ID == "" || len(a.ID) > 128 || len(a.Qualifiers) > 64 || a.Version == 0 || a.Validate == nil || a.Authorize == nil || (len(a.Qualifiers) > 0 && a.Qualify == nil) {
			return nil, ErrInvalid
		}
		if _, found := r.adapters[key]; found {
			return nil, ErrInvalid
		}
		seen := make(map[Qualifier]bool)
		for _, q := range a.Qualifiers {
			if q.ID == "" || len(q.ID) > 128 || q.Version == 0 || seen[q] {
				return nil, ErrInvalid
			}
			seen[q] = true
		}
		a.Qualifiers = append([]Qualifier(nil), a.Qualifiers...)
		r.adapters[key] = a
	}
	return r, nil
}

func (r *Registry) Lookup(id string, version uint32) (Adapter, bool) {
	if r == nil {
		return Adapter{}, false
	}
	a, ok := r.adapters[adapterKey{id, version}]
	a.Qualifiers = append([]Qualifier(nil), a.Qualifiers...)
	return a, ok
}

// Adapters returns owned registration metadata in stable order. Callback
// implementations are trusted immutable functions installed at construction.
func (r *Registry) Adapters() []Adapter {
	if r == nil {
		return nil
	}
	result := make([]Adapter, 0, len(r.adapters))
	for _, adapter := range r.adapters {
		adapter.Qualifiers = append([]Qualifier(nil), adapter.Qualifiers...)
		result = append(result, adapter)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ID == result[j].ID {
			return result[i].Version < result[j].Version
		}
		return result[i].ID < result[j].ID
	})
	return result
}

type Clock interface {
	Now() time.Time
	Elapsed() time.Duration
}
type systemClock struct{ start time.Time }

func (c systemClock) Now() time.Time         { return time.Now() }
func (c systemClock) Elapsed() time.Duration { return time.Since(c.start) }

type Config struct {
	ProcessorID string
	HunterID    string
	Domains     []DomainID
	// SupportedProtocols bounds the complete source capture path. Nil retains
	// the initial UDP/TCP contract; sources can explicitly constrain it.
	SupportedProtocols  []Protocol
	MaxRules            int
	MaxBytes            int
	MaxEndpoints        int
	MaxEndpointsPerRule int
	MaxSubscribers      int
	SubscriptionBuffer  int
	MaxLifetime         time.Duration
	ClockUncertainty    time.Duration
	Clock               Clock
	Observer            Observer
	Registry            *Registry
}

func (c Config) validate() error {
	if c.ProcessorID == "" || c.Registry == nil || c.MaxRules <= 0 || c.MaxBytes <= 0 || c.MaxEndpoints <= 0 || c.MaxEndpointsPerRule <= 0 || c.MaxSubscribers <= 0 || c.SubscriptionBuffer <= 0 || c.MaxLifetime <= 0 || c.ClockUncertainty < 0 {
		return ErrInvalid
	}
	if c.HunterID != "" && len(c.Domains) == 0 {
		return ErrScope
	}
	if len(c.SupportedProtocols) > 2 {
		return ErrUnsupported
	}
	protocols := make(map[Protocol]bool)
	for _, p := range c.SupportedProtocols {
		if (p != UDP && p != TCP) || protocols[p] {
			return ErrUnsupported
		}
		protocols[p] = true
	}
	seen := make(map[DomainID]bool)
	for _, d := range c.Domains {
		if seen[d] {
			return fmt.Errorf("duplicate domain: %w", ErrScope)
		}
		seen[d] = true
	}
	return nil
}

var (
	ErrAuthority   = errors.New("learned rule issuer is not the authenticated authority")
	ErrSession     = errors.New("stale learned rule control session")
	ErrRevision    = errors.New("stale or discontinuous learned rule revision")
	ErrNotReady    = errors.New("learned rules require a complete snapshot")
	ErrCapacity    = errors.New("learned rule configured capacity exceeded")
	ErrScope       = errors.New("learned rule outside capture scope")
	ErrInvalid     = errors.New("invalid learned rule")
	ErrUnsupported = errors.New("unsupported learned rule capability")
	ErrClosed      = errors.New("learned rule store closed")
)

type RemovalReason string

const (
	RemovedExplicit RemovalReason = "removed"
	RemovedExpired  RemovalReason = "expired"
	RemovedSnapshot RemovalReason = "snapshot"
	RemovedSession  RemovalReason = "session"
)

type Removal struct {
	Rule   Binding
	Reason RemovalReason
}
type Snapshot struct {
	Session  Session
	Revision Revision
	Sequence uint64
	Ready    bool
	Rules    []Binding
}
type Change struct {
	Snapshot
	Active         []Binding
	Removed        []Removal
	ResyncRequired bool
}
type Observer interface{ OnLearnedRulesChanged(Change) }
type Status struct {
	Session            Session
	Revision           Revision
	Sequence           uint64
	Ready              bool
	Rules              int
	Bytes              int
	Endpoints          int
	Subscribers        int
	Expired            uint64
	StaleUpdates       uint64
	Resyncs            uint64
	CandidateOverflows uint64
	CapacityRejections uint64
}

// Candidates are scoped hints, never unique subject attribution. Overflow is
// explicit and callers must not resolve the retained subset as complete.
type Candidates struct {
	Bindings []Binding
	Overflow bool
}
