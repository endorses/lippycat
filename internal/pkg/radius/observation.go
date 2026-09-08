package radius

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/layers"
)

// Identity identifies an observation or request instance, independently of the
// eight-bit RADIUS Identifier. A zero sequence is never allocated.
type Identity struct {
	Epoch    [16]byte
	Sequence uint64
}

// IDGenerator belongs to exactly one capture source opening. Reopening a source,
// a capture gap, or reconnecting requires a new generator and association state.
// It is safe for concurrent use, but must not be copied after first use.
type IDGenerator struct {
	mu       sync.Mutex
	epoch    [16]byte
	sequence uint64
}

// NewIDGenerator obtains an unpredictable capture epoch from the OS.
func NewIDGenerator() (*IDGenerator, error) {
	g := &IDGenerator{}
	if _, err := rand.Read(g.epoch[:]); err != nil {
		return nil, fmt.Errorf("generate RADIUS capture epoch: %w", err)
	}
	if g.epoch == [16]byte{} {
		return nil, ErrCaptureEpochMissing
	}
	return g, nil
}

// Epoch returns this capture source's immutable epoch.
func (g *IDGenerator) Epoch() [16]byte { return g.epoch }

var ErrIdentityExhausted = errors.New("RADIUS identity sequence exhausted")

// ErrCaptureEpochMissing rejects a generator not initialized by NewIDGenerator.
var ErrCaptureEpochMissing = errors.New("RADIUS capture epoch is missing")

// Next allocates an opaque identity. Exhaustion permanently fails closed; it
// never wraps or silently starts a new epoch within an existing capture source.
func (g *IDGenerator) Next() (Identity, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.epoch == [16]byte{} {
		return Identity{}, ErrCaptureEpochMissing
	}
	if g.sequence == math.MaxUint64 {
		return Identity{}, ErrIdentityExhausted
	}
	g.sequence++
	return Identity{Epoch: g.epoch, Sequence: g.sequence}, nil
}

// CaptureScope is origin provenance, not a scope inferred from packet attributes.
// Relays preserve it unchanged. Populating these fields does not authenticate
// them: future admission must establish source trust independently.
type CaptureScope struct {
	OriginNodeID    string
	Epoch           [16]byte
	SourceID        string
	OperatorScope   string
	ProfileRevision string
}

type CaptureInfo struct {
	Timestamp      time.Time
	LinkType       layers.LinkType
	CapturedLength int
	OriginalLength int
	ID             Identity
}

// Endpoints distinguishes observed transport addresses from optional NAS AVPs.
// Client/server roles follow message code, never a NAS attribute or port guess.
type Endpoints struct {
	IPFamily    uint8
	Source      netip.AddrPort
	Destination netip.AddrPort
	Client      netip.AddrPort
	Server      netip.AddrPort
}

// NASIdentity preserves repeated NAS and line values without concatenation or
// text normalization. Address values come from fully validated attributes;
// extraction retains defensive length guards for manually constructed Messages.
type NASIdentity struct {
	IPv4            []netip.Addr
	IPv6            []netip.Addr
	Identifiers     [][]byte
	PortIDs         [][]byte
	AgentCircuitIDs [][]byte
}

type AssociationStatus string

const (
	AssociationUnprocessed        AssociationStatus = "unprocessed"
	AssociationRequest            AssociationStatus = "request"
	AssociationUnique             AssociationStatus = "unique"
	AssociationMissing            AssociationStatus = "missing"
	AssociationUnmatched                            = AssociationMissing
	AssociationAmbiguous          AssociationStatus = "ambiguous"
	AssociationExpired            AssociationStatus = "expired"
	AssociationIncompatible       AssociationStatus = "incompatible"
	AssociationCapacitySuppressed AssociationStatus = "capacity_suppressed"
)

// Association describes an observational relationship, not authentication.
// Only the future correlator can populate a unique originating request.
type Association struct {
	Status               AssociationStatus
	RequestInstanceID    Identity
	RequestObservationID Identity
	RequestFirstSeen     time.Time
}

// CriterionReference retains one member of a complete conjunctive criterion
// group. Value is the exact compiled value bytes, not normalized display text.
// TargetKind preserves the administrative kind (NAI, account, MAC, or line).
type CriterionReference struct {
	TargetKind     string
	FilterID       string
	FilterRevision uint64
	AttributeType  uint8
	VendorID       uint32
	VendorType     uint8
	Value          []byte
}

// AttributionReference is one independent owner's complete criterion group.
// Ordinary filters leave TaskID empty and cannot authorize LI. These transport
// references are claims requiring current-generation admission, never proof by
// themselves. Do not flatten groups or combine partial matches across owners.
type AttributionReference struct {
	CriterionGroupID string
	Criteria         []CriterionReference
	TaskID           string
	TaskGeneration   uint64
	Scope            CaptureScope
}

// Observation owns all mutable storage. Treat it as immutable after publication
// to asynchronous consumers; use Clone when a consumer needs to mutate it.
// Packet includes captured encapsulation and padding; Message.Raw contains only
// the validated RADIUS message. Invalid outcomes have no Message, NAS or evidence.
type Observation struct {
	Capture     CaptureInfo
	Scope       CaptureScope
	Endpoints   Endpoints
	Packet      []byte
	Message     *Message
	NAS         NASIdentity
	Association Association
	Direct      []AttributionReference
	Inherited   []AttributionReference
}

// Clone produces independently owned bytes, attributes, NAS values and evidence.
func (o *Observation) Clone() *Observation {
	if o == nil {
		return nil
	}
	copy := *o
	copy.Packet = append([]byte(nil), o.Packet...)
	if o.Message != nil {
		m := *o.Message
		m.Raw = append([]byte(nil), o.Message.Raw...)
		m.Attributes = append([]Attribute(nil), o.Message.Attributes...)
		for i := range m.Attributes {
			a := &m.Attributes[i]
			a.Raw = append([]byte(nil), a.Raw...)
			a.Value = append([]byte(nil), a.Value...)
			a.VendorAttributes = append([]VendorAttribute(nil), a.VendorAttributes...)
			for j := range a.VendorAttributes {
				v := &a.VendorAttributes[j]
				v.Raw = append([]byte(nil), v.Raw...)
				v.Value = append([]byte(nil), v.Value...)
			}
		}
		copy.Message = &m
	}
	copy.NAS.IPv4 = append([]netip.Addr(nil), o.NAS.IPv4...)
	copy.NAS.IPv6 = append([]netip.Addr(nil), o.NAS.IPv6...)
	copy.NAS.Identifiers = cloneByteValues(o.NAS.Identifiers)
	copy.NAS.PortIDs = cloneByteValues(o.NAS.PortIDs)
	copy.NAS.AgentCircuitIDs = cloneByteValues(o.NAS.AgentCircuitIDs)
	copy.Direct = cloneReferences(o.Direct)
	copy.Inherited = cloneReferences(o.Inherited)
	return &copy
}

func cloneByteValues(values [][]byte) [][]byte {
	if values == nil {
		return nil
	}
	result := make([][]byte, len(values))
	for i, value := range values {
		result[i] = append([]byte(nil), value...)
	}
	return result
}

func cloneReferences(refs []AttributionReference) []AttributionReference {
	result := append([]AttributionReference(nil), refs...)
	for i := range result {
		result[i].Criteria = append([]CriterionReference(nil), refs[i].Criteria...)
		for j := range result[i].Criteria {
			result[i].Criteria[j].Value = append([]byte(nil), refs[i].Criteria[j].Value...)
		}
	}
	return result
}

// nasIdentity is called only after the complete message has passed Decode.
func nasIdentity(m *Message) NASIdentity {
	var result NASIdentity
	for _, a := range m.Attributes {
		switch a.Type {
		case 4:
			if len(a.Value) == 4 {
				result.IPv4 = append(result.IPv4, netip.AddrFrom4([4]byte(a.Value)))
			}
		case 95:
			if len(a.Value) == 16 {
				result.IPv6 = append(result.IPv6, netip.AddrFrom16([16]byte(a.Value)))
			}
		case 32:
			result.Identifiers = append(result.Identifiers, append([]byte(nil), a.Value...))
		case 87:
			result.PortIDs = append(result.PortIDs, append([]byte(nil), a.Value...))
		case 26:
			if a.VendorID == 3561 {
				for _, v := range a.VendorAttributes {
					if v.Type == 1 {
						result.AgentCircuitIDs = append(result.AgentCircuitIDs, append([]byte(nil), v.Value...))
					}
				}
			}
		}
	}
	return result
}

// Outcome is the single validation classification at first analysis ingress.
// Unmatched and ambiguous are separate association statuses on valid messages.
type Outcome string

const (
	OutcomeValid       Outcome = "valid"
	OutcomeFragmented  Outcome = "fragmented"
	OutcomeMalformed   Outcome = "malformed"
	OutcomeUnsupported Outcome = "unsupported"
)

// ValidationCounters belongs to one analysis ingress. Pure decoders and
// downstream revalidation never increment it. Association, admission, and sink
// counters belong to their respective future components, not this counter set.
// Do not copy this value after first use.
type ValidationCounters struct {
	valid       atomic.Uint64
	fragmented  atomic.Uint64
	malformed   atomic.Uint64
	unsupported atomic.Uint64
}

type ValidationStats struct {
	Valid       uint64
	Fragmented  uint64
	Malformed   uint64
	Unsupported uint64
}

func (c *ValidationCounters) record(outcome Outcome) {
	switch outcome {
	case OutcomeValid:
		c.valid.Add(1)
	case OutcomeFragmented:
		c.fragmented.Add(1)
	case OutcomeMalformed:
		c.malformed.Add(1)
	case OutcomeUnsupported:
		c.unsupported.Add(1)
	default:
		panic("invalid RADIUS validation counter outcome")
	}
}

// Snapshot reads each counter atomically; concurrent observations may advance
// between field reads. Labels are fixed and count observations, not AVPs.
func (c *ValidationCounters) Snapshot() ValidationStats {
	return ValidationStats{Valid: c.valid.Load(), Fragmented: c.fragmented.Load(), Malformed: c.malformed.Load(), Unsupported: c.unsupported.Load()}
}
