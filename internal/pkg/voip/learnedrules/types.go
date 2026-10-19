// Package learnedrules implements the versioned VoIP interpretation of learned
// capture relationships. It does not own a second lifecycle registry.
package learnedrules

import (
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"time"
)

const AdapterID = "voip"
const ContextVersion uint32 = 1
const AttributionContext = "voip.call"

type Revision = core.Revision
type Session = core.Session

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

type Resolution struct {
	// Rule is an owned exact media rule for the unambiguous resolved owner.
	Rule      *Rule
	Call      CallAssociation
	Resolved  bool
	Ambiguous bool
}
