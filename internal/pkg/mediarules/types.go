// Package mediarules preserves the media-selection API as a VoIP view over the
// shared learned-rule engine. A rule selects capture candidates; attribution and
// output authorization remain separate decisions.
package mediarules

import (
	"errors"
	"fmt"
	"time"

	core "github.com/endorses/lippycat/internal/pkg/learnedrules"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	voiprules "github.com/endorses/lippycat/internal/pkg/voip/learnedrules"
)

// Compatibility names retain the public media API while the VoIP adapter owns
// call context and the common engine owns session authority.
type Revision = core.Revision
type Session = core.Session
type Control = core.Control
type Scope = voiprules.Scope
type MediaKind = voiprules.MediaKind

const (
	RTP        = voiprules.RTP
	RTCP       = voiprules.RTCP
	RTPAndRTCP = voiprules.RTPAndRTCP
)

type Endpoint = voiprules.Endpoint
type SelectionRef = voiprules.SelectionRef
type CallAssociation = voiprules.CallAssociation
type Rule = voiprules.Rule

// Clock separates wall time used to validate remote timestamps from monotonic
// elapsed time used to enforce installed deadlines.
type Clock = core.Clock

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
	ErrAuthority = core.ErrAuthority
	ErrSession   = core.ErrSession
	ErrRevision  = core.ErrRevision
	ErrNotReady  = core.ErrNotReady
	ErrCapacity  = core.ErrCapacity
	ErrScope     = core.ErrScope
	ErrInvalid   = core.ErrInvalid
	ErrClosed    = core.ErrClosed
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

type Resolution = voiprules.Resolution

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
