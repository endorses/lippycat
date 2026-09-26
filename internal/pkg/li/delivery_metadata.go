package li

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DeliveryMetadata preserves local admission time and lifecycle identity across
// reorder, fan-out and retry. CapturedAt is diagnostic, never an age clock.
type DeliveryMetadata struct {
	StateIncarnation uuid.UUID
	Provenance       DeliveryProvenance
	AdmittedAt       time.Time
	CapturedAt       time.Time
	Deadline         time.Time
	// TaskEndAt is the effective task authorization cutoff: EndTime only when
	// ImplicitDeactivationAllowed is true, zero otherwise. It is independent of
	// the original product retention deadline. Recovered work receives current
	// committed policy facts; packet metadata cannot extend remembered authority.
	TaskEndAt             time.Time
	TaskGeneration        uint64
	DestinationGeneration uint64
	CallGeneration        uint64
	// CallIncarnation is independent of CallID and the process-local generation.
	// Zero remains valid for non-call producers and legacy memory-only callers.
	CallIncarnation uuid.UUID
	CallID          string
}

// DestinationDeliveryGeneration binds queued product to one endpoint incarnation.
// A configuration change or a newly created destination changes this identity.
func DestinationDeliveryGeneration(d *Destination) uint64 {
	if d == nil {
		return 0
	}
	identity := fmt.Sprintf("%s\x00%d\x00%s\x00%d\x00%s\x00%t\x00%t", d.DID, d.CreatedAt.UnixNano(), d.Address, d.Port, d.ProtocolType, d.X2Enabled, d.X3Enabled)
	// Keep legacy revision-zero identities stable across upgrades.
	if d.DeliveryRevision != 0 {
		identity += fmt.Sprintf("\x00%d", d.DeliveryRevision)
	}
	sum := sha256.Sum256([]byte(identity))
	generation := binary.BigEndian.Uint64(sum[:8])
	if generation == 0 {
		return 1
	}
	return generation
}
