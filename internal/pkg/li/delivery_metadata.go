package li

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// DeliveryMetadata preserves local admission time and lifecycle identity across
// reorder, fan-out and retry. CapturedAt is diagnostic, never an age clock.
type DeliveryMetadata struct {
	AdmittedAt            time.Time
	CapturedAt            time.Time
	Deadline              time.Time
	TaskGeneration        uint64
	DestinationGeneration uint64
	CallGeneration        uint64
	CallID                string
}

// DestinationDeliveryGeneration binds queued product to one endpoint incarnation.
// A configuration change or a newly created destination changes this identity.
func DestinationDeliveryGeneration(d *Destination) uint64 {
	if d == nil {
		return 0
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%d\x00%s\x00%t\x00%t", d.DID, d.CreatedAt.UnixNano(), d.Address, d.Port, d.ProtocolType, d.X2Enabled, d.X3Enabled)))
	generation := binary.BigEndian.Uint64(sum[:8])
	if generation == 0 {
		return 1
	}
	return generation
}
