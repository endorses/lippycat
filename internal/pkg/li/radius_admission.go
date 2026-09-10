//go:build li

package li

import (
	"bytes"

	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
)

// processRADIUSPacket never uses the generic filter-ID union. Each independent
// owner must supply its complete current criterion group. Inherited evidence is
// meaningful only when the ingress established the source of the correlator.
func (m *Manager) processRADIUSPacket(pkt *types.PacketDisplay, provenance PacketFilterProvenance) {
	o := provenance.RADIUS
	if !m.config.Enabled || pkt == nil || !provenance.RADIUSTrusted || o == nil || radius.ValidateProvenance(o) != nil || !bytes.Equal(pkt.RawData, o.Packet) || !pkt.Timestamp.Equal(o.Capture.Timestamp) {
		return
	}
	m.stats.packetsProcessed.Add(1)
	holder := m.onPacketMatch.Load()
	radiusHolder := m.onRADIUSMatch.Load()
	if holder == nil && radiusHolder == nil {
		return
	}
	seen := make(map[uuid.UUID]bool)
	for _, inherited := range []bool{false, true} {
		refs := o.Direct
		if inherited {
			refs = o.Inherited
		}
		for _, ref := range refs {
			if inherited && o.Association.Status != radius.AssociationUnique {
				continue
			}
			group, ok := m.filters.LookupRADIUSGroup(ref.CriterionGroupID)
			if ref.TaskID == "" {
				continue
			}
			if !ok || !group.CurrentReference(ref) {
				m.stats.radiusStaleReferences.Add(1)
				continue
			}
			if !inherited {
				current, matched, err := group.Match(o)
				if err != nil || !matched || !group.CurrentReference(current) {
					continue
				}
			}
			xid, err := uuid.Parse(ref.TaskID)
			if err != nil || seen[xid] {
				continue
			}
			admission, active := m.AcquireTaskAdmission(xid, ref.TaskGeneration)
			if !active {
				m.stats.radiusStaleReferences.Add(1)
				continue
			}
			task, err := m.registry.GetTaskDetails(xid)
			// The callback performs its own enqueue admission using this immutable
			// generation. Do not hold the lifecycle lock across external callbacks.
			admission.Release()
			if err != nil || task.ActivationGeneration != ref.TaskGeneration || task.DeliveryType != DeliveryX2Only {
				continue
			}
			seen[xid] = true
			m.stats.packetsMatched.Add(1)
			if radiusHolder != nil {
				radiusHolder.fn(task, o)
				continue
			}
			// Presentation metadata must not reinterpret the validated RADIUS
			// payload as SIP/RTP. Copy before sanitizing to preserve other sinks.
			admittedPacket := *pkt
			admittedPacket.VoIPData = nil
			admittedPacket.Protocol = "RADIUS"
			admittedPacket.RADIUSData = types.RADIUSMetadataFromObservation(o)
			holder.fn(task, &admittedPacket)
		}
	}
}
