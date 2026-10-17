//go:build (processor || tap || all) && li

package processor

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
)

func (p *Processor) newRTPProvenance(pkt *types.PacketDisplay) (li.DeliveryProvenance, error) {
	bad := errors.New("invalid persistent RTP observation identity")
	if p.liStorage == nil || p.liStorage.captureEpoch == uuid.Nil || pkt == nil || pkt.VoIPData == nil {
		return li.DeliveryProvenance{}, bad
	}
	src, err := netip.ParseAddr(pkt.SrcIP)
	if err != nil || src.Zone() != "" {
		return li.DeliveryProvenance{}, bad
	}
	dst, err := netip.ParseAddr(pkt.DstIP)
	if err != nil || dst.Zone() != "" {
		return li.DeliveryProvenance{}, bad
	}
	srcPort, err := strconv.ParseUint(pkt.SrcPort, 10, 16)
	if err != nil {
		return li.DeliveryProvenance{}, bad
	}
	dstPort, err := strconv.ParseUint(pkt.DstPort, 10, 16)
	if err != nil {
		return li.DeliveryProvenance{}, bad
	}
	if pkt.NodeID == "" || pkt.Interface == "" {
		return li.DeliveryProvenance{}, bad
	}
	var sequence uint64
	for {
		previous := p.liStorage.observationSequence.Load()
		if previous == ^uint64(0) {
			return li.DeliveryProvenance{}, bad
		}
		if p.liStorage.observationSequence.CompareAndSwap(previous, previous+1) {
			sequence = previous + 1
			break
		}
	}
	return li.DeliveryProvenance{Kind: "non_call", SourceKind: "rtp", OriginNodeID: pkt.NodeID, SourceID: pkt.Interface,
		CaptureEpoch: p.liStorage.captureEpoch, ObservationSequence: sequence, Transport: pkt.Transport,
		SourceAddress: src.Unmap().String(), DestinationAddress: dst.Unmap().String(), SourcePort: uint16(srcPort), DestinationPort: uint16(dstPort), SSRC: pkt.VoIPData.SSRC}, nil
}

// persistentX3Metadata binds delayed ordered product to the original capture
// grant. Reordering never renews its admission deadline or source provenance.
func (p *Processor) persistentX3Metadata(task *li.InterceptTask, pkt *types.PacketDisplay, metadata li.DeliveryMetadata, admission *CallAdmission) (li.DeliveryMetadata, bool) {
	metadata.StateIncarnation = p.liManager.StateIncarnation()
	metadata.TaskEndAt = li.TaskAuthorizationCutoff(task)
	metadata.Deadline = metadata.AdmittedAt.Add(p.config.LIDeliveryX3MaxAge)
	metadata.CallID = pkt.VoIPData.CallID
	if admission != nil {
		metadata.CallGeneration, metadata.CallIncarnation = admission.Generation(), admission.Incarnation()
		metadata.Provenance = li.DeliveryProvenance{Kind: "call", CallID: metadata.CallID, CallGeneration: metadata.CallGeneration, CallIncarnation: metadata.CallIncarnation}
	} else {
		value, ok := p.liStorage.packetProvenance.Load(pkt)
		if !ok || metadata.CallID != "" {
			return metadata, false
		}
		metadata.Provenance = value.(li.DeliveryProvenance)
	}
	return metadata, true
}

func (p *Processor) closePersistentLICall(event CallFinalizationEvent) error {
	if liDeliveryClient == nil {
		return errors.New("persistent call closure has no delivery owner")
	}
	var result error
	liReorderBuffers.Range(func(_, value any) bool {
		buffer := value.(*delivery.ReorderBuffer)
		if !buffer.HasAcceptedCall(event.CallID, event.Generation, event.CallIncarnation) {
			return true
		}
		ticket, err := buffer.DrainCall(event.CallID, event.Generation, event.CallIncarnation)
		if err == nil {
			err = ticket.Wait(context.Background())
		}
		result = errors.Join(result, err)
		return true
	})
	if result != nil {
		return result
	}
	return liDeliveryClient.CloseCapture(context.Background(), event.CallID, event.Generation, event.CallIncarnation)
}

func (p *Processor) authorizePersistentX3Replay(record delivery.JournalRecord) bool {
	if record.StateIncarnation != p.liManager.StateIncarnation() || !p.liManager.ReplayTaskAuthorized(record.XID, record.TaskGeneration) {
		return false
	}
	task, err := p.liManager.GetTaskDetails(record.XID)
	if err != nil || !task.IsActive() || task.ActivationGeneration != record.TaskGeneration {
		return false
	}
	if cutoff := li.TaskAuthorizationCutoff(task); !cutoff.IsZero() && !time.Now().Before(cutoff) {
		return false
	}
	member := false
	for _, did := range task.DestinationIDs {
		if did == record.DID {
			member = true
			break
		}
	}
	if !member {
		return false
	}
	destination, err := liDeliveryMgr.GetDestination(record.DID)
	if err != nil || !destination.X3Enabled || li.DestinationDeliveryGeneration(destination) != record.DestinationGeneration {
		return false
	}
	// Committed publication owns delivery facts. This snapshot may race a newer
	// timing modification, so replay must never write it back into the gate.
	return true
}
