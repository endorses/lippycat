//go:build (processor || tap || all) && li

package processor

import (
	"context"
	"errors"
	"fmt"
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

// The caller holds the original task/call capture grants across the entire
// bounded fan-out. Delayed callbacks use only their one-use accepted permit.
func (p *Processor) deliverPersistentX3(task *li.InterceptTask, pkt *types.PacketDisplay, data []byte, metadata li.DeliveryMetadata, admission *CallAdmission) {
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
			recordBufferedX3Discard(len(task.DestinationIDs))
			return
		}
		metadata.Provenance = value.(li.DeliveryProvenance)
	}
	for _, did := range task.DestinationIDs {
		destination, err := liDeliveryMgr.GetDestination(did)
		if err != nil {
			recordBufferedX3Discard(1)
			continue
		}
		copyMetadata := metadata
		copyMetadata.DestinationGeneration = li.DestinationDeliveryGeneration(destination)
		permit, err := liDeliveryClient.PrepareX3(task.XID, did, data, copyMetadata)
		if err != nil {
			recordBufferedX3Discard(1)
			continue
		}
		key := fmt.Sprintf("%s-%s", task.XID, did)
		buffer, loaded := liReorderBuffers.Load(key)
		if !loaded {
			candidate := delivery.NewBudgetedCallAwareReorderBuffer(func(entry delivery.ReorderEntry) {
				// This path never enters Manager/adminMu or ordinary CallAdmission.
				// Client owns exact monotonic revocation/expiry eligibility.
				if err := liDeliveryClient.SendAcceptedX3(entry.Accepted); err != nil {
					recordBufferedX3Discard(1)
				}
			}, 60*time.Millisecond, liReorderBudget, recordBufferedX3Discard)
			if candidate == nil {
				permit.Release()
				recordBufferedX3Discard(1)
				continue
			}
			candidate.SetWorkerGroup(liReorderWorkers)
			var exists bool
			buffer, exists = liReorderBuffers.LoadOrStore(key, candidate)
			if exists {
				candidate.Discard()
			}
		}
		buffer.(*delivery.ReorderBuffer).AcceptEntryX3AfterCommit(delivery.ReorderEntry{Accepted: permit, PDU: data, Metadata: copyMetadata,
			CallID: metadata.CallID, Generation: metadata.CallGeneration}, pkt.VoIPData.SSRC, pkt.VoIPData.SequenceNum, nil)
	}
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
