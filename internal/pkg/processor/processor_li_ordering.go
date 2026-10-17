//go:build (processor || tap || all) && li

package processor

import (
	"fmt"
	"time"

	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/li/delivery"
	"github.com/endorses/lippycat/internal/pkg/li/x2x3"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/uuid"
)

func liOrderedBufferKey(xid uuid.UUID, generation uint64) string {
	return fmt.Sprintf("%s-ordered-%d", xid, generation)
}

// queueOrderedX3 accepts one immutable observation before allocating its output
// sequence. Destination permits reserve exact product/storage ownership first;
// all copies receive the same sequence only after the shared RTP ordering stage.
func (p *Processor) queueOrderedX3(task *li.InterceptTask, pkt *types.PacketDisplay, data []byte, sequence *x2x3.DeferredSequence, metadata li.DeliveryMetadata, admission *CallAdmission, taskAdmission *li.TaskAdmission, ownsAdmission bool, published func()) bool {
	release := func() {
		taskAdmission.Release()
		if ownsAdmission && admission != nil {
			admission.Release()
		}
	}
	metadata.CallID = pkt.VoIPData.CallID
	if admission != nil {
		metadata.CallGeneration, metadata.CallIncarnation = admission.Generation(), admission.Incarnation()
	}
	if p.config.LIDeliveryX3SpoolDir != "" {
		var ok bool
		metadata, ok = p.persistentX3Metadata(task, pkt, metadata, admission)
		if !ok {
			release()
			recordBufferedX3Discard(len(task.DestinationIDs))
			return false
		}
	}
	permits := make([]*delivery.AcceptedX3, 0, len(task.DestinationIDs))
	for _, did := range task.DestinationIDs {
		destination, err := liDeliveryMgr.GetDestination(did)
		if err != nil || !delivery.DestinationAcceptsPDU(destination, delivery.PDUTypeX3) {
			if err != nil {
				recordBufferedX3Discard(1)
			}
			continue
		}
		copyMetadata := metadata
		copyMetadata.DestinationGeneration = li.DestinationDeliveryGeneration(destination)
		permit, err := liDeliveryClient.PrepareDeferredX3(task.XID, did, data, copyMetadata, sequence.Context())
		if err != nil {
			recordBufferedX3Discard(1)
			continue
		}
		permits = append(permits, permit)
	}
	if len(permits) == 0 {
		release()
		return false
	}
	key := liOrderedBufferKey(task.XID, task.ActivationGeneration)
	buffer, loaded := liReorderBuffers.Load(key)
	if !loaded {
		candidate := delivery.NewBudgetedCallAwareReorderBuffer(func(entry delivery.ReorderEntry) { p.emitOrderedX3(task.XID, task.ActivationGeneration, entry) }, 60*time.Millisecond, liReorderBudget, recordBufferedX3Discard)
		if candidate == nil {
			for _, permit := range permits {
				permit.Release()
			}
			release()
			recordBufferedX3Discard(len(permits))
			return false
		}
		candidate.SetWorkerGroup(liReorderWorkers)
		var exists bool
		buffer, exists = liReorderBuffers.LoadOrStore(key, candidate)
		if exists {
			candidate.Discard()
		}
	}
	accepted := buffer.(*delivery.ReorderBuffer).AcceptEntryX3AfterCommit(delivery.ReorderEntry{PDU: data, Metadata: metadata, CallID: metadata.CallID, Generation: metadata.CallGeneration, DeferredCopies: permits, DeferredSequence: sequence, ReserveCall: p.config.LIDeliveryX3SpoolDir != ""}, pkt.VoIPData.SSRC, pkt.VoIPData.SequenceNum, release)
	if accepted && published != nil {
		published()
	}
	return accepted
}

func (p *Processor) emitOrderedX3(xid uuid.UUID, generation uint64, entry delivery.ReorderEntry) {
	eligible := false
	for _, permit := range entry.DeferredCopies {
		if liDeliveryClient.DeferredX3Eligible(permit) {
			eligible = true
			break
		}
	}
	if !eligible {
		recordBufferedX3Discard(len(entry.DeferredCopies))
		return
	}
	persistent := p.config.LIDeliveryX3SpoolDir != ""
	var taskAdmission *li.TaskAdmission
	var callAdmission *CallAdmission
	release := func() {
		if taskAdmission != nil {
			taskAdmission.Release()
		}
		if callAdmission != nil {
			callAdmission.Release()
		}
	}
	acquire := func() bool {
		var active bool
		taskAdmission, active = p.liManager.AcquireTaskAdmission(xid, generation)
		if !active {
			return false
		}
		if entry.CallID != "" && p.callLifecycle != nil {
			var err error
			callAdmission, err = p.callLifecycle.AdmitGeneration(entry.CallID, entry.Generation)
			if err != nil {
				taskAdmission.Release()
				return false
			}
			if callAdmission.Incarnation() != entry.Metadata.CallIncarnation {
				release()
				return false
			}
		}
		return true
	}
	if !persistent && !acquire() {
		recordBufferedX3Discard(len(entry.DeferredCopies))
		return
	}
	defer release()
	if entry.DeferredSequence == nil {
		recordBufferedX3Discard(len(entry.DeferredCopies))
		return
	}
	sequence, err := entry.DeferredSequence.Allocate()
	if err != nil {
		liX3Errors.Add(1)
		recordBufferedX3Discard(len(entry.DeferredCopies))
		return
	}
	liX3Encoded.Add(1)
	for index, permit := range entry.DeferredCopies {
		if !persistent && index > 0 {
			release()
			taskAdmission, callAdmission = nil, nil
			if !acquire() {
				recordBufferedX3Discard(len(entry.DeferredCopies) - index)
				return
			}
		}
		if err := liDeliveryClient.SendAcceptedX3WithSequence(permit, sequence); err != nil {
			recordBufferedX3Discard(1)
			logger.Debug("Ordered X3 delivery failed", "xid", xid, "error", err)
		}
	}
}
