//go:build (processor || tap || all) && li

package processor

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/types"
	"time"
)

func (p *Processor) processLIRADIUSPacket(display *types.PacketDisplay, packet *data.CapturedPacket, batch *source.PacketBatch) {
	if p.liManager == nil || batch == nil || !batch.RADIUSSourceTrusted {
		return
	}
	observation, err := grpcadapter.RADIUSFromProto(packet)
	if err != nil || observation == nil || observation.Scope.OriginNodeID != batch.SourceID {
		return
	}
	display.RADIUSData = types.RADIUSMetadataFromObservation(observation)
	p.liManager.ProcessPacketWithProvenance(display, li.PacketFilterProvenance{RADIUS: observation, RADIUSTrusted: true})
}

// deliverLIRADIUS is called only after the manager has validated complete current
// attribution. Check eligibility before encoding and acquire a fresh task lease
// for queue admission so task changes during allocation or encoding take effect.
func (p *Processor) deliverLIRADIUS(task *li.InterceptTask, observation *radius.Observation) {
	if task == nil || observation == nil || !li.IsRADIUSTask(task) || task.DeliveryType != li.DeliveryX2Only {
		return
	}
	admission, active := p.liManager.AcquireTaskAdmission(task.XID, task.ActivationGeneration)
	if !active {
		return
	}
	admission.Release()
	// Serialize allocation/encoding/enqueue and shutdown for this POI. This also
	// preserves sequence order when capture sources invoke callbacks concurrently.
	p.radiusLIMu.Lock()
	defer p.radiusLIMu.Unlock()
	if p.radiusLIStopped {
		liX2Skipped.Add(1)
		return
	}
	if liRADIUSEncoder == nil {
		liNoEncoder.Add(1)
		return
	}
	if p.radiusLIAllocator == nil {
		path := p.config.LIRADIUSCorrelationStateFile
		if path == "" && p.config.LIStateFile != "" {
			path = p.config.LIStateFile + ".radius-correlation"
		}
		allocator, err := li.NewRADIUSCorrelationAllocator(li.RADIUSCorrelationConfig{Path: path, NFID: p.config.ProcessorID, IPID: p.config.ProcessorID})
		if err != nil {
			liX2Errors.Add(1)
			logger.Warn("RADIUS correlation allocator unavailable", "error", err)
			return
		}
		p.radiusLIAllocator = allocator
	}
	correlation, err := p.radiusLIAllocator.Allocate(observation)
	if err != nil {
		liX2Errors.Add(1)
		logger.Warn("RADIUS correlation allocation failed", "error", err)
		return
	}
	pdu, err := liRADIUSEncoder.Encode(observation, task.XID, correlation)
	if err != nil {
		liX2Errors.Add(1)
		logger.Warn("RADIUS X2 encoding failed", "error", err)
		return
	}
	raw, err := pdu.MarshalBinary()
	if err != nil {
		liX2Errors.Add(1)
		logger.Warn("RADIUS X2 serialization failed", "error", err)
		return
	}
	liX2Encoded.Add(1)
	if liDeliveryClient == nil {
		liX2Skipped.Add(1)
		return
	}
	admission, active = p.liManager.AcquireTaskAdmission(task.XID, task.ActivationGeneration)
	if !active {
		liX2Skipped.Add(1)
		return
	}
	defer admission.Release()
	metadata := li.DeliveryMetadata{TaskGeneration: task.ActivationGeneration, CapturedAt: observation.Capture.Timestamp, AdmittedAt: time.Now()}
	if err := liDeliveryClient.SendX2WithMetadata(task.XID, task.DestinationIDs, raw, metadata); err != nil {
		liX2Errors.Add(1)
		logger.Debug("RADIUS X2 queue admission failed", "error", err)
	}
}

func (p *Processor) closeLIRADIUS() {
	p.radiusLIMu.Lock()
	defer p.radiusLIMu.Unlock()
	p.radiusLIStopped = true
	if p.radiusLIAllocator != nil {
		if err := p.radiusLIAllocator.Close(); err != nil {
			logger.Error("Close RADIUS correlation allocator", "error", err)
		}
		p.radiusLIAllocator = nil
	}
}
