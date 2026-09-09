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
		p.radiusLIMu.Lock()
		p.radiusLIStats.StaleGeneration++
		p.logRADIUSDeliveryStats()
		p.radiusLIMu.Unlock()
		return
	}
	admission.Release()
	// Serialize allocation/encoding/enqueue and shutdown for this POI. This also
	// preserves sequence order when capture sources invoke callbacks concurrently.
	p.radiusLIMu.Lock()
	defer p.radiusLIMu.Unlock()
	defer func() {
		if time.Since(p.radiusLILastReport) >= time.Minute {
			p.logRADIUSDeliveryStats()
		}
	}()
	if p.radiusLIStopped {
		liX2Skipped.Add(1)
		p.radiusLIStats.Skipped++
		return
	}
	if liRADIUSEncoder == nil {
		liNoEncoder.Add(1)
		p.radiusLIStats.Skipped++
		return
	}
	if p.radiusLIAllocator == nil {
		path := p.config.LIRADIUSCorrelationStateFile
		if path == "" && p.config.LIStateFile != "" {
			path = p.config.LIStateFile + ".radius-correlation"
		}
		allocator, err := li.NewRADIUSCorrelationAllocator(li.RADIUSCorrelationConfig{RequestLifetime: p.config.LIRADIUSCorrelationLifetime, Path: path, NFID: p.config.ProcessorID, IPID: p.config.ProcessorID})
		if err != nil {
			liX2Errors.Add(1)
			p.radiusLIStats.AllocationErrors++
			logger.Warn("RADIUS correlation allocator unavailable", "error", err)
			return
		}
		p.radiusLIAllocator = allocator
	}
	correlation, err := p.radiusLIAllocator.Allocate(observation)
	if err != nil {
		liX2Errors.Add(1)
		p.radiusLIStats.AllocationErrors++
		logger.Warn("RADIUS correlation allocation failed", "error", err)
		return
	}
	pdu, err := liRADIUSEncoder.Encode(observation, task.XID, correlation)
	if err != nil {
		liX2Errors.Add(1)
		p.radiusLIStats.EncodingErrors++
		logger.Warn("RADIUS X2 encoding failed", "error", err)
		return
	}
	raw, err := pdu.MarshalBinary()
	if err != nil {
		liX2Errors.Add(1)
		p.radiusLIStats.EncodingErrors++
		logger.Warn("RADIUS X2 serialization failed", "error", err)
		return
	}
	liX2Encoded.Add(1)
	p.radiusLIStats.Encoded++
	if liDeliveryClient == nil {
		liX2Skipped.Add(1)
		p.radiusLIStats.Skipped++
		return
	}
	admission, active = p.liManager.AcquireTaskAdmission(task.XID, task.ActivationGeneration)
	if !active {
		p.radiusLIStats.StaleGeneration++
		liX2Skipped.Add(1)
		p.radiusLIStats.Skipped++
		return
	}
	defer admission.Release()
	metadata := li.DeliveryMetadata{TaskGeneration: task.ActivationGeneration, CapturedAt: observation.Capture.Timestamp, AdmittedAt: time.Now()}
	if err := liDeliveryClient.SendX2WithMetadata(task.XID, task.DestinationIDs, raw, metadata); err != nil {
		liX2Errors.Add(1)
		p.radiusLIStats.QueueErrors++
		logger.Debug("RADIUS X2 queue admission failed", "error", err)
	} else {
		p.radiusLIStats.QueueAccepted++
	}
}

func (p *Processor) closeLIRADIUS() {
	p.radiusLIMu.Lock()
	defer p.radiusLIMu.Unlock()
	p.radiusLIStopped = true
	p.logRADIUSDeliveryStats()
	if p.radiusLIAllocator != nil {
		if err := p.radiusLIAllocator.Close(); err != nil {
			logger.Error("Close RADIUS correlation allocator", "error", err)
		}
		p.radiusLIAllocator = nil
	}
}

func (p *Processor) logRADIUSDeliveryStats() {
	s := p.radiusLIStats
	logger.Info("RADIUS X2 counters", "processor_id", p.config.ProcessorID,
		"stale_generations", s.StaleGeneration, "allocation_errors", s.AllocationErrors,
		"encoding_errors", s.EncodingErrors, "encoded", s.Encoded, "queue_accepted", s.QueueAccepted,
		"queue_errors", s.QueueErrors, "skipped", s.Skipped)
	p.radiusLILastReport = time.Now()
}
