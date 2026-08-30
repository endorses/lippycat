//go:build processor || tap || all

package processor

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

func (p *Processor) emitProtocolEvents(batchSource string, packets []*data.CapturedPacket) {
	if p.eventRuntime == nil {
		return
	}
	producerNodeID, provenance := p.eventSource(batchSource)
	if err := p.eventRuntime.ObserveCaptured(eventanalysis.Source{NodeID: producerNodeID, CaptureSource: provenance.CaptureSource, ProcessorNodeIDs: provenance.ProcessorNodeIDs}, packets); err != nil {
		logger.Warn("Failed to analyze normalized protocol events", "source_id", batchSource, "error", err)
	}
}

func (p *Processor) eventSource(sourceID string) (string, events.SourceProvenance) {
	producerNodeID := sourceID
	if p.config.ProcessorID != "" && sourceID == p.config.ProcessorID+"-local" {
		producerNodeID = p.config.ProcessorID
	}
	provenance := events.SourceProvenance{CaptureSource: sourceID}
	if p.config.ProcessorID != "" {
		provenance.ProcessorNodeIDs = []string{p.config.ProcessorID}
	}
	return producerNodeID, provenance
}
