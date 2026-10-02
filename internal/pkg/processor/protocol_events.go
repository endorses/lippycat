//go:build processor || tap || all

package processor

import (
	"fmt"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/fileanalysis"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// monitorEventMode follows negotiated forwarding when an upstream exists, and
// the configured mode for standalone nodes.
func (p *Processor) monitorEventMode() bool {
	if p.upstreamManager != nil {
		return p.upstreamManager.ForwardingEvents()
	}
	return p.config.UpstreamForwardMode == "events"
}

func (p *Processor) wantsEventAnalysis() bool {
	p.eventAnalysisMu.RLock()
	defer p.eventAnalysisMu.RUnlock()
	return p.wantsEventAnalysisLocked()
}

func (p *Processor) wantsEventAnalysisLocked() bool {
	if p.eventAnalysisClosed {
		return false
	}
	if p.localEventAnalysis || (p.eventAnalysisSubscribers > 0 && p.monitorEventMode()) {
		return true
	}
	if p.upstreamManager != nil {
		return p.upstreamManager.ForwardingEvents()
	}
	return p.config.UpstreamAddr != "" && p.config.UpstreamForwardMode == "events"
}

func (p *Processor) initializeEventAnalysis() error {
	p.eventAnalysisMu.Lock()
	defer p.eventAnalysisMu.Unlock()
	return p.initializeEventAnalysisLocked()
}

func (p *Processor) initializeEventAnalysisLocked() error {
	if p.eventAnalysisClosed {
		return fmt.Errorf("event analysis is shut down")
	}
	if p.eventRuntime != nil {
		return nil
	}
	fileCfg := fileanalysis.Config{}
	includeHeaders, includeEmailBody := false, false
	if cfg := p.config.LogConfig; cfg != nil {
		fileCfg = fileanalysis.Config{MaxFileSize: cfg.FileMaxSize, MaxTotalSize: cfg.FileTotalSize, Extract: cfg.ExtractFiles, Directory: cfg.ExtractionDirectory}
		includeHeaders, includeEmailBody = cfg.IncludeHTTPHeaders, cfg.IncludeEmailBodyPreview
	}
	runtime, err := eventanalysis.New(eventanalysis.Config{
		Dispatcher: p.eventDispatcher, Files: fileCfg,
		IncludeHTTPHeaders: includeHeaders, IncludeEmailBodyPreview: includeEmailBody,
		LiveExpiry: true,
	})
	if err != nil {
		return fmt.Errorf("initialize event analysis runtime: %w", err)
	}
	p.eventRuntime = runtime
	return nil
}

func (p *Processor) emitProtocolEvents(batchSource string, packets []*data.CapturedPacket) {
	p.eventAnalysisMu.RLock()
	defer p.eventAnalysisMu.RUnlock()
	if p.eventRuntime == nil || !p.wantsEventAnalysisLocked() {
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

// beginEventSubscription enables capture analysis only for event-mode nodes.
// Packet-mode subscriptions can still consume normalized upstream ingress.
func (p *Processor) beginEventSubscription() (func(), error) {
	p.eventAnalysisMu.Lock()
	defer p.eventAnalysisMu.Unlock()
	if p.eventAnalysisClosed {
		return nil, fmt.Errorf("event analysis is shut down")
	}
	if !p.monitorEventMode() {
		return func() {}, nil
	}
	if err := p.initializeEventAnalysisLocked(); err != nil {
		return nil, err
	}
	p.eventAnalysisSubscribers++
	return p.endEventSubscription, nil
}

func (p *Processor) endEventSubscription() {
	p.eventAnalysisMu.Lock()
	defer p.eventAnalysisMu.Unlock()
	p.eventAnalysisSubscribers--
	p.releaseUnusedEventAnalysisLocked()
}

func (p *Processor) releaseUnusedEventAnalysisLocked() {
	if p.eventRuntime != nil && !p.wantsEventAnalysisLocked() {
		p.eventRuntime.Close()
		p.eventRuntime = nil
	}
}

func (p *Processor) resetEventAnalysis() error {
	p.eventAnalysisMu.RLock()
	defer p.eventAnalysisMu.RUnlock()
	if p.eventRuntime != nil {
		return p.eventRuntime.Reset()
	}
	return nil
}

func (p *Processor) eventAnalysisStats() eventanalysis.Stats {
	p.eventAnalysisMu.RLock()
	defer p.eventAnalysisMu.RUnlock()
	if p.eventRuntime != nil {
		return p.eventRuntime.Stats()
	}
	return eventanalysis.Stats{}
}
