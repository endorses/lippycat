//go:build processor || tap || all

package processor

import (
	"bytes"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket/layers"
)

// Remote metadata carries ports but not SDP completeness. Inspect complete raw
// SIP messages once on actual ingress, independently of output/event demand.
// This diagnostic derivation never changes metadata, selection or endpoints.
type processorSDPDiagnostics struct {
	counters      sip.SDPParseCounters
	reporter      *sip.SDPDiagnosticReporter
	endpointLimit int
	stop, done    chan struct{}
	closeOnce     sync.Once
}

func newProcessorSDPDiagnostics() *processorSDPDiagnostics {
	d := &processorSDPDiagnostics{stop: make(chan struct{}), done: make(chan struct{}), endpointLimit: voip.DefaultConfig().MaxEndpointsPerCall}
	d.reporter = sip.NewSDPDiagnosticReporter(&d.counters, sip.SDPDistributedProcessorPath)
	go func() {
		defer close(d.done)
		ticker := time.NewTicker(sip.SDPWarningInterval)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				d.reporter.Report(now)
			case <-d.stop:
				return
			}
		}
	}()
	return d
}

func (d *processorSDPDiagnostics) close() {
	if d == nil {
		return
	}
	d.closeOnce.Do(func() {
		close(d.stop)
		<-d.done
		d.reporter.Flush()
	})
}

func (p *Processor) observeSDPDiagnostics(batch *source.PacketBatch) {
	if p.sdpDiagnostics == nil {
		return
	}
	// A tap's local VoIP processor already owns this parse/reporting path.
	if local, ok := p.packetSource.(*source.LocalSource); ok && local.GetVoIPProcessor() != nil && batch.SourceID == local.SourceID() {
		return
	}
	for _, envelope := range batch.Envelopes {
		if body := completeSDPBody(envelope); len(body) > 0 {
			p.sdpDiagnostics.counters.Observe(sip.ParseSDPResult(string(body), p.sdpDiagnostics.endpointLimit))
		}
	}
}

func completeSDPBody(envelope *pipeline.PacketEnvelope) []byte {
	if envelope == nil || (envelope.OriginalLength > 0 && len(envelope.Data) < envelope.OriginalLength) {
		return nil
	}
	packet := envelope.Packet()
	if packet == nil || packet.ErrorLayer() != nil {
		return nil
	}
	var payload []byte
	isTCP := false
	if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		payload = tcp.LayerPayload()
		isTCP = true
	} else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		payload = udp.LayerPayload()
	}
	if len(payload) == 0 || len(payload) > sip.MaxMessageSize {
		return nil
	}
	payload = bytes.TrimLeft(payload, "\r\n")
	lineEnd := bytes.IndexByte(payload, '\n')
	if lineEnd < 0 || !sip.IsStartLine(string(bytes.TrimSuffix(payload[:lineEnd], []byte("\r")))) {
		return nil
	}
	parsed, err := sip.Parse(payload, sip.ParseOptions{})
	if err != nil {
		return nil
	}
	if _, framed := parsed.Headers["content-length"]; isTCP && !framed {
		return nil
	}
	return parsed.SDP
}
