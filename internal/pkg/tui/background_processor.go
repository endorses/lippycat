//go:build tui || all

package tui

import (
	"sync"
	"sync/atomic"

	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

// BackgroundProcessorConfig holds configuration for the background processor
type BackgroundProcessorConfig struct {
	DNSView     *components.DNSQueriesView
	HTTPView    *components.HTTPView
	EmailView   *components.EmailView
	CallAgg     *LocalCallAggregator
	CaptureMode components.CaptureMode
}

// BackgroundProcessor handles non-critical packet processing in a separate goroutine
// to prevent blocking the TUI's Update() loop. It processes:
// - DNS metadata parsing
// - HTTP metadata parsing
// - Email metadata extraction
// - Call aggregator updates
type BackgroundProcessor struct {
	mu sync.RWMutex

	// Processing channels - buffered to absorb bursts
	packetChan chan backgroundPacket
	done       chan struct{}

	// Views to update (set via Configure)
	dnsView   *components.DNSQueriesView
	httpView  *components.HTTPView
	emailView *components.EmailView

	// Call aggregator
	callAgg     *LocalCallAggregator
	captureMode components.CaptureMode

	// Statistics
	packetsProcessed int64
	packetsDropped   int64
}

// backgroundPacket holds packet data for background processing
type backgroundPacket struct {
	Packet   components.PacketDisplay
	LinkType layers.LinkType
}

// NewBackgroundProcessor creates a new background processor
func NewBackgroundProcessor() *BackgroundProcessor {
	bp := &BackgroundProcessor{
		packetChan: make(chan backgroundPacket, 1000), // Large buffer for bursts
		done:       make(chan struct{}),
	}
	go bp.run()
	return bp
}

// Configure sets the views and call aggregator to update
// This must be called before packets are submitted
func (bp *BackgroundProcessor) Configure(config BackgroundProcessorConfig) {
	bp.mu.Lock()
	defer bp.mu.Unlock()

	bp.dnsView = config.DNSView
	bp.httpView = config.HTTPView
	bp.emailView = config.EmailView
	bp.callAgg = config.CallAgg
	bp.captureMode = config.CaptureMode
}

// SetCallAggregator updates the call aggregator (for mode switching)
func (bp *BackgroundProcessor) SetCallAggregator(agg *LocalCallAggregator, mode components.CaptureMode) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.callAgg = agg
	bp.captureMode = mode
}

// Submit adds a packet for background processing (non-blocking)
func (bp *BackgroundProcessor) Submit(packet components.PacketDisplay, linkType layers.LinkType) {
	select {
	case bp.packetChan <- backgroundPacket{Packet: packet, LinkType: linkType}:
		// Successfully queued
	default:
		// Queue full - drop packet for background processing
		// This is acceptable since background processing is non-critical
		atomic.AddInt64(&bp.packetsDropped, 1)
	}
}

// SubmitBatch adds multiple packets for background processing (non-blocking)
func (bp *BackgroundProcessor) SubmitBatch(packets []components.PacketDisplay, linkType layers.LinkType) {
	for i := range packets {
		bp.Submit(packets[i], linkType)
	}
}

// Stop shuts down the background processor
func (bp *BackgroundProcessor) Stop() {
	close(bp.done)
}

// Stats returns processing statistics
func (bp *BackgroundProcessor) Stats() (processed, dropped int64) {
	return atomic.LoadInt64(&bp.packetsProcessed), atomic.LoadInt64(&bp.packetsDropped)
}

// run is the main processing loop
func (bp *BackgroundProcessor) run() {
	for {
		select {
		case <-bp.done:
			return
		case bgPkt := <-bp.packetChan:
			bp.processPacket(bgPkt)
			atomic.AddInt64(&bp.packetsProcessed, 1)
		}
	}
}

// processPacket handles non-critical processing for a single packet
func (bp *BackgroundProcessor) processPacket(bgPkt backgroundPacket) {
	bp.mu.RLock()
	dnsView := bp.dnsView
	httpView := bp.httpView
	emailView := bp.emailView
	callAgg := bp.callAgg
	captureMode := bp.captureMode
	bp.mu.RUnlock()

	packet := bgPkt.Packet

	// Process DNS packets
	if packet.Protocol == "DNS" {
		// Parse DNS from raw data if not already parsed
		if packet.DNSData == nil && len(packet.RawData) > 0 {
			packet.DNSData = parseDNSFromRawData(packet.RawData, bgPkt.LinkType)
		}
		if packet.DNSData != nil && dnsView != nil {
			typesPacket := types.PacketDisplay(packet)
			dnsView.UpdateFromPacket(&typesPacket)
		}
	}

	// Process HTTP packets
	if packet.Protocol == "HTTP" {
		// Parse HTTP from raw data if not already parsed
		if packet.HTTPData == nil && len(packet.RawData) > 0 {
			packet.HTTPData = parseHTTPFromRawData(packet.RawData, bgPkt.LinkType)
		}
		if packet.HTTPData != nil && httpView != nil {
			typesPacket := types.PacketDisplay(packet)
			httpView.UpdateFromPacket(&typesPacket)
		}
	}

	// Process Email packets
	if packet.EmailData != nil && emailView != nil {
		typesPacket := types.PacketDisplay(packet)
		emailView.UpdateFromPacket(&typesPacket)
	}

	// Process through call aggregator for VoIP packets
	if callAgg != nil && (packet.Protocol == "SIP" || packet.Protocol == "RTP") {
		if captureMode == components.CaptureModeOffline || captureMode == components.CaptureModeLive {
			typesPacket := types.PacketDisplay(packet)
			callAgg.ProcessPacket(&typesPacket)
		}
	}
}
