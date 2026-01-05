//go:build hunter || all

package email

import (
	"context"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// EmailPacketProcessor processes email packets (SMTP) with TCP reassembly for hunter mode.
// It buffers TCP packets and feeds them to the assembler for SMTP parsing.
// When a complete email is detected (DATA_COMPLETE), the handler applies content filtering
// and forwards matched sessions to the processor.
type EmailPacketProcessor struct {
	ctx       context.Context
	assembler *tcpassembly.Assembler
	handler   *EmailHunterHandler
	factory   tcpassembly.StreamFactory
}

// NewEmailPacketProcessor creates a packet processor for email capture in hunter mode.
// It sets up TCP reassembly with the provided handler for content filtering.
func NewEmailPacketProcessor(ctx context.Context, forwarder EmailPacketForwarder, contentFilter *ContentFilter, config SMTPStreamFactoryConfig) *EmailPacketProcessor {
	// Create email hunter handler
	handler := NewEmailHunterHandler(forwarder, contentFilter)

	// Enable body capture for content filtering
	config.CaptureBody = true
	if config.MaxBodySize <= 0 {
		config.MaxBodySize = 64 * 1024 // 64KB default
	}

	// Create SMTP stream factory with hunter handler
	factory := NewSMTPStreamFactory(ctx, handler, config)

	// Create assembler with stream pool
	streamPool := tcpassembly.NewStreamPool(factory)
	assembler := tcpassembly.NewAssembler(streamPool)

	// Configure assembler for SMTP traffic
	assembler.MaxBufferedPagesPerConnection = 100 // Limit memory per connection
	assembler.MaxBufferedPagesTotal = 10000       // Total memory limit

	processor := &EmailPacketProcessor{
		ctx:       ctx,
		assembler: assembler,
		handler:   handler,
		factory:   factory,
	}

	// Start background cleanup goroutine
	go processor.cleanupRoutine()

	logger.Info("Email packet processor initialized with TCP reassembly",
		"capture_body", config.CaptureBody,
		"max_body_size", config.MaxBodySize,
		"server_ports", config.ServerPorts)

	return processor
}

// ProcessPacket processes an email packet and returns true if it should be forwarded immediately.
// For TCP packets, returns false (handled by assembler), for non-TCP returns false (dropped).
func (p *EmailPacketProcessor) ProcessPacket(pktInfo capture.PacketInfo) bool {
	packet := pktInfo.Packet

	// Check if this is a network packet
	if packet.NetworkLayer() == nil {
		logger.Debug("Dropping non-network packet in email mode")
		return false
	}

	// Check if it has a transport layer
	if packet.TransportLayer() == nil {
		logger.Debug("Dropping non-transport packet in email mode")
		return false
	}

	// Handle based on transport protocol
	switch layer := packet.TransportLayer().(type) {
	case *layers.TCP:
		// TCP packets - buffer and feed to assembler
		p.handleTCPPacket(pktInfo, layer)
		// Return false - packets are forwarded by handler after filter matching
		return false

	case *layers.UDP:
		// SMTP is TCP-only, drop UDP packets
		logger.Debug("Dropping UDP packet in email mode",
			"src_port", layer.SrcPort,
			"dst_port", layer.DstPort)
		return false

	default:
		logger.Debug("Dropping non-TCP/UDP packet in email mode",
			"type", packet.TransportLayer().LayerType())
		return false
	}
}

// handleTCPPacket buffers and processes a TCP packet through the assembler.
func (p *EmailPacketProcessor) handleTCPPacket(pktInfo capture.PacketInfo, tcpLayer *layers.TCP) {
	packet := pktInfo.Packet

	// Get network flow for buffering and assembly
	netFlow := packet.NetworkLayer().NetworkFlow()

	// Create session ID from flow
	sessionID := createSessionIDFromFlows(netFlow, tcpLayer)

	// Buffer the packet for potential forwarding
	BufferEmailTCPPacket(sessionID, pktInfo)

	// Feed to TCP assembler for stream reconstruction
	p.assembler.AssembleWithTimestamp(
		netFlow,
		tcpLayer,
		packet.Metadata().Timestamp,
	)
}

// createSessionIDFromFlows creates a session ID from network and transport flows.
func createSessionIDFromFlows(netFlow gopacket.Flow, tcpLayer *layers.TCP) string {
	// Create transport flow using TCP's built-in method
	transportFlow := tcpLayer.TransportFlow()
	return createSessionID(netFlow, transportFlow)
}

// cleanupRoutine periodically cleans up stale buffers and old assembler streams.
func (p *EmailPacketProcessor) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			// Clean up old email TCP buffers
			CleanupOldEmailBuffers(60 * time.Second)

			// Flush old assembler connections
			flushed, _ := p.assembler.FlushOlderThan(time.Now().Add(-60 * time.Second))
			if flushed > 0 {
				logger.Debug("Flushed old email TCP streams", "count", flushed)
			}

			// Cleanup stale handler sessions
			p.handler.CleanupStaleSessions()
		}
	}
}

// UpdateContentFilter updates the content filter configuration at runtime.
func (p *EmailPacketProcessor) UpdateContentFilter(filter *ContentFilter) {
	p.handler.UpdateContentFilter(filter)
}

// GetHandler returns the email hunter handler.
func (p *EmailPacketProcessor) GetHandler() *EmailHunterHandler {
	return p.handler
}

// GetBufferStats returns TCP buffer statistics.
func (p *EmailPacketProcessor) GetBufferStats() EmailTCPBufferStats {
	return GetEmailTCPBufferStats()
}

// Close gracefully shuts down the processor.
func (p *EmailPacketProcessor) Close() {
	// Flush remaining streams
	if p.assembler != nil {
		p.assembler.FlushAll()
	}

	// Close the factory if it supports closing
	if closer, ok := p.factory.(interface{ Close() }); ok {
		closer.Close()
	}

	logger.Info("Email packet processor closed")
}
