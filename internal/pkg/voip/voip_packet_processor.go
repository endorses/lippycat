//go:build hunter || all

package voip

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/google/gopacket/layers"
)

// VoIPPacketProcessor processes VoIP packets (SIP/RTP) with buffering for hunter mode
type VoIPPacketProcessor struct {
	udpHandler *UDPPacketHandler
	tcpHandler *HunterForwardHandler      // Optional: for wiring ApplicationFilter to TCP handler
	assembler  *pipeline.ReassemblyEngine // TCP stream assembler for SIP reassembly
	config     *Config
}

// NewVoIPPacketProcessor creates a packet processor for VoIP buffering in hunter mode
func NewVoIPPacketProcessor(tracker *CallTracker, forwarder PacketForwarder, bufferMgr *BufferManager) *VoIPPacketProcessor {
	return &VoIPPacketProcessor{
		udpHandler: NewUDPPacketHandler(tracker, forwarder, bufferMgr),
		config:     tracker.config,
	}
}

// SetTCPHandler sets the TCP handler reference for ApplicationFilter wiring.
// This allows SetApplicationFilter to propagate to both UDP and TCP handlers.
func (p *VoIPPacketProcessor) SetTCPHandler(handler *HunterForwardHandler) {
	p.tcpHandler = handler
}

// Close drains the independently buffered SIP sinks owned by both transports.
func (p *VoIPPacketProcessor) Close() {
	p.udpHandler.Close()
	if p.tcpHandler != nil {
		p.tcpHandler.Close()
	}
}

// IdentityInheritanceSuppressed reports media packets that failed closed
// before hunter forwarding because ownership was not authoritative.
func (p *VoIPPacketProcessor) IdentityInheritanceSuppressed() uint64 {
	return p.udpHandler.IdentityInheritanceSuppressed()
}

// SetAssembler sets the TCP stream assembler for SIP message reassembly.
// When set, TCP packets are fed to the assembler for stream reconstruction.
func (p *VoIPPacketProcessor) SetAssembler(assembler *pipeline.ReassemblyEngine) {
	p.assembler = assembler
}

// SetApplicationFilter sets the application filter for proper filter matching.
// When set, this filter is used instead of the legacy sipusers.IsSurveiled() check.
// This supports all filter types including phone_number, sip_user, sipuri, ip_address, etc.
// If a TCP handler is set, the filter is also propagated to it.
func (p *VoIPPacketProcessor) SetApplicationFilter(filter ApplicationFilter) {
	p.udpHandler.SetApplicationFilter(filter)
	if p.tcpHandler != nil {
		p.tcpHandler.SetApplicationFilter(filter)
	}
}

// ProcessPacket processes a packet and returns true if it should be forwarded immediately.
// Returns false if the packet was buffered (waiting for filter decision) or filtered out.
func (p *VoIPPacketProcessor) ProcessPacket(pktInfo capture.PacketInfo) bool {
	packet := pktInfo.Packet

	// Check if this is a network packet
	if packet.NetworkLayer() == nil {
		// Not a network packet, drop it
		logger.Debug("Dropping non-network packet in VoIP mode")
		return false
	}

	// Check if it has a transport layer
	if packet.TransportLayer() == nil {
		// No transport layer (e.g., ICMP, ARP) - drop in VoIP mode
		// VoIP traffic is TCP or UDP only
		logger.Debug("Dropping non-transport packet in VoIP mode",
			"type", packet.NetworkLayer().LayerType())
		return false
	}

	// Handle based on transport protocol
	switch layer := packet.TransportLayer().(type) {
	case *layers.TCP:
		// TCP packets are fed to the TCP stream assembler for SIP reassembly.
		// The assembler reconstructs complete SIP messages and calls HunterForwardHandler.
		// HunterForwardHandler checks filters and forwards matched calls to processor.
		if p.assembler != nil {
			// Get the network flow for buffering and assembly
			flow := packet.NetworkLayer().NetworkFlow()
			transportFlow := layer.TransportFlow()

			// Buffer the raw packet for later forwarding when SIP message is matched
			BufferTCPPacketWithConfig(flow, transportFlow, pktInfo, p.config)

			// Feed the packet to the TCP assembler for stream reconstruction
			if err := p.assembler.Assemble(captureadapter.FromPacketInfo(pktInfo, pipeline.SourceLiveCapture)); err != nil {
				logger.Error("Failed to assemble TCP packet", "error", err)
			}
		} else {
			logger.Debug("TCP packet received but no assembler configured - dropping",
				"src_port", layer.SrcPort,
				"dst_port", layer.DstPort)
		}
		// Return false - TCP packets are handled asynchronously via the assembler
		// The HunterForwardHandler will forward matched packets when SIP is reassembled
		return false

	case *layers.UDP:
		// UDP packets (SIP/RTP) go through the buffer manager
		shouldForward := p.udpHandler.HandleUDPPacket(pktInfo, layer)
		if shouldForward {
			logger.Debug("UDP VoIP packet forwarded immediately",
				"src", layer.SrcPort,
				"dst", layer.DstPort)
		}
		// UDPPacketHandler owns accepted forwarding so buffered releases and
		// immediate packets share one provenance-aware enqueue path.
		return false

	default:
		// Unknown transport (not TCP/UDP) - drop when in VoIP mode
		// VoIP traffic is TCP or UDP only; other protocols should be filtered out
		logger.Debug("Dropping non-TCP/UDP packet in VoIP mode",
			"type", packet.TransportLayer().LayerType())
		return false
	}
}
