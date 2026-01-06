//go:build hunter || all
// +build hunter all

package voip

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/layers"
)

// VoIPPacketProcessor processes VoIP packets (SIP/RTP) with buffering for hunter mode
type VoIPPacketProcessor struct {
	udpHandler *UDPPacketHandler
	tcpHandler *HunterForwardHandler // Optional: for wiring ApplicationFilter to TCP handler
}

// NewVoIPPacketProcessor creates a packet processor for VoIP buffering in hunter mode
func NewVoIPPacketProcessor(forwarder PacketForwarder, bufferMgr *BufferManager) *VoIPPacketProcessor {
	return &VoIPPacketProcessor{
		udpHandler: NewUDPPacketHandler(forwarder, bufferMgr),
	}
}

// SetTCPHandler sets the TCP handler reference for ApplicationFilter wiring.
// This allows SetApplicationFilter to propagate to both UDP and TCP handlers.
func (p *VoIPPacketProcessor) SetTCPHandler(handler *HunterForwardHandler) {
	p.tcpHandler = handler
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
		// TCP packets are handled by the TCP stream assembler (NewSipStreamFactory)
		// which reassembles SIP messages and checks filters via HunterForwardHandler.
		// Return false to let the assembler handle them - don't forward raw TCP packets.
		// The assembler will forward complete, filtered SIP messages.
		return false

	case *layers.UDP:
		// UDP packets (SIP/RTP) go through the buffer manager
		shouldForward := p.udpHandler.HandleUDPPacket(pktInfo, layer)
		if shouldForward {
			logger.Debug("UDP VoIP packet forwarded immediately",
				"src", layer.SrcPort,
				"dst", layer.DstPort)
		}
		return shouldForward

	default:
		// Unknown transport (not TCP/UDP) - drop when in VoIP mode
		// VoIP traffic is TCP or UDP only; other protocols should be filtered out
		logger.Debug("Dropping non-TCP/UDP packet in VoIP mode",
			"type", packet.TransportLayer().LayerType())
		return false
	}
}
