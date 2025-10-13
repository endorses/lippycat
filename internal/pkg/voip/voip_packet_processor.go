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
}

// NewVoIPPacketProcessor creates a packet processor for VoIP buffering in hunter mode
func NewVoIPPacketProcessor(forwarder PacketForwarder, bufferMgr *BufferManager) *VoIPPacketProcessor {
	return &VoIPPacketProcessor{
		udpHandler: NewUDPPacketHandler(forwarder, bufferMgr),
	}
}

// ProcessPacket processes a packet and returns true if it should be forwarded immediately.
// Returns false if the packet was buffered (waiting for filter decision) or filtered out.
func (p *VoIPPacketProcessor) ProcessPacket(pktInfo capture.PacketInfo) bool {
	packet := pktInfo.Packet

	// Check if this is a network packet with transport layer
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		// Not a network packet, forward as-is
		return true
	}

	// Handle based on transport protocol
	switch layer := packet.TransportLayer().(type) {
	case *layers.TCP:
		// TCP packets are handled by the TCP stream assembler
		// which is set up separately via NewSipStreamFactory
		// So we forward TCP packets immediately - they'll be
		// reassembled and processed by HunterForwardHandler
		return true

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
		// Unknown transport, forward as-is
		return true
	}
}
