package voip

import (
	"context"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// handleTcpPackets processes TCP packets and feeds them to the assembler
func handleTcpPackets(pkt capture.PacketInfo, layer *layers.TCP, assembler *tcpassembly.Assembler) {
	// Set the current link type for TCP stream processing
	if linkLayer := pkt.Packet.LinkLayer(); linkLayer != nil {
		setCurrentLinkType(layers.LinkTypeEthernet) // Default to ethernet
	}

	// Process through plugin system if enabled
	if err := ProcessPacketWithPlugins(context.Background(), pkt.Packet); err != nil {
		logger.Debug("Plugin processing error for TCP packet", "error", err)
	}

	// Buffer the packet for potential PCAP writing
	flow := pkt.Packet.NetworkLayer().NetworkFlow()
	BufferTCPPacket(flow, pkt)

	// Feed the packet to the TCP assembler for stream reconstruction
	assembler.AssembleWithTimestamp(
		pkt.Packet.NetworkLayer().NetworkFlow(),
		layer,
		pkt.Packet.Metadata().Timestamp,
	)
}
